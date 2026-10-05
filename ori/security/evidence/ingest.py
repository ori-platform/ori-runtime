# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Verifying what arrives back, per `ori-specs/evidence-exchange/v2`.

The runtime seals evidence and hands it to a courier. Three things come back,
and each says something different that the runtime is entitled to act on only
once it has been proven:

* a **custody acknowledgement** — the gateway holds these bytes durably;
* a **delivery receipt** — the authority recorded this contiguous range;
* an **epoch confirmation** — this anchor epoch is active.

None is interchangeable, and the verification is what stops them being. A
receipt signed under the epoch key would say "the authority recorded your
evidence" using a key held to say something else entirely, and accepting it
collapses a distinction the fail-closed rules rest on.

Every rejection is recorded rather than raised past the caller. An artifact
that fails to verify is information — about the courier, the authority, or an
attacker — and discarding it silently would leave the device unable to explain
why its evidence never reached anyone.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Any, Mapping

from ori.security.ed25519_keys import admit_public_key
from ori.security.evidence.authority_keys import (
    PURPOSE_EPOCH,
    PURPOSE_RECEIPT,
    SELECT_RETIRED_KEY,
    SELECT_WRONG_PURPOSE,
    AuthorityKey,
    AuthorityKeyError,
    select_verifying_key,
)
from ori.security.evidence.canonical import CanonicalisationError, canonical_json
from ori.security.evidence.custody_keys import (
    CUSTODY_KEY_PURPOSE,
    CUSTODY_MAC_RE,
    CustodyKeyRegistry,
    is_well_formed_key_id,
)

CUSTODY_DOMAIN = b"ori.evidence_custody_ack.v1\x00"
RECEIPT_DOMAIN = b"ori.evidence_delivery_receipt.v1\x00"
_SHA256_DIGEST_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
EPOCH_DOMAIN = b"ori.evidence_epoch_confirmation.v1\x00"

PURPOSE_CUSTODY = "gateway_custody"

ARTIFACT_VERSION = 1

#: Every field each authority artifact defines, with its exact JSON type. The
#: required set is these keys, so a field cannot be required without a type.
CUSTODY_SHAPE: Mapping[str, type] = {
    "v": int,
    "device_id": str,
    "local_seq": int,
    "envelope_digest": str,
    "custody_at_ms": int,
    "key_id": str,
    "mac": str,
}
RECEIPT_SHAPE: Mapping[str, type] = {
    "v": int,
    "device_id": str,
    "from_seq": int,
    "to_seq": int,
    "range_digest": str,
    "accepted_at_ms": int,
    "key_id": str,
    "signature": str,
}
EPOCH_SHAPE: Mapping[str, type] = {
    "v": int,
    "device_id": str,
    "anchor_epoch_id": str,
    "pubkey_hex": str,
    "actor": str,
    "confirmed_at_ms": int,
    "key_id": str,
    "signature": str,
}
CUSTODY_FIELDS = frozenset(CUSTODY_SHAPE)
RECEIPT_FIELDS = frozenset(RECEIPT_SHAPE)
EPOCH_FIELDS = frozenset(EPOCH_SHAPE)

# Why an artifact was refused. A closed set for the same reason delivery
# failure reasons are: this is recorded where an operator can read it, and a
# rejection quoting an endpoint or a private identity would disclose through
# the diagnostic channel.
REJECT_UNRECOGNISED_VERSION = "unrecognised_version"
REJECT_MALFORMED = "malformed"
REJECT_UNKNOWN_KEY = "unknown_key"
REJECT_RETIRED_KEY = "retired_key"
REJECT_WRONG_PURPOSE = "wrong_purpose"
REJECT_BAD_AUTHENTICATOR = "bad_authenticator"
REJECT_UNKNOWN_SEQUENCE = "unknown_sequence"
REJECT_BINDING_MISMATCH = "binding_mismatch"
REJECT_NON_CONTIGUOUS = "non_contiguous_range"

#: The contract's integer zone.
MAX_JSON_INTEGER = 9007199254740991


def is_json_integer(value: object) -> bool:
    """An `int` and not a `bool`, inside the contract's integer zone.

    Python's `True == 1` would otherwise read `"v": true` as version 1.
    """
    return type(value) is int and -MAX_JSON_INTEGER <= value <= MAX_JSON_INTEGER


def _has_type(value: object, expected: type) -> bool:
    if expected is int:
        return is_json_integer(value)
    if expected is str:
        return type(value) is str
    return False


#: A disposition whose effect is already in force.
REJECT_SUPERSEDED = "superseded"
REJECT_REASONS = frozenset(
    {
        REJECT_SUPERSEDED,
        REJECT_UNRECOGNISED_VERSION,
        REJECT_MALFORMED,
        REJECT_UNKNOWN_KEY,
        REJECT_RETIRED_KEY,
        REJECT_WRONG_PURPOSE,
        REJECT_BAD_AUTHENTICATOR,
        REJECT_UNKNOWN_SEQUENCE,
        REJECT_BINDING_MISMATCH,
        REJECT_NON_CONTIGUOUS,
    }
)


class IngestRejectedError(Exception):
    """An arriving artifact did not verify. Carries a closed-set reason."""

    def __init__(self, reason: str, detail: str) -> None:
        if reason not in REJECT_REASONS:
            raise ValueError(f"{reason!r} is not a recognised rejection reason")
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class VerifiedCustody:
    device_id: str
    local_seq: int
    envelope_digest: str
    custody_at_ms: int
    key_id: str


@dataclass(frozen=True)
class VerifiedReceipt:
    device_id: str
    from_seq: int
    to_seq: int
    sequences: tuple[int, ...]
    range_digest: str
    accepted_at_ms: int
    key_id: str


@dataclass(frozen=True)
class VerifiedEpochConfirmation:
    device_id: str
    anchor_epoch_id: str
    pubkey_hex: str
    actor: str
    confirmed_at_ms: int
    key_id: str


def _require_shape(
    artifact: Any, shape: Mapping[str, type], label: str
) -> dict[str, Any]:
    if not isinstance(artifact, dict):
        raise IngestRejectedError(REJECT_MALFORMED, f"the {label} is not an object")
    present = set(artifact)
    if present != set(shape):
        raise IngestRejectedError(
            REJECT_MALFORMED,
            f"the {label} carries {sorted(present - set(shape))} and is missing "
            f"{sorted(set(shape) - present)}",
        )
    # Exact JSON types before any field is read, so nothing below coerces.
    wrong = sorted(
        name
        for name, expected in shape.items()
        if not _has_type(artifact[name], expected)
    )
    if wrong:
        raise IngestRejectedError(
            REJECT_MALFORMED, f"the {label} carries {wrong} of the wrong JSON type"
        )
    # Version is checked before anything else is trusted: an unrecognised
    # version means the rest of the object is not this contract's to interpret,
    # and guessing at it is how a future field gets silently ignored.
    if artifact["v"] != ARTIFACT_VERSION:
        raise IngestRejectedError(
            REJECT_UNRECOGNISED_VERSION,
            f"the {label} declares version {artifact.get('v')!r}",
        )
    return dict(artifact)


def _signing_bytes(
    artifact: dict[str, Any], authenticator: str, domain: bytes
) -> bytes:
    body = {k: v for k, v in artifact.items() if k != authenticator}
    try:
        return domain + canonical_json(body)
    except CanonicalisationError as exc:
        raise IngestRejectedError(
            REJECT_MALFORMED, "the artifact is not canonicalisable"
        ) from exc


def _decode_ed25519(text: str) -> bytes:
    if not text.startswith("ed25519:"):
        raise IngestRejectedError(
            REJECT_MALFORMED, "a signature must carry exactly one 'ed25519:' prefix"
        )
    body = text[len("ed25519:") :]
    if "ed25519:" in body:
        raise IngestRejectedError(
            REJECT_MALFORMED, "a signature must carry exactly one prefix"
        )
    try:
        raw = base64.b64decode(body, validate=True)
    except Exception as exc:
        raise IngestRejectedError(
            REJECT_MALFORMED, "a signature must be standard Base64"
        ) from exc
    if len(raw) != 64:
        raise IngestRejectedError(
            REJECT_MALFORMED, f"a signature is 64 bytes, not {len(raw)}"
        )
    return raw


def _select(
    registry: dict[tuple[str, str], AuthorityKey], purpose: str, key_id: str
) -> AuthorityKey:
    try:
        return select_verifying_key(registry, purpose, key_id)
    except AuthorityKeyError as exc:
        # Named at each branch rather than computed into a variable, so every
        # call site states its reason literally and can be checked statically.
        # A reason assembled at runtime is one nothing can audit.
        if exc.rule == SELECT_WRONG_PURPOSE:
            raise IngestRejectedError(REJECT_WRONG_PURPOSE, str(exc)) from exc
        if exc.rule == SELECT_RETIRED_KEY:
            raise IngestRejectedError(REJECT_RETIRED_KEY, str(exc)) from exc
        raise IngestRejectedError(REJECT_UNKNOWN_KEY, str(exc)) from exc


def _verify_ed25519(
    key: AuthorityKey, signature: bytes, signed: bytes, label: str
) -> None:
    try:
        admit_public_key(bytes.fromhex(key.public_key_hex)).verify(signature, signed)
    except Exception as exc:
        raise IngestRejectedError(
            REJECT_BAD_AUTHENTICATOR, f"the {label} signature does not verify"
        ) from exc


def _held_under_another_purpose(
    key_id: str, authority_keys: Mapping[tuple[str, str], Any] | None
) -> bool:
    """Whether *key_id* is registered for some purpose other than custody."""
    if not authority_keys:
        return False
    return any(
        held_key_id == key_id and purpose != CUSTODY_KEY_PURPOSE
        for purpose, held_key_id in authority_keys
    )


def verify_custody_acknowledgement(
    artifact: Any,
    *,
    device_id: str,
    custody_keys: CustodyKeyRegistry,
    expected_digest: str,
    expected_local_seq: int,
    authority_keys: Mapping[tuple[str, str], Any] | None = None,
) -> VerifiedCustody:
    """Prove the gateway acknowledged the envelope this device actually sealed.

    Authenticated under a secret dedicated to custody rather than the
    runtime-gateway envelope secret, and with a MAC rather than a signature,
    because the gateway signs nothing on the evidence path. The MAC is what
    stops any process on the site network forging custody: the runtime uses
    custody state to manage its queue, so a forged acknowledgement would let an
    attacker cause evidence to be deprioritised that was never carried.

    The secret is **selected by `key_id`**, never found by trying each one held.
    Trial verification would accept an artifact whose `key_id` names one
    generation while its MAC was produced under another, which makes "which key
    authenticated this" unanswerable afterwards -- and during a rotation it
    would silently accept under the wrong generation.
    """
    parsed = _require_shape(artifact, CUSTODY_SHAPE, "custody acknowledgement")

    # Shape before registry: an identifier that cannot name any generation is
    # malformed, which is a different fact from one that is well formed and not
    # held. Comparison is byte-exact, so uppercase hex is malformed rather than
    # equivalent.
    key_id = parsed["key_id"]
    if not is_well_formed_key_id(key_id):
        raise IngestRejectedError(
            REJECT_MALFORMED, "a custody key_id must be hkdf-sha256 with 32 hex digits"
        )

    generation = custody_keys.lookup(key_id)
    if generation is None:
        # Purpose separation before absence. An identifier held under another
        # purpose is a different fact from one held under none, and answering
        # `unknown_key` for it would hide a key being used across purposes --
        # which is what purpose separation exists to prevent. The defect lives
        # in receiver state rather than in the artifact, so it cannot be
        # detected from the bytes alone.
        if _held_under_another_purpose(key_id, authority_keys):
            raise IngestRejectedError(
                REJECT_WRONG_PURPOSE,
                "that key_id is held for a different key purpose",
            )
        raise IngestRejectedError(
            REJECT_UNKNOWN_KEY, "no custody generation is held for that key_id"
        )
    if not generation.can_verify:
        # A tombstone: the identifier was kept and the secret destroyed, so this
        # is unverifiable by construction rather than merely unverified.
        raise IngestRejectedError(
            REJECT_RETIRED_KEY,
            "that custody generation was retired and its secret destroyed",
        )

    # Shape before comparison. A value of the wrong length or alphabet was
    # never a candidate authenticator, so reporting it as a failed
    # authentication sends an operator hunting a key mismatch that does not
    # exist. Checking only the prefix would let every one of those through.
    mac_wire = parsed["mac"]
    if not CUSTODY_MAC_RE.fullmatch(mac_wire):
        raise IngestRejectedError(
            REJECT_MALFORMED,
            "a custody MAC must be hmac-sha256 with 64 lowercase hex digits",
        )
    signed = _signing_bytes(parsed, "mac", CUSTODY_DOMAIN)
    secret = generation.secret
    assert secret is not None  # can_verify above
    expected_mac = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac_wire[len("hmac-sha256:") :], expected_mac):
        raise IngestRejectedError(
            REJECT_BAD_AUTHENTICATOR,
            "the custody MAC does not verify under the generation its key_id names",
        )

    if parsed["device_id"] != device_id:
        raise IngestRejectedError(
            REJECT_BINDING_MISMATCH, "the custody names another device"
        )
    if parsed["local_seq"] != int(expected_local_seq):
        raise IngestRejectedError(
            REJECT_UNKNOWN_SEQUENCE, "the custody names another envelope"
        )
    if parsed["envelope_digest"] != expected_digest:
        raise IngestRejectedError(
            REJECT_BINDING_MISMATCH,
            "the custody digest does not match the envelope this device sealed",
        )
    return VerifiedCustody(
        device_id=parsed["device_id"],
        local_seq=parsed["local_seq"],
        envelope_digest=parsed["envelope_digest"],
        custody_at_ms=parsed["custody_at_ms"],
        key_id=parsed["key_id"],
    )


def verify_delivery_receipt(
    artifact: Any,
    *,
    device_id: str,
    registry: dict[tuple[str, str], AuthorityKey],
    chain_row_digests: Mapping[int, str],
) -> VerifiedReceipt:
    """Prove the authority recorded exactly the range it claims.

    The range digest covers the raw 32-byte `chain_row_digest` of every sealed
    envelope in the closed interval, in ascending `local_seq` order, so a
    receipt cannot assert a range it did not actually receive. It is not taken
    over envelope digests: those cover the wire bytes, signature included.
    """
    parsed = _require_shape(artifact, RECEIPT_SHAPE, "delivery receipt")
    key = _select(registry, PURPOSE_RECEIPT, parsed["key_id"])
    signature = _decode_ed25519(parsed["signature"])
    _verify_ed25519(
        key, signature, _signing_bytes(parsed, "signature", RECEIPT_DOMAIN), "receipt"
    )

    if parsed["device_id"] != device_id:
        raise IngestRejectedError(
            REJECT_BINDING_MISMATCH, "the receipt names another device"
        )

    from_seq, to_seq = parsed["from_seq"], parsed["to_seq"]
    if from_seq < 1 or to_seq < from_seq:
        raise IngestRejectedError(
            REJECT_NON_CONTIGUOUS, "the receipt range is not a closed interval"
        )

    # Counted, never enumerated: the interval is signed, so its width is the
    # authority's to choose, and only the sealed rows inside it are walked.
    claimed = to_seq - from_seq + 1
    held = sorted(
        seq
        for seq in chain_row_digests
        if type(seq) is int and from_seq <= seq <= to_seq
    )
    if (
        len(held) != claimed
        or held[0] != from_seq
        or held[-1] != to_seq
        or any(later - earlier != 1 for earlier, later in zip(held, held[1:]))
    ):
        raise IngestRejectedError(
            REJECT_UNKNOWN_SEQUENCE,
            f"the receipt covers {claimed} sequences and this device sealed "
            f"{len(held)} of them",
        )
    unreadable = [
        seq
        for seq in held
        if not _SHA256_DIGEST_RE.fullmatch(str(chain_row_digests[seq]))
    ]
    if unreadable:
        raise IngestRejectedError(
            REJECT_BINDING_MISMATCH,
            f"{len(unreadable)} sealed chain row digests in the range are unreadable",
        )
    concatenated = b"".join(
        bytes.fromhex(str(chain_row_digests[seq])[len("sha256:") :]) for seq in held
    )
    expected = "sha256:" + hashlib.sha256(concatenated).hexdigest()
    if parsed["range_digest"] != expected:
        raise IngestRejectedError(
            REJECT_BINDING_MISMATCH,
            "the receipt range digest does not match the chain rows this device sealed",
        )
    return VerifiedReceipt(
        device_id=parsed["device_id"],
        from_seq=from_seq,
        to_seq=to_seq,
        sequences=tuple(held),
        range_digest=parsed["range_digest"],
        accepted_at_ms=parsed["accepted_at_ms"],
        key_id=parsed["key_id"],
    )


def verify_epoch_confirmation(
    artifact: Any,
    *,
    device_id: str,
    registry: dict[tuple[str, str], AuthorityKey],
    expected_pubkey_hex: str,
) -> VerifiedEpochConfirmation:
    """Prove the authority confirmed this device's anchor for an epoch.

    The confirmation names the public key it is confirming, and it must be this
    device's. Without that binding an authority statement about some other
    device's anchor would advance this one's epoch — which is the substitution
    the whole `(purpose, key_id)` and device-binding apparatus exists to stop.
    """
    parsed = _require_shape(artifact, EPOCH_SHAPE, "epoch confirmation")
    key = _select(registry, PURPOSE_EPOCH, parsed["key_id"])
    signature = _decode_ed25519(parsed["signature"])
    _verify_ed25519(
        key,
        signature,
        _signing_bytes(parsed, "signature", EPOCH_DOMAIN),
        "epoch confirmation",
    )

    if parsed["device_id"] != device_id:
        raise IngestRejectedError(
            REJECT_BINDING_MISMATCH, "the confirmation names another device"
        )
    if parsed["pubkey_hex"].lower() != expected_pubkey_hex.lower():
        raise IngestRejectedError(
            REJECT_BINDING_MISMATCH,
            "the confirmation names a verification key that is not this device's",
        )
    if not parsed["anchor_epoch_id"]:
        raise IngestRejectedError(REJECT_MALFORMED, "the confirmation names no epoch")
    return VerifiedEpochConfirmation(
        device_id=parsed["device_id"],
        anchor_epoch_id=parsed["anchor_epoch_id"],
        pubkey_hex=parsed["pubkey_hex"],
        actor=parsed["actor"],
        confirmed_at_ms=parsed["confirmed_at_ms"],
        key_id=parsed["key_id"],
    )
