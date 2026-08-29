# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Verifying what arrives back, per `ori-specs/evidence-exchange/v1`.

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
from dataclasses import dataclass
from typing import Any, Mapping

from ori.security.evidence.authority_keys import (
    PURPOSE_EPOCH,
    PURPOSE_RECEIPT,
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
EPOCH_DOMAIN = b"ori.evidence_epoch_confirmation.v1\x00"

PURPOSE_CUSTODY = "gateway_custody"

ARTIFACT_VERSION = 1

CUSTODY_FIELDS = frozenset(
    {"v", "device_id", "local_seq", "envelope_digest", "custody_at_ms", "key_id", "mac"}
)
RECEIPT_FIELDS = frozenset(
    {
        "v",
        "device_id",
        "from_seq",
        "to_seq",
        "range_digest",
        "accepted_at_ms",
        "key_id",
        "signature",
    }
)
EPOCH_FIELDS = frozenset(
    {
        "v",
        "device_id",
        "anchor_epoch_id",
        "pubkey_hex",
        "actor",
        "confirmed_at_ms",
        "key_id",
        "signature",
    }
)

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
REJECT_REASONS = frozenset(
    {
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


def _require_shape(artifact: Any, fields: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(artifact, dict):
        raise IngestRejectedError(REJECT_MALFORMED, f"the {label} is not an object")
    present = set(artifact)
    if present != set(fields):
        raise IngestRejectedError(
            REJECT_MALFORMED,
            f"the {label} carries {sorted(present - set(fields))} and is missing "
            f"{sorted(set(fields) - present)}",
        )
    # Version is checked before anything else is trusted: an unrecognised
    # version means the rest of the object is not this contract's to interpret,
    # and guessing at it is how a future field gets silently ignored.
    if artifact.get("v") != ARTIFACT_VERSION:
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


def _decode_ed25519(wire: Any) -> bytes:
    text = str(wire)
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
    registry: dict[tuple[str, str], AuthorityKey], purpose: str, key_id: Any
) -> AuthorityKey:
    try:
        return select_verifying_key(registry, purpose, str(key_id))
    except AuthorityKeyError as exc:
        # Named at each branch rather than computed into a variable, so every
        # call site states its reason literally and can be checked statically.
        # A reason assembled at runtime is one nothing can audit.
        if "is held for" in str(exc):
            raise IngestRejectedError(REJECT_WRONG_PURPOSE, str(exc)) from exc
        raise IngestRejectedError(REJECT_UNKNOWN_KEY, str(exc)) from exc


def _verify_ed25519(
    key: AuthorityKey, signature: bytes, signed: bytes, label: str
) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key.public_key_hex)).verify(
            signature, signed
        )
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
    parsed = _require_shape(artifact, CUSTODY_FIELDS, "custody acknowledgement")

    # Shape before registry: an identifier that cannot name any generation is
    # malformed, which is a different fact from one that is well formed and not
    # held. Comparison is byte-exact, so uppercase hex is malformed rather than
    # equivalent.
    key_id = str(parsed["key_id"])
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
    mac_wire = str(parsed["mac"])
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

    if str(parsed["device_id"]) != device_id:
        raise IngestRejectedError(
            REJECT_BINDING_MISMATCH, "the custody names another device"
        )
    if int(parsed["local_seq"]) != int(expected_local_seq):
        raise IngestRejectedError(
            REJECT_UNKNOWN_SEQUENCE, "the custody names another envelope"
        )
    if str(parsed["envelope_digest"]) != expected_digest:
        raise IngestRejectedError(
            REJECT_BINDING_MISMATCH,
            "the custody digest does not match the envelope this device sealed",
        )
    return VerifiedCustody(
        device_id=str(parsed["device_id"]),
        local_seq=int(parsed["local_seq"]),
        envelope_digest=str(parsed["envelope_digest"]),
        custody_at_ms=int(parsed["custody_at_ms"]),
        key_id=str(parsed["key_id"]),
    )


def verify_delivery_receipt(
    artifact: Any,
    *,
    device_id: str,
    registry: dict[tuple[str, str], AuthorityKey],
    envelope_digests: dict[int, str],
) -> VerifiedReceipt:
    """Prove the authority recorded exactly the range it claims.

    The range digest is what makes the prefix claim checkable: it covers the
    raw digests of every envelope in the closed interval, in order, so a
    receipt cannot assert a range it did not actually receive. Recomputing it
    locally is the difference between a receipt that says something and one
    that merely looks signed.
    """
    parsed = _require_shape(artifact, RECEIPT_FIELDS, "delivery receipt")
    key = _select(registry, PURPOSE_RECEIPT, parsed["key_id"])
    signature = _decode_ed25519(parsed["signature"])
    _verify_ed25519(
        key, signature, _signing_bytes(parsed, "signature", RECEIPT_DOMAIN), "receipt"
    )

    if str(parsed["device_id"]) != device_id:
        raise IngestRejectedError(
            REJECT_BINDING_MISMATCH, "the receipt names another device"
        )

    from_seq, to_seq = int(parsed["from_seq"]), int(parsed["to_seq"])
    if from_seq < 1 or to_seq < from_seq:
        raise IngestRejectedError(
            REJECT_NON_CONTIGUOUS, "the receipt range is not a closed interval"
        )

    missing = [
        seq for seq in range(from_seq, to_seq + 1) if seq not in envelope_digests
    ]
    if missing:
        raise IngestRejectedError(
            REJECT_UNKNOWN_SEQUENCE,
            f"the receipt covers {len(missing)} sequences this device never sealed",
        )
    concatenated = b"".join(
        bytes.fromhex(envelope_digests[seq].split("sha256:", 1)[-1])
        for seq in range(from_seq, to_seq + 1)
    )
    expected = "sha256:" + hashlib.sha256(concatenated).hexdigest()
    if str(parsed["range_digest"]) != expected:
        raise IngestRejectedError(
            REJECT_BINDING_MISMATCH,
            "the receipt range digest does not match the envelopes this device sealed",
        )
    return VerifiedReceipt(
        device_id=str(parsed["device_id"]),
        from_seq=from_seq,
        to_seq=to_seq,
        range_digest=str(parsed["range_digest"]),
        accepted_at_ms=int(parsed["accepted_at_ms"]),
        key_id=str(parsed["key_id"]),
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
    parsed = _require_shape(artifact, EPOCH_FIELDS, "epoch confirmation")
    key = _select(registry, PURPOSE_EPOCH, parsed["key_id"])
    signature = _decode_ed25519(parsed["signature"])
    _verify_ed25519(
        key,
        signature,
        _signing_bytes(parsed, "signature", EPOCH_DOMAIN),
        "epoch confirmation",
    )

    if str(parsed["device_id"]) != device_id:
        raise IngestRejectedError(
            REJECT_BINDING_MISMATCH, "the confirmation names another device"
        )
    if str(parsed["pubkey_hex"]).lower() != expected_pubkey_hex.lower():
        raise IngestRejectedError(
            REJECT_BINDING_MISMATCH,
            "the confirmation names a verification key that is not this device's",
        )
    if not str(parsed["anchor_epoch_id"]):
        raise IngestRejectedError(REJECT_MALFORMED, "the confirmation names no epoch")
    return VerifiedEpochConfirmation(
        device_id=str(parsed["device_id"]),
        anchor_epoch_id=str(parsed["anchor_epoch_id"]),
        pubkey_hex=str(parsed["pubkey_hex"]),
        actor=str(parsed["actor"]),
        confirmed_at_ms=int(parsed["confirmed_at_ms"]),
        key_id=str(parsed["key_id"]),
    )
