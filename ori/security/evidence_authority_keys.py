# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The authority keys this device will verify evidence artifacts against.

Receipts and epoch confirmations are the authority telling a device what it may
believe: that evidence arrived, that an epoch is active. The keys that make
those statements trustworthy are therefore trust roots, and where they come
from decides whether any of it means anything.

They come from the signed release, and only from there. `evidence-exchange/v1`
is explicit: a device MUST NOT accept an authority key delivered through the
exchange itself. An authority that can hand a device new trust roots over the
channel it is being trusted on has no independent standing — it could replace
the keys that check its own claims, and every subsequent verification would
succeed by construction.

Purposes are disjoint and enforced. A key held for issuing receipts must not
verify an epoch confirmation, because those assert different things: one says
evidence was recorded, the other says an anchor is active. Accepting either
under the other's key collapses a distinction the fail-closed rules depend on.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

PURPOSE_RECEIPT = "evidence_authority_receipt"
PURPOSE_EPOCH = "evidence_authority_epoch"
AUTHORITY_PURPOSES = frozenset({PURPOSE_RECEIPT, PURPOSE_EPOCH})

REGISTRY_SCHEMA = "ori.evidence_authority_keys.v1"

# `active` signs and verifies, `verify_only` verifies what it signed before a
# rotation, `revoked` verifies nothing. A retired key that still verified would
# make rotation cosmetic.
STATUS_ACTIVE = "active"
STATUS_VERIFY_ONLY = "verify_only"
STATUS_REVOKED = "revoked"
_VERIFYING_STATUSES = frozenset({STATUS_ACTIVE, STATUS_VERIFY_ONLY})
_STATUSES = _VERIFYING_STATUSES | {STATUS_REVOKED}

_REGISTRY_FIELDS = {"schema", "keys"}
_KEY_FIELDS = {"key_id", "public_key_hex", "purpose", "status"}


class AuthorityKeyError(RuntimeError):
    """The authority key registry could not be loaded or trusted."""


@dataclass(frozen=True)
class AuthorityKey:
    key_id: str
    public_key_hex: str
    purpose: str
    status: str

    @property
    def verifies(self) -> bool:
        return self.status in _VERIFYING_STATUSES


def _require_exact_fields(
    obj: dict[str, object], expected: set[str], label: str
) -> None:
    actual = set(obj)
    if actual != expected:
        unexpected = sorted(actual - expected)
        missing = sorted(expected - actual)
        raise AuthorityKeyError(
            f"{label} fields are wrong: unexpected {unexpected}, missing {missing}"
        )


def load_authority_key_registry(
    path: str | Path,
) -> dict[tuple[str, str], AuthorityKey]:
    """Load the release-shipped registry, keyed by `(purpose, key_id)`.

    Keyed by the pair deliberately. A verifier selects by purpose *and*
    identity, so the same `key_id` under two purposes is two different keys and
    a lookup that ignored purpose would let one stand in for the other.
    """
    source = Path(path)
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AuthorityKeyError(f"no authority key registry at {source}") from exc
    except ValueError as exc:
        raise AuthorityKeyError("the authority key registry is not valid JSON") from exc

    if not isinstance(raw, dict):
        raise AuthorityKeyError("the authority key registry must be an object")
    _require_exact_fields(raw, _REGISTRY_FIELDS, "authority key registry")
    if raw.get("schema") != REGISTRY_SCHEMA:
        raise AuthorityKeyError(
            f"unsupported authority key registry schema {raw.get('schema')!r}"
        )
    entries = raw.get("keys")
    if not isinstance(entries, list) or not entries:
        raise AuthorityKeyError("the authority key registry must contain keys")

    registry: dict[tuple[str, str], AuthorityKey] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise AuthorityKeyError(f"authority key #{index + 1} is not an object")
        _require_exact_fields(entry, _KEY_FIELDS, f"authority key #{index + 1}")
        key_id = str(entry["key_id"])
        purpose = str(entry["purpose"])
        status = str(entry["status"])
        public_key_hex = str(entry["public_key_hex"])
        if not key_id:
            raise AuthorityKeyError(f"authority key #{index + 1} has no key_id")
        if purpose not in AUTHORITY_PURPOSES:
            raise AuthorityKeyError(
                f"authority key {key_id!r} carries purpose {purpose!r}, which this "
                "registry does not govern"
            )
        if status not in _STATUSES:
            raise AuthorityKeyError(f"authority key {key_id!r} has status {status!r}")
        try:
            raw_key = bytes.fromhex(public_key_hex)
        except ValueError as exc:
            raise AuthorityKeyError(
                f"authority key {key_id!r} public key is not hex"
            ) from exc
        if len(raw_key) != 32:
            raise AuthorityKeyError(
                f"authority key {key_id!r} is {len(raw_key)} bytes, not 32"
            )
        identity = (purpose, key_id)
        if identity in registry:
            raise AuthorityKeyError(
                f"authority key {key_id!r} appears twice for purpose {purpose!r}"
            )
        registry[identity] = AuthorityKey(
            key_id=key_id,
            public_key_hex=public_key_hex,
            purpose=purpose,
            status=status,
        )
    return registry


def select_verifying_key(
    registry: dict[tuple[str, str], AuthorityKey], purpose: str, key_id: str
) -> AuthorityKey:
    """Find the key an artifact names, refusing every near miss distinctly.

    "Unknown", "held for something else" and "revoked" are three different
    findings, and collapsing them into one would make a rotation error look
    identical to an attack.
    """
    held = registry.get((purpose, key_id))
    if held is None:
        # Named under another purpose is worth saying, because it is the shape
        # of a cross-purpose substitution rather than a missing key.
        elsewhere = sorted(
            other
            for (other, held_id) in registry
            if held_id == key_id and other != purpose
        )
        if elsewhere:
            raise AuthorityKeyError(
                f"key {key_id!r} is held for {elsewhere}, not for {purpose!r}"
            )
        raise AuthorityKeyError(f"no key {key_id!r} is held for purpose {purpose!r}")
    if not held.verifies:
        raise AuthorityKeyError(
            f"key {key_id!r} for {purpose!r} is {held.status} and verifies nothing"
        )
    return held
