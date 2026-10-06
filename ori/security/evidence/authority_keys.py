# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The authority keys this device will verify evidence artifacts against.

Receipts, epoch confirmations and dispositions are the authority telling a
device what it may believe. The keys that make those statements trustworthy are
therefore trust roots, and where they come from decides whether any of it means
anything.

They come from the signed release, and only from there. `evidence-exchange/v2`
is explicit: a device MUST NOT accept an authority key delivered through the
exchange itself. An authority that can hand a device new trust roots over the
channel it is being trusted on has no independent standing — it could replace
the keys that check its own claims, and every subsequent verification would
succeed by construction.

Purposes are disjoint and enforced. A key held for issuing receipts must not
verify an epoch confirmation, because those assert different things: one says
evidence was recorded, the other says an anchor is active. Accepting either
under the other's key collapses a distinction the fail-closed rules depend on.

The document is held to `evidence-exchange/v2`, *The authority key registry*:
exact members, all strings, lowercase hex, a `key_id` recomputed from its key,
public keys decoded under RFC 8032 section 5.1.3 with small-order points
refused, no key under two purposes, and one `active` key per purpose present.
One refused key refuses the whole registry.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ori.security.ed25519_keys import refused_public_key_clause
from ori.security.published_test_keys import PUBLISHED_TEST_KEYS

PURPOSE_RECEIPT = "evidence_authority_receipt"
PURPOSE_EPOCH = "evidence_authority_epoch"
PURPOSE_DISPOSITION = "evidence_authority_disposition"
AUTHORITY_PURPOSES = frozenset({PURPOSE_RECEIPT, PURPOSE_EPOCH, PURPOSE_DISPOSITION})
# The purposes this release has a verifier for. Disposition keys are accepted
# in a registry but verify nothing until a disposition verifier is installed.
VERIFIED_PURPOSES = frozenset({PURPOSE_RECEIPT, PURPOSE_EPOCH})

REGISTRY_SCHEMA = "ori.evidence_authority_keys.v1"

# `active` signs and verifies, `verify_only` verifies what it signed before a
# rotation, `revoked` verifies nothing. A retired key that still verified would
# make rotation cosmetic.
STATUS_ACTIVE = "active"
STATUS_VERIFY_ONLY = "verify_only"
STATUS_REVOKED = "revoked"
_VERIFYING_STATUSES = frozenset({STATUS_ACTIVE, STATUS_VERIFY_ONLY})
AUTHORITY_STATUSES = _VERIFYING_STATUSES | {STATUS_REVOKED}

_REGISTRY_FIELDS = {"schema", "keys"}
_KEY_FIELDS = {"key_id", "public_key_hex", "purpose", "status"}

_KEY_ID_RE = re.compile(r"sha256:[0-9a-f]{64}")
_PUBLIC_KEY_RE = re.compile(r"[0-9a-f]{64}")

# Registry refusals, named as the contract's corpus names them.
RULE_UNREADABLE = "unreadable"
RULE_MEMBERS = "members"
RULE_SCHEMA = "schema"
RULE_EMPTY = "empty"
RULE_KEY_ID_ENCODING = "key_id_encoding"
RULE_PUBLIC_KEY_ENCODING = "public_key_encoding"
RULE_KEY_ID_MISMATCH = "key_id_mismatch"
RULE_REFUSED_KEY = "refused_key"
RULE_PURPOSE = "purpose"
RULE_STATUS = "status"
RULE_DUPLICATE = "duplicate"
RULE_CROSS_PURPOSE = "cross_purpose"
RULE_ACTIVE_COUNT = "active_count"
RULE_PUBLISHED_TEST_KEY = "published_test_key"

# Selection refusals, named as the contract names the artifact rejection.
SELECT_UNKNOWN_KEY = "unknown_key"
SELECT_WRONG_PURPOSE = "wrong_purpose"
SELECT_RETIRED_KEY = "retired_key"


class AuthorityKeyError(RuntimeError):
    """The authority key registry could not be loaded or trusted, or a key not selected."""

    def __init__(self, rule: str, detail: str) -> None:
        super().__init__(detail)
        self.rule = rule


@dataclass(frozen=True)
class AuthorityKey:
    key_id: str
    public_key_hex: str
    purpose: str
    status: str

    @property
    def verifies(self) -> bool:
        return self.status in _VERIFYING_STATUSES


@dataclass(frozen=True)
class ReleaseAuthorityKeys:
    """What the release shipped: its keys, and whether a present registry was refused."""

    keys: dict[tuple[str, str], AuthorityKey]
    refused: bool = False


def verifying_purposes(registry: Mapping[tuple[str, str], Any]) -> frozenset[str]:
    """The purposes holding at least one key that verifies."""
    return frozenset(
        purpose
        for (purpose, _key_id), key in registry.items()
        if isinstance(key, AuthorityKey) and key.verifies
    )


def derive_key_id(public_key: bytes) -> str:
    """`sha256:` and the lowercase hex SHA-256 of the 32 raw public-key bytes."""
    return "sha256:" + hashlib.sha256(public_key).hexdigest()


def _reject_repeated_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    names = [name for name, _ in pairs]
    if len(set(names)) != len(names):
        raise AuthorityKeyError(RULE_MEMBERS, "a JSON object repeats a member name")
    return dict(pairs)


def _require_exact_fields(obj: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(obj)
    if actual != expected:
        unexpected = sorted(actual - expected)
        missing = sorted(expected - actual)
        raise AuthorityKeyError(
            RULE_MEMBERS,
            f"{label} fields are wrong: unexpected {unexpected}, missing {missing}",
        )


def _parse_key(entry: object, label: str) -> AuthorityKey:
    if not isinstance(entry, dict):
        raise AuthorityKeyError(RULE_MEMBERS, f"{label} is not an object")
    _require_exact_fields(entry, _KEY_FIELDS, label)
    key_id = entry["key_id"]
    public_key_hex = entry["public_key_hex"]
    purpose = entry["purpose"]
    status = entry["status"]
    if not (
        isinstance(key_id, str)
        and isinstance(public_key_hex, str)
        and isinstance(purpose, str)
        and isinstance(status, str)
    ):
        raise AuthorityKeyError(
            RULE_MEMBERS, f"{label} has a member that is not a string"
        )
    if purpose not in AUTHORITY_PURPOSES:
        raise AuthorityKeyError(
            RULE_PURPOSE, f"{label} carries a purpose this registry does not govern"
        )
    if status not in AUTHORITY_STATUSES:
        raise AuthorityKeyError(RULE_STATUS, f"{label} has an unknown status")
    if not _KEY_ID_RE.fullmatch(key_id):
        raise AuthorityKeyError(
            RULE_KEY_ID_ENCODING,
            f"{label} key_id is not sha256: and 64 lowercase hex digits",
        )
    if not _PUBLIC_KEY_RE.fullmatch(public_key_hex):
        raise AuthorityKeyError(
            RULE_PUBLIC_KEY_ENCODING,
            f"{label} public key is not 64 lowercase hex digits",
        )
    raw_key = bytes.fromhex(public_key_hex)
    clause = refused_public_key_clause(raw_key)
    if clause is not None:
        raise AuthorityKeyError(
            RULE_REFUSED_KEY, f"{label} public key is refused ({clause})"
        )
    if derive_key_id(raw_key) != key_id:
        raise AuthorityKeyError(
            RULE_KEY_ID_MISMATCH, f"{label} key_id is not derived from its key"
        )
    return AuthorityKey(
        key_id=key_id, public_key_hex=public_key_hex, purpose=purpose, status=status
    )


def parse_authority_key_registry(
    document: object,
) -> dict[tuple[str, str], AuthorityKey]:
    """Hold a decoded registry document to the contract, keyed by `(purpose, key_id)`."""
    if not isinstance(document, dict):
        raise AuthorityKeyError(
            RULE_MEMBERS, "the authority key registry must be an object"
        )
    _require_exact_fields(document, _REGISTRY_FIELDS, "authority key registry")
    if document["schema"] != REGISTRY_SCHEMA:
        raise AuthorityKeyError(
            RULE_SCHEMA, "unsupported authority key registry schema"
        )
    entries = document["keys"]
    if not isinstance(entries, list):
        raise AuthorityKeyError(RULE_MEMBERS, "the registry's keys must be an array")
    if not entries:
        raise AuthorityKeyError(
            RULE_EMPTY, "the authority key registry must contain keys"
        )

    registry: dict[tuple[str, str], AuthorityKey] = {}
    for index, entry in enumerate(entries):
        key = _parse_key(entry, f"authority key #{index + 1}")
        identity = (key.purpose, key.key_id)
        if identity in registry:
            raise AuthorityKeyError(
                RULE_DUPLICATE,
                f"authority key #{index + 1} repeats a (purpose, key_id)",
            )
        registry[identity] = key

    purposes_by_key_id: dict[str, set[str]] = {}
    for purpose, key_id in registry:
        purposes_by_key_id.setdefault(key_id, set()).add(purpose)
    if any(len(held) > 1 for held in purposes_by_key_id.values()):
        raise AuthorityKeyError(
            RULE_CROSS_PURPOSE, "one key_id is held under two purposes"
        )

    active = Counter(
        key.purpose for key in registry.values() if key.status == STATUS_ACTIVE
    )
    for purpose in sorted({key.purpose for key in registry.values()}):
        if active[purpose] != 1:
            raise AuthorityKeyError(
                RULE_ACTIVE_COUNT,
                f"purpose {purpose!r} holds {active[purpose]} active keys, not one",
            )
    return registry


def load_authority_key_registry(
    path: str | Path,
) -> dict[tuple[str, str], AuthorityKey]:
    """Load a registry document from *path* and hold it to the contract.

    Keyed by `(purpose, key_id)` deliberately: a verifier selects by purpose
    *and* identity, so a lookup that ignored purpose would let one key stand in
    for another.
    """
    source = Path(path)
    try:
        text = source.read_bytes().decode("utf-8")
    except FileNotFoundError as exc:
        raise AuthorityKeyError(
            RULE_UNREADABLE, "no authority key registry is present"
        ) from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise AuthorityKeyError(
            RULE_UNREADABLE, "the authority key registry cannot be read"
        ) from exc
    return parse_authority_key_registry_text(text)


def parse_authority_key_registry_text(
    text: str,
) -> dict[tuple[str, str], AuthorityKey]:
    """Decode registry JSON strictly, refusing repeated member names, and hold it to the contract."""
    try:
        document = json.loads(text, object_pairs_hook=_reject_repeated_members)
    except AuthorityKeyError:
        raise
    except (ValueError, RecursionError) as exc:
        raise AuthorityKeyError(
            RULE_UNREADABLE, "the authority key registry is not valid JSON"
        ) from exc
    return parse_authority_key_registry(document)


def load_release_authority_key_registry(
    path: str | Path,
) -> dict[tuple[str, str], AuthorityKey]:
    """Load the registry a release ships, refusing any published test key.

    A key whose private seed is committed in this repository proves nothing
    about who signed, so a release trusting one would accept forged artifacts
    from anyone holding a clone.
    """
    return refuse_published_test_keys(load_authority_key_registry(path))


def refuse_published_test_keys(
    registry: dict[tuple[str, str], AuthorityKey],
) -> dict[tuple[str, str], AuthorityKey]:
    """Return *registry* unless it holds a key whose private seed is published."""
    for key in registry.values():
        if bytes.fromhex(key.public_key_hex) in PUBLISHED_TEST_KEYS:
            raise AuthorityKeyError(
                RULE_PUBLISHED_TEST_KEY,
                "the registry holds a key whose private seed is published",
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
                SELECT_WRONG_PURPOSE,
                f"key {key_id!r} is held for {elsewhere}, not for {purpose!r}",
            )
        raise AuthorityKeyError(
            SELECT_UNKNOWN_KEY, f"no key {key_id!r} is held for purpose {purpose!r}"
        )
    if not held.verifies:
        raise AuthorityKeyError(
            SELECT_RETIRED_KEY,
            f"key {key_id!r} for {purpose!r} is {held.status} and verifies nothing",
        )
    return held
