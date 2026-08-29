# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Custody secret generations, and the identifiers derived from them.

`evidence-exchange/v1` authenticates a custody acknowledgement under a secret
dedicated to that purpose -- not the runtime-gateway envelope secret. The two
are symmetric secrets between the same two parties, which is exactly why they
must not be the same bytes: domain separation makes the preimages differ, but
it does not stop a component holding the secret for one purpose from minting
artifacts for the other.

Each generation is named by a `key_id` derived from its own secret. Deriving
rather than configuring is what makes the rotation window enforceable. A
configured name survives a rotation unless an operator remembers to change it,
and an identifier that names two different secrets cannot select between them
-- which is the selector's whole function.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

#: Salt and info are fixed by the contract and MUST NOT vary per device or per
#: site. The identifier names a secret generation, not a device: one gateway
#: holding custody for several devices under one secret issues the same
#: `key_id` for all of them, and that is correct rather than a collision.
CUSTODY_KEY_ID_SALT = b"ori.evidence_custody_key_id.v1"
CUSTODY_KEY_ID_INFO = b"gateway_custody"
CUSTODY_KEY_ID_PREFIX = "hkdf-sha256:"
CUSTODY_KEY_ID_BYTES = 16

#: Exact wire shape. A verifier compares identifiers as bytes and never
#: case-folds, so uppercase hex is malformed rather than equivalent.
CUSTODY_KEY_ID_RE = re.compile(r"^hkdf-sha256:[0-9a-f]{32}$")

#: The authenticator's exact shape. Checked before the MAC is compared, so a
#: value that was never a candidate authenticator is malformed rather than a
#: failed authentication.
CUSTODY_MAC_RE = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")

#: The purpose this key material is registered under. Named here so the
#: verifier can tell "held for something else" from "not held at all".
CUSTODY_KEY_PURPOSE = "gateway_custody"

ACTIVE = "active"
VERIFY_ONLY = "verify_only"
RETIRED = "retired"


class CustodyKeyRegistryError(ValueError):
    """The registry cannot be constructed as described."""


def derive_custody_key_id(secret: str) -> str:
    """The `(gateway_custody, key_id)` selector for one secret generation.

    Keys from the secret's exact UTF-8 bytes, and normalises nothing. A secret
    carrying a stray newline -- the ordinary shape of one read from a file or a
    systemd `EnvironmentFile` -- is refused rather than trimmed, because
    trimming would key from bytes the operator never provisioned and derive an
    identifier no conforming peer reproduces. That divergence presents as
    `bad_authenticator` on every acknowledgement instead of as the
    configuration error it is, and the two sides can only agree here by
    agreeing exactly.
    """
    if not secret:
        raise CustodyKeyRegistryError("a custody secret must not be empty")
    if secret != secret.strip():
        raise CustodyKeyRegistryError(
            "a custody secret must not carry leading or trailing whitespace; "
            "the key is the secret's exact UTF-8 bytes"
        )
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=CUSTODY_KEY_ID_BYTES,
        salt=CUSTODY_KEY_ID_SALT,
        info=CUSTODY_KEY_ID_INFO,
    ).derive(secret.encode("utf-8"))
    return CUSTODY_KEY_ID_PREFIX + material.hex()


def is_well_formed_key_id(value: str) -> bool:
    """Whether *value* has the shape the contract fixes, ignoring the registry."""
    return bool(CUSTODY_KEY_ID_RE.fullmatch(value))


@dataclass(frozen=True)
class CustodyGeneration:
    """One generation. A retired one is a tombstone and carries no secret."""

    key_id: str
    status: str
    secret: str | None

    @property
    def can_verify(self) -> bool:
        return self.secret is not None


class CustodyKeyRegistry:
    """Selects a custody secret by `key_id`, and never by trial verification.

    Retirement destroys the secret and keeps the identifier. Without that
    tombstone a retired generation is indistinguishable from one that never
    existed, and the only honest answer would be `unknown_key` -- which loses a
    distinction an operator needs. `unknown_key` says a gateway is presenting a
    secret this runtime never shared with it, a misconfiguration or an
    intrusion. `retired_key` says the courier is holding evidence acknowledged
    under a generation since destroyed, a stalled queue.
    """

    def __init__(
        self,
        *,
        active_secret: str,
        previous_secret: str | None = None,
        retired_key_ids: tuple[str, ...] = (),
        forbidden_secrets: tuple[str, ...] = (),
    ) -> None:
        if not active_secret:
            raise CustodyKeyRegistryError("an active custody secret is required")

        # Separation is enforced on the bytes, not on the variable names. Two
        # environment variables can hold the same value, and an operator who
        # points both at one secret has reused the envelope secret for custody
        # -- the exact confusion the dedicated secret exists to end. Comparing
        # names would report that configuration as correct.
        forbidden = {value for value in forbidden_secrets if value}
        for label, candidate in (
            ("active", active_secret),
            ("previous", previous_secret),
        ):
            if candidate and candidate in forbidden:
                raise CustodyKeyRegistryError(
                    f"the {label} custody secret is also a runtime-gateway envelope "
                    "secret; custody requires key material of its own"
                )

        generations: dict[str, CustodyGeneration] = {}
        active_id = derive_custody_key_id(active_secret)
        generations[active_id] = CustodyGeneration(active_id, ACTIVE, active_secret)

        if previous_secret:
            # Two distinct causes, both refused. Identical bytes configured as
            # both generations is an operator error that would silently collapse
            # the rotation window. Distinct secrets deriving one identifier is
            # the truncation collision -- vanishingly unlikely, and refused
            # rather than assumed away, because the consequence is selecting the
            # wrong secret.
            previous_id = derive_custody_key_id(previous_secret)
            if previous_id in generations:
                if previous_secret == active_secret:
                    raise CustodyKeyRegistryError(
                        "the previous custody secret is the active one; a rotation "
                        "window needs two distinct secrets"
                    )
                raise CustodyKeyRegistryError(
                    "two distinct custody secrets derive the same key_id"
                )
            generations[previous_id] = CustodyGeneration(
                previous_id, VERIFY_ONLY, previous_secret
            )

        for raw in retired_key_ids:
            key_id = str(raw).strip()
            if not is_well_formed_key_id(key_id):
                raise CustodyKeyRegistryError(
                    f"retired custody key_id is not well formed: {key_id!r}"
                )
            if key_id in generations:
                # A live generation cannot also be a tombstone: the tombstone
                # says the secret was destroyed, and it demonstrably was not.
                raise CustodyKeyRegistryError(
                    "a retired custody key_id names a generation that still holds "
                    "a secret"
                )
            generations[key_id] = CustodyGeneration(key_id, RETIRED, None)

        self._generations = generations
        self._active_id = active_id

    @property
    def active_key_id(self) -> str:
        return self._active_id

    def lookup(self, key_id: str) -> CustodyGeneration | None:
        """The generation named, or None when nothing is held for it.

        Returns rather than raises, so the caller maps registry state onto the
        refusal vocabulary. The registry has no opinion about ingest reasons.
        """
        return self._generations.get(key_id)
