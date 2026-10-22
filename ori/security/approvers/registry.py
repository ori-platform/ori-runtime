# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The approver registry's state transitions, decided in one store transaction.

tier-c-approvers/v1 owns what each operation means and operator-socket/v3 the
order in which a request is refused. Every operation here reads and writes the
registry inside one ``BEGIN IMMEDIATE`` on the store's writer connection, so
registry operations, phone commits and Tier C admission run in one serial
order.

Challenges, received phone authorizations and pending phone operations belong
to the run that created them. Each row carries the run's ID, every query is
scoped to it, so a restart invalidates them and a persisted challenge never
regains a deadline. Other runs' rows are deleted when a run's registry is
prepared, as housekeeping.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Final, Protocol

from cryptography.exceptions import InvalidSignature

from ori.security.approvers.forms import (
    ENROL_DOMAIN,
    PHONE_CHANNELS,
    POSSESSION_DOMAIN,
    REVOKE_DOMAIN,
    b64,
    canonical,
    canonical_b64,
    challenge_object,
    is_device_id,
    is_e164,
    is_id,
    is_integer,
    is_sha256_hex,
    lan_key,
    sha256_hex,
    signed_preimage,
    spki_sha256,
    value_key,
)
from ori.security.ed25519_keys import admit_public_key, key_identity
from ori.utils.strict_json import unique_members

#: The challenge window, and the separate phone possession window.
CHALLENGE_WINDOW_MS: Final = 60_000
POSSESSION_WINDOW_MS: Final = 600_000
MAX_TARGETS: Final = 32

POSSESS_TOKEN: Final = "ORI-POSSESS-V1"
ENROL_TOKEN: Final = "ORI-ENROL-V1"


class RegistryRefusedError(Exception):
    """A registry refusal under its contract code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ChallengeStateLockedError(Exception):
    """A used marker could not be committed: no challenge may be presented."""


class Minter(Protocol):
    """Where every ID, epoch and code comes from. Implemented by CsprngMinter."""

    def challenge_id(self) -> str:
        """A fresh challenge ID."""
        raise NotImplementedError

    def approver_id(self) -> str:
        """A fresh approver ID."""
        raise NotImplementedError

    def credential_id(self) -> str:
        """A fresh credential ID."""
        raise NotImplementedError

    def identity_epoch(self) -> str:
        """A fresh identity epoch."""
        raise NotImplementedError

    def possession_code(self) -> str:
        """A fresh phone possession code."""
        raise NotImplementedError


class CsprngMinter:
    """Every ID, epoch and code from the operating system's CSPRNG."""

    def challenge_id(self) -> str:
        return b64(secrets.token_bytes(16))

    def approver_id(self) -> str:
        return "a-" + secrets.token_hex(16)

    def credential_id(self) -> str:
        return "c-" + secrets.token_hex(16)

    def identity_epoch(self) -> str:
        return b64(secrets.token_bytes(16))

    def possession_code(self) -> str:
        return b64(secrets.token_bytes(16))


@dataclass(frozen=True)
class Anchors:
    """The configured anchors, raw. *current* is None when it is not configured.

    *verified_config* is whether the running configuration was verified under
    the current provisioning anchor: unsigned development posture has none.
    """

    current: bytes | None
    previous: bytes | None = None
    other_class: tuple[bytes, ...] = ()
    verified_config: bool = True

    def _configured(self) -> list[bytes]:
        keys = [self.current, self.previous, *self.other_class]
        return [k for k in keys if k is not None]

    def usable(self) -> bool:
        if self.current is None or not self.verified_config:
            return False
        try:
            admit_public_key(self.current)
        except ValueError:
            return False
        identities = [key_identity(k) for k in self._configured()]
        return len(set(identities)) == len(identities)

    def recognise(self, key: bytes) -> str | None:
        """``current``, ``previous``, ``other`` or None, by key identity."""
        identity = key_identity(key)
        if self.current is not None and key_identity(self.current) == identity:
            return "current"
        if self.previous is not None and key_identity(self.previous) == identity:
            return "previous"
        if any(key_identity(k) == identity for k in self.other_class):
            return "other"
        return None


@dataclass(frozen=True)
class RunContext:
    """What the running configuration fixes for this run."""

    device_id: str
    verified_site_id: str | None
    authenticated_phone_channels: frozenset[str]
    anchors: Anchors
    run_id: str


@dataclass
class Outcome:
    """An operation's answer and what must happen after its commit."""

    result: dict[str, Any]
    possession_message: tuple[str, str, str] | None = None  # channel, to, text
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Header:
    device_id: str
    site_id: str
    identity_epoch: str
    revision: int
    last_external_revision: int
    last_external_document_sha256: str | None
    credential_sequence: int


def _verify(key: bytes, signature_b64: str, message: bytes) -> bool:
    signature = canonical_b64(signature_b64, 64)
    if signature is None:
        return False
    try:
        admit_public_key(key).verify(signature, message)
    except (ValueError, InvalidSignature):
        return False
    return True


def read_header(conn: sqlite3.Connection) -> Header | None:
    """The registry header, or None when the registry is locked.

    Absent and corrupt are both locked: a header whose values are not their
    contract forms is not a registry.
    """
    try:
        rows = conn.execute(
            "SELECT device_id, site_id, identity_epoch, revision,"
            " last_external_revision, last_external_document_sha256,"
            " credential_sequence FROM approver_registry WHERE singleton = 1"
        ).fetchall()
    except sqlite3.DatabaseError:
        return None
    if len(rows) != 1:
        return None
    device, site, epoch, revision, external, document, sequence = rows[0]
    if not (
        is_device_id(device)
        and is_id(site)
        and canonical_b64(epoch, 16) is not None
        and is_integer(revision, 1)
        and is_integer(external)
        and (document is None or is_sha256_hex(document))
        and is_integer(sequence)
    ):
        return None
    return Header(device, site, epoch, revision, external, document, sequence)


class ApproverRegistry:
    """One device's registry, against the store connection it is given."""

    def __init__(
        self,
        context: RunContext,
        *,
        clock: Callable[[], int],
        minter: Minter | None = None,
    ) -> None:
        self.context = context
        self._clock = clock
        self._minter = minter or CsprngMinter()
        self._challenge_state_locked = False

    # ─── transaction shape ──────────────────────────────────────────────────

    def run(
        self, conn: sqlite3.Connection, operation: Callable[..., Outcome], *args: Any
    ) -> Outcome:
        """Run *operation* in one transaction; a refusal commits only a used marker."""
        conn.execute("BEGIN IMMEDIATE")
        try:
            outcome = operation(conn, *args)
            conn.commit()
        except _ConsumedError as consumed:
            # Whatever the operation wrote is discarded: a refusal changes
            # nothing but its challenge's used marker, in its own transaction.
            conn.rollback()
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "UPDATE approver_challenges SET used = 1"
                    " WHERE challenge_id = ? AND run_id = ?",
                    (consumed.challenge_id, self.context.run_id),
                )
                conn.commit()
            except sqlite3.Error:
                if conn.in_transaction:
                    conn.rollback()
                self._challenge_state_locked = True
                raise
            raise RegistryRefusedError(consumed.code) from None
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            raise
        return outcome

    def _verified_site(self) -> str:
        site = self.context.verified_site_id
        if not site:
            raise RegistryRefusedError("registry_unavailable")
        return site

    def _site_matches(self, header: Header | None, site: str) -> None:
        # The registry belongs to one device. A header bound to another is
        # held like a site change: nothing mutates it, and recovery waits for
        # the original device identity rather than inheriting its epoch.
        if header is not None and header.device_id != self.context.device_id:
            raise RegistryRefusedError("device_binding_mismatch")
        if header is not None and header.site_id != site:
            raise RegistryRefusedError("site_binding_mismatch")

    # ─── state reads ────────────────────────────────────────────────────────

    def _active(self, conn: sqlite3.Connection) -> list[dict[str, Any]]:
        rows = conn.execute(
            "SELECT credential_id, approver_id, channel, value, value_key, sequence"
            " FROM approver_credentials ORDER BY sequence"
        ).fetchall()
        return [
            dict(
                zip(
                    (
                        "credential_id",
                        "approver_id",
                        "channel",
                        "value",
                        "value_key",
                        "sequence",
                    ),
                    row,
                )
            )
            for row in rows
        ]

    def _tombstoned(self, conn: sqlite3.Connection, kind: str, name: str) -> bool:
        return (
            conn.execute(
                "SELECT 1 FROM approver_tombstones WHERE kind = ? AND name = ?",
                (kind, name),
            ).fetchone()
            is not None
        )

    def _approver_known(self, conn: sqlite3.Connection, approver_id: str) -> bool:
        """Active, tombstoned, or the owner of a tombstoned credential."""
        return (
            any(c["approver_id"] == approver_id for c in self._active(conn))
            or self._tombstoned(conn, "approver", approver_id)
            or conn.execute(
                "SELECT 1 FROM approver_tombstones"
                " WHERE kind = 'credential' AND approver_id = ?",
                (approver_id,),
            ).fetchone()
            is not None
        )

    def _pending_for(self, conn: sqlite3.Connection, value: str) -> bool:
        """Whether *value* has a pending phone operation still in its window.

        A timed-out one is removed here: it refuses, and frees its value.
        """
        row = conn.execute(
            "SELECT window_start_ms FROM approver_pending_phone"
            " WHERE value = ? AND run_id = ?",
            (value, self.context.run_id),
        ).fetchone()
        if row is None:
            return False
        if self._clock() - row[0] > POSSESSION_WINDOW_MS:
            conn.execute(
                "DELETE FROM approver_pending_phone WHERE value = ? AND run_id = ?",
                (value, self.context.run_id),
            )
            return False
        return True

    def _challenge(
        self, conn: sqlite3.Connection, challenge_id: str
    ) -> dict[str, Any] | None:
        row = conn.execute(
            "SELECT canonical, issued_at_ms, credential_sequence_at_issue, used,"
            " code_sha256, approver_minted FROM approver_challenges"
            " WHERE challenge_id = ? AND run_id = ?",
            (challenge_id, self.context.run_id),
        ).fetchone()
        if row is None:
            return None
        canonical_bytes, issued, sequence, used, code, minted = row
        return {
            "object": json.loads(canonical_bytes, object_pairs_hook=unique_members()),
            "canonical": bytes(canonical_bytes),
            "issued_at_ms": issued,
            "credential_sequence_at_issue": sequence,
            "used": bool(used),
            "code_sha256": code,
            "approver_minted": bool(minted),
        }

    # ─── Challenge ──────────────────────────────────────────────────────────

    def issue(self, conn: sqlite3.Connection, request: dict[str, Any]) -> Outcome:
        site = self._verified_site()
        operation = request["challenge_operation"]
        candidate = request["candidate"]
        header = read_header(conn)
        if operation == "local_seed" and candidate["channel"] != "lan_ed25519":
            raise RegistryRefusedError("lan_key_required")
        self._site_matches(header, site)
        if operation == "recover" and header is not None:
            raise RegistryRefusedError("recovery_not_available")
        if operation in ("local_seed", "enrol") and header is None:
            raise RegistryRefusedError("registry_unavailable")
        if (
            operation == "enrol"
            and candidate["channel"] in PHONE_CHANNELS
            and candidate["channel"] not in self.context.authenticated_phone_channels
        ):
            raise RegistryRefusedError("channel_unauthenticated")
        active = self._active(conn)
        if operation == "local_seed" and active:
            raise RegistryRefusedError("active_authorizer_exists")
        named = candidate.get("approver_id") if operation == "enrol" else None
        if named is not None:
            if self._tombstoned(conn, "approver", named):
                raise RegistryRefusedError("approver_revoked")
            if not any(c["approver_id"] == named for c in active):
                raise RegistryRefusedError("approver_unknown")
        if candidate is not None:
            key = value_key(candidate["channel"], candidate["value"])
            if self._tombstoned(conn, "value", key):
                raise RegistryRefusedError("value_tombstoned")
            if any(c["value_key"] == key for c in active):
                raise RegistryRefusedError("duplicate_value")
            if candidate["channel"] in PHONE_CHANNELS and self._pending_for(
                conn, candidate["value"]
            ):
                raise RegistryRefusedError("phone_pending_for_value")

        challenge_id = self._minter.challenge_id()
        if operation == "recover":
            epoch, revision, candidates = self._minter.identity_epoch(), 0, []
        else:
            assert header is not None and candidate is not None
            epoch, revision = header.identity_epoch, header.revision
            candidates = [
                {
                    "approver_id": named or self._minter.approver_id(),
                    "credential_id": self._minter.credential_id(),
                    "channel": candidate["channel"],
                    "value": candidate["value"],
                }
            ]
        challenge = challenge_object(
            challenge_id=challenge_id,
            device_id=self.context.device_id,
            site_id=site,
            identity_epoch=epoch,
            operation=operation,
            registry_revision=revision,
            candidates=candidates,
        )
        code = None
        message = None
        if candidates and candidates[0]["channel"] in PHONE_CHANNELS:
            code = self._minter.possession_code()
            message = (
                candidates[0]["channel"],
                candidates[0]["value"],
                f"{POSSESS_TOKEN} {challenge_id} {code}",
            )
        conn.execute(
            "INSERT INTO approver_challenges (challenge_id, run_id, operation,"
            " canonical, issued_at_ms, credential_sequence_at_issue, used,"
            " code_sha256, approver_minted) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)",
            (
                challenge_id,
                self.context.run_id,
                operation,
                canonical(challenge),
                self._clock(),
                0 if header is None else header.credential_sequence,
                None if code is None else sha256_hex(code.encode("ascii")),
                1 if candidates and named is None else 0,
            ),
        )
        return Outcome({"challenge": challenge}, possession_message=message)

    # ─── Challenges presented ───────────────────────────────────────────────

    def _presented(
        self,
        conn: sqlite3.Connection,
        header: Header | None,
        site: str,
        request: dict[str, Any],
        operation: str,
    ) -> dict[str, Any]:
        if self._challenge_state_locked:
            raise ChallengeStateLockedError()
        self._site_matches(header, site)
        challenge_id = request["challenge_id"]
        held = self._challenge(conn, challenge_id)
        if held is not None and held["used"]:
            raise RegistryRefusedError("challenge_reused")
        if held is None:
            raise RegistryRefusedError("challenge_unavailable")
        if self._clock() - held["issued_at_ms"] > CHALLENGE_WINDOW_MS:
            raise _ConsumedError("challenge_expired", challenge_id)
        candidates = held["object"]["candidates"]
        presented = request.get("candidate")
        if (
            held["object"]["operation"] != operation
            or ([presented] if presented is not None else []) != candidates
        ):
            raise _ConsumedError("candidate_changed", challenge_id)
        return held

    def recover(self, conn: sqlite3.Connection, request: dict[str, Any]) -> Outcome:
        site = self._verified_site()
        header = read_header(conn)
        held = self._presented(conn, header, site, request, "recover")
        challenge_id = request["challenge_id"]
        if header is not None:
            raise _ConsumedError("recovery_not_available", challenge_id)
        challenge = held["object"]
        if (
            challenge["device_id"] != self.context.device_id
            or challenge["site_id"] != site
        ):
            raise _ConsumedError("challenge_stale", challenge_id)
        invalidated = conn.execute(
            "SELECT challenge_id FROM approver_pending_phone WHERE run_id = ?",
            (self.context.run_id,),
        ).fetchall()
        for table in (
            "approver_registry",
            "approver_credentials",
            "approver_tombstones",
            "approver_challenges",
            "approver_phone_authorizations",
            "approver_pending_phone",
        ):
            conn.execute(f"DELETE FROM {table}")  # noqa: S608 - fixed names
        conn.executemany(
            "INSERT OR IGNORE INTO approver_invalidated_phone (challenge_id, run_id)"
            " VALUES (?, ?)",
            [(row[0], self.context.run_id) for row in invalidated],
        )
        conn.execute(
            "INSERT INTO approver_registry (singleton, device_id, site_id,"
            " identity_epoch, revision, last_external_revision,"
            " last_external_document_sha256, credential_sequence)"
            " VALUES (1, ?, ?, ?, 1, 0, NULL, 0)",
            (self.context.device_id, site, challenge["identity_epoch"]),
        )
        return Outcome({"status": "recovered", "registry_revision": 1})

    def _stale(
        self, header: Header | None, challenge: dict[str, Any], cid: str
    ) -> Header:
        if header is None:
            raise _ConsumedError("registry_unavailable", cid)
        if (
            challenge["registry_revision"] != header.revision
            or challenge["identity_epoch"] != header.identity_epoch
        ):
            raise _ConsumedError("challenge_stale", cid)
        return header

    def _possession(
        self,
        held: dict[str, Any],
        candidate: dict[str, Any],
        possession: dict[str, Any],
    ) -> None:
        cid = held["object"]["challenge_id"]
        if (
            possession["challenge_id"] != cid
            or possession["challenge_sha256"] != sha256_hex(held["canonical"])
            or possession["candidate_credential_id"] != candidate["credential_id"]
        ):
            raise _ConsumedError("possession_invalid", cid)
        key = lan_key(candidate["value"])
        assert key is not None
        if not _verify(
            key, possession["signature"], signed_preimage(POSSESSION_DOMAIN, possession)
        ):
            raise _ConsumedError("signature_invalid", cid)

    def _candidate_unused(
        self,
        conn: sqlite3.Connection,
        candidate: dict[str, Any],
        cid: str,
        *,
        duplicate: bool,
    ) -> str:
        if self._tombstoned(conn, "approver", candidate["approver_id"]):
            raise _ConsumedError("approver_revoked", cid)
        active = self._active(conn)
        if self._tombstoned(conn, "credential", candidate["credential_id"]) or any(
            c["credential_id"] == candidate["credential_id"] for c in active
        ):
            raise _ConsumedError("credential_reused", cid)
        key = value_key(candidate["channel"], candidate["value"])
        if self._tombstoned(conn, "value", key):
            raise _ConsumedError("value_tombstoned", cid)
        if duplicate and any(c["value_key"] == key for c in active):
            raise _ConsumedError("duplicate_value", cid)
        return key

    def _add(
        self,
        conn: sqlite3.Connection,
        header: Header,
        candidate: dict[str, Any],
        key: str,
    ) -> int:
        sequence = header.credential_sequence + 1
        revision = header.revision + 1
        raw = lan_key(candidate["value"])
        conn.execute(
            "INSERT INTO approver_credentials (credential_id, approver_id, channel,"
            " value, value_key, spki_sha256, sequence) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                candidate["credential_id"],
                candidate["approver_id"],
                candidate["channel"],
                candidate["value"],
                key,
                None if raw is None else spki_sha256(raw),
                sequence,
            ),
        )
        conn.execute(
            "UPDATE approver_registry SET credential_sequence = ?, revision = ?"
            " WHERE singleton = 1",
            (sequence, revision),
        )
        return revision

    def _consume(self, conn: sqlite3.Connection, challenge_id: str) -> None:
        conn.execute(
            "UPDATE approver_challenges SET used = 1 WHERE challenge_id = ? AND run_id = ?",
            (challenge_id, self.context.run_id),
        )

    def local_seed(self, conn: sqlite3.Connection, request: dict[str, Any]) -> Outcome:
        site = self._verified_site()
        header = read_header(conn)
        held = self._presented(conn, header, site, request, "local_seed")
        cid = request["challenge_id"]
        header = self._stale(header, held["object"], cid)
        candidate = request["candidate"]
        if self._active(conn):
            raise _ConsumedError("active_authorizer_exists", cid)
        self._possession(held, candidate, request["possession"])
        key = self._candidate_unused(conn, candidate, cid, duplicate=False)
        revision = self._add(conn, header, candidate, key)
        self._consume(conn, cid)
        return Outcome({"status": "seeded", "registry_revision": revision})

    def enrol(self, conn: sqlite3.Connection, request: dict[str, Any]) -> Outcome:
        site = self._verified_site()
        header = read_header(conn)
        held = self._presented(conn, header, site, request, "enrol")
        cid = request["challenge_id"]
        header = self._stale(header, held["object"], cid)
        candidate = request["candidate"]
        challenge_sha256 = sha256_hex(held["canonical"])
        active = {c["credential_id"]: c for c in self._active(conn)}

        authorization = request["authorization"]
        if authorization is not None:
            authorizer = active.get(authorization["authorizer_credential_id"])
            if authorizer is None or authorizer["channel"] != "lan_ed25519":
                raise _ConsumedError("authorizer_unavailable", cid)
        else:
            first = conn.execute(
                "SELECT challenge_sha256, authorizer_credential_id"
                " FROM approver_phone_authorizations"
                " WHERE challenge_id = ? AND run_id = ? ORDER BY arrival LIMIT 1",
                (cid, self.context.run_id),
            ).fetchone()
            authorizer = None if first is None else active.get(first[1])
            if (
                first is None
                or authorizer is None
                or authorizer["channel"] not in PHONE_CHANNELS
                or first[0] != challenge_sha256
            ):
                raise _ConsumedError("authorizer_unavailable", cid)
        if authorizer["sequence"] > held["credential_sequence_at_issue"]:
            raise _ConsumedError("authorizer_not_preexisting", cid)
        if authorization is not None:
            authorizer_key = lan_key(authorizer["value"])
            assert authorizer_key is not None
            if (
                authorization["challenge_id"] != cid
                or authorization["challenge_sha256"] != challenge_sha256
                or not _verify(
                    authorizer_key,
                    authorization["signature"],
                    signed_preimage(ENROL_DOMAIN, authorization),
                )
            ):
                raise _ConsumedError("signature_invalid", cid)
        owners = {c["approver_id"] for c in active.values()}
        if (
            candidate["approver_id"] in owners
            and authorizer["approver_id"] != candidate["approver_id"]
        ):
            raise _ConsumedError("authorizer_not_approver", cid)
        phone = candidate["channel"] in PHONE_CHANNELS
        if not phone:
            self._possession(held, candidate, request["possession"])
        key = self._candidate_unused(conn, candidate, cid, duplicate=True)
        if phone and self._pending_for(conn, candidate["value"]):
            raise _ConsumedError("phone_pending_for_value", cid)

        self._consume(conn, cid)
        if not phone:
            revision = self._add(conn, header, candidate, key)
            return Outcome({"status": "enrolled", "registry_revision": revision})
        conn.execute(
            "INSERT INTO approver_pending_phone (value, run_id, challenge_id, channel,"
            " candidate_json, code_sha256, window_start_ms, authorizer_credential_id,"
            " registry_revision, identity_epoch, site_id, approver_minted)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                candidate["value"],
                self.context.run_id,
                cid,
                candidate["channel"],
                canonical(candidate).decode("utf-8"),
                held["code_sha256"],
                held["issued_at_ms"],
                authorizer["credential_id"],
                header.revision,
                header.identity_epoch,
                header.site_id,
                1 if held["approver_minted"] else 0,
            ),
        )
        return Outcome(
            {"status": "phone_pending", "registry_revision": header.revision}
        )

    # ─── Revoke ─────────────────────────────────────────────────────────────

    def revoke(self, conn: sqlite3.Connection, request: dict[str, Any]) -> Outcome:
        site = self._verified_site()
        anchors = self.context.anchors
        if not anchors.usable():
            raise RegistryRefusedError("anchor_unavailable")
        document = request["document"]
        if not _is_revocation(document):
            raise RegistryRefusedError("malformed")
        signing_key = canonical_b64(document["signing_key"][len("ed25519:") :], 32)
        assert signing_key is not None
        recognised = anchors.recognise(signing_key)
        if recognised is None:
            raise RegistryRefusedError("unknown_signer")
        if not _verify(
            signing_key, document["signature"], signed_preimage(REVOKE_DOMAIN, document)
        ):
            raise RegistryRefusedError("signature_invalid")
        if recognised == "previous":
            raise RegistryRefusedError("superseded_signer")
        if recognised == "other":
            raise RegistryRefusedError("wrong_authority")
        header = read_header(conn)
        if header is None:
            raise RegistryRefusedError("registry_unavailable")
        self._site_matches(header, site)
        if (
            document["device_id"] != self.context.device_id
            or document["site_id"] != header.site_id
            or document["identity_epoch"] != header.identity_epoch
        ):
            raise RegistryRefusedError("binding_mismatch")
        fingerprint = sha256_hex(canonical(document))
        revision = document["revision"]
        if revision < header.last_external_revision:
            raise RegistryRefusedError("revision_regressed")
        if revision == header.last_external_revision:
            if fingerprint != header.last_external_document_sha256:
                raise RegistryRefusedError("revision_conflict")
            return Outcome(
                {
                    "status": "replayed",
                    "registry_revision": header.revision,
                    "last_external_revision": header.last_external_revision,
                }
            )
        active = self._active(conn)
        removals: list[dict[str, Any]] = []
        approvers: list[str] = []
        for target in document["targets"]:
            kind, _, name = target.partition(":")
            if kind == "credential":
                if not (
                    any(c["credential_id"] == name for c in active)
                    or self._tombstoned(conn, "credential", name)
                ):
                    raise RegistryRefusedError("unknown_target")
                removals += [c for c in active if c["credential_id"] == name]
            else:
                if not self._approver_known(conn, name):
                    raise RegistryRefusedError("unknown_target")
                removals += [c for c in active if c["approver_id"] == name]
                approvers.append(name)
        for credential in {c["credential_id"]: c for c in removals}.values():
            conn.execute(
                "DELETE FROM approver_credentials WHERE credential_id = ?",
                (credential["credential_id"],),
            )
            conn.execute(
                "INSERT OR IGNORE INTO approver_tombstones (kind, name, approver_id,"
                " value) VALUES ('credential', ?, ?, NULL)",
                (credential["credential_id"], credential["approver_id"]),
            )
            conn.execute(
                "INSERT OR IGNORE INTO approver_tombstones (kind, name, approver_id,"
                " value) VALUES ('value', ?, NULL, ?)",
                (credential["value_key"], credential["value"]),
            )
        for approver in approvers:
            conn.execute(
                "INSERT OR IGNORE INTO approver_tombstones (kind, name, approver_id,"
                " value) VALUES ('approver', ?, NULL, NULL)",
                (approver,),
            )
        conn.execute(
            "UPDATE approver_registry SET revision = ?, last_external_revision = ?,"
            " last_external_document_sha256 = ? WHERE singleton = 1",
            (header.revision + 1, revision, fingerprint),
        )
        return Outcome(
            {
                "status": "revoked",
                "registry_revision": header.revision + 1,
                "last_external_revision": revision,
            }
        )

    # ─── Binding ────────────────────────────────────────────────────────────

    def binding(self, conn: sqlite3.Connection, _request: dict[str, Any]) -> Outcome:
        site = self._verified_site()
        header = read_header(conn)
        if header is None:
            raise RegistryRefusedError("registry_unavailable")
        self._site_matches(header, site)
        return Outcome(
            {
                "device_id": self.context.device_id,
                "site_id": header.site_id,
                "identity_epoch": header.identity_epoch,
                "registry_revision": header.revision,
            }
        )

    # ─── phone ingress ──────────────────────────────────────────────────────

    def phone_text(
        self,
        conn: sqlite3.Connection,
        channel: str,
        sender: str,
        text: str,
        authenticated: bool,
    ) -> Outcome:
        """One text from a phone ingress: an authorization or a possession reply.

        *authenticated* is the ingress's own verdict on the message. A message
        it did not authenticate, or one on a channel with no authenticated
        ingress this run, reaches no registry state.
        """
        if (
            not authenticated
            or channel not in self.context.authenticated_phone_channels
            or not is_e164(sender)
        ):
            return Outcome({"outcome": "ingress_unauthenticated"})
        tokens = text.split(" ")
        if " ".join(tokens) != text or len(tokens) != 3:
            return Outcome({"outcome": "not_registry_text"})
        if tokens[0] == ENROL_TOKEN:
            return self._phone_authorization(
                conn, channel, sender, tokens[1], tokens[2]
            )
        if tokens[0] == POSSESS_TOKEN:
            return self._phone_commit(conn, channel, sender, tokens[1], tokens[2])
        return Outcome({"outcome": "not_registry_text"})

    def _phone_authorization(
        self,
        conn: sqlite3.Connection,
        channel: str,
        sender: str,
        challenge_id: str,
        challenge_sha256: str,
    ) -> Outcome:
        if canonical_b64(challenge_id, 16) is None or not is_sha256_hex(
            challenge_sha256
        ):
            return Outcome({"outcome": "not_registry_text"})
        held = self._challenge(conn, challenge_id)
        if held is None or held["used"] or held["object"]["operation"] != "enrol":
            return Outcome({"outcome": "challenge_unavailable"})
        first = conn.execute(
            "SELECT 1 FROM approver_phone_authorizations"
            " WHERE challenge_id = ? AND run_id = ?",
            (challenge_id, self.context.run_id),
        ).fetchone()
        if first is not None:
            return Outcome({"outcome": "ignored"})
        attributed = None
        for credential in self._active(conn):
            if credential["channel"] == channel and credential["value"] == sender:
                attributed = credential["credential_id"]
        conn.execute(
            "INSERT INTO approver_phone_authorizations (run_id, challenge_id,"
            " challenge_sha256, authorizer_credential_id) VALUES (?, ?, ?, ?)",
            (self.context.run_id, challenge_id, challenge_sha256, attributed),
        )
        return Outcome({"outcome": "recorded"})

    def _phone_commit(
        self,
        conn: sqlite3.Connection,
        channel: str,
        sender: str,
        challenge_id: str,
        code: str,
    ) -> Outcome:
        # Before every other check of the commit, its window and a locked
        # registry included: a recovery ended this operation.
        if conn.execute(
            "DELETE FROM approver_invalidated_phone"
            " WHERE challenge_id = ? AND run_id = ?",
            (challenge_id, self.context.run_id),
        ).rowcount:
            return Outcome({"outcome": "epoch_changed"})
        row = conn.execute(
            "SELECT value, channel, candidate_json, code_sha256, window_start_ms,"
            " authorizer_credential_id, registry_revision, identity_epoch, site_id,"
            " approver_minted"
            " FROM approver_pending_phone WHERE challenge_id = ? AND run_id = ?",
            (challenge_id, self.context.run_id),
        ).fetchone()
        if row is None:
            return Outcome({"outcome": "pending_unavailable"})
        value, pending_channel, candidate_json, code_sha256, start, authorizer = row[:6]
        revision, epoch, site, minted = row[6:]
        # An attempted commit consumes the pending operation, whatever it decides.
        conn.execute(
            "DELETE FROM approver_pending_phone WHERE value = ? AND run_id = ?",
            (value, self.context.run_id),
        )
        if self._clock() - start > POSSESSION_WINDOW_MS:
            return Outcome({"outcome": "possession_expired"})
        digest = hashlib.sha256(code.encode("utf-8", "surrogatepass")).hexdigest()
        if not (
            hmac.compare_digest(digest, code_sha256 or "")
            and sender == value
            and channel == pending_channel
        ):
            return Outcome({"outcome": "possession_invalid"})
        header = read_header(conn)
        if header is None:
            return Outcome({"outcome": "registry_unavailable"})
        # In the contract's order: the authorizer, the revision, the device
        # and site bindings, the epoch. Within one run the site and epoch can change
        # only through recovery, which removes every pending operation first.
        active = self._active(conn)
        if not any(c["credential_id"] == authorizer for c in active):
            return Outcome({"outcome": "authorizer_unavailable"})
        if header.revision != revision:
            return Outcome({"outcome": "registry_changed"})
        if header.device_id != self.context.device_id:
            return Outcome({"outcome": "device_binding_mismatch"})
        if header.site_id != site or header.site_id != self.context.verified_site_id:
            return Outcome({"outcome": "site_binding_mismatch"})
        if header.identity_epoch != epoch:
            return Outcome({"outcome": "epoch_changed"})
        candidate = json.loads(candidate_json, object_pairs_hook=unique_members())
        key = value_key(candidate["channel"], candidate["value"])
        if (
            self._tombstoned(conn, "credential", candidate["credential_id"])
            or self._tombstoned(conn, "approver", candidate["approver_id"])
            or self._tombstoned(conn, "value", key)
            or any(
                c["credential_id"] == candidate["credential_id"]
                or c["value_key"] == key
                or (bool(minted) and c["approver_id"] == candidate["approver_id"])
                for c in active
            )
        ):
            return Outcome({"outcome": "candidate_unavailable"})
        new_revision = self._add(conn, header, candidate, key)
        return Outcome({"outcome": "enrolled", "registry_revision": new_revision})


class _ConsumedError(Exception):
    """A refusal from `challenge_expired` on: it marks its challenge used."""

    def __init__(self, code: str, challenge_id: str) -> None:
        super().__init__(code)
        self.code = code
        self.challenge_id = challenge_id


def _is_revocation(document: object) -> bool:
    if not isinstance(document, dict) or getattr(document, "duplicated", False):
        return False
    if set(document) != {
        "v",
        "device_id",
        "site_id",
        "identity_epoch",
        "revision",
        "targets",
        "signing_key",
        "signature",
    }:
        return False
    targets = document["targets"]
    return (
        type(document["v"]) is int
        and document["v"] == 1
        and is_device_id(document["device_id"])
        and is_id(document["site_id"])
        and canonical_b64(document["identity_epoch"], 16) is not None
        and is_integer(document["revision"], 1)
        and isinstance(targets, list)
        and 0 < len(targets) <= MAX_TARGETS
        and all(isinstance(t, str) and _is_target(t) for t in targets)
        and targets == sorted(set(targets))
        and isinstance(document["signing_key"], str)
        and document["signing_key"].startswith("ed25519:")
        and canonical_b64(document["signing_key"][len("ed25519:") :], 32) is not None
        and canonical_b64(document["signature"], 64) is not None
    )


def _is_target(target: str) -> bool:
    kind, sep, name = target.partition(":")
    return sep == ":" and kind in ("credential", "approver") and is_id(name)


__all__ = [
    "Anchors",
    "ApproverRegistry",
    "ChallengeStateLockedError",
    "CsprngMinter",
    "Header",
    "Minter",
    "Outcome",
    "RegistryRefusedError",
    "RunContext",
    "read_header",
    "spki_sha256",
]
