# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Approver registry rules the two corpora do not reach on their own.

Each test drives the real registry against a real store, through
`StateStore.run_approver_operation`, or the socket's answer path.
"""

from __future__ import annotations

import asyncio
import hashlib
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ori.operator_socket import OperatorSocketServer, PeerCredentials
from ori.security.approvers.forms import (
    ENROL_DOMAIN,
    POSSESSION_DOMAIN,
    REVOKE_DOMAIN,
    b64,
    canonical,
    sha256_hex,
    signed_preimage,
)
from ori.security.approvers.registry import (
    Anchors,
    ApproverRegistry,
    ChallengeStateLockedError,
    RegistryRefusedError,
    RunContext,
)
from ori.security.approvers.requests import MAX_DEPTH, SocketRequestError, parse
from ori.security.approvers.service import RegistryService
from ori.state.store import StateStore

ANCHOR_SEED = b"anchor".ljust(32, b".")


def _private(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(f"engine {name}".encode()).digest()
    )


def _raw(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _lan(name: str) -> str:
    return "ed25519:" + b64(_raw(_private(name)))


class _Minter:
    def __init__(self) -> None:
        self.count = 0

    def _next(self, kind: str) -> str:
        self.count += 1
        return f"{kind}-{self.count}"

    def challenge_id(self) -> str:
        self.count += 1
        return b64(self.count.to_bytes(16, "big"))

    def approver_id(self) -> str:
        return self._next("a")

    def credential_id(self) -> str:
        return self._next("c")

    def identity_epoch(self) -> str:
        return b64(b"\x07" * 16)

    def possession_code(self) -> str:
        return b64(b"\x01" * 16)


class Site:
    def __init__(self, store: StateStore, *, device: str = "edge-1") -> None:
        self.store = store
        self.now = 1_000_000
        self.keys: dict[str, str] = {}
        anchor = _raw(Ed25519PrivateKey.from_private_bytes(ANCHOR_SEED))
        self.registry = ApproverRegistry(
            RunContext(
                device_id=device,
                verified_site_id="site-1",
                authenticated_phone_channels=frozenset({"sms"}),
                anchors=Anchors(current=anchor),
                run_id="run",
            ),
            clock=lambda: self.now,
            minter=_Minter(),
        )

    async def op(self, name: str, *args: Any) -> Any:
        return await self.store.run_approver_operation(self.registry, name, *args)

    async def issue(self, operation: str, candidate: Any) -> dict[str, Any]:
        outcome = await self.op(
            "issue", {"challenge_operation": operation, "candidate": candidate}
        )
        return outcome.result["challenge"]

    def possession(self, challenge: dict[str, Any], key: str, **over: Any) -> dict:
        (candidate,) = challenge["candidates"]
        unsigned = {
            "v": 1,
            "challenge_id": challenge["challenge_id"],
            "challenge_sha256": sha256_hex(canonical(challenge)),
            "candidate_credential_id": candidate["credential_id"],
        } | over
        signature = _private(key).sign(
            signed_preimage(POSSESSION_DOMAIN, {**unsigned, "signature": ""})
        )
        return {**unsigned, "signature": b64(signature)}

    def authorization(
        self, challenge: dict[str, Any], authorizer: str, key: str, **over: Any
    ) -> dict:
        unsigned = {
            "v": 1,
            "challenge_id": challenge["challenge_id"],
            "challenge_sha256": sha256_hex(canonical(challenge)),
            "authorizer_credential_id": authorizer,
        } | over
        signature = _private(key).sign(
            signed_preimage(ENROL_DOMAIN, {**unsigned, "signature": ""})
        )
        return {**unsigned, "signature": b64(signature)}

    async def seeded(self) -> str:
        """Recover and seed one LAN approver; its credential ID."""
        challenge = await self.issue("recover", None)
        await self.op("recover", {"challenge_id": challenge["challenge_id"]})
        challenge = await self.issue(
            "local_seed", {"channel": "lan_ed25519", "value": _lan("owner")}
        )
        (candidate,) = challenge["candidates"]
        await self.op(
            "local_seed",
            {
                "challenge_id": challenge["challenge_id"],
                "candidate": candidate,
                "possession": self.possession(challenge, "owner"),
            },
        )
        return str(candidate["credential_id"])

    async def used(self, challenge_id: str) -> bool:
        row = await self.store._run_read(
            lambda conn: conn.execute(
                "SELECT used FROM approver_challenges WHERE challenge_id = ?",
                (challenge_id,),
            ).fetchone()
        )
        return bool(row and row[0])


@pytest.fixture
async def store(tmp_path: Path):
    s = StateStore(db_path=str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


async def _refused(site: Site, name: str, request: dict[str, Any]) -> str:
    with pytest.raises(RegistryRefusedError) as refused:
        await site.op(name, request)
    return refused.value.code


async def test_a_challenge_presented_for_another_operation_is_changed(
    store: StateStore,
) -> None:
    site = Site(store)
    await site.seeded()
    challenge = await site.issue(
        "enrol", {"approver_id": None, "channel": "lan_ed25519", "value": _lan("new")}
    )
    (candidate,) = challenge["candidates"]
    request = {
        "challenge_id": challenge["challenge_id"],
        "candidate": candidate,
        "possession": site.possession(challenge, "new"),
    }
    assert await _refused(site, "local_seed", request) == "candidate_changed"
    assert await site.used(challenge["challenge_id"])


@pytest.mark.parametrize("member", ["challenge_id", "challenge_sha256"])
async def test_a_possession_for_another_challenge_is_invalid(
    store: StateStore, member: str
) -> None:
    site = Site(store)
    other_id = b64(b"\xee" * 16)
    challenge = await site.issue("recover", None)
    await site.op("recover", {"challenge_id": challenge["challenge_id"]})
    challenge = await site.issue(
        "local_seed", {"channel": "lan_ed25519", "value": _lan("owner")}
    )
    (candidate,) = challenge["candidates"]
    wrong = (
        {"challenge_id": other_id}
        if member == "challenge_id"
        else {"challenge_sha256": "0" * 64}
    )
    request = {
        "challenge_id": challenge["challenge_id"],
        "candidate": candidate,
        "possession": site.possession(challenge, "owner", **wrong),
    }
    assert await _refused(site, "local_seed", request) == "possession_invalid"


@pytest.mark.parametrize("member", ["challenge_id", "challenge_sha256"])
async def test_an_authorization_for_another_challenge_is_refused(
    store: StateStore, member: str
) -> None:
    site = Site(store)
    owner = await site.seeded()
    challenge = await site.issue(
        "enrol", {"approver_id": None, "channel": "lan_ed25519", "value": _lan("new")}
    )
    (candidate,) = challenge["candidates"]
    wrong = (
        {"challenge_id": b64(b"\xee" * 16)}
        if member == "challenge_id"
        else {"challenge_sha256": "0" * 64}
    )
    request = {
        "challenge_id": challenge["challenge_id"],
        "candidate": candidate,
        "authorization": site.authorization(challenge, owner, "owner", **wrong),
        "possession": site.possession(challenge, "new"),
    }
    assert await _refused(site, "enrol", request) == "signature_invalid"


async def test_a_challenge_issued_before_a_later_enrolment_is_stale(
    store: StateStore,
) -> None:
    site = Site(store)
    owner = await site.seeded()
    late = await site.issue(
        "enrol", {"approver_id": None, "channel": "lan_ed25519", "value": _lan("late")}
    )
    second = await site.issue(
        "enrol", {"approver_id": None, "channel": "lan_ed25519", "value": _lan("two")}
    )
    (two,) = second["candidates"]
    await site.op(
        "enrol",
        {
            "challenge_id": second["challenge_id"],
            "candidate": two,
            "authorization": site.authorization(second, owner, "owner"),
            "possession": site.possession(second, "two"),
        },
    )
    (candidate,) = late["candidates"]
    # An authorizer enrolled after the challenge cannot reach
    # authorizer_not_preexisting: its enrolment moved the revision first.
    request = {
        "challenge_id": late["challenge_id"],
        "candidate": candidate,
        "authorization": site.authorization(late, two["credential_id"], "two"),
        "possession": site.possession(late, "late"),
    }
    assert await _refused(site, "enrol", request) == "challenge_stale"


async def test_a_revocation_for_another_device_is_a_binding_mismatch(
    store: StateStore,
) -> None:
    site = Site(store)
    owner = await site.seeded()
    signer = Ed25519PrivateKey.from_private_bytes(ANCHOR_SEED)
    document = {
        "v": 1,
        "device_id": "edge-2",
        "site_id": "site-1",
        "identity_epoch": b64(b"\x07" * 16),
        "revision": 1,
        "targets": [f"credential:{owner}"],
        "signing_key": "ed25519:" + b64(_raw(signer)),
    }
    document["signature"] = b64(
        signer.sign(signed_preimage(REVOKE_DOMAIN, {**document, "signature": ""}))
    )
    assert await _refused(site, "revoke", {"document": document}) == "binding_mismatch"


async def test_recovery_clears_pending_phone_operations(store: StateStore) -> None:
    site = Site(store)
    owner = await site.seeded()
    challenge = await site.issue(
        "enrol", {"approver_id": None, "channel": "sms", "value": "+2348012345678"}
    )
    (candidate,) = challenge["candidates"]
    await site.op(
        "enrol",
        {
            "challenge_id": challenge["challenge_id"],
            "candidate": candidate,
            "authorization": site.authorization(challenge, owner, "owner"),
            "possession": None,
        },
    )

    def wipe(conn: Any) -> None:
        conn.execute("DELETE FROM approver_registry")
        conn.commit()

    await store._run_write(lambda: wipe(store._conn))
    recover = await site.issue("recover", None)
    await site.op("recover", {"challenge_id": recover["challenge_id"]})
    left = await store._run_read(
        lambda conn: conn.execute(
            "SELECT COUNT(*) FROM approver_pending_phone"
        ).fetchone()
    )
    assert tuple(left) == (0,)


async def test_a_used_marker_that_cannot_be_committed_locks_challenge_state(
    store: StateStore,
) -> None:
    site = Site(store)
    challenge = await site.issue("recover", None)
    site.now += 60_001

    def refuse_marker(conn: sqlite3.Connection) -> None:
        conn.execute(
            "CREATE TEMP TRIGGER refuse_used BEFORE UPDATE OF used"
            " ON approver_challenges BEGIN SELECT RAISE(ABORT, 'disk I/O'); END"
        )

    conn = store._conn
    assert conn is not None
    await store._run_write(lambda: refuse_marker(conn))
    with pytest.raises(sqlite3.Error):
        await site.op("recover", {"challenge_id": challenge["challenge_id"]})
    with pytest.raises(ChallengeStateLockedError):
        await site.op("recover", {"challenge_id": challenge["challenge_id"]})


@pytest.mark.parametrize("deepest", [MAX_DEPTH, MAX_DEPTH + 1])
def test_the_depth_bound_is_thirty_two_levels(deepest: int) -> None:
    """The request object is level 1; its deepest object here is *deepest*."""
    nested = "{}"
    for _ in range(deepest - 2):
        nested = '{"a":' + nested + "}"
    raw = ('{"operation":"approver_registry_binding","x":' + nested + "}").encode()
    if deepest <= MAX_DEPTH:
        assert parse(raw)["operation"] == "approver_registry_binding"
    else:
        with pytest.raises(SocketRequestError) as refused:
            parse(raw)
        assert refused.value.code == "invalid_arguments"


async def test_a_stopping_socket_cancels_a_registry_operation_unrun(
    store: StateStore, tmp_path: Path
) -> None:
    site = Site(store)
    service = RegistryService(store, site.registry)

    async def nothing(*_args: Any) -> Any:
        raise AssertionError("not a registry operation")

    server = OperatorSocketServer(
        directory=tmp_path / "run",
        reconcile=nothing,
        commission=nothing,
        operator_uid=lambda: 1001,
        registry=service,
    )
    server._closing = True

    async def caller() -> PeerCredentials:
        return PeerCredentials(uid=1001, pid=None, login_uid=None)

    answer = await server.answer(
        b'{"operation":"approver_registry_challenge","challenge_operation":"recover",'
        b'"candidate":null}\n',
        caller,
    )
    assert answer["error"]["code"] == "cancelled"
    assert service.try_admit(), "the slot was left taken"
    held = await store._run_read(
        lambda conn: conn.execute("SELECT COUNT(*) FROM approver_challenges").fetchone()
    )
    assert tuple(held) == (0,)


async def test_the_slot_is_held_until_the_answer_is_written(
    store: StateStore, tmp_path: Path
) -> None:
    site = Site(store)
    service = RegistryService(store, site.registry)

    async def nothing(*_args: Any) -> Any:
        raise AssertionError("not a registry operation")

    server = OperatorSocketServer(
        directory=tmp_path / "run",
        reconcile=nothing,
        commission=nothing,
        operator_uid=lambda: 1001,
        registry=service,
    )

    async def caller() -> PeerCredentials:
        return PeerCredentials(uid=1001, pid=None, login_uid=None)

    answered = asyncio.Event()
    answer = await server.answer(
        b'{"operation":"approver_registry_binding"}\n', caller, answered
    )
    assert answer["ok"] is False
    await asyncio.sleep(0)
    assert not service.try_admit(), "released before the answer was written"
    answered.set()
    for _ in range(20):
        await asyncio.sleep(0)
    assert service.try_admit()


async def _rebind_device(store: StateStore, device: str) -> None:
    def rebind(conn: Any) -> None:
        conn.execute("UPDATE approver_registry SET device_id = ?", (device,))
        conn.commit()

    await store._run_write(lambda: rebind(store._conn))


@pytest.mark.parametrize(
    ("operation", "candidate"),
    [
        ("recover", None),
        ("enrol", {"approver_id": None, "channel": "lan_ed25519", "value": _lan("x")}),
    ],
)
async def test_a_registry_bound_to_another_device_is_locked(
    store: StateStore, operation: str, candidate: Any
) -> None:
    """Restarted as another device on the same site, nothing is inherited."""
    await Site(store).seeded()
    other = Site(store, device="edge-2")
    assert await _refused(other, "binding", {}) == "device_binding_mismatch"
    request = {"challenge_operation": operation, "candidate": candidate}
    assert await _refused(other, "issue", request) == "device_binding_mismatch"
    original = await Site(store).op("binding", {})
    assert original.result["device_id"] == "edge-1"


async def test_recovery_binds_the_registry_to_its_device(store: StateStore) -> None:
    await Site(store).seeded()
    row = await store._run_read(
        lambda conn: conn.execute("SELECT device_id FROM approver_registry").fetchone()
    )
    assert tuple(row) == ("edge-1",)


async def test_a_header_without_its_device_is_locked(store: StateStore) -> None:
    """Locked, not bound elsewhere: an explicit recovery binds it afresh."""
    site = Site(store)
    await site.seeded()
    await _rebind_device(store, "")
    assert await _refused(site, "binding", {}) == "registry_unavailable"
    challenge = await site.issue("recover", None)
    await site.op("recover", {"challenge_id": challenge["challenge_id"]})
    assert (await site.op("binding", {})).result["device_id"] == "edge-1"


async def test_a_header_table_without_a_device_column_gains_one_and_is_locked(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.db"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE approver_registry (singleton INTEGER PRIMARY KEY"
        " CHECK (singleton = 1), site_id TEXT NOT NULL, identity_epoch TEXT NOT NULL,"
        " revision INTEGER NOT NULL, last_external_revision INTEGER NOT NULL,"
        " last_external_document_sha256 TEXT, credential_sequence INTEGER NOT NULL)"
    )
    conn.execute(
        "INSERT INTO approver_registry VALUES (1, 'site-1', ?, 1, 0, NULL, 0)",
        (b64(b"\x07" * 16),),
    )
    conn.commit()
    conn.close()
    store = StateStore(db_path=str(path))
    await store.open()
    try:
        site = Site(store)
        assert await _refused(site, "binding", {}) == "registry_unavailable"
        challenge = await site.issue("recover", None)
        await site.op("recover", {"challenge_id": challenge["challenge_id"]})
        assert (await site.op("binding", {})).result["device_id"] == "edge-1"
    finally:
        await store.close()


async def test_a_phone_commit_on_a_header_for_another_device_is_refused(
    store: StateStore,
) -> None:
    site = Site(store)
    owner = await site.seeded()
    value = "+2348012345678"
    challenge = await site.issue(
        "enrol", {"approver_id": None, "channel": "sms", "value": value}
    )
    (candidate,) = challenge["candidates"]
    await site.op(
        "enrol",
        {
            "challenge_id": challenge["challenge_id"],
            "candidate": candidate,
            "authorization": site.authorization(challenge, owner, "owner"),
            "possession": None,
        },
    )
    await _rebind_device(store, "edge-2")
    code = b64(b"\x01" * 16)
    text = f"ORI-POSSESS-V1 {challenge['challenge_id']} {code}"
    outcome = await site.op("phone_text", "sms", value, text, True)
    assert outcome.result == {"outcome": "device_binding_mismatch"}
    assert await _count_credentials(store) == 1


async def _count_credentials(store: StateStore) -> int:
    row = await store._run_read(
        lambda conn: conn.execute(
            "SELECT COUNT(*) FROM approver_credentials"
        ).fetchone()
    )
    return int(row[0])


@pytest.mark.parametrize("then", ["in_window", "late", "locked"])
async def test_a_reply_to_an_operation_a_recovery_ended_is_an_epoch_change(
    store: StateStore, then: str
) -> None:
    """Before every other check of the commit, its window and a lock included."""
    site = Site(store)
    owner = await site.seeded()
    value = "+2348012345678"
    challenge = await site.issue(
        "enrol", {"approver_id": None, "channel": "sms", "value": value}
    )
    (candidate,) = challenge["candidates"]
    await site.op(
        "enrol",
        {
            "challenge_id": challenge["challenge_id"],
            "candidate": candidate,
            "authorization": site.authorization(challenge, owner, "owner"),
            "possession": None,
        },
    )

    def wipe(conn: Any) -> None:
        conn.execute("DELETE FROM approver_registry")
        conn.commit()

    await store._run_write(lambda: wipe(store._conn))
    recover = await site.issue("recover", None)
    await site.op("recover", {"challenge_id": recover["challenge_id"]})
    if then == "late":
        site.now += 600_001
    elif then == "locked":
        await store._run_write(lambda: wipe(store._conn))
    code = b64(b"\x01" * 16)
    text = f"ORI-POSSESS-V1 {challenge['challenge_id']} {code}"
    outcome = await site.op("phone_text", "sms", value, text, True)
    assert outcome.result == {"outcome": "epoch_changed"}
    again = await site.op("phone_text", "sms", value, text, True)
    assert again.result == {"outcome": "pending_unavailable"}
    assert await _count_credentials(store) == 0
