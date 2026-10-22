# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""operator-socket/v3 Approver Registry Operations, every case of its corpus.

Each case's context is loaded into a real state store, its request bytes go
through the operator socket's own answer path (bound, parse, members, caller,
in-flight check), and the registry runs against the store. The answer is
compared with the case, and the state the store holds afterwards is compared,
as the corpus's closed change vocabulary, with what the case says it commits.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from ori.operator_socket import OperatorSocketServer, PeerCredentials
from ori.security.approvers.forms import canonical, value_key
from ori.security.approvers.registry import Anchors, ApproverRegistry, RunContext
from ori.security.approvers.service import REGISTRY_ERRORS, RegistryService
from ori.state.store import StateStore

VECTORS = Path(__file__).parent / "vectors" / "operator_socket"
CORPUS = json.loads((VECTORS / "approver-registry-v3.json").read_text(encoding="utf-8"))
CASES = {case["name"]: case for case in CORPUS["cases"]}
RUN = "run-under-test"
NOW_MS = 10_000_000
CODE = "AAAAAAAAAAAAAAAAAAAAAA=="


def test_the_corpus_is_the_contracts() -> None:
    assert CORPUS["contract"] == "operator-socket/v3"
    assert CORPUS["bound_bytes"] == 16_384
    assert set(CORPUS["codes"]) <= REGISTRY_ERRORS
    assert len(CASES) == len(CORPUS["cases"]) >= 500


class _Minter:
    def __init__(self, minted: dict[str, str] | None) -> None:
        self._minted = minted or {}

    def _take(self, name: str) -> str:
        assert name in self._minted, f"the case mints no {name}"
        return self._minted[name]

    def challenge_id(self) -> str:
        return self._take("challenge_id")

    def approver_id(self) -> str:
        return self._take("approver_id")

    def credential_id(self) -> str:
        return self._take("credential_id")

    def identity_epoch(self) -> str:
        return self._take("identity_epoch")

    def possession_code(self) -> str:
        return CODE


def _raw(text: str | None) -> bytes | None:
    return None if text is None else base64.b64decode(text)


def _value_key(value: str) -> str:
    return value_key("lan_ed25519" if value.startswith("ed25519:") else "sms", value)


def _load(store: StateStore, context: dict[str, Any]) -> None:
    conn = store._conn
    assert conn is not None
    registry = context["registry"]
    if registry is not None:
        conn.execute(
            "INSERT INTO approver_registry (singleton, device_id, site_id,"
            " identity_epoch, revision, last_external_revision,"
            " last_external_document_sha256, credential_sequence)"
            " VALUES (1, ?, ?, ?, ?, ?, ?, ?)",
            (
                registry["device_id"],
                registry["site_id"],
                registry["identity_epoch"],
                registry["registry_revision"],
                registry["last_external_revision"],
                registry["last_external_document_sha256"],
                registry["credential_sequence"],
            ),
        )
        for credential in registry["credentials"]:
            conn.execute(
                "INSERT INTO approver_credentials (credential_id, approver_id,"
                " channel, value, value_key, sequence) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    credential["credential_id"],
                    credential["approver_id"],
                    credential["channel"],
                    credential["value"],
                    value_key(credential["channel"], credential["value"]),
                    credential["sequence"],
                ),
            )
        for tombstone in registry["tombstoned_credentials"]:
            conn.execute(
                "INSERT INTO approver_tombstones (kind, name, approver_id)"
                " VALUES ('credential', ?, ?)",
                (tombstone["credential_id"], tombstone["approver_id"]),
            )
        for approver in registry["tombstoned_approvers"]:
            conn.execute(
                "INSERT INTO approver_tombstones (kind, name) VALUES ('approver', ?)",
                (approver,),
            )
        for value in registry["tombstoned_values"]:
            conn.execute(
                "INSERT INTO approver_tombstones (kind, name, value)"
                " VALUES ('value', ?, ?)",
                (_value_key(value), value),
            )
    for held in context["challenges"]:
        challenge = held["challenge"]
        conn.execute(
            "INSERT INTO approver_challenges (challenge_id, run_id, operation,"
            " canonical, issued_at_ms, credential_sequence_at_issue, used,"
            " code_sha256) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
            (
                challenge["challenge_id"],
                RUN,
                challenge["operation"],
                canonical(challenge),
                NOW_MS - held["elapsed_ms"],
                held["credential_sequence_at_issue"],
                1 if held["state"] == "used" else 0,
            ),
        )
    for authorization in context["phone_authorizations"]:
        conn.execute(
            "INSERT INTO approver_phone_authorizations (run_id, challenge_id,"
            " challenge_sha256, authorizer_credential_id) VALUES (?, ?, ?, ?)",
            (
                RUN,
                authorization["challenge_id"],
                authorization["challenge_sha256"],
                authorization["authorizer_credential_id"],
            ),
        )
    for index, value in enumerate(context["pending_phone_values"]):
        conn.execute(
            "INSERT INTO approver_pending_phone (value, run_id, challenge_id,"
            " channel, candidate_json, code_sha256, window_start_ms,"
            " authorizer_credential_id, registry_revision, identity_epoch,"
            " site_id) VALUES (?, ?, ?, 'sms', '{}', NULL, ?, 'held', 0, '', '')",
            (value, RUN, f"held-{index}", NOW_MS),
        )
    conn.commit()


def _snapshot(store: StateStore) -> dict[str, Any]:
    conn = store._conn
    assert conn is not None
    header = conn.execute(
        "SELECT identity_epoch, revision, last_external_revision,"
        " credential_sequence FROM approver_registry"
    ).fetchone()
    return {
        "header": header,
        "challenges": dict(
            conn.execute(
                "SELECT challenge_id, used FROM approver_challenges"
            ).fetchall()
        ),
        "credentials": {
            row[0]
            for row in conn.execute("SELECT credential_id FROM approver_credentials")
        },
        "tombstones": set(
            conn.execute("SELECT kind, name, value FROM approver_tombstones").fetchall()
        ),
        "pending": {
            row[0] for row in conn.execute("SELECT value FROM approver_pending_phone")
        },
        "authorizations": conn.execute(
            "SELECT COUNT(*) FROM approver_phone_authorizations"
        ).fetchone()[0],
    }


def _changes(
    before: dict[str, Any],
    after: dict[str, Any],
    sent: list[tuple[str, str, str]],
    request: dict[str, Any] | None,
) -> list[str]:
    changes: list[str] = []
    header = after["header"]
    created = before["header"] is None and header is not None
    if created:
        assert header is not None
        changes.append(f"registry_created:{header[0]}")
        changes += [
            "challenges_cleared",
            "phone_authorizations_cleared",
            "pending_phone_cleared",
        ]
        assert request is not None
        changes.append(f"used:{request['challenge_id']}")
        assert after["challenges"] == {} and after["pending"] == set()
        assert after["authorizations"] == 0
        assert after["credentials"] == set() and after["tombstones"] == set()
        assert header[1:] == (1, 0, 0)
    else:
        for challenge_id, used in after["challenges"].items():
            if challenge_id not in before["challenges"]:
                changes.append(f"challenge_added:{challenge_id}")
                assert used == 0
            elif used and not before["challenges"][challenge_id]:
                changes.append(f"used:{challenge_id}")
        assert set(before["challenges"]) <= set(after["challenges"])
        changes += [
            f"credential_added:{c}"
            for c in after["credentials"] - before["credentials"]
        ]
        changes += [
            f"pending_phone_added:{v}" for v in after["pending"] - before["pending"]
        ]
        assert before["pending"] <= after["pending"]
        assert after["authorizations"] == before["authorizations"]
        # credential_tombstoned is an active credential removed: one leaves
        # only by revocation, and revocation tombstones exactly what it removes.
        removed = before["credentials"] - after["credentials"]
        tombstoned = {
            name
            for kind, name, _ in after["tombstones"] - before["tombstones"]
            if kind == "credential"
        }
        assert removed == tombstoned, (removed, tombstoned)
        for kind, name, value in after["tombstones"] - before["tombstones"]:
            changes.append(f"{kind}_tombstoned:{value if kind == 'value' else name}")
        assert before["tombstones"] <= after["tombstones"]
        if before["header"] is not None and after["header"] is not None:
            _, revision, external, sequence = after["header"]
            _, was_revision, was_external, was_sequence = before["header"]
            if revision != was_revision:
                changes.append(f"revision:{revision}")
            if sequence != was_sequence:
                changes.append(f"sequence:{sequence}")
            if external != was_external:
                changes.append(f"last_external_revision:{external}")
    for _channel, _to, text in sent:
        changes.append(f"code_sent:{text.split(' ')[1]}")
    return sorted(changes)


@pytest.fixture
async def store(tmp_path: Path):
    s = StateStore(db_path=str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


async def _no_operation(*_args: Any) -> Any:
    raise AssertionError("not a registry operation")


@pytest.mark.parametrize("name", list(CASES))
async def test_every_case(store: StateStore, tmp_path: Path, name: str) -> None:
    case = CASES[name]
    context = case["context"]
    _load(store, context)
    anchors = context["anchors"]
    run = RunContext(
        device_id=context["device_id"],
        verified_site_id=context["verified_site_id"],
        authenticated_phone_channels=frozenset(context["authenticated_phone_channels"]),
        anchors=Anchors(
            current=_raw(anchors["current"]) if context["anchor_available"] else None,
            previous=_raw(anchors["previous"]),
            other_class=tuple(
                k for k in (_raw(anchors["other_class"]),) if k is not None
            ),
        ),
        run_id=RUN,
    )
    sent: list[tuple[str, str, str]] = []

    async def send(channel: str, to: str, text: str) -> None:
        sent.append((channel, to, text))

    service = RegistryService(
        store,
        ApproverRegistry(run, clock=lambda: NOW_MS, minter=_Minter(context["minted"])),
        send_possession=send,
    )
    if context["registry_operation_in_flight"]:
        assert service.try_admit()
    server = OperatorSocketServer(
        directory=tmp_path / "run",
        reconcile=_no_operation,
        commission=_no_operation,
        operator_uid=lambda: context["operator_uid"],
        registry=service,
    )

    async def caller() -> PeerCredentials | None:
        uid = context["peer_uid"]
        return (
            None if uid is None else PeerCredentials(uid=uid, pid=None, login_uid=None)
        )

    received = case["request"].encode("utf-8") + (b"\n" if case["terminated"] else b"")
    assert len(case["request"].encode("utf-8")) == case["request_bytes"]
    before = _snapshot(store)
    answer = await server.answer(received, caller)
    after = _snapshot(store)

    expected = case["expected"]
    assert answer["ok"] is expected["ok"], answer
    if expected["ok"]:
        assert answer["result"] == expected["result"]
    else:
        assert answer["error"]["code"] == expected["code"], answer
    try:
        request = json.loads(case["request"].partition("\n")[0])
    except ValueError:
        request = None
    if not isinstance(request, dict):
        request = None
    assert _changes(before, after, sent, request) == sorted(expected["changes"])
    if "consumes_challenge" in expected:
        assert request is not None
        challenge_id = request["challenge_id"]
        consumed = (
            after["header"] is not None
            and before["header"] is None
            or bool(after["challenges"].get(challenge_id))
            and not before["challenges"].get(challenge_id)
        )
        assert consumed is expected["consumes_challenge"]
