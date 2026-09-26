# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The operator-socket/v1 reconcile corpus, driven through the socket and the bridge.

Every sequence in `tests/vectors/operator_socket/tier-c-reconcile.json` runs
through the admission replayer against the real dispatcher and a real SQLite
file; every local reconcile step is submitted by the real bridge
(`ori.cli_bridge`, `evidence reconcile-tier-c`) to a real
`OperatorSocketServer` over a Unix socket. The harness stands in for the
kernel only: which peer credentials the runtime reads, and whether the
bridge's peer is the runtime service identity. The installed operator
identity is `read_operator_uid` over the corpus's `operator_uid_cases`.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import sqlite3
import stat
import tempfile
from pathlib import Path
from typing import Any

import pytest

from ori import cli_bridge
from ori.operator_socket import (
    FilesystemView,
    OperatorSocketServer,
    PeerCredentials,
    read_operator_uid,
)
from ori.runtime import OriRuntime
from tests.test_tier_c_approval_sequences import (
    EXPECTED_NOT_REPRESENTED,
    Replay,
    _bounded_run,
)

CORPUS = json.loads(
    (
        Path(__file__).parent / "vectors" / "operator_socket" / "tier-c-reconcile.json"
    ).read_text()
)
UID_CASES = {case["name"]: case for case in CORPUS["operator_uid_cases"]}
REFUSALS = frozenset(
    {
        "invalid_arguments",
        "unauthenticated",
        "device_mismatch",
        "unknown_proposal",
        "zone_mismatch",
        "already_reconciled",
        "not_uncertain",
    }
)
#: The expectations this transport reads; the rest are the replayer's.
TRANSPORT_KEYS = frozenset(
    {
        "result",
        "response",
        "reconciliations",
        "reconciliation",
        "audit_required",
        "audit_attempts",
        "audit_principals",
        "bridge_files_created",
    }
)
#: Sequences whose refusal the corpus also expects as an operator notice. A
#: refusal is the socket's answer, and the bridge relays it to the caller; the
#: runtime sends no further notice. Every other expectation runs.
NOTICE_SEQUENCES = frozenset(
    {
        "a different request after reconciliation is refused already_reconciled",
        "an unauthenticated caller is refused before any record is read, and only root or the installed operator is admitted",
    }
)


def fake_filesystem(case: dict[str, Any]) -> FilesystemView:
    """The case's ownership and modes, which a non-root test cannot create."""
    entries = {
        case["install_root"]["path"]: case["install_root"],
        **{a["path"]: a for a in case["ancestors"]},
    }
    file_path = case["install_root"]["path"] + "/operator-uid"

    def result(kind: int, owner: int, mode: str) -> os.stat_result:
        return os.stat_result((kind | int(mode, 8), 1, 1, 1, owner, 0, 0, 0, 0, 0))

    def lstat(path: str) -> os.stat_result:
        entry = entries.get(path)
        if entry is None:
            raise FileNotFoundError(path)
        return result(stat.S_IFDIR, entry["owner"], entry["mode"])

    def read_nofollow(path: str) -> tuple[os.stat_result, bytes]:
        assert path == file_path, path
        if case["file"]["symlink"]:
            raise OSError(40, "Too many levels of symbolic links", path)
        info = result(stat.S_IFREG, case["file"]["owner"], case["file"]["mode"])
        return info, case["content"].encode("utf-8")

    return FilesystemView(lstat=lstat, read_nofollow=read_nofollow)


def operator_uid_of(case: dict[str, Any]) -> int | None:
    return read_operator_uid(
        Path(case["install_root"]["path"]),
        service_uid=int(case["service_uid"]),
        fs=fake_filesystem(case),
    )


@pytest.mark.parametrize("case", CORPUS["operator_uid_cases"], ids=lambda c: c["name"])
def test_operator_uid_cases(case: dict[str, Any]) -> None:
    assert operator_uid_of(case) == case["expected"]


class _Server(OperatorSocketServer):
    """The real server, counting what reached it and able to drop its answer."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.received = 0
        self.drop_answer = False

    async def _answer(self, reader: Any, writer: Any) -> dict[str, Any]:
        readline = reader.readline

        async def counted() -> bytes:
            line = await readline()
            if line:
                self.received += 1
            return line

        reader.readline = counted
        return await super()._answer(reader, writer)

    async def _write(self, writer: Any, response: dict[str, Any]) -> None:
        if self.drop_answer:
            return
        await super()._write(writer, response)


class SocketTransport:
    """Submits a corpus reconcile step through the bridge and the socket."""

    def __init__(self, monkeypatch: Any) -> None:
        self.monkeypatch = monkeypatch
        # AF_UNIX paths are short on macOS; a pytest tmp_path is too long.
        self.root = Path(tempfile.mkdtemp(prefix="ori-op-", dir="/tmp"))
        self.cwd = self.root / "cwd"
        self.cwd.mkdir()

    def close(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    async def __call__(
        self, replay: Replay, step: dict[str, Any], main: str, caplog: Any
    ) -> list[str]:
        from tests.test_tier_c_approval_sequences import _check

        assert replay.dispatcher is not None and replay.store is not None
        expect = dict(step.get("expect", {}))
        unrepresented: list[str] = []
        if expect.pop("notice", None) == "reconcile_refused":
            unrepresented.append(
                "notice:reconcile_refused (a refusal is the socket's answer, "
                "relayed to the caller by the bridge, not an operator notice)"
            )
        attempts_before = self._attempts(replay)
        answer, server = await self._submit(replay, step)
        await self._assert_transport(
            replay, step, expect, answer, server, attempts_before
        )
        rest = {k: v for k, v in expect.items() if k not in TRANSPORT_KEYS}
        unrepresented += await _check(replay, {**step, "expect": rest}, main, caplog)
        return unrepresented

    # ── the world the step describes ─────────────────────────────────────
    def _operator_uid(self, step: dict[str, Any]) -> int | None:
        if step.get("operator_identity") == "not_installed":
            return None
        if "operator_uid_file" in step:
            return operator_uid_of(UID_CASES[step["operator_uid_file"]])
        return int(CORPUS["installed_operator_uid"])

    def _peer(self, step: dict[str, Any]) -> tuple[PeerCredentials | None, str | None]:
        caller = step.get("caller", {})
        if caller.get("credentials") != "peer":
            return None, None
        login = None if caller.get("pidfd_pinned") is False else caller.get("login_uid")
        return (
            PeerCredentials(uid=int(caller["uid"]), pid=None, login_uid=login),
            caller.get("account"),
        )

    def _argv(self, step: dict[str, Any], socket_path: Path) -> list[str]:
        argv = ["evidence", "reconcile-tier-c"]
        for option, member in (
            ("--proposal-id", "proposal_id"),
            ("--device-id", "device_id"),
            ("--zone", "zone_id"),
            ("--outcome", "outcome"),
            ("--reason", "reason"),
            ("--note", "note"),
        ):
            if member in step:
                argv += [option, str(step[member])]
        if step.get("socket") == "explicit":
            argv += ["--socket", str(socket_path)]
        return argv

    def _raw_request(self, step: dict[str, Any]) -> bytes:
        """What a caller other than the bridge puts on the socket."""
        members: list[tuple[str, Any]] = []
        operation = step.get("operation", "reconcile_tier_c")
        if operation is not None:
            members.append(("operation", operation))
        for member in ("proposal_id", "device_id", "zone_id", "outcome", "reason"):
            if member in step:
                members.append((member, step[member]))
        members.append(("note", step.get("note")))
        members += list(step.get("request_fields", {}).items())
        for name in step.get("duplicate_members", []):
            members.append((name, dict(members)[name]))
        body = ",".join(json.dumps(k) + ":" + json.dumps(v) for k, v in members)
        return ("{" + body + "}\n").encode("utf-8")

    async def _submit(
        self, replay: Replay, step: dict[str, Any]
    ) -> tuple[tuple[int, dict[str, Any]], _Server | None]:
        assert replay.dispatcher is not None and replay.store is not None
        directory = self.root / "run"
        socket_path = directory / "operator.sock"
        peer, account = self._peer(step)
        store = replay.store
        dispatcher = replay.dispatcher
        runtime_device = str(step.get("runtime_device", replay.proposal["device_id"]))

        # The runtime's own reconcile, against this sequence's dispatcher and store.
        runtime = OriRuntime.__new__(OriRuntime)
        runtime._dispatcher = dispatcher
        runtime._state_store = store
        runtime._device_id = runtime_device
        reconcile = runtime._reconcile_from_operator

        operator_uid = self._operator_uid(step)
        server = _Server(
            directory=directory,
            reconcile=reconcile,
            operator_uid=lambda: operator_uid,
            peer_credentials=lambda _sock: peer,
            grant=lambda _d, _s, _u: None,
            account=lambda _uid: account,
        )
        runtime = step.get("runtime")
        if runtime != "unreachable":
            await server.start()
        if runtime == "lost_after_submit":
            server.drop_answer = True
        if step.get("operational") == "cancelled":
            server._closing = True

        failing: Any = None
        if step.get("runtime_store") == "unavailable":
            failing = sqlite3.DatabaseError("unable to open database file")
        elif step.get("operational") == "state_store_locked":
            failing = sqlite3.OperationalError("database is locked")
        if failing is not None:

            async def refuse(**_k: Any) -> Any:
                raise failing

            store.reconcile_tier_c = refuse  # type: ignore[method-assign]

        expected_uid = (
            os.geteuid() if step.get("peer") != "unverified" else os.geteuid() + 1
        )
        self.monkeypatch.setattr(
            cli_bridge, "_operator_install", lambda: (socket_path, expected_uid)
        )
        before = self._files()
        try:
            if (
                step.get("request_fields")
                or step.get("duplicate_members")
                or ("operation" in step and step["operation"] != "reconcile_tier_c")
            ):
                answer = await self._direct(socket_path, step)
            else:
                old = os.getcwd()
                os.chdir(self.cwd)
                try:
                    answer = await asyncio.to_thread(
                        cli_bridge.run_bridge, self._argv(step, socket_path)
                    )
                finally:
                    os.chdir(old)
        finally:
            if failing is not None:
                del store.reconcile_tier_c
            server._closing = False
            await server.close()
        self.created = sorted(self._files() - before)
        if (
            answer[1].get("error", {}).get("code") == "invalid_arguments"
            and runtime != "unreachable"
            and step.get("peer") != "unverified"
        ):
            # The bridge refused before connecting; the runtime decides it again.
            await server.start()
            try:
                again = await self._direct(socket_path, step)
            finally:
                await server.close()
            assert again[1]["error"]["code"] == "invalid_arguments", (again, step)
        return answer, (server if runtime != "unreachable" else None)

    async def _direct(
        self, socket_path: Path, step: dict[str, Any]
    ) -> tuple[int, dict[str, Any]]:
        """A hostile client: its request never passes the bridge's own check."""
        reader, writer = await asyncio.open_unix_connection(str(socket_path))
        try:
            writer.write(self._raw_request(step))
            await writer.drain()
            raw = await reader.readline()
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
        answer = json.loads(raw)
        if answer["ok"]:
            return 0, {"ok": True, "result": answer["result"]}
        return 2, {"ok": False, "error": answer["error"]}

    def _files(self) -> set[str]:
        return {
            str(p.relative_to(self.root))
            for p in self.root.rglob("*")
            if not str(p.relative_to(self.root)).startswith("run")
        }

    def _attempts(self, replay: Replay) -> list[dict[str, Any]]:
        with sqlite3.connect(replay.path) as conn:
            conn.row_factory = sqlite3.Row
            return [
                dict(r)
                for r in conn.execute(
                    "SELECT * FROM tier_c_reconcile_attempts ORDER BY id"
                ).fetchall()
            ]

    def _reconciliations(
        self, replay: Replay, proposal_id: str
    ) -> list[dict[str, Any]]:
        with sqlite3.connect(replay.path) as conn:
            conn.row_factory = sqlite3.Row
            return [
                dict(r)
                for r in conn.execute(
                    "SELECT * FROM tier_c_reconciliations WHERE proposal_id = ?",
                    (proposal_id,),
                ).fetchall()
            ]

    # ── what the corpus reads ─────────────────────────────────────────────
    async def _assert_transport(
        self,
        replay: Replay,
        step: dict[str, Any],
        expect: dict[str, Any],
        answer: tuple[int, dict[str, Any]],
        server: _Server | None,
        attempts_before: list[dict[str, Any]],
    ) -> None:
        rc, payload = answer
        main = str(replay.proposal["proposal_id"])
        if payload["ok"]:
            assert rc == 0, payload
            result = (
                "already_recorded"
                if payload["result"]["already_recorded"]
                else "recorded"
            )
        else:
            code = payload["error"]["code"]
            assert rc == 2, payload
            result = f"refused:{code}" if code in REFUSALS else code
        assert result == expect["result"], (result, payload, step)
        if step.get("peer") == "unverified" or step.get("runtime") == "unreachable":
            assert server is None or server.received == 0, "the runtime received it"
        if "response" in expect:
            if expect["response"] == "reconciliation":
                assert payload["ok"] and set(payload["result"]) >= {
                    "proposal_id",
                    "decision_state",
                    "operator",
                    "entry_point",
                    "recorded_at_ms",
                }, payload
            else:
                assert "result" not in payload and set(payload.get("error", {})) <= {
                    "code",
                    "detail",
                }, payload
        rows = self._reconciliations(replay, main)
        if "reconciliations" in expect:
            assert len(rows) == expect["reconciliations"], (rows, step)
        if "reconciliation" in expect:
            assert len(rows) == 1, rows
            row = rows[0]
            recorded = {
                "proposal_id": row["proposal_id"],
                "device_id": row["device_id"],
                "zone_id": row["zone_id"],
                "decision_state": row["decision_state"],
                "reason": row["reason"],
                "note": row["note"],
                "operator": {
                    "uid": row["principal_uid"],
                    "account": row["principal_account"],
                    "login_uid": row["principal_login_uid"],
                },
                "entry_point": row["entry_point"],
            }
            assert recorded == expect["reconciliation"], (recorded, step)
            if payload["ok"]:
                relayed = dict(payload["result"])
                relayed.pop("recorded_at_ms")
                relayed.pop("already_recorded")
                assert relayed == recorded, (relayed, recorded)
        attempts = self._attempts(replay)
        if "audit_required" in expect:
            new = attempts[len(attempts_before) :]
            if expect["audit_required"]:
                caller = step["caller"]
                principal = (caller["uid"], caller.get("login_uid"))
                assert any(
                    (a["principal_uid"], a["principal_login_uid"]) == principal
                    for a in attempts
                ), (attempts, step)
            else:
                assert new == [], (new, step)
        if "audit_attempts" in expect:
            got = [
                {
                    "kind": a["kind"],
                    "caller": {
                        "uid": a["principal_uid"],
                        "account": a["principal_account"],
                        "login_uid": a["principal_login_uid"],
                    },
                    "reconciliation": a["proposal_id"],
                }
                for a in attempts
            ]
            if expect["audit_attempts"]:
                assert (
                    got[: len(expect["audit_attempts"])] == expect["audit_attempts"]
                ), got
            else:
                assert got == [], got
        if "audit_principals" in expect:
            principals = sorted(
                {(a["principal_uid"], a["principal_login_uid"]) for a in attempts},
                key=lambda p: (p[0], -1 if p[1] is None else p[1]),
            )
            wanted = [(p["uid"], p["login_uid"]) for p in expect["audit_principals"]]
            assert principals == wanted, (principals, step)
        if "bridge_files_created" in expect:
            assert self.created == expect["bridge_files_created"], self.created


def _sequences() -> list[Any]:
    return [pytest.param(seq, id=seq["name"]) for seq in CORPUS["sequences"]]


@pytest.mark.parametrize("sequence", _sequences())
async def test_operator_socket_sequence(
    sequence: dict[str, Any], tmp_path: Path, monkeypatch: Any, caplog: Any
) -> None:
    replay = Replay(tmp_path, dict(CORPUS["proposal"]), monkeypatch)
    transport = SocketTransport(monkeypatch)
    replay.operator_transport = transport
    try:
        unrepresented = await _bounded_run(replay, sequence, caplog)
    finally:
        transport.close()
        if replay.store is not None and replay.store._conn is not None:
            await replay.crash()
    assert sequence["name"] not in EXPECTED_NOT_REPRESENTED
    if unrepresented:
        assert sequence["name"] in NOTICE_SEQUENCES, (sequence["name"], unrepresented)
        assert set(unrepresented) == {
            "notice:reconcile_refused (a refusal is the socket's answer, "
            "relayed to the caller by the bridge, not an operator notice)"
        }, unrepresented
    else:
        assert sequence["name"] not in NOTICE_SEQUENCES, sequence["name"]


def test_every_notice_sequence_exists_in_the_corpus() -> None:
    names = {seq["name"] for seq in CORPUS["sequences"]}
    assert NOTICE_SEQUENCES <= names
