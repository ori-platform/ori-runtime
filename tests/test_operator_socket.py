# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The operator socket over real Unix sockets, real peer credentials and the real bridge."""

from __future__ import annotations

import asyncio
import contextlib
import errno
import functools
import json
import logging
import os
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
from collections.abc import AsyncIterator, Awaitable, Iterator
from pathlib import Path
from typing import Any, cast

import pytest

from ori import cli_bridge
from ori import operator_socket as op
from ori.operator_socket import (
    AccessGrantError,
    OperatorSocketServer,
    PeerCredentials,
    ReconcileRequest,
)
from ori.runtime import OriRuntime

REPO = Path(__file__).resolve().parents[1]
VALID = {
    "operation": "reconcile_tier_c",
    "proposal_id": "AB12CD34",
    "device_id": "dev-1",
    "zone_id": "zone-a",
    "outcome": "executed",
    "reason": "site_inspection",
    "note": None,
}
RECORD = {
    "proposal_id": "AB12CD34",
    "device_id": "dev-1",
    "zone_id": "zone-a",
    "decision_state": "reconciled_executed",
    "reason": "site_inspection",
    "note": None,
    "principal_uid": 0,
    "principal_account": "root",
    "principal_login_uid": None,
    "entry_point": "local_operator_socket",
    "recorded_at_ms": 1,
}


@pytest.fixture
def short_dir() -> Iterator[Path]:
    """AF_UNIX paths are bounded near 104 bytes on macOS; pytest's tmp_path is not."""
    root = Path(tempfile.mkdtemp(prefix="ori-ops-", dir="/tmp"))
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


class Recorder:
    def __init__(self, answer: Any = None) -> None:
        self.calls: list[tuple[ReconcileRequest, PeerCredentials, str | None]] = []
        self.answer: Any = (
            answer
            if answer is not None
            else {"ok": True, "record": RECORD, "already_recorded": False}
        )

    async def __call__(
        self, request: ReconcileRequest, peer: PeerCredentials, account: str | None
    ) -> Any:
        self.calls.append((request, peer, account))
        if isinstance(self.answer, BaseException):
            raise self.answer
        if callable(self.answer):
            return await cast(Awaitable[Any], self.answer())
        return (
            {**self.answer, "record": self._record(request, peer)}
            if self.answer.get("ok")
            else self.answer
        )

    @staticmethod
    def _record(request: ReconcileRequest, peer: PeerCredentials) -> dict[str, Any]:
        """What the store appends for *request*: its outcome, reason and note."""
        return {
            **RECORD,
            "decision_state": "reconciled_executed"
            if request.outcome == "executed"
            else "reconciled_not_executed",
            "reason": request.reason,
            "note": request.note,
            "principal_uid": peer.uid,
        }


async def _no_commission(*_args: Any) -> Any:
    raise AssertionError("a reconciliation request reached the commission handler")


@contextlib.asynccontextmanager
async def serving(
    directory: Path, recorder: Recorder, **kwargs: Any
) -> AsyncIterator[OperatorSocketServer]:
    kwargs.setdefault("operator_uid", os.geteuid)
    kwargs.setdefault("commission", _no_commission)
    kwargs.setdefault("grant", lambda _d, _s, _u: None)
    server = OperatorSocketServer(
        directory=directory / "run", reconcile=recorder, **kwargs
    )
    await server.start()
    try:
        yield server
    finally:
        await server.close()


async def send(path: Path, raw: bytes, *, close_write: bool = True) -> dict[str, Any]:
    reader, writer = await asyncio.open_unix_connection(str(path))
    try:
        writer.write(raw)
        await writer.drain()
        if close_write and writer.can_write_eof():
            writer.write_eof()
        line = await asyncio.wait_for(reader.readline(), 10)
    finally:
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()
    assert line.endswith(b"\n") and line.count(b"\n") == 1, line
    return json.loads(line)


def request(**changes: Any) -> bytes:
    body = {**VALID, **changes}
    return json.dumps({k: v for k, v in body.items() if v is not ...}).encode() + b"\n"


# ── the caller, from the kernel ───────────────────────────────────────────────


async def test_the_real_peer_is_admitted_as_the_operator_identity(
    short_dir: Path,
) -> None:
    recorder = Recorder()
    async with serving(short_dir, recorder) as server:
        answer = await send(server.path, request())
    assert answer["ok"] is True, answer
    ((req, peer, _account),) = recorder.calls
    assert peer.uid == os.geteuid()
    assert answer["result"]["operator"]["uid"] == os.geteuid()
    assert req.proposal_id == "AB12CD34"
    if sys.platform.startswith("linux"):
        assert peer.pid == os.getpid()
        text = Path("/proc/self/loginuid").read_text().strip()
        unset = text == str(op.UNSET_LOGIN_UID)
        # Pinned only where the kernel offers SO_PEERPIDFD.
        assert peer.login_uid in (None if unset else int(text), None)
    else:
        assert peer.login_uid is None


@pytest.mark.skipif(os.geteuid() == 0, reason="root is always admitted")
async def test_a_real_peer_that_is_not_admitted_learns_nothing(short_dir: Path) -> None:
    recorder = Recorder()
    async with serving(short_dir, recorder, operator_uid=lambda: None) as server:
        answer = await send(server.path, request())
        other = await send(server.path, request(operator="reconcile"))
    assert answer == {
        "schema_version": 1,
        "ok": False,
        "error": {"code": "unauthenticated", "detail": "the caller is not admitted"},
    }
    assert other["error"]["code"] == "invalid_arguments"
    assert recorder.calls == []


@pytest.mark.skipif(
    not sys.platform.startswith("linux") or os.geteuid() != 0,
    reason="setting an audit login user ID needs root on Linux",
)
async def test_a_pinned_peers_audit_login_uid_is_recorded(short_dir: Path) -> None:
    recorder = Recorder()
    async with serving(short_dir, recorder, operator_uid=lambda: None) as server:
        child = (
            "import socket,sys\n"
            "open('/proc/self/loginuid','w').write('4242')\n"
            "s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])\n"
            f"s.sendall({request()!r}); print(s.makefile().readline())\n"
        )
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            child,
            str(server.path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await asyncio.wait_for(proc.communicate(), 20)
    if b"loginuid" in err and b"Operation not permitted" in err:
        pytest.skip("this kernel refuses setting the audit login user ID here")
    assert proc.returncode == 0, err
    ((_req, peer, _account),) = recorder.calls
    assert peer.uid == 0
    if peer.login_uid is None:
        pytest.skip("SO_PEERPIDFD is not available on this kernel")
    assert peer.login_uid == 4242


LINUX = sys.platform.startswith("linux")


class _PidfdSock:
    """A socket whose SO_PEERPIDFD is a real pidfd for *pid*."""

    def __init__(self, pid: int) -> None:
        self.pid = pid

    def getsockopt(self, *_a: Any) -> int:
        return os.pidfd_open(self.pid)  # type: ignore[attr-defined,unused-ignore]


@pytest.mark.skipif(not LINUX, reason="pidfds are Linux's")
def test_a_pinned_login_uid_needs_no_permission_over_the_peer(monkeypatch: Any) -> None:
    # pid 1 is another user's process for an unprivileged test, which may not
    # signal it; the pin must hold anyway.
    monkeypatch.setattr(op, "_read_login_uid", lambda _pid: "4242\n")
    assert op._pinned_login_uid(_PidfdSock(1), 1) == 4242


@pytest.mark.skipif(not LINUX, reason="pidfds are Linux's")
def test_a_login_uid_is_dropped_unless_the_pidfd_names_the_peer(
    monkeypatch: Any,
) -> None:
    monkeypatch.setattr(op, "_read_login_uid", lambda _pid: "4242\n")
    # The pidfd names pid 1 while the credentials name this process.
    assert op._pinned_login_uid(_PidfdSock(1), os.getpid()) is None
    # The process the pidfd pinned is gone by the time the read is checked.
    answers = iter([1, -1])
    monkeypatch.setattr(op, "_pidfd_pid", lambda _fd: next(answers))
    assert op._pinned_login_uid(_PidfdSock(1), 1) is None
    # An unset login UID is null.
    monkeypatch.setattr(op, "_pidfd_pid", lambda _fd: 1)
    monkeypatch.setattr(op, "_read_login_uid", lambda _pid: "4294967295")
    assert op._pinned_login_uid(_PidfdSock(1), 1) is None


def _sudo_available() -> bool:
    if not LINUX or os.geteuid() == 0 or shutil.which("sudo") is None:
        return False
    return subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0


@pytest.mark.skipif(
    not _sudo_available(), reason="needs Linux, a non-root runtime and sudo"
)
async def test_an_unprivileged_runtime_records_roots_login_uid(short_dir: Path) -> None:
    """The installed shape: the service is not root and the caller is another user."""
    recorder = Recorder()
    async with serving(short_dir, recorder, operator_uid=lambda: None) as server:
        child = (
            "import socket,sys\n"
            "open('/proc/self/loginuid','w').write('4242')\n"
            "s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])\n"
            f"s.sendall({request()!r}); print(s.makefile().readline())\n"
        )
        proc = await asyncio.create_subprocess_exec(
            "sudo",
            "-n",
            sys.executable,
            "-c",
            child,
            str(server.path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _out, err = await asyncio.wait_for(proc.communicate(), 30)
    if b"loginuid" in err:
        pytest.skip(
            f"this kernel refuses setting the audit login user ID: {err[-200:]!r}"
        )
    assert proc.returncode == 0, err
    ((_req, peer, _account),) = recorder.calls
    assert peer.uid == 0
    assert peer.login_uid == 4242


async def test_no_peer_credentials_is_unauthenticated(short_dir: Path) -> None:
    recorder = Recorder()
    async with serving(short_dir, recorder, peer_credentials=lambda _s: None) as server:
        answer = await send(server.path, request())
    assert answer["error"]["code"] == "unauthenticated"
    assert recorder.calls == []


async def test_arguments_are_decided_before_the_caller(short_dir: Path) -> None:
    recorder = Recorder()
    async with serving(
        short_dir, recorder, peer_credentials=lambda _s: None, operator_uid=lambda: None
    ) as server:
        answer = await send(server.path, request(reason="operator_said_so"))
    assert answer["error"]["code"] == "invalid_arguments"
    assert recorder.calls == []


def test_the_login_uid_is_kept_only_for_a_pinned_peer(monkeypatch: Any) -> None:
    class Sock:
        def getsockopt(self, *_a: Any) -> Any:
            raise OSError(errno.ENOPROTOOPT, "no pidfd")

    assert op._pinned_login_uid(Sock(), 1234) is None
    assert op._pinned_login_uid(Sock(), 0) is None


# ── hostile requests ──────────────────────────────────────────────────────────

HOSTILE: list[tuple[str, bytes]] = [
    ("empty line", b"\n"),
    ("nothing then EOF", b""),
    ("not json", b"reconcile please\n"),
    ("an array", b"[1,2]\n"),
    ("a string", b'"reconcile_tier_c"\n'),
    ("nesting past the recursion limit", b"[" * 4000 + b"]" * 4000 + b"\n"),
    (
        "an integer past the digit limit",
        request()[:-2] + b', "n": ' + b"9" * 5000 + b"}\n",
    ),
    ("invalid utf-8", b'{"operation":"\xff"}\n'),
    ("a NUL in the note", request(note="a\x00b")),
    (
        "a duplicate member",
        b'{"operation":"reconcile_tier_c","operation":"reconcile_tier_c"}\n',
    ),
    (
        "a member repeated after a valid request",
        request()[:-2] + b',"reason":"site_inspection"}\n',
    ),
    ("an extra member", request(uid=0)),
    ("a missing member", request(reason=...)),
    ("a missing note member", request(note=...)),
    ("no operation", request(operation=...)),
    ("a null operation", request(operation=None)),
    ("another operation", request(operation="reconcile")),
    ("evidence_commission", request(operation="evidence_commission")),
    ("an integer proposal", request(proposal_id=12)),
    ("an empty proposal", request(proposal_id="")),
    ("an object zone", request(zone_id={"z": 1})),
    ("an outcome outside the set", request(outcome="not_executed")),
    ("a reason outside the set", request(reason="operator_said_so")),
    ("an integer note", request(note=5)),
    ("a note with a control character", request(note="a\x07b")),
    ("a note with C1", request(note="a\x85b")),
    ("a note with DEL", request(note="a\x7fb")),
    ("a note one byte over", request(note="x" * 281)),
    (
        "a note of lone surrogates",
        b'{"operation":"reconcile_tier_c","proposal_id":"A","device_id":"d","zone_id":"z","outcome":"executed","reason":"site_inspection","note":"\\ud800"}\n',
    ),
    (
        "a line over the bound",
        b'{"note":"' + b"x" * (op.MAX_REQUEST_BYTES + 10) + b'"}\n',
    ),
    ("NaN", b'{"operation":NaN}\n'),
    *[
        (
            f"a lone surrogate in {name}",
            (
                json.dumps({**VALID, name: "AB"}).replace('"AB"', '"AB\\ud800"') + "\n"
            ).encode(),
        )
        for name in ("proposal_id", "device_id", "zone_id")
    ],
]


@pytest.mark.parametrize("raw", [r for _, r in HOSTILE], ids=[n for n, _ in HOSTILE])
async def test_hostile_requests_are_refused_before_any_state(
    short_dir: Path, raw: bytes
) -> None:
    recorder = Recorder()
    async with serving(short_dir, recorder) as server:
        answer = await send(server.path, raw)
    assert answer["ok"] is False
    assert answer["error"]["code"] == "invalid_arguments", answer
    assert set(answer) == {"schema_version", "ok", "error"}
    assert recorder.calls == []


async def test_the_note_bound_is_accepted(short_dir: Path) -> None:
    recorder = Recorder()
    async with serving(short_dir, recorder) as server:
        answer = await send(server.path, request(note="é" * 140))
    assert answer["ok"] is True
    assert recorder.calls[0][0].note == "é" * 140


async def test_a_silent_peer_is_answered_and_dropped(
    short_dir: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(op, "REQUEST_TIMEOUT_S", 0.2)
    recorder = Recorder()
    async with serving(short_dir, recorder) as server:
        answer = await send(server.path, b'{"operation"', close_write=False)
    assert answer["error"]["code"] == "invalid_arguments"
    assert recorder.calls == []


# ── operational outcomes ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("raised", "code"),
    [
        (sqlite3.OperationalError("database is locked"), "state_store_locked"),
        (sqlite3.OperationalError("database table is busy"), "state_store_locked"),
        (sqlite3.OperationalError("disk I/O error"), "runtime_store_unavailable"),
        (sqlite3.DatabaseError("file is not a database"), "runtime_store_unavailable"),
        (PermissionError(errno.EACCES, "read-only store"), "runtime_store_unavailable"),
        (RuntimeError("a bug"), "internal_error"),
    ],
)
async def test_store_failures_answer_their_code(
    short_dir: Path, raised: Exception, code: str
) -> None:
    async with serving(short_dir, Recorder(raised)) as server:
        answer = await send(server.path, request())
    assert answer["error"]["code"] == code


async def test_an_unknown_store_refusal_is_internal(short_dir: Path) -> None:
    async with serving(
        short_dir, Recorder({"ok": False, "error": "surprise"})
    ) as server:
        answer = await send(server.path, request())
    assert answer["error"]["code"] == "internal_error"


async def test_a_stopping_runtime_cancels_before_the_append(short_dir: Path) -> None:
    recorder = Recorder()
    async with serving(short_dir, recorder) as server:
        server._closing = True
        answer = await send(server.path, request())
        server._closing = False
    assert answer["error"]["code"] == "cancelled"
    assert recorder.calls == []


async def test_a_stopping_runtime_tells_an_unadmitted_caller_nothing(
    short_dir: Path,
) -> None:
    recorder = Recorder()
    async with serving(short_dir, recorder, peer_credentials=lambda _s: None) as server:
        server._closing = True
        answer = await send(server.path, request())
        server._closing = False
    assert answer["error"]["code"] == "unauthenticated"


async def test_an_append_begun_completes_when_the_socket_closes(
    short_dir: Path,
) -> None:
    started = asyncio.Event()
    release = asyncio.Event()
    finished: list[bool] = []

    async def slow() -> Any:
        started.set()
        await release.wait()
        finished.append(True)
        return {"ok": True, "record": RECORD, "already_recorded": False}

    server = OperatorSocketServer(
        directory=short_dir / "run",
        reconcile=Recorder(slow),
        commission=_no_commission,
        operator_uid=os.geteuid,
        grant=lambda _d, _s, _u: None,
    )
    await server.start()
    client = asyncio.create_task(send(server.path, request()))
    await asyncio.wait_for(started.wait(), 5)
    closing = asyncio.create_task(server.close())
    await asyncio.sleep(0.05)
    assert not closing.done(), "close did not wait for the append"
    release.set()
    await asyncio.wait_for(closing, 5)
    assert finished == [True]
    with contextlib.suppress(Exception):
        await asyncio.wait_for(client, 5)


async def test_a_held_append_lands_before_the_store_closes(
    short_dir: Path,
) -> None:
    """A begun append completes before the socket, and then the store, close.

    The append is held inside its store transaction while the runtime's
    shutdown order runs: the socket closes, then the store. Neither may finish
    underneath it, and the record must be there.
    """
    import threading

    from ori.state.store import StateStore

    store = StateStore(str(short_dir / "s.db"))
    await store.open()
    entered = threading.Event()
    release = threading.Event()
    original = store._reconcile_tier_c_sync

    def held(req: dict[str, Any]) -> dict[str, Any]:
        entered.set()
        release.wait(10)
        assert store._conn is not None
        store._conn.execute(
            "INSERT INTO tier_c_reconcile_attempts (proposal_id, kind, recorded_at_ms)"
            " VALUES ('AB12CD34', 'probe', 1)"
        )
        store._conn.commit()
        return {"ok": False, "error": "unknown_proposal"}

    store._reconcile_tier_c_sync = held  # type: ignore[method-assign]

    async def reconcile(
        request: ReconcileRequest, peer: PeerCredentials, _a: Any
    ) -> Any:
        return await store.reconcile_tier_c(
            proposal_id=request.proposal_id,
            device_id=request.device_id,
            runtime_device_id="dev-1",
            zone_id=request.zone_id,
            outcome=request.outcome,
            reason=request.reason,
            note=request.note,
            source="operator_local",
            entry_point="local_operator_socket",
            principal_uid=peer.uid,
            principal_account=None,
            principal_login_uid=None,
        )

    server = OperatorSocketServer(
        directory=short_dir / "run",
        reconcile=reconcile,
        commission=_no_commission,
        operator_uid=os.geteuid,
        grant=lambda _d, _s, _u: None,
    )
    await server.start()
    client = asyncio.create_task(send(server.path, request()))
    assert await asyncio.to_thread(entered.wait, 5)
    # The runtime's order: the socket closes, then the store. Both start while
    # the append is held, past the socket's close timeout.
    closing_socket = asyncio.create_task(server.close())
    await asyncio.sleep(0.05)
    closing_store = asyncio.create_task(store.close())
    await asyncio.sleep(0.4)
    assert not closing_socket.done(), "the socket closed with an append begun"
    assert not closing_store.done(), "the store closed underneath a begun append"
    release.set()
    await asyncio.wait_for(asyncio.gather(closing_socket, closing_store), 10)
    store._reconcile_tier_c_sync = original  # type: ignore[method-assign]
    with contextlib.suppress(Exception):
        await asyncio.wait_for(client, 5)
    with sqlite3.connect(short_dir / "s.db") as conn:
        rows = conn.execute(
            "SELECT count(*) FROM tier_c_reconcile_attempts WHERE kind = 'probe'"
        ).fetchone()
    assert rows == (1,)


# ── binding ───────────────────────────────────────────────────────────────────


async def test_the_socket_and_directory_grant_no_group_or_world_access(
    short_dir: Path,
) -> None:
    server = OperatorSocketServer(
        directory=short_dir / "run",
        reconcile=Recorder(),
        commission=_no_commission,
        operator_uid=lambda: None,
    )
    await server.start()
    try:
        assert stat.S_IMODE(os.lstat(server.path).st_mode) == 0o600
        assert stat.S_IMODE(os.lstat(short_dir / "run").st_mode) == 0o700
    finally:
        await server.close()
    assert not os.path.lexists(server.path)


async def test_a_grant_that_fails_leaves_no_socket(short_dir: Path) -> None:
    def refuse(_d: Path, _s: Path, _u: int | None) -> None:
        raise AccessGrantError("no access-control lists here")

    server = OperatorSocketServer(
        directory=short_dir / "run",
        reconcile=Recorder(),
        commission=_no_commission,
        operator_uid=lambda: 1001,
        grant=refuse,
    )
    with pytest.raises(AccessGrantError):
        await server.start()
    assert not os.path.lexists(server.path)


@pytest.mark.skipif(
    sys.platform.startswith("linux"), reason="this platform has access-control lists"
)
async def test_an_operator_identity_without_access_control_lists_binds_nothing(
    short_dir: Path,
) -> None:
    server = OperatorSocketServer(
        directory=short_dir / "run",
        reconcile=Recorder(),
        commission=_no_commission,
        operator_uid=lambda: 1001,
    )
    with pytest.raises(AccessGrantError):
        await server.start()
    assert not os.path.lexists(server.path)


async def test_a_live_listener_is_never_displaced(short_dir: Path) -> None:
    async with serving(short_dir, Recorder()) as first:
        second = OperatorSocketServer(
            directory=short_dir / "run",
            reconcile=Recorder(),
            commission=_no_commission,
            operator_uid=lambda: None,
            grant=lambda _d, _s, _u: None,
        )
        with pytest.raises(OSError) as raised:
            await second.start()
        assert raised.value.errno == errno.EADDRINUSE
        answer = await send(first.path, request())
        assert answer["ok"] is True


async def test_a_stale_socket_is_replaced_and_a_file_is_refused(
    short_dir: Path,
) -> None:
    run = short_dir / "run"
    run.mkdir(mode=0o700)
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(str(run / op.SOCKET_NAME))
    stale.close()
    async with serving(short_dir, Recorder()) as server:
        assert (await send(server.path, request()))["ok"] is True
    (run / op.SOCKET_NAME).write_text("not a socket")
    server = OperatorSocketServer(
        directory=run,
        reconcile=Recorder(),
        commission=_no_commission,
        operator_uid=lambda: None,
        grant=lambda _d, _s, _u: None,
    )
    with pytest.raises(RuntimeError, match="not a socket"):
        await server.start()
    assert (run / op.SOCKET_NAME).read_text() == "not a socket"


def test_access_control_lists_encode_the_operator_alone() -> None:
    raw = op._exact_acl(0o6, 1001, 0o6)
    entries = op._decode_acl(raw)
    assert entries == sorted(entries)
    assert (op._ACL_USER, 0o6, 1001) in entries
    assert (op._ACL_GROUP_OBJ, 0, op._ACL_UNDEFINED_ID) in entries
    assert (op._ACL_OTHER, 0, op._ACL_UNDEFINED_ID) in entries
    assert [e for e in entries if e[0] == op._ACL_USER] == [(op._ACL_USER, 0o6, 1001)]
    with pytest.raises(AccessGrantError):
        op._decode_acl(b"\x02\x00\x00\x00\x01")


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="no access-control lists"
)
def test_real_access_control_entries_name_the_operator(short_dir: Path) -> None:
    run = short_dir / "run"
    run.mkdir(mode=0o700)
    sock = run / "s"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(sock))
    s.close()
    try:
        op.grant_access(run, sock, 1001)
    except AccessGrantError as exc:
        pytest.skip(f"this filesystem refuses access-control lists: {exc}")
    socket_entries = op._decode_acl(os.getxattr(sock, op._ACL_XATTR))
    dir_entries = op._decode_acl(os.getxattr(run, op._ACL_XATTR))
    assert (op._ACL_USER, 0o6, 1001) in socket_entries
    assert (op._ACL_USER, 0o1, 1001) in dir_entries
    assert stat.S_IMODE(os.lstat(run).st_mode) & 0o007 == 0
    op.grant_access(run, sock, None)
    assert stat.S_IMODE(os.lstat(run).st_mode) == 0o700
    with pytest.raises(OSError):
        os.getxattr(run, op._ACL_XATTR)


def _set_acl(path: Path, entries: list[tuple[int, int, int]]) -> None:
    os.setxattr(path, op._ACL_XATTR, op._encode_acl(entries))  # type: ignore[attr-defined,unused-ignore]


@pytest.mark.skipif(not LINUX, reason="no access-control lists")
def test_an_ancestor_gains_search_for_the_operator_and_nothing_else(
    short_dir: Path,
) -> None:
    # An operator other than whoever runs the test, which owns these directories.
    operator = 1001 if os.geteuid() != 1001 else 1002
    parent = short_dir / "parent"
    parent.mkdir(mode=0o700)
    run = parent / "run"
    run.mkdir(mode=0o700)
    sock = run / "s"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(sock))
    s.close()
    try:
        op.grant_access(run, sock, operator)
    except AccessGrantError as exc:
        pytest.skip(f"this filesystem refuses access-control lists: {exc}")
    entries = sorted(op._decode_acl(os.getxattr(parent, op._ACL_XATTR)))  # type: ignore[attr-defined,unused-ignore]
    assert entries == sorted(
        [
            (op._ACL_USER_OBJ, 0o7, op._ACL_UNDEFINED_ID),
            (op._ACL_USER, 0o1, operator),
            (op._ACL_GROUP_OBJ, 0, op._ACL_UNDEFINED_ID),
            (op._ACL_MASK, 0o1, op._ACL_UNDEFINED_ID),
            (op._ACL_OTHER, 0, op._ACL_UNDEFINED_ID),
        ]
    )


@pytest.mark.skipif(not LINUX, reason="no access-control lists")
def test_a_mask_that_withholds_search_is_never_widened(short_dir: Path) -> None:
    ancestor = short_dir / "ancestor"
    ancestor.mkdir(mode=0o700)
    before = [
        (op._ACL_USER_OBJ, 0o7, op._ACL_UNDEFINED_ID),
        (op._ACL_GROUP_OBJ, 0o5, op._ACL_UNDEFINED_ID),
        (op._ACL_MASK, 0o4, op._ACL_UNDEFINED_ID),
        (op._ACL_OTHER, 0, op._ACL_UNDEFINED_ID),
    ]
    try:
        _set_acl(ancestor, before)
    except OSError as exc:
        pytest.skip(f"this filesystem refuses access-control lists: {exc}")
    with pytest.raises(AccessGrantError, match="mask"):
        op._grant_search(ancestor, 1001)
    assert sorted(op._decode_acl(os.getxattr(ancestor, op._ACL_XATTR))) == sorted(
        before
    )  # type: ignore[attr-defined,unused-ignore]


@pytest.mark.skipif(
    not LINUX or os.geteuid() != 0, reason="needs root to give the directory away"
)
async def test_a_runtime_directory_another_user_owns_is_refused(
    short_dir: Path,
) -> None:
    run = short_dir / "run"
    run.mkdir(mode=0o700)
    os.chown(run, 12345, 12345)
    server = OperatorSocketServer(
        directory=run,
        reconcile=Recorder(),
        commission=_no_commission,
        operator_uid=lambda: None,
    )
    with pytest.raises(RuntimeError, match="this runtime owns"):
        await server.start()
    assert not os.path.lexists(run / op.SOCKET_NAME)


# ── the installed operator identity, on the real filesystem ──────────────────


def test_the_identity_file_is_never_followed_or_blocked_on(short_dir: Path) -> None:
    target = short_dir / "real"
    target.write_text("1001\n")
    link = short_dir / "operator-uid"
    link.symlink_to(target)
    with pytest.raises(OSError):
        op._read_nofollow(str(link))
    fifo = short_dir / "fifo"
    os.mkfifo(fifo)
    info, content = op._read_nofollow(str(fifo))
    assert stat.S_ISFIFO(info.st_mode) and content == b""


def test_an_installation_this_test_owns_installs_no_operator(short_dir: Path) -> None:
    (short_dir / "operator-uid").write_text("1001\n")
    assert op.read_operator_uid(short_dir, service_uid=998) is None
    assert op.read_operator_uid(None, service_uid=998) is None
    assert op.read_operator_uid(Path("relative"), service_uid=998) is None


@pytest.mark.parametrize(
    ("prefix", "root"),
    [
        ("/opt/ori/current/venv", "/opt/ori"),
        ("/opt/ori/releases/2.5.0/venv", "/opt/ori"),
        ("/home/u/.local/ori/current/venv", "/home/u/.local/ori"),
        ("/home/u/ori/.venv", None),
        ("/usr", None),
        ("venv", None),
        ("/opt/ori/other/venv", None),
    ],
)
def test_the_install_root_is_the_interpreters(prefix: str, root: str | None) -> None:
    got = op.install_root_for_prefix(prefix)
    assert (str(got) if got else None) == root


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("/run/ori", "/run/ori"),
        ("", None),
        ("run/ori", None),
        ("/run/ori:/run/other", None),
    ],
)
def test_the_runtime_directory_is_systemds(value: str, expected: str | None) -> None:
    got = op.runtime_directory({"RUNTIME_DIRECTORY": value})
    assert (str(got) if got else None) == expected
    assert op.runtime_directory({}) is None


# ── the runtime binds it ──────────────────────────────────────────────────────


def _bare_runtime() -> OriRuntime:
    runtime = OriRuntime.__new__(OriRuntime)
    runtime._operator_socket_server = None
    runtime._dispatcher = None
    runtime._state_store = None
    runtime._device_id = "dev-1"
    return runtime


async def test_no_runtime_directory_binds_nothing_and_says_so(
    monkeypatch: Any, caplog: Any
) -> None:
    monkeypatch.delenv("RUNTIME_DIRECTORY", raising=False)
    runtime = _bare_runtime()
    with caplog.at_level(logging.WARNING, logger="ori.runtime"):
        await runtime._start_operator_socket("development")
    assert runtime._operator_socket_server is None
    (record,) = [
        r for r in caplog.records if "operator socket is not bound" in r.getMessage()
    ]
    assert record.levelno == logging.WARNING


@pytest.mark.parametrize("profile", ["staging", "production"])
async def test_no_runtime_directory_outside_development_is_critical(
    monkeypatch: Any, caplog: Any, profile: str
) -> None:
    monkeypatch.delenv("RUNTIME_DIRECTORY", raising=False)
    runtime = _bare_runtime()
    with caplog.at_level(logging.WARNING, logger="ori.runtime"):
        await runtime._start_operator_socket(profile)
    assert runtime._operator_socket_server is None
    (record,) = [
        r for r in caplog.records if "operator socket is not bound" in r.getMessage()
    ]
    assert record.levelno == logging.CRITICAL


async def test_a_socket_that_cannot_bind_is_critical_and_leaves_nothing(
    short_dir: Path, monkeypatch: Any, caplog: Any
) -> None:
    blocker = short_dir / "file"
    blocker.write_text("")
    monkeypatch.setenv("RUNTIME_DIRECTORY", str(blocker / "ori"))
    runtime = _bare_runtime()
    with caplog.at_level(logging.CRITICAL, logger="ori.runtime"):
        await runtime._start_operator_socket("development")
    assert runtime._operator_socket_server is None
    critical = [r for r in caplog.records if r.levelno == logging.CRITICAL]
    assert (
        critical and str(blocker / "ori" / op.SOCKET_NAME) in critical[0].getMessage()
    )
    assert not os.path.lexists(blocker / "ori")


async def test_the_runtime_answers_through_its_dispatcher(
    short_dir: Path, monkeypatch: Any
) -> None:
    monkeypatch.setenv("RUNTIME_DIRECTORY", str(short_dir / "run"))
    installed: list[Any] = []

    def operator_uid(root: Any, *, service_uid: int) -> int:
        installed.append((root, service_uid))
        return os.geteuid()

    monkeypatch.setattr("ori.runtime.read_operator_uid", operator_uid)
    # Access-control lists are Linux's; this proves the wiring, not the grant.
    monkeypatch.setattr(
        "ori.runtime.OperatorSocketServer",
        functools.partial(
            OperatorSocketServer,
            grant=lambda _d, _s, _u: None,
            peer_credentials=lambda _s: PeerCredentials(
                uid=os.geteuid(), pid=None, login_uid=4242
            ),
        ),
    )
    runtime = _bare_runtime()
    store = object()
    runtime._state_store = store  # type: ignore[assignment]
    seen: dict[str, Any] = {}

    class Dispatcher:
        async def reconcile_tier_c(self, given: Any, **kwargs: Any) -> Any:
            seen.update(kwargs, store=given)
            return {"ok": False, "error": "device_mismatch"}

    runtime._dispatcher = Dispatcher()  # type: ignore[assignment]
    await runtime._start_operator_socket("production")
    server = runtime._operator_socket_server
    assert server is not None
    try:
        answer = await send(server.path, request(device_id="dev-2", note="seen"))
    finally:
        await server.close()
    assert answer["error"]["code"] == "device_mismatch"
    assert seen["store"] is store
    assert seen["runtime_device_id"] == "dev-1" and seen["device_id"] == "dev-2"
    assert seen["principal_uid"] == os.geteuid() and seen["note"] == "seen"
    assert seen["principal_login_uid"] == 4242
    assert installed and installed[0][1] == os.geteuid()


# ── the bridge ────────────────────────────────────────────────────────────────


def _bridge_argv(**changes: Any) -> list[str]:
    args = {
        "--proposal-id": "AB12CD34",
        "--device-id": "dev-1",
        "--zone": "zone-a",
        "--outcome": "executed",
        "--reason": "site_inspection",
        **changes,
    }
    argv = ["evidence", "reconcile-tier-c"]
    for key, value in args.items():
        if value is not None:
            argv += [key, value]
    return argv


async def test_the_bridge_verifies_the_real_peer_before_sending(
    short_dir: Path, monkeypatch: Any
) -> None:
    recorder = Recorder()
    async with serving(short_dir, recorder) as server:
        monkeypatch.setattr(
            cli_bridge, "_operator_install", lambda: (server.path, os.geteuid())
        )
        rc, payload = await asyncio.to_thread(cli_bridge.run_bridge, _bridge_argv())
        assert (rc, payload["ok"]) == (0, True), payload
        assert payload["command"] == "evidence reconcile-tier-c"
        assert payload["result"]["decision_state"] == "reconciled_executed"
        monkeypatch.setattr(
            cli_bridge,
            "_operator_install",
            lambda: (Path("/nonexistent"), os.geteuid() + 1),
        )
        rc, payload = await asyncio.to_thread(
            cli_bridge.run_bridge, _bridge_argv(**{"--socket": str(server.path)})
        )
    assert (rc, payload["error"]["code"]) == (2, "runtime_unavailable"), payload
    assert len(recorder.calls) == 1


@pytest.mark.parametrize(
    "reply",
    [
        b"",
        b'{"schema_version":1,"ok":tr',
        b'{"schema_version":1,"ok":true,"result":{"already_recorded":false}}',
    ],
    ids=["nothing", "a partial object", "a whole object with no terminator"],
)
async def test_an_answer_the_connection_cut_short_establishes_nothing(
    short_dir: Path, monkeypatch: Any, reply: bytes
) -> None:
    path = short_dir / "fake.sock"

    async def cut(reader: Any, writer: Any) -> None:
        await reader.readline()
        writer.write(reply)
        await writer.drain()
        writer.close()

    server = await asyncio.start_unix_server(cut, path=str(path))
    monkeypatch.setattr(cli_bridge, "_operator_install", lambda: (path, os.geteuid()))
    try:
        rc, payload = await asyncio.to_thread(cli_bridge.run_bridge, _bridge_argv())
    finally:
        server.close()
        await server.wait_closed()
    assert (rc, payload["error"]["code"]) == (2, "runtime_unavailable"), payload


async def test_the_bridge_relays_an_internal_error_as_exit_one(
    short_dir: Path, monkeypatch: Any
) -> None:
    async with serving(short_dir, Recorder(RuntimeError("bug"))) as server:
        monkeypatch.setattr(
            cli_bridge, "_operator_install", lambda: (server.path, os.geteuid())
        )
        rc, payload = await asyncio.to_thread(cli_bridge.run_bridge, _bridge_argv())
    assert (rc, payload["error"]["code"]) == (1, "internal_error")
    # A fault, not a refusal: it is outside the contract's closed exit-2 set.
    assert "internal_error" not in op.RECONCILE_ERRORS


_RECONCILED = {
    "proposal_id": "AB12CD34",
    "device_id": "dev-1",
    "zone_id": "zone-a",
    "decision_state": "reconciled_executed",
    "reason": "site_inspection",
    "note": None,
    "operator": {"uid": 0, "account": "root", "login_uid": None},
    "entry_point": "local_operator_socket",
    "recorded_at_ms": 1,
    "already_recorded": False,
}


_FEEDBACK_RECORD = {
    **_RECONCILED,
    "reason": "actuator_position_observed",
    "operator": {"uid": None, "account": None, "login_uid": None},
    "entry_point": "commissioned_feedback",
    "already_recorded": True,
}
_NO_OPERATOR = {"uid": None, "account": None, "login_uid": None}
_UNBOUND_RECONCILED: list[tuple[str, dict[str, Any]]] = [
    ("a lie", {"lie": True}),
    ("another proposal", {**_RECONCILED, "proposal_id": "ZZ99ZZ99"}),
    ("another device", {**_RECONCILED, "device_id": "dev-2"}),
    ("another zone", {**_RECONCILED, "zone_id": "zone-b"}),
    ("an extra field", {**_RECONCILED, "extra": 1}),
    (
        "a missing field",
        {k: v for k, v in _RECONCILED.items() if k != "recorded_at_ms"},
    ),
    ("another outcome", {**_RECONCILED, "decision_state": "reconciled_not_executed"}),
    ("an unreconciled state", {**_RECONCILED, "decision_state": "dispatch_not_proven"}),
    ("another reason", {**_RECONCILED, "reason": "instrument_measurement"}),
    ("another note", {**_RECONCILED, "note": "seen"}),
    ("an operator that is not an object", {**_RECONCILED, "operator": 0}),
    (
        "an operator with an extra member",
        {**_RECONCILED, "operator": {**_RECONCILED["operator"], "pid": 1}},
    ),
    (
        "an operator uid as text",
        {**_RECONCILED, "operator": {**_RECONCILED["operator"], "uid": "0"}},
    ),
    (
        "an operator uid as a boolean",
        {**_RECONCILED, "operator": {**_RECONCILED["operator"], "uid": False}},
    ),
    (
        "a negative operator uid",
        {**_RECONCILED, "operator": {**_RECONCILED["operator"], "uid": -1}},
    ),
    ("a socket record with no operator", {**_RECONCILED, "operator": _NO_OPERATOR}),
    (
        "an operator account that is not text",
        {**_RECONCILED, "operator": {**_RECONCILED["operator"], "account": 0}},
    ),
    (
        "an operator login uid as text",
        {**_RECONCILED, "operator": {**_RECONCILED["operator"], "login_uid": "1"}},
    ),
    ("another entry point", {**_RECONCILED, "entry_point": "cli_bridge"}),
    (
        "a new record from feedback",
        {**_FEEDBACK_RECORD, "already_recorded": False},
    ),
    (
        "a feedback record with an operator",
        {**_FEEDBACK_RECORD, "operator": _RECONCILED["operator"]},
    ),
    ("a negative time", {**_RECONCILED, "recorded_at_ms": -1}),
    ("a time as a float", {**_RECONCILED, "recorded_at_ms": 1.0}),
    ("a time as a boolean", {**_RECONCILED, "recorded_at_ms": True}),
    ("already_recorded as an integer", {**_RECONCILED, "already_recorded": 0}),
]


async def _relay_through_fake_peer(
    short_dir: Path, monkeypatch: Any, envelope: Any, argv: list[str]
) -> tuple[int, dict[str, Any]]:
    """The real bridge, against a verified peer that answers *envelope*."""
    path = short_dir / "fake.sock"

    async def answer(reader: Any, writer: Any) -> None:
        await reader.readline()
        writer.write(json.dumps(envelope).encode() + b"\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_unix_server(answer, path=str(path))
    monkeypatch.setattr(cli_bridge, "_operator_install", lambda: (path, os.geteuid()))
    try:
        return await asyncio.to_thread(cli_bridge.run_bridge, argv)
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.parametrize(
    "result,argv",
    [
        (_RECONCILED, _bridge_argv()),
        ({**_RECONCILED, "already_recorded": True}, _bridge_argv()),
        (
            {**_RECONCILED, "decision_state": "reconciled_not_executed", "note": "x"},
            _bridge_argv(**{"--outcome": "not-executed", "--note": "x"}),
        ),
        (
            _FEEDBACK_RECORD,
            _bridge_argv(**{"--reason": "actuator_position_observed"}),
        ),
    ],
    ids=["bound", "already recorded", "not executed with a note", "feedback repeat"],
)
async def test_a_reconcile_success_bound_to_this_request_is_relayed(
    short_dir: Path, monkeypatch: Any, result: dict[str, Any], argv: list[str]
) -> None:
    rc, payload = await _relay_through_fake_peer(
        short_dir,
        monkeypatch,
        {"schema_version": 1, "ok": True, "result": result},
        argv,
    )
    assert (rc, payload["ok"], payload["result"]) == (0, True, result), payload


@pytest.mark.parametrize(
    "result",
    [row for _, row in _UNBOUND_RECONCILED],
    ids=[name for name, _ in _UNBOUND_RECONCILED],
)
async def test_a_reconcile_success_is_relayed_only_for_this_request(
    short_dir: Path, monkeypatch: Any, result: dict[str, Any]
) -> None:
    argv = _bridge_argv(
        **(
            {"--reason": "actuator_position_observed"}
            if result.get("entry_point") == "commissioned_feedback"
            else {}
        )
    )
    rc, payload = await _relay_through_fake_peer(
        short_dir,
        monkeypatch,
        {"schema_version": 1, "ok": True, "result": result},
        argv,
    )
    assert payload["ok"] is False and "result" not in payload, payload
    assert (rc, payload["error"]["code"]) == (1, "internal_error")


def _reconcile_request(argv: list[str]) -> dict[str, Any]:
    request, _socket = cli_bridge._reconcile_arguments(argv[2:])
    return request


@pytest.mark.parametrize(
    "result",
    [row for _, row in _UNBOUND_RECONCILED],
    ids=[name for name, _ in _UNBOUND_RECONCILED],
)
def test_the_reconcile_bound_refuses_without_raising(result: dict[str, Any]) -> None:
    """Every unbound row is a refusal of the bound itself, never a crash past it."""
    reason = (
        {"--reason": "actuator_position_observed"}
        if result.get("entry_point") == "commissioned_feedback"
        else {}
    )
    assert (
        cli_bridge._reconcile_bound(_reconcile_request(_bridge_argv(**reason)))(result)
        is False
    )


async def test_a_reconcile_success_for_a_device_id_no_runtime_has_is_not_relayed(
    short_dir: Path, monkeypatch: Any
) -> None:
    """Echoing a device ID the bridge accepted is not enough: it must be one."""
    result = {**_RECONCILED, "device_id": "dev 1"}
    argv = _bridge_argv(**{"--device-id": "dev 1"})
    assert cli_bridge._reconcile_bound(_reconcile_request(argv))(result) is False
    rc, payload = await _relay_through_fake_peer(
        short_dir,
        monkeypatch,
        {"schema_version": 1, "ok": True, "result": result},
        argv,
    )
    assert (rc, payload["error"]["code"]) == (1, "internal_error"), payload


@pytest.mark.parametrize(
    "envelope",
    [
        {"schema_version": 1, "ok": True, "result": _RECONCILED, "extra": 1},
        {"ok": True, "result": _RECONCILED},
        {"schema_version": 2, "ok": True, "result": _RECONCILED},
        {"schema_version": True, "ok": True, "result": _RECONCILED},
        {"schema_version": "1", "ok": True, "result": _RECONCILED},
        {"schema_version": 1, "ok": True, "result": [_RECONCILED]},
        {"schema_version": 1, "ok": True},
    ],
    ids=[
        "an extra member",
        "no schema version",
        "another schema version",
        "a boolean schema version",
        "a text schema version",
        "a result that is not an object",
        "no result",
    ],
)
async def test_a_success_envelope_the_runtime_does_not_send_is_not_relayed(
    short_dir: Path, monkeypatch: Any, envelope: dict[str, Any]
) -> None:
    rc, payload = await _relay_through_fake_peer(
        short_dir, monkeypatch, envelope, _bridge_argv()
    )
    assert payload["ok"] is False and "result" not in payload, payload
    assert (rc, payload["error"]["code"]) == (1, "internal_error")


async def _returning(answer: Any) -> Any:
    return answer


@pytest.mark.parametrize(
    "answer",
    [
        {"ok": True, "record": RECORD},
        {"ok": True, "record": RECORD, "already_recorded": 0},
        {"ok": True, "record": RECORD, "already_recorded": False, "extra": 1},
        {"ok": 1, "record": RECORD, "already_recorded": False},
        {
            "ok": True,
            "record": {**RECORD, "principal_uid": "0"},
            "already_recorded": False,
        },
        {
            "ok": True,
            "record": {**RECORD, "principal_uid": None},
            "already_recorded": False,
        },
        {
            "ok": True,
            "record": {**RECORD, "reason": "trust_me"},
            "already_recorded": False,
        },
        {"ok": True, "record": {**RECORD, "note": "x"}, "already_recorded": False},
        {
            "ok": True,
            "record": {**RECORD, "zone_id": "zone-b"},
            "already_recorded": False,
        },
        {
            "ok": True,
            "record": {**RECORD, "decision_state": "dispatch_not_proven"},
            "already_recorded": False,
        },
        {
            "ok": True,
            "record": {**RECORD, "entry_point": "x"},
            "already_recorded": False,
        },
        {
            "ok": True,
            "record": {**RECORD, "recorded_at_ms": "1"},
            "already_recorded": False,
        },
        {"ok": False, "error": 7},
        {"ok": False, "error": "device_mismatch", "detail": "x"},
        {"ok": 0, "error": "device_mismatch"},
    ],
    ids=[
        "no already_recorded",
        "already_recorded as an integer",
        "an extra member",
        "ok as an integer",
        "a principal uid as text",
        "a socket record with no principal",
        "another reason",
        "another note",
        "another zone",
        "an unreconciled state",
        "another entry point",
        "a time as text",
        "a refusal code that is not text",
        "a refusal with an extra member",
        "a refusal with ok as an integer",
    ],
)
async def test_the_socket_never_normalises_a_malformed_reconcile_answer(
    short_dir: Path, answer: dict[str, Any]
) -> None:
    """The server's own answer is `internal_error`, never a coerced success."""
    recorder = Recorder(lambda: _returning(answer))
    async with serving(short_dir, recorder) as server:
        reply = await send(server.path, request())
    assert reply["ok"] is False and "result" not in reply, reply
    assert reply["error"]["code"] == "internal_error", reply


async def test_the_socket_answers_a_feedback_record_repeat(short_dir: Path) -> None:
    """The positive control: the earlier record, written by feedback, is answered."""
    record = {
        **RECORD,
        "reason": "actuator_position_observed",
        "principal_uid": None,
        "principal_account": None,
        "entry_point": "commissioned_feedback",
    }
    answer = {"ok": True, "record": record, "already_recorded": True}
    recorder = Recorder(lambda: _returning(answer))
    async with serving(short_dir, recorder) as server:
        reply = await send(server.path, request(reason="actuator_position_observed"))
    assert reply["ok"] is True, reply
    assert reply["result"]["operator"] == {
        "uid": None,
        "account": None,
        "login_uid": None,
    }
    assert reply["result"]["entry_point"] == "commissioned_feedback"


def test_the_bridge_derives_the_user_scope_identity(
    short_dir: Path, monkeypatch: Any
) -> None:
    root = short_dir / "ori"
    (root / "current" / "venv").mkdir(parents=True)
    monkeypatch.setattr(sys, "prefix", str(root / "current" / "venv"))
    path, uid = cli_bridge._operator_install()
    assert uid == os.lstat(root).st_uid
    assert path == Path("/run/user") / str(uid) / "ori" / "operator.sock"


def test_the_bridge_derives_the_system_scope_identity(
    short_dir: Path, monkeypatch: Any
) -> None:
    import pwd

    from ori.installer import paths

    root = short_dir / "opt-ori"
    unit = short_dir / "ori-runtime.service"
    me = pwd.getpwuid(os.geteuid()).pw_name
    unit.write_text(f"[Service]\nUser={me}\n")
    monkeypatch.setattr(paths, "SYSTEM_ROOT", root)
    monkeypatch.setattr(paths, "SYSTEM_UNIT", unit)
    monkeypatch.setattr(sys, "prefix", str(root / "releases" / "2.5.0" / "venv"))
    assert cli_bridge._operator_install() == (
        Path("/run/ori/operator.sock"),
        os.geteuid(),
    )
    unit.write_text("[Service]\nUser=no-such-account-ori\n")
    with pytest.raises(cli_bridge.BridgeError) as raised:
        cli_bridge._operator_install()
    assert raised.value.code == "runtime_unavailable"


BRIDGE_HOSTILE: list[tuple[str, list[str], str]] = [
    ("no arguments", ["evidence", "reconcile-tier-c"], "invalid_arguments"),
    ("a missing reason", _bridge_argv(**{"--reason": None}), "invalid_arguments"),
    (
        "a reason outside the set",
        _bridge_argv(**{"--reason": "trust_me"}),
        "invalid_arguments",
    ),
    (
        "an outcome outside the set",
        _bridge_argv(**{"--outcome": "maybe"}),
        "invalid_arguments",
    ),
    ("a repeated option", _bridge_argv() + ["--zone", "zone-b"], "invalid_arguments"),
    ("a spoofed uid", _bridge_argv() + ["--uid", "0"], "invalid_arguments"),
    ("a positional argument", _bridge_argv() + ["SECRET-VALUE"], "invalid_arguments"),
    (
        "a value-carrying option",
        _bridge_argv() + ["--token=SECRET-VALUE"],
        "invalid_arguments",
    ),
    ("a dangling option", _bridge_argv() + ["--note"], "invalid_arguments"),
    ("an empty value", _bridge_argv(**{"--zone": ""}), "invalid_arguments"),
    (
        "a control character in the note",
        _bridge_argv(**{"--note": "a\x07b"}),
        "invalid_arguments",
    ),
    (
        "a note over the bound",
        _bridge_argv(**{"--note": "x" * 281}),
        "invalid_arguments",
    ),
    *[
        (
            f"invalid UTF-8 in {option}",
            _bridge_argv(**{option: os.fsdecode(b"AB\xff")}),
            "invalid_arguments",
        )
        for option in ("--proposal-id", "--device-id", "--zone", "--note")
    ],
    ("valid arguments, no installation", _bridge_argv(), "runtime_unavailable"),
    (
        "valid arguments, an explicit socket",
        _bridge_argv(**{"--socket": "/tmp/nothing.sock"}),
        "runtime_unavailable",
    ),
]


@pytest.mark.parametrize(
    ("argv", "code"),
    [(a, c) for _, a, c in BRIDGE_HOSTILE],
    ids=[n for n, _, _ in BRIDGE_HOSTILE],
)
def test_the_bridge_entry_point_refuses_with_one_object_and_no_file(
    tmp_path: Path, argv: list[str], code: str
) -> None:
    before = set(tmp_path.iterdir())
    env = {k: v for k, v in os.environ.items() if k != "RUNTIME_DIRECTORY"}
    env["PYTHONPATH"] = str(REPO)
    proc = subprocess.run(
        [sys.executable, "-B", "-m", "ori.cli_bridge", *argv],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    lines = proc.stdout.splitlines()
    assert len(lines) == 1, proc.stdout + proc.stderr
    payload = json.loads(lines[0])
    assert proc.returncode == 2, payload
    assert payload["ok"] is False and payload["error"]["code"] == code, payload
    assert "SECRET-VALUE" not in proc.stdout + proc.stderr
    assert set(tmp_path.iterdir()) == before
