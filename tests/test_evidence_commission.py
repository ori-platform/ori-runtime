# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""`evidence commission`, submitted over the operator socket to the runtime.

The socket is the runtime's own server, answering through the runtime's own
handler, which reads its own started attestor and records through its own
open store. The bridge runs as a subprocess of an installation whose service
identity is this test process, under an audit hook that reports every store,
file and socket it touches. The reference recorded is then read by the
runtime's own reconciliation, which seals the registration it implies.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import textwrap
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from ori import operator_socket as op
from ori.config import Config, ConfigValidationError
from ori.operator_socket import CommissionRequest, OperatorSocketServer
from ori.runtime import OriRuntime
from ori.security.evidence.disposition import (
    DispositionScope,
    DispositionValue,
    VerifiedDisposition,
)
from ori.security.evidence.first_party import FirstPartyEvidenceAttestor
from ori.state.store import StateStore

REPO = Path(__file__).resolve().parent.parent
DEVICE = "bench-01"
REFERENCE = "sha256:" + "ab" * 32
OTHER_REFERENCE = "sha256:" + "cd" * 32

#: Runs the bridge's real entry point as an installed bridge whose runtime
#: service identity is argv[2], recording what the process touches.
_SHIM = textwrap.dedent("""\
    import json, os, sys
    out, sock, uid, watched = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
    watched = (watched, os.path.realpath(watched))
    events = []

    def hook(event, args):
        if event == "sqlite3.connect":
            events.append(["sqlite3.connect", str(args[0])])
        elif event == "open" and isinstance(args[0], (str, bytes, os.PathLike)):
            path = os.fsdecode(args[0])
            if path.startswith(watched):
                events.append(["open", path])
        elif event == "socket.connect":
            events.append(["socket.connect", str(args[1])])

    sys.addaudithook(hook)
    from pathlib import Path
    from ori import cli_bridge
    cli_bridge._operator_install = lambda: (Path(sock), uid)
    try:
        rc = cli_bridge.main(sys.argv[5:])
    finally:
        with open(out, "w") as handle:
            json.dump(events, handle)
    sys.exit(rc)
    """)


@dataclass
class BridgeRun:
    rc: int
    payload: dict[str, Any]
    stderr: str
    events: list[list[str]]

    def touched(self, kind: str) -> list[str]:
        return [e[1] for e in self.events if e[0] == kind]


async def run_installed_bridge(
    socket_path: Path, watched: Path, *argv: str, service_uid: int | None = None
) -> BridgeRun:
    """The bridge's entry point, as a subprocess of an installation."""
    record = Path(tempfile.mkstemp(prefix="ori-audit-", dir="/tmp")[1])
    env = {k: v for k, v in os.environ.items() if k != "RUNTIME_DIRECTORY"}
    env["PYTHONPATH"] = str(REPO)
    try:
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-B",
            "-c",
            _SHIM,
            str(record),
            str(socket_path),
            str(os.geteuid() if service_uid is None else service_uid),
            str(watched),
            *argv,
            cwd=str(watched),
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await asyncio.wait_for(proc.communicate(), timeout=60)
        events = json.loads(record.read_text() or "[]")
    finally:
        record.unlink(missing_ok=True)
    lines = out.decode("utf-8").splitlines()
    assert len(lines) == 1, f"expected exactly one JSON line: {out!r} {err!r}"
    assert proc.returncode is not None
    return BridgeRun(proc.returncode, json.loads(lines[0]), err.decode(), events)


async def _no_reconcile(*_args: Any) -> Any:
    raise AssertionError("a commission request reached the reconcile handler")


@dataclass
class Site:
    root: Path
    store: StateStore | None = None
    attestor: FirstPartyEvidenceAttestor | None = None
    runtime: OriRuntime | None = None
    server: OperatorSocketServer | None = None
    calls: list[CommissionRequest] = field(default_factory=list)
    health_reads: list[int] = field(default_factory=list)
    operator_uid: Callable[[], int | None] = os.geteuid

    @property
    def db(self) -> Path:
        return self.root / "state.db"

    @property
    def socket(self) -> Path:
        return self.root / "run" / op.SOCKET_NAME

    async def start_runtime(self, *, evidence: bool = True) -> None:
        """What a started runtime holds: its store open, evidence up, socket bound."""
        self.store = StateStore(str(self.db))
        await self.store.open()
        runtime = object.__new__(OriRuntime)
        runtime._state_store = self.store
        runtime._evidence_attestor = None
        if evidence:
            self.attestor = FirstPartyEvidenceAttestor(
                db_path=str(self.root / "evidence.db"),
                key_path=str(self.root / "evidence.key"),
                device_secret="install-secret-for-commission-tests",
                device_id=DEVICE,
            )
            assert await self.attestor.start() is True
            read = self.attestor.registration_health

            async def counted(at_ms: int) -> dict[str, Any] | None:
                self.health_reads.append(at_ms)
                return await read(at_ms)

            self.attestor.registration_health = counted  # type: ignore[method-assign]
            runtime._evidence_attestor = self.attestor
        self.runtime = runtime
        await self.serve()

    async def serve(self) -> None:
        assert self.runtime is not None
        handler = self.runtime._commission_from_operator

        async def commission(request: CommissionRequest, *rest: Any) -> Any:
            self.calls.append(request)
            return await handler(request, *rest)

        self.server = OperatorSocketServer(
            directory=self.root / "run",
            reconcile=_no_reconcile,
            commission=commission,
            operator_uid=lambda: self.operator_uid(),
            grant=lambda _d, _s, _u: None,
        )
        await self.server.start()

    def override_registration(self, **fields: Any) -> None:
        """The attestor's own registration health, with *fields* changed."""
        assert self.attestor is not None
        read = self.attestor.registration_health

        async def provide(at_ms: int) -> dict[str, Any] | None:
            health = await read(at_ms)
            assert health is not None
            return {**health, **fields}

        self.attestor.registration_health = provide  # type: ignore[method-assign]

    async def stop(self) -> None:
        if self.server is not None:
            await self.server.close()
        if self.attestor is not None:
            self.attestor.close()
        if self.store is not None:
            await self.store.close()

    def references(self) -> list[tuple[Any, ...]]:
        if not self.db.exists():
            return []
        conn = sqlite3.connect(f"{self.db.resolve().as_uri()}?mode=ro", uri=True)
        try:
            return list(
                conn.execute(
                    "SELECT anchor_epoch_id, device_id, commissioning_reference,"
                    " recorded_at_ms, replacements FROM evidence_commissioning_reference"
                )
            )
        finally:
            conn.close()

    def listing(self) -> list[str]:
        return sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*"))

    async def bridge(self, *argv: str, service_uid: int | None = None) -> BridgeRun:
        return await run_installed_bridge(
            self.socket, self.root, *argv, service_uid=service_uid
        )


@pytest.fixture
async def site() -> AsyncIterator[Site]:
    # Short and under /tmp: a Unix socket path has a length limit the pytest
    # temporary directory can exceed.
    root = Path(tempfile.mkdtemp(prefix="ori-ec-", dir="/tmp"))
    state = Site(root=root)
    try:
        yield state
    finally:
        await state.stop()
        shutil.rmtree(root, ignore_errors=True)


def _commission(reference: str = REFERENCE, *extra: str) -> list[str]:
    return ["evidence", "commission", "--reference", reference, *extra]


def _refused(run: BridgeRun, code: str) -> None:
    assert run.rc == 2, run.payload
    assert run.payload["ok"] is False
    assert run.payload["command"] == "evidence commission"
    assert run.payload["error"]["code"] == code, run.payload


def _touched_nothing(run: BridgeRun, site: Site, *, connected: bool) -> None:
    """No store, no file under the installation, and only the operator socket."""
    assert run.touched("sqlite3.connect") == [], run.events
    assert run.touched("open") == [], run.events
    assert run.touched("socket.connect") == ([str(site.socket)] if connected else [])


# --------------------------------------------------------------------------
# Recording
# --------------------------------------------------------------------------


async def test_a_reference_is_recorded_against_the_runtimes_own_epoch(site):
    await site.start_runtime()
    assert site.attestor is not None and site.attestor.anchor is not None
    epoch = site.attestor.anchor.anchor_epoch_id

    run = await site.bridge(*_commission())

    assert run.rc == 0, run.payload
    assert run.payload["ok"] is True and run.payload["command"] == "evidence commission"
    assert run.payload["result"] == {
        "device_id": DEVICE,
        "anchor_epoch_id": epoch,
        "commissioning_reference": REFERENCE,
        "replaced": False,
        "registration_status": "pending_confirmation",
    }
    rows = site.references()
    assert [(r[0], r[1], r[2], r[4]) for r in rows] == [(epoch, DEVICE, REFERENCE, 0)]


async def test_the_bridge_touches_no_store_no_configuration_and_no_health(site):
    """Everything it does is one connection to the operator socket."""
    await site.start_runtime()
    (site.root / "ori.yaml").write_text("device: {}\n", encoding="utf-8")
    (site.root / "health.sock").touch()
    before = site.listing()

    run = await site.bridge(*_commission())

    assert run.rc == 0, run.payload
    _touched_nothing(run, site, connected=True)
    assert site.listing() == before
    assert len(site.references()) == 1


async def test_the_runtime_seals_the_registration_the_recorded_reference_implies(
    site,
):
    await site.start_runtime()
    assert site.attestor is not None and site.runtime is not None
    assert (await site.attestor.registration_health(0) or {})[
        "registration_status"
    ] == "pending_authorisation"

    assert (await site.bridge(*_commission())).rc == 0

    status = await site.runtime._reconcile_evidence_registration(site.attestor)
    assert status is not None and status.value == "pending_confirmation"
    assert site.attestor.outbound is not None
    carried = await site.attestor.outbound.pending_artifacts()
    assert [row["artifact_type"] for row in carried] == ["anchor_registration"]
    assert json.loads(carried[0]["artifact_json"])["commissioning_digest"] == REFERENCE


async def test_recording_the_same_reference_again_changes_nothing(site):
    await site.start_runtime()
    assert (await site.bridge(*_commission())).rc == 0
    first = site.references()

    run = await site.bridge(*_commission())

    assert run.rc == 0, run.payload
    assert run.payload["result"]["replaced"] is False
    assert site.references() == first


async def test_a_different_reference_is_refused_without_force(site):
    await site.start_runtime()
    assert (await site.bridge(*_commission())).rc == 0
    first = site.references()

    _refused(
        await site.bridge(*_commission(OTHER_REFERENCE)), "reference_already_recorded"
    )
    assert site.references() == first


async def test_force_replaces_the_reference_for_the_same_epoch_and_says_so(site):
    await site.start_runtime()
    assert (await site.bridge(*_commission())).rc == 0
    (epoch, *_rest) = site.references()[0]

    run = await site.bridge(*_commission(OTHER_REFERENCE, "--force"))

    assert run.rc == 0, run.payload
    assert run.payload["result"]["replaced"] is True
    assert run.payload["result"]["anchor_epoch_id"] == epoch
    assert [(r[0], r[2], r[4]) for r in site.references()] == [
        (epoch, OTHER_REFERENCE, 1)
    ]


async def test_a_reference_recorded_for_another_device_is_never_rewritten(site):
    await site.start_runtime()
    assert site.attestor is not None and site.attestor.anchor is not None
    epoch = site.attestor.anchor.anchor_epoch_id
    conn = sqlite3.connect(str(site.db))
    try:
        conn.execute(
            "INSERT INTO evidence_commissioning_reference VALUES (?, ?, ?, 1, 0)",
            (epoch, "another-device", OTHER_REFERENCE),
        )
        conn.commit()
    finally:
        conn.close()
    before = site.references()

    for extra in ((), ("--force",)):
        _refused(
            await site.bridge(*_commission(REFERENCE, *extra)),
            "reference_device_mismatch",
        )
    assert site.references() == before


@pytest.mark.parametrize(
    "fields,expected",
    [
        ({"registration_status": "confirmed"}, "confirmed"),
        (
            {
                "registration_status": "pending_confirmation",
                "delivery_stop_status": "epoch_stopped",
            },
            "pending_confirmation",
        ),
        (
            {
                "registration_status": "pending_authorisation",
                "delivery_stop_status": "identity_stopped",
            },
            "pending_authorisation",
        ),
        (
            {
                "registration_status": "pending_authorisation",
                "delivery_stop_status": "not_stopped",
            },
            "pending_confirmation",
        ),
    ],
    ids=["confirmed", "stopped-pending", "stopped-unregistered", "ordinary"],
)
async def test_the_reported_status_is_what_the_runtime_will_report(
    site, fields, expected
):
    """Confirmed stays confirmed; a stop is passed through, not reported pending."""
    await site.start_runtime()
    site.override_registration(**fields)
    run = await site.bridge(*_commission())
    assert run.rc == 0, run.payload
    assert run.payload["result"]["registration_status"] == expected


async def _obligation_states(site: Site) -> list[str]:
    attestor = site.attestor
    assert attestor is not None and attestor._ledger is not None
    connection = attestor._ledger._connection
    return attestor._executor.run(
        lambda: [
            str(row["state"])
            for row in connection.execute(
                "SELECT state FROM evidence_registration_obligation ORDER BY id"
            )
        ]
    )


async def _close_an_attempt_under(site: Site, reference: str) -> None:
    """Seal under *reference* and close it as a terminal disposition would."""
    attestor = site.attestor
    assert attestor is not None and attestor.anchor is not None
    await attestor.reconcile_registration(reference)
    ledger = attestor._ledger
    assert ledger is not None and attestor.outbound is not None
    [held] = await attestor.outbound.pending_artifacts()
    attestor._executor.run(
        ledger._apply_verified_disposition,
        VerifiedDisposition(
            digest="sha256:" + "d" * 64,
            triggering_digest=str(held["artifact_digest"]),
            device_id=DEVICE,
            anchor_epoch_id=attestor.anchor.anchor_epoch_id,
            scope=DispositionScope.ARTIFACT,
            value=DispositionValue.ARTIFACT_TERMINAL,
            decided_at_ms=1,
            key_id="authority-disposition-1",
        ),
        at_ms=1,
    )
    health = await attestor.registration_health(1)
    assert health is not None
    assert health["registration_status"] == "pending_confirmation"
    assert health["registration_offer"] == "closed"


@pytest.mark.parametrize(
    "state_store_holds,recorded,extra,states,offer",
    [
        (None, REFERENCE, (), ["closed"], "closed"),
        (REFERENCE, REFERENCE, (), ["closed"], "closed"),
        (None, OTHER_REFERENCE, (), ["closed", "open"], "offering"),
        (REFERENCE, OTHER_REFERENCE, ("--force",), ["closed", "open"], "offering"),
    ],
    ids=[
        "same-reference-row-lost",
        "same-reference-held",
        "other-reference-row-lost",
        "other-reference-forced",
    ],
)
async def test_a_closed_attempt_stays_pending_and_only_a_fresh_reference_reseals(
    site, state_store_holds, recorded, extra, states, offer
):
    """The status stays `pending_confirmation`; the closure is the offer.

    Recording the closed attempt's own reference again reopens nothing, and a
    fresh reference starts a new attempt beside the closed one.
    """
    await site.start_runtime()
    await _close_an_attempt_under(site, REFERENCE)
    if state_store_holds is not None:
        assert (await site.bridge(*_commission(state_store_holds))).rc == 0
    run = await site.bridge(*_commission(recorded, *extra))
    assert run.rc == 0, run.payload
    assert run.payload["result"]["registration_status"] == "pending_confirmation"
    assert site.attestor is not None
    await site.attestor.reconcile_registration(recorded)
    assert await _obligation_states(site) == states
    health = await site.attestor.registration_health(2)
    assert health is not None and health["registration_offer"] == offer


# --------------------------------------------------------------------------
# Refusals at the bridge, before it connects
# --------------------------------------------------------------------------


MALFORMED = [
    "sha256:",
    "sha256:" + "a" * 63,
    "sha256:" + "a" * 65,
    "sha256:" + "A" * 64,
    "SHA256:" + "a" * 64,
    "sha512:" + "a" * 64,
    "sha256:" + "g" * 64,
    " sha256:" + "a" * 64,
    "sha256:" + "a" * 64 + " ",
    "sha256:" + "a" * 64 + "\n",
    "sha256:" + "١" * 64,
    "a" * 64,
    "https://authority.example/commission?token=s3cr3t",
]


@pytest.mark.parametrize("bad", MALFORMED, ids=range(len(MALFORMED)))
async def test_a_malformed_reference_is_refused_before_anything_is_touched(site, bad):
    await site.start_runtime()
    before = site.listing()

    run = await site.bridge(*_commission(bad))

    _refused(run, "invalid_reference")
    if len(bad.strip()) > len("sha256:"):
        assert bad.strip() not in json.dumps(run.payload), "the value was echoed"
        assert bad.strip() not in run.stderr
    _touched_nothing(run, site, connected=False)
    assert site.calls == []
    assert site.references() == []
    assert site.listing() == before


async def test_an_argument_the_command_does_not_define_is_refused_unechoed(site):
    await site.start_runtime()
    secret = "https://authority.example/ingest"

    for extra in (
        ["--endpoint", secret],
        [f"--endpoint={secret}"],
        [secret],
        ["--force", "--force"],
        ["--reference", OTHER_REFERENCE],
        ["--socket", str(site.socket), "--socket", str(site.socket)],
        # The configuration is no longer an input to this command.
        ["--path", secret],
    ):
        run = await site.bridge(*_commission(), *extra)
        _refused(run, "invalid_arguments")
        assert secret not in json.dumps(run.payload) and secret not in run.stderr
        _touched_nothing(run, site, connected=False)
    assert site.references() == []
    assert site.calls == []


@pytest.mark.parametrize(
    "argv",
    [
        ["evidence", "commission"],
        ["evidence", "commission", "--reference"],
        ["evidence", "commission", "--reference", ""],
        ["evidence", "commission", "--reference", "   "],
        ["evidence", "commission", "--force"],
        ["evidence", "commission", "--reference", "--force"],
        ["evidence"],
        ["evidence", "register"],
    ],
)
async def test_argument_errors_are_one_refusal_each(site, argv):
    await site.start_runtime()
    run = await site.bridge(*argv)
    assert run.rc == 2 and run.payload["ok"] is False
    assert run.payload["error"]["code"] in {"invalid_arguments", "unknown_command"}
    _touched_nothing(run, site, connected=False)
    assert site.calls == []


async def test_arguments_are_decided_before_the_reference(site):
    await site.start_runtime()
    run = await site.bridge(*_commission("not-a-reference", "--endpoint", "x"))
    _refused(run, "invalid_arguments")


# --------------------------------------------------------------------------
# Refusals and outcomes at the runtime
# --------------------------------------------------------------------------


async def test_before_the_first_start_nothing_is_created(site):
    """No runtime has run: no store, no socket. The tool must build neither."""
    before = site.listing()

    run = await site.bridge(*_commission())

    _refused(run, "runtime_unavailable")
    assert run.touched("sqlite3.connect") == [] and run.touched("open") == []
    assert site.listing() == before


async def test_a_peer_that_is_not_the_runtime_is_sent_nothing(site):
    await site.start_runtime()
    run = await site.bridge(*_commission(), service_uid=os.geteuid() + 1)
    _refused(run, "runtime_unavailable")
    assert site.calls == []
    assert site.references() == []


async def test_an_explicit_socket_does_not_waive_peer_verification(site):
    await site.start_runtime()
    run = await site.bridge(
        *_commission(REFERENCE, "--socket", str(site.socket)),
        service_uid=os.geteuid() + 1,
    )
    _refused(run, "runtime_unavailable")
    assert site.calls == []


@pytest.mark.skipif(os.geteuid() == 0, reason="root is always admitted")
async def test_an_unadmitted_caller_learns_nothing_and_nothing_is_read(site):
    await site.start_runtime()
    site.operator_uid = lambda: None
    site.health_reads.clear()

    run = await site.bridge(*_commission())

    _refused(run, "unauthenticated")
    assert site.calls == []
    assert site.health_reads == []
    assert site.references() == []


async def test_evidence_disabled_runtime_has_no_epoch(site):
    await site.start_runtime(evidence=False)
    _refused(await site.bridge(*_commission()), "evidence_epoch_unavailable")
    assert site.references() == []


async def test_evidence_that_did_not_start_has_no_epoch(site):
    await site.start_runtime()
    assert site.runtime is not None
    unstarted = FirstPartyEvidenceAttestor(
        db_path=str(site.root / "other-evidence.db"),
        key_path=str(site.root / "other-evidence.key"),
        device_secret="install-secret-for-commission-tests",
        device_id=DEVICE,
    )
    site.runtime._evidence_attestor = unstarted
    try:
        _refused(await site.bridge(*_commission()), "evidence_epoch_unavailable")
    finally:
        unstarted.close()
    assert site.references() == []


async def test_registration_that_cannot_be_read_records_nothing(site):
    await site.start_runtime()
    assert site.attestor is not None

    async def unreadable(_at_ms: int) -> None:
        return None

    site.attestor.registration_health = unreadable  # type: ignore[method-assign]
    _refused(await site.bridge(*_commission()), "evidence_epoch_unavailable")
    assert site.references() == []


async def test_a_status_the_runtime_cannot_state_records_nothing(site):
    """Decided before the record, so a success is never followed by a fault."""
    await site.start_runtime()
    site.override_registration(registration_status="refused")
    run = await site.bridge(*_commission())
    assert (run.rc, run.payload["error"]["code"]) == (1, "internal_error")
    assert site.references() == []


async def test_a_runtime_with_no_store_is_store_unavailable(site):
    await site.start_runtime()
    assert site.runtime is not None
    site.runtime._state_store = None
    _refused(await site.bridge(*_commission()), "runtime_store_unavailable")


async def test_a_closed_store_is_store_unavailable_and_is_not_reopened(site):
    await site.start_runtime()
    assert site.store is not None
    await site.store.close()
    before = site.references()
    _refused(await site.bridge(*_commission()), "runtime_store_unavailable")
    assert site.references() == before == []


async def test_a_held_write_lock_is_a_lock_failure_not_a_wait_forever(site):
    await site.start_runtime()
    holder = sqlite3.connect(str(site.db), isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    try:
        run = await site.bridge(*_commission())
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    _refused(run, "state_store_locked")
    assert site.references() == []


async def test_a_stopping_runtime_cancels_before_the_record(site):
    await site.start_runtime()
    assert site.server is not None
    site.server._closing = True
    try:
        _refused(await site.bridge(*_commission()), "cancelled")
    finally:
        site.server._closing = False
    assert site.calls == []
    assert site.references() == []


async def test_an_answer_the_runtime_does_not_define_is_internal(site):
    await site.start_runtime()
    assert site.runtime is not None

    async def surprise(*_a: Any) -> Any:
        return {"ok": False, "error": "unknown_proposal"}

    site.runtime._commission_from_operator = surprise  # type: ignore[method-assign]
    assert site.server is not None
    await site.server.close()
    await site.serve()
    run = await site.bridge(*_commission())
    assert (run.rc, run.payload["error"]["code"]) == (1, "internal_error")


# --------------------------------------------------------------------------
# The socket, driven directly
# --------------------------------------------------------------------------


async def _send(path: Path, raw: bytes) -> dict[str, Any]:
    reader, writer = await asyncio.open_unix_connection(str(path))
    try:
        writer.write(raw)
        await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
        line = await asyncio.wait_for(reader.readline(), 10)
    finally:
        writer.close()
        await writer.wait_closed()
    assert line.endswith(b"\n") and line.count(b"\n") == 1, line
    return json.loads(line)


def _request(**changes: Any) -> bytes:
    body = {"operation": "evidence_commission", "reference": REFERENCE, "force": False}
    body.update(changes)
    return json.dumps({k: v for k, v in body.items() if v is not ...}).encode() + b"\n"


HOSTILE: list[tuple[str, bytes, str]] = [
    ("no reference", _request(reference=...), "invalid_arguments"),
    ("no force", _request(force=...), "invalid_arguments"),
    ("a uid member", _request(uid=0), "invalid_arguments"),
    ("a device member", _request(device_id=DEVICE), "invalid_arguments"),
    ("an epoch member", _request(anchor_epoch_id=REFERENCE), "invalid_arguments"),
    ("an endpoint member", _request(endpoint="https://a.example"), "invalid_arguments"),
    ("force as a string", _request(force="true"), "invalid_arguments"),
    ("force as an integer", _request(force=1), "invalid_arguments"),
    ("force null", _request(force=None), "invalid_arguments"),
    (
        "a member named twice",
        _request()[:-2] + b',"reference":"' + OTHER_REFERENCE.encode() + b'"}\n',
        "invalid_arguments",
    ),
    (
        "the operation named twice",
        b'{"operation":"evidence_commission","operation":"evidence_commission",'
        b'"reference":"' + REFERENCE.encode() + b'","force":false}\n',
        "invalid_arguments",
    ),
    (
        "a bad reference and a bad force",
        _request(reference=7, force="x"),
        "invalid_arguments",
    ),
    ("reconcile members", _request(proposal_id="AB12CD34"), "invalid_arguments"),
    ("a reference as an integer", _request(reference=7), "invalid_reference"),
    ("a reference null", _request(reference=None), "invalid_reference"),
    ("a reference as a list", _request(reference=[REFERENCE]), "invalid_reference"),
    (
        "an uppercase reference",
        _request(reference=REFERENCE.upper()),
        "invalid_reference",
    ),
    (
        "a reference with a NUL",
        _request(reference=REFERENCE[:-1] + "\x00"),
        "invalid_reference",
    ),
    (
        "a reference with a lone surrogate",
        _request(reference="R").replace(b'"R"', b'"sha256:' + b"a" * 63 + b'\\ud800"'),
        "invalid_reference",
    ),
]


@pytest.mark.parametrize(
    "raw,code", [(r, c) for _, r, c in HOSTILE], ids=[n for n, _, _ in HOSTILE]
)
async def test_hostile_requests_are_refused_before_any_state(site, raw, code):
    await site.start_runtime()
    site.health_reads.clear()
    answer = await _send(site.socket, raw)
    assert answer == {
        "schema_version": 1,
        "ok": False,
        "error": {"code": code, "detail": answer["error"]["detail"]},
    }
    assert site.calls == [] and site.health_reads == []
    assert site.references() == []


@pytest.mark.skipif(os.geteuid() == 0, reason="root is always admitted")
@pytest.mark.parametrize(
    "raw,code",
    [
        (_request(reference="sha256:" + "A" * 64), "invalid_reference"),
        (_request(reference="nope", extra=1), "invalid_arguments"),
        (_request(), "unauthenticated"),
    ],
    ids=["reference-before-caller", "arguments-before-reference", "then-the-caller"],
)
async def test_the_contract_order_holds_for_an_unadmitted_caller(site, raw, code):
    await site.start_runtime()
    site.operator_uid = lambda: None
    answer = await _send(site.socket, raw)
    assert answer["error"]["code"] == code
    assert site.calls == []


async def test_force_true_over_the_socket_replaces(site):
    await site.start_runtime()
    assert (await _send(site.socket, _request()))["ok"] is True
    answer = await _send(site.socket, _request(reference=OTHER_REFERENCE, force=True))
    assert answer["ok"] is True and answer["result"]["replaced"] is True
    assert [r[2] for r in site.references()] == [OTHER_REFERENCE]


# --------------------------------------------------------------------------
# The record itself
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE evidence_commissioning_reference SET anchor_epoch_id = 'sha256:"
        + "0" * 64
        + "'",
        "UPDATE evidence_commissioning_reference SET device_id = 'other'",
        "UPDATE evidence_commissioning_reference SET commissioning_reference = 'x'",
        "DELETE FROM evidence_commissioning_reference",
        "INSERT INTO evidence_commissioning_reference VALUES ('', 'd', 'sha256:"
        + "0" * 64
        + "', 1, 0)",
    ],
)
async def test_a_recorded_reference_stays_bound_to_its_epoch(site, statement):
    await site.start_runtime()
    assert (await site.bridge(*_commission())).rc == 0
    conn = sqlite3.connect(str(site.db))
    try:
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute(statement)
    finally:
        conn.close()


def test_a_reference_in_configuration_is_refused(tmp_path):
    config = tmp_path / "ori.yaml"
    config.write_text(
        textwrap.dedent(f"""\
            device:
              id: {DEVICE}
              name: Bench
              location: Test Lab
              deployment_profile: development
            sensors:
              - id: cpu
                type: cpu_percent
                protocol: psutil
                poll_interval_ms: 1000
            skills: []
            reasoning:
              default_tier: rule
            database:
              path: {tmp_path / "state.db"}
            evidence:
              enabled: true
              commissioning_reference: {REFERENCE}
              db_path: {tmp_path / "evidence.db"}
              key_path: {tmp_path / "evidence.key"}
              device_secret_env: ORI_TEST_EVIDENCE_SECRET
            """),
        encoding="utf-8",
    )
    with pytest.raises(ConfigValidationError, match="evidence commission"):
        Config.load(str(config))
