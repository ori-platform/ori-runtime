# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""`evidence commission`, driven as a subprocess against a live runtime surface.

The health socket is the runtime's own server, answering with the evidence
object the runtime's own health code builds from a started attestor, and the
state store is the runtime's own store, held open as a running runtime holds
it. The reference the command records is then read by the runtime's own
reconciliation, which seals the registration it implies.
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
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from ori.config import Config
from ori.runtime import OriRuntime
from ori.runtime_health_socket import RuntimeHealthSocketServer
from ori.security.evidence.disposition import (
    DispositionScope,
    DispositionValue,
    VerifiedDisposition,
)
from ori.security.evidence.first_party import FirstPartyEvidenceAttestor
from ori.state.store import StateStore

REPO = Path(__file__).resolve().parent.parent
DEVICE = "bench-01"
SECRET_ENV = "ORI_TEST_EVIDENCE_SECRET"
REFERENCE = "sha256:" + "ab" * 32
OTHER_REFERENCE = "sha256:" + "cd" * 32

Provider = Callable[[], Awaitable[dict[str, Any]]]


def _config_text(root: Path, *, evidence: bool = True) -> str:
    body = textwrap.dedent(f"""\
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
          path: {root / "state.db"}
        logging:
          level: INFO
          file: {root / "ori.log"}
        """)
    if evidence:
        body += textwrap.dedent(f"""\
            evidence:
              enabled: true
              db_path: {root / "evidence.db"}
              key_path: {root / "evidence.key"}
              device_secret_env: {SECRET_ENV}
            """)
    return body


@dataclass
class Site:
    root: Path
    config: Path
    socket: Path
    store: StateStore | None = None
    attestor: FirstPartyEvidenceAttestor | None = None
    runtime: OriRuntime | None = None
    server: RuntimeHealthSocketServer | None = None
    health_requests: list[int] = field(default_factory=list)
    override: Provider | None = None

    @property
    def db(self) -> Path:
        return self.root / "state.db"

    async def real_snapshot(self) -> dict[str, Any]:
        assert self.runtime is not None
        return {"device_id": DEVICE, "evidence": await self.runtime._evidence_health()}

    async def _provide(self) -> dict[str, Any]:
        self.health_requests.append(1)
        if self.override is not None:
            return await self.override()
        return await self.real_snapshot()

    async def start_runtime(self) -> None:
        """What a started runtime holds: its store open, evidence up, health served."""
        self.store = StateStore(str(self.db))
        await self.store.open()
        self.attestor = FirstPartyEvidenceAttestor(
            db_path=str(self.root / "evidence.db"),
            key_path=str(self.root / "evidence.key"),
            device_secret="install-secret-for-commission-tests",
            device_id=DEVICE,
        )
        assert await self.attestor.start() is True
        runtime = object.__new__(OriRuntime)
        runtime._evidence_attestor = self.attestor
        runtime._config = Config.load(str(self.config))
        runtime._state_store = self.store
        runtime._evidence_inbound_subscriber = None
        runtime._evidence_posture_problems = []
        self.runtime = runtime
        await self.serve()

    async def serve(self) -> None:
        self.server = RuntimeHealthSocketServer(
            socket_path=str(self.socket), mode=0o600, snapshot_provider=self._provide
        )
        await self.server.start()

    async def stop(self) -> None:
        if self.server is not None:
            await self.server.close()
        if self.attestor is not None:
            self.attestor.close()
        if self.store is not None:
            await self.store.close()

    def references(self) -> list[tuple[Any, ...]]:
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
        return sorted(p.name for p in self.root.iterdir())


@pytest.fixture
async def site() -> AsyncIterator[Site]:
    # Short and under /tmp: a Unix socket path has a length limit the pytest
    # temporary directory can exceed.
    root = Path(tempfile.mkdtemp(prefix="ori-ec-", dir="/tmp"))
    config = root / "ori.yaml"
    config.write_text(_config_text(root), encoding="utf-8")
    state = Site(root=root, config=config, socket=root / "h.sock")
    try:
        yield state
    finally:
        await state.stop()
        shutil.rmtree(root, ignore_errors=True)


async def _bridge(site: Site, *args: str) -> tuple[int, dict[str, Any], str]:
    env = {k: v for k, v in os.environ.items() if k != SECRET_ENV}
    env["PYTHONPATH"] = str(REPO)
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "ori.cli_bridge",
        *args,
        cwd=str(site.root),
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await asyncio.wait_for(proc.communicate(), timeout=60)
    lines = out.decode("utf-8").splitlines()
    assert len(lines) == 1, f"expected exactly one JSON line: {out!r} {err!r}"
    assert proc.returncode is not None
    return proc.returncode, json.loads(lines[0]), err.decode("utf-8")


def _commission(site: Site, reference: str = REFERENCE, *extra: str) -> list[str]:
    return [
        "evidence",
        "commission",
        "--path",
        str(site.config),
        "--reference",
        reference,
        "--socket",
        str(site.socket),
        *extra,
    ]


def _refused(rc: int, payload: dict[str, Any], code: str) -> None:
    assert rc == 2, payload
    assert payload["ok"] is False
    assert payload["command"] == "evidence commission"
    assert payload["error"]["code"] == code, payload


# --------------------------------------------------------------------------
# Recording
# --------------------------------------------------------------------------


async def test_a_reference_is_recorded_against_the_epoch_the_runtime_reports(site):
    await site.start_runtime()
    assert site.attestor is not None and site.attestor.anchor is not None
    epoch = site.attestor.anchor.anchor_epoch_id

    rc, payload, _ = await _bridge(site, *_commission(site))

    assert rc == 0, payload
    assert payload["ok"] is True and payload["command"] == "evidence commission"
    assert set(payload["result"]) == {
        "device_id",
        "anchor_epoch_id",
        "commissioning_reference",
        "replaced",
        "registration_status",
    }
    assert payload["result"] == {
        "device_id": DEVICE,
        "anchor_epoch_id": epoch,
        "commissioning_reference": REFERENCE,
        "replaced": False,
        "registration_status": "pending_confirmation",
    }
    rows = site.references()
    assert [(r[0], r[1], r[2], r[4]) for r in rows] == [(epoch, DEVICE, REFERENCE, 0)]


async def test_the_runtime_seals_the_registration_the_recorded_reference_implies(
    site,
):
    await site.start_runtime()
    assert site.runtime is not None and site.attestor is not None
    before = await site.runtime._evidence_health()
    assert before["registration_status"] == "pending_authorisation"
    assert before["registration_pending_since_ms"] is None

    rc, payload, _ = await _bridge(site, *_commission(site))
    assert rc == 0, payload

    status = await site.runtime._reconcile_evidence_registration(site.attestor)
    assert status is not None and status.value == "pending_confirmation"
    after = await site.runtime._evidence_health()
    assert after["registration_status"] == "pending_confirmation"
    assert isinstance(after["registration_pending_since_ms"], int)
    assert after["registration_confirmation_overdue"] is False
    assert site.attestor.outbound is not None
    carried = await site.attestor.outbound.pending_artifacts()
    assert [row["artifact_type"] for row in carried] == ["anchor_registration"]
    assert json.loads(carried[0]["artifact_json"])["commissioning_digest"] == REFERENCE


async def test_recording_the_same_reference_again_changes_nothing(site):
    await site.start_runtime()
    assert (await _bridge(site, *_commission(site)))[0] == 0
    first = site.references()

    rc, payload, _ = await _bridge(site, *_commission(site))

    assert rc == 0, payload
    assert payload["result"]["replaced"] is False
    assert site.references() == first


async def test_a_different_reference_is_refused_without_force(site):
    await site.start_runtime()
    assert (await _bridge(site, *_commission(site)))[0] == 0
    first = site.references()

    rc, payload, _ = await _bridge(site, *_commission(site, OTHER_REFERENCE))

    _refused(rc, payload, "reference_already_recorded")
    assert site.references() == first


async def test_force_replaces_the_reference_for_the_same_epoch_and_says_so(site):
    await site.start_runtime()
    assert (await _bridge(site, *_commission(site)))[0] == 0
    (epoch, *_rest) = site.references()[0]

    rc, payload, _ = await _bridge(site, *_commission(site, OTHER_REFERENCE, "--force"))

    assert rc == 0, payload
    assert payload["result"]["replaced"] is True
    assert payload["result"]["anchor_epoch_id"] == epoch
    rows = site.references()
    assert [(r[0], r[2], r[4]) for r in rows] == [(epoch, OTHER_REFERENCE, 1)]


async def test_a_confirmed_epoch_is_reported_confirmed(site):
    await site.start_runtime()
    site.override = _evidence_override(site, registration_status="confirmed")
    rc, payload, _ = await _bridge(site, *_commission(site))
    assert rc == 0, payload
    assert payload["result"]["registration_status"] == "confirmed"


@pytest.mark.parametrize(
    "snapshot,expected",
    [
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
    ids=[
        "stopped-pending",
        "stopped-unregistered",
        "ordinary",
    ],
)
async def test_the_reported_status_is_what_the_runtime_will_report(
    site, snapshot, expected
):
    """A stop is passed through, not reported as pending."""
    await site.start_runtime()
    site.override = _evidence_override(site, **snapshot)
    rc, payload, _ = await _bridge(site, *_commission(site))
    assert rc == 0, payload
    assert payload["result"]["registration_status"] == expected


@pytest.mark.parametrize(
    "status", ["not-a-status", None, 7], ids=["unknown", "null", "int"]
)
async def test_a_status_the_bridge_cannot_read_records_nothing(site, status):
    """Absent or unknown, the status cannot be stated, so nothing is recorded."""
    await site.start_runtime()
    site.override = _evidence_override(site, registration_status=status)
    rc, payload, _ = await _bridge(site, *_commission(site))
    _refused(rc, payload, "health_unavailable")
    assert site.references() == []


async def test_an_absent_status_records_nothing(site):
    await site.start_runtime()

    async def provide() -> dict[str, Any]:
        snapshot = await site.real_snapshot()
        del snapshot["evidence"]["registration_status"]
        return snapshot

    site.override = provide
    rc, payload, _ = await _bridge(site, *_commission(site))
    _refused(rc, payload, "health_unavailable")
    assert site.references() == []


async def test_a_status_outside_the_contract_vocabulary_refuses_the_command(site):
    """`refused` is not a registration status; a snapshot claiming one is refused."""
    await site.start_runtime()
    assert site.attestor is not None
    await site.attestor.reconcile_registration(REFERENCE)
    site.override = _evidence_override(site, registration_status="refused")
    rc, payload, _ = await _bridge(site, *_commission(site))
    _refused(rc, payload, "health_unavailable")
    assert site.references() == []


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
    evidence = (await site.real_snapshot())["evidence"]
    assert evidence["registration_status"] == "pending_confirmation"
    assert evidence["registration_offer"] == "closed"


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
        rc, _payload, _ = await _bridge(site, *_commission(site, state_store_holds))
        assert rc == 0
    rc, payload, _ = await _bridge(site, *_commission(site, recorded, *extra))
    assert rc == 0, payload
    assert payload["result"]["registration_status"] == "pending_confirmation"
    assert site.attestor is not None
    await site.attestor.reconcile_registration(recorded)
    assert await _obligation_states(site) == states
    assert (await site.real_snapshot())["evidence"]["registration_offer"] == offer


# --------------------------------------------------------------------------
# Refusals
# --------------------------------------------------------------------------


MALFORMED = [
    "",
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

    rc, payload, stderr = await _bridge(site, *_commission(site, bad))

    if bad == "" or not bad.strip():
        _refused(rc, payload, "invalid_arguments")
    else:
        _refused(rc, payload, "invalid_reference")
        if len(bad.strip()) > len("sha256:"):
            assert bad.strip() not in json.dumps(payload), "the value was echoed"
            assert bad.strip() not in stderr
    assert site.health_requests == [], "the runtime was asked before the reference"
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
    ):
        rc, payload, stderr = await _bridge(site, *_commission(site), *extra)
        _refused(rc, payload, "invalid_arguments")
        assert secret not in json.dumps(payload) and secret not in stderr
    assert site.references() == []
    assert site.health_requests == []


@pytest.mark.parametrize(
    "args",
    [
        ["evidence", "commission"],
        ["evidence", "commission", "--reference", REFERENCE],
        ["evidence", "commission", "--path"],
        ["evidence"],
        ["evidence", "register"],
    ],
)
async def test_argument_errors_are_one_refusal_each(site, args):
    rc, payload, _ = await _bridge(site, *args)
    assert rc == 2 and payload["ok"] is False
    assert payload["error"]["code"] in {"invalid_arguments", "unknown_command"}


async def test_an_absent_configuration_is_refused(site):
    rc, payload, _ = await _bridge(
        site,
        "evidence",
        "commission",
        "--path",
        str(site.root / "missing.yaml"),
        "--reference",
        REFERENCE,
    )
    assert rc == 2 and payload["ok"] is False


async def test_before_the_first_start_nothing_is_created(site):
    """No runtime has run: no store, no socket. The tool must build neither."""
    before = site.listing()

    rc, payload, _ = await _bridge(site, *_commission(site))

    _refused(rc, payload, "health_socket_unavailable")
    assert site.listing() == before


async def test_a_socket_answering_with_no_store_behind_it_creates_none(site):
    """The runtime answering holds a store somewhere this configuration does not name."""
    site.config.write_text(
        _config_text(site.root).replace(
            str(site.root / "state.db"), str(site.root / "absent" / "state.db")
        ),
        encoding="utf-8",
    )
    await site.start_runtime()
    target = site.root / "absent" / "state.db"

    rc, payload, _ = await _bridge(site, *_commission(site))

    _refused(rc, payload, "state_store_unavailable")
    assert not target.parent.exists(), "the tool created the store's directory"
    assert not target.exists()


async def test_a_store_no_runtime_holds_open_is_refused(site):
    await site.start_runtime()
    assert site.store is not None
    await site.store.close()
    site.store = None
    assert not Path(f"{site.db}-wal").exists()
    before = site.listing()

    rc, payload, _ = await _bridge(site, *_commission(site))

    _refused(rc, payload, "state_store_unavailable")
    assert site.listing() == before


def _evidence_override(site: Site, **evidence: Any) -> Provider:
    async def provide() -> dict[str, Any]:
        snapshot = await site.real_snapshot()
        snapshot["evidence"].update(evidence)
        return snapshot

    return provide


@pytest.mark.parametrize(
    "evidence",
    [
        {"anchor_epoch_id": ""},
        {"anchor_epoch_id": None},
        {"anchor_epoch_id": "sha256:" + "A" * 64},
        {"anchor_epoch_id": "epoch-1"},
        {"anchor_epoch_id": 7},
        {"enabled": False},
        {"available": False},
    ],
)
async def test_no_well_formed_epoch_records_nothing(site, evidence):
    await site.start_runtime()
    site.override = _evidence_override(site, **evidence)

    rc, payload, _ = await _bridge(site, *_commission(site))

    _refused(rc, payload, "evidence_epoch_unavailable")
    assert site.references() == []


async def test_an_absent_epoch_field_records_nothing(site):
    await site.start_runtime()

    async def provide() -> dict[str, Any]:
        snapshot = await site.real_snapshot()
        del snapshot["evidence"]["anchor_epoch_id"]
        return snapshot

    site.override = provide
    rc, payload, _ = await _bridge(site, *_commission(site))
    _refused(rc, payload, "evidence_epoch_unavailable")
    assert site.references() == []


async def test_evidence_disabled_runtime_has_no_epoch(site):
    site.config.write_text(_config_text(site.root, evidence=False), encoding="utf-8")
    site.store = StateStore(str(site.db))
    await site.store.open()
    runtime = object.__new__(OriRuntime)
    runtime._evidence_attestor = None
    runtime._config = Config.load(str(site.config))
    runtime._state_store = site.store
    runtime._evidence_inbound_subscriber = None
    runtime._evidence_posture_problems = []
    site.runtime = runtime
    await site.serve()

    rc, payload, _ = await _bridge(site, *_commission(site))

    _refused(rc, payload, "evidence_epoch_unavailable")
    assert site.references() == []
    assert site.health_requests == [], "the socket was asked for an epoch"


async def test_a_runtime_for_another_device_is_refused(site):
    await site.start_runtime()

    async def provide() -> dict[str, Any]:
        snapshot = await site.real_snapshot()
        snapshot["device_id"] = "someone-else"
        return snapshot

    site.override = provide
    rc, payload, _ = await _bridge(site, *_commission(site))
    _refused(rc, payload, "health_device_mismatch")
    assert site.references() == []


@pytest.mark.parametrize(
    "lie",
    [
        {"anchor_epoch_id": "sha256:" + "0" * 64},
        {"public_key_hex": "11" * 32},
        {"anchor_epoch_id": "sha256:" + "0" * 64, "public_key_hex": "11" * 32},
    ],
    ids=["epoch", "key", "both"],
)
async def test_a_socket_cannot_choose_the_epoch_a_reference_is_recorded_against(
    site, lie
):
    """Whatever answers on the socket, the epoch must be this installation's own."""
    await site.start_runtime()
    site.override = _evidence_override(site, **lie)

    rc, payload, _ = await _bridge(site, *_commission(site))

    _refused(rc, payload, "evidence_epoch_unbound")
    assert site.references() == []


async def test_an_evidence_store_with_no_recorded_anchor_binds_nothing(site):
    await site.start_runtime()
    conn = sqlite3.connect(str(site.root / "evidence.db"))
    try:
        conn.execute("DROP TABLE evidence_current_anchor")
        conn.commit()
    finally:
        conn.close()

    rc, payload, _ = await _bridge(site, *_commission(site))

    _refused(rc, payload, "evidence_epoch_unbound")
    assert site.references() == []


async def test_a_real_health_snapshot_fits_well_inside_the_read_limit(site):
    """Measured from the runtime's own health, not assumed."""
    from ori.cli_bridge import _HEALTH_REPLY_LIMIT_BYTES

    await site.start_runtime()
    rc, payload, _ = await _bridge(
        site, "health", "snapshot", "--socket", str(site.socket)
    )
    assert rc == 0, payload
    size = len(json.dumps(payload["result"]).encode("utf-8"))
    assert size * 16 < _HEALTH_REPLY_LIMIT_BYTES, size


async def _raw_socket(site: Site, payload: bytes) -> asyncio.AbstractServer:
    if site.server is not None:
        await site.server.close()
        site.server = None
    site.socket.unlink(missing_ok=True)

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        await reader.readline()
        try:
            writer.write(payload)
            await writer.drain()
        except (ConnectionError, OSError):
            pass
        writer.close()

    return await asyncio.start_unix_server(handle, path=str(site.socket))


@pytest.mark.parametrize(
    "name,payload,code",
    [
        ("deep", b"[" * 60000 + b"\n", "health_socket_invalid_json"),
        (
            "over-limit",
            b'{"ok":true,"pad":"' + b"x" * (5 * 1024 * 1024) + b'"}\n',
            "health_reply_too_large",
        ),
        (
            "large-but-valid",
            b'{"ok":true,"health":{"pad":"' + b"x" * 200_000 + b'"}}\n',
            "health_device_mismatch",
        ),
        ("bad-utf8", b"\xff\xfe\n", "health_socket_invalid_json"),
        ("ok-string", b'{"ok":"true","health":{}}\n', "health_unavailable"),
        ("no-newline", b'{"ok":true}', "health_unavailable"),
    ],
    ids=[
        "deep",
        "over-limit",
        "large-but-valid",
        "bad-utf8",
        "ok-string",
        "no-newline",
    ],
)
async def test_a_hostile_health_reply_is_one_refusal(site, name, payload, code):
    await site.start_runtime()
    server = await _raw_socket(site, payload)
    try:
        rc, out, stderr = await _bridge(site, *_commission(site))
    finally:
        server.close()
    _refused(rc, out, code)
    assert "Traceback" not in stderr
    assert site.references() == []


async def test_a_held_write_lock_is_a_lock_failure_not_a_wait_forever(site):
    await site.start_runtime()
    holder = sqlite3.connect(str(site.db), isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    try:
        rc, payload, _ = await _bridge(site, *_commission(site))
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    _refused(rc, payload, "state_store_locked")
    assert site.references() == []


async def test_a_store_older_than_the_reference_table_is_not_migrated(site):
    await site.start_runtime()
    assert site.store is not None
    await site.store.close()
    site.store = None
    site.db.unlink()
    legacy = sqlite3.connect(str(site.db), isolation_level=None)
    legacy.execute("PRAGMA journal_mode=WAL")
    legacy.execute("CREATE TABLE action_log (id INTEGER PRIMARY KEY)")
    try:
        rc, payload, _ = await _bridge(site, *_commission(site))
        tables = {
            row[0]
            for row in legacy.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    finally:
        legacy.close()
    _refused(rc, payload, "state_migration_required")
    assert tables == {"action_log"}


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
    assert (await _bridge(site, *_commission(site)))[0] == 0
    conn = sqlite3.connect(str(site.db))
    try:
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute(statement)
    finally:
        conn.close()


async def test_a_reference_in_configuration_is_refused(site):
    site.config.write_text(
        _config_text(site.root).replace(
            "  enabled: true\n",
            f"  enabled: true\n  commissioning_reference: {REFERENCE}\n",
        ),
        encoding="utf-8",
    )
    rc, payload, _ = await _bridge(
        site, "config", "validate", "--path", str(site.config)
    )
    assert rc == 2 and payload["error"]["code"] == "config_validation_error"
    assert "evidence commission" in payload["error"]["detail"]
