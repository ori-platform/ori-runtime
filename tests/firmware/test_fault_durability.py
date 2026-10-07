# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""An admitted fault is durable: its row and the freshness advance commit together."""

from __future__ import annotations

import asyncio
import base64
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ori.security.firmware.ingest import FirmwareTelemetryGate
from ori.security.firmware.telemetry import canonical_json_bytes
from ori.state.store import StateStore
from tests.firmware.test_telemetry import (
    SEALED_DEVICE,
    provision_and_approve,
    signed_fault_message,
)

SEQ = 130_486


@pytest.fixture
async def store(tmp_path: Path):
    s = StateStore(db_path=str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


@pytest.fixture
async def gate(store: StateStore) -> FirmwareTelemetryGate:
    gate = FirmwareTelemetryGate(store)
    await provision_and_approve(gate, "manifest_full_sealed")
    return gate


async def _ddl(store: StateStore, sql: str) -> None:
    def run() -> None:
        assert store._conn is not None
        store._conn.execute(sql)
        store._conn.commit()

    await store._run_write(run)


async def _faults(store: StateStore) -> list[tuple[Any, ...]]:
    def read(conn: Any) -> list[tuple[Any, ...]]:
        return [
            tuple(r)
            for r in conn.execute(
                "SELECT device_id, boot_id, seq FROM firmware_fault_events"
            ).fetchall()
        ]

    return await store._run_read(read)


async def _mark(store: StateStore) -> tuple[int, int, Any]:
    row = await store.get_firmware_device(SEALED_DEVICE)
    assert row is not None
    return int(row["last_boot_id"]), int(row["last_seq"]), row["last_uptime_ms"]


async def _assert_mark_iff_row(store: StateStore) -> None:
    """Never a mark advanced without its row, never a row without the mark."""
    boot_id, seq, _ = await _mark(store)
    faults = await _faults(store)
    if seq == 0:
        assert faults == [], "a fault row exists without the mark it consumed"
    else:
        assert (SEALED_DEVICE, boot_id, seq) in faults, (
            "the mark advanced past a fault that was never recorded"
        )


INJECTIONS = {
    "fault-insert-refused": (
        "CREATE TRIGGER inject BEFORE INSERT ON firmware_fault_events "
        "BEGIN SELECT RAISE(ABORT, 'injected'); END"
    ),
    "fault-written-then-failed": (
        "CREATE TRIGGER inject AFTER INSERT ON firmware_fault_events "
        "BEGIN SELECT RAISE(ABORT, 'injected'); END"
    ),
    "advance-refused": (
        "CREATE TRIGGER inject BEFORE UPDATE ON firmware_device_registry "
        "BEGIN SELECT RAISE(ABORT, 'injected'); END"
    ),
}


@pytest.mark.parametrize("injection", sorted(INJECTIONS))
async def test_a_fault_whose_write_fails_is_not_admitted_and_is_redeliverable(
    gate: FirmwareTelemetryGate, store: StateStore, injection: str
) -> None:
    message = signed_fault_message(seq=SEQ)
    before = await _mark(store)
    await _ddl(store, INJECTIONS[injection])

    with pytest.raises(sqlite3.IntegrityError, match="injected"):
        await gate.ingest_fault(message, received_at_ms=1)

    assert await _mark(store) == before
    assert await _faults(store) == []

    await _ddl(store, "DROP TRIGGER inject")
    verification = await gate.ingest_fault(message, received_at_ms=2)

    assert verification.accepted, verification.error_detail
    assert (await _mark(store))[:2] == (41, SEQ)
    assert await _faults(store) == [(SEALED_DEVICE, 41, SEQ)]


async def test_an_admitted_fault_leaves_the_mark_advanced_and_one_row(
    gate: FirmwareTelemetryGate, store: StateStore
) -> None:
    verification = await gate.ingest_fault(signed_fault_message(seq=SEQ))

    assert verification.accepted, verification.error_detail
    assert (await _mark(store))[:2] == (41, SEQ)
    assert await _faults(store) == [(SEALED_DEVICE, 41, SEQ)]


async def test_a_redelivery_after_admission_is_a_replay_and_records_nothing(
    gate: FirmwareTelemetryGate, store: StateStore
) -> None:
    message = signed_fault_message(seq=SEQ)
    assert (await gate.ingest_fault(message)).accepted

    verification = await gate.ingest_fault(message)

    assert verification.error_code == "sequence_replay"
    assert (await _mark(store))[:2] == (41, SEQ)
    assert await _faults(store) == [(SEALED_DEVICE, 41, SEQ)]


async def test_concurrent_deliveries_of_one_fault_admit_exactly_one(
    gate: FirmwareTelemetryGate, store: StateStore
) -> None:
    message = signed_fault_message(seq=SEQ)

    results = await asyncio.gather(*(gate.ingest_fault(message) for _ in range(8)))

    assert sum(r.accepted for r in results) == 1
    assert {r.error_code for r in results if not r.accepted} == {"sequence_replay"}
    assert await _faults(store) == [(SEALED_DEVICE, 41, SEQ)]
    await _assert_mark_iff_row(store)


@pytest.mark.parametrize("failing", range(4))
async def test_interleaved_faults_and_failures_never_split_mark_from_row(
    gate: FirmwareTelemetryGate, store: StateStore, failing: int
) -> None:
    """A failure on any one write leaves the mark on the newest recorded fault."""
    await _ddl(
        store,
        "CREATE TRIGGER inject BEFORE INSERT ON firmware_fault_events "
        f"WHEN NEW.seq = {SEQ + failing} BEGIN SELECT RAISE(ABORT, 'injected'); END",
    )
    messages = [signed_fault_message(seq=SEQ + n) for n in range(4)]

    results = await asyncio.gather(
        *(gate.ingest_fault(m) for m in messages), return_exceptions=True
    )

    for result in results:
        assert isinstance(result, sqlite3.IntegrityError) or not isinstance(
            result, BaseException
        ), result
    admitted = {
        r.seq for r in results if not isinstance(r, BaseException) and r.accepted
    }
    assert {row[2] for row in await _faults(store)} == admitted
    assert (await _mark(store))[1] == max(admitted, default=0)
    await _assert_mark_iff_row(store)


async def test_a_fault_for_an_unknown_device_writes_nothing(
    gate: FirmwareTelemetryGate, store: StateStore
) -> None:
    message = signed_fault_message(seq=SEQ)
    message["fault"] = dict(message["fault"], device_id="unknown-device")

    verification = await gate.ingest_fault(message)

    assert verification.error_code == "anchor_missing"
    assert await _faults(store) == []
    assert (await _mark(store))[1] == 0


async def test_telemetry_advances_alone_and_records_no_fault(
    gate: FirmwareTelemetryGate, store: StateStore
) -> None:
    from tests.firmware.test_uptime_freshness import _telemetry

    verification, readings = await gate.ingest(
        _telemetry(boot_id=41, seq=7, uptime=1000)
    )

    assert verification.accepted and readings
    assert (await _mark(store))[:2] == (41, 7)
    assert await _faults(store) == []


async def _signed_under_rotated_key(store: StateStore, seq: int) -> dict[str, Any]:
    from tests.firmware.test_uptime_freshness import _ROTATED_SEED

    rotated = await store.get_firmware_device(SEALED_DEVICE)
    assert rotated is not None
    body = dict(
        signed_fault_message(seq=seq)["fault"],
        capability_hash=rotated["capability_hash"],
    )
    signature = Ed25519PrivateKey.from_private_bytes(_ROTATED_SEED).sign(
        canonical_json_bytes(body)
    )
    return {
        "fault": body,
        "signature": "ed25519:" + base64.b64encode(signature).decode(),
    }


async def _epochs(store: StateStore) -> list[tuple[Any, ...]]:
    def read(conn: Any) -> list[tuple[Any, ...]]:
        return [
            tuple(r)
            for r in conn.execute(
                "SELECT key_epoch_id, boot_id, seq FROM firmware_fault_events "
                "ORDER BY id"
            ).fetchall()
        ]

    return await store._run_read(read)


async def test_a_new_key_epoch_records_a_fault_reusing_an_old_boot_and_seq(
    gate: FirmwareTelemetryGate, store: StateStore
) -> None:
    from tests.firmware.test_uptime_freshness import _rotate_key

    first = await store.get_firmware_device(SEALED_DEVICE)
    assert first is not None
    assert (await gate.ingest_fault(signed_fault_message(seq=SEQ))).accepted
    await _rotate_key(gate)
    rotated = await store.get_firmware_device(SEALED_DEVICE)
    assert rotated is not None and (await _mark(store))[:2] == (0, 0)
    assert rotated["key_epoch_id"] != first["key_epoch_id"]

    verification = await gate.ingest_fault(await _signed_under_rotated_key(store, SEQ))

    assert verification.accepted, verification.error_detail
    assert (await _mark(store))[:2] == (41, SEQ)
    assert await _epochs(store) == [
        (first["key_epoch_id"], 41, SEQ),
        (rotated["key_epoch_id"], 41, SEQ),
    ]


async def test_a_collision_within_one_key_epoch_refuses_the_advance(
    gate: FirmwareTelemetryGate, store: StateStore
) -> None:
    """Unreachable through the mark; if it happens, nothing moves."""
    row = await store.get_firmware_device(SEALED_DEVICE)
    assert row is not None

    def plant() -> None:
        assert store._conn is not None
        store._conn.execute(
            "INSERT INTO firmware_fault_events (device_id, key_epoch_id, boot_id, "
            "seq, grade, posture, capability_hash, code, device_uptime_ms, "
            "received_at_ms, fault_json) VALUES (?, ?, 41, ?, 'attested', "
            "'sealed_flash', '', 'planted', 0, 0, '{}')",
            (SEALED_DEVICE, row["key_epoch_id"], SEQ),
        )
        store._conn.commit()

    await store._run_write(plant)

    with pytest.raises(sqlite3.IntegrityError, match="UNIQUE"):
        await gate.ingest_fault(signed_fault_message(seq=SEQ))

    assert (await _mark(store))[:2] == (0, 0)
    assert await _epochs(store) == [(row["key_epoch_id"], 41, SEQ)]


# The table as stores created before the epoch key hold it, verbatim.
_UNKEYED_DDL = """
CREATE TABLE firmware_fault_events (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id         TEXT    NOT NULL,
    boot_id           INTEGER NOT NULL,
    seq               INTEGER NOT NULL,
    grade             TEXT    NOT NULL,
    posture           TEXT    NOT NULL,
    capability_hash   TEXT    NOT NULL,
    code              TEXT    NOT NULL,
    subject           TEXT    NOT NULL DEFAULT '',
    detail            TEXT    NOT NULL DEFAULT '',
    device_uptime_ms  INTEGER NOT NULL,
    received_at_ms    INTEGER NOT NULL,
    fault_json        TEXT    NOT NULL,
    UNIQUE(device_id, boot_id, seq)
);
"""
_OLD_COLUMNS = (
    "id, device_id, boot_id, seq, grade, posture, capability_hash, code, "
    "subject, detail, device_uptime_ms, received_at_ms, fault_json"
)


def _unkeyed_store(path: Path) -> list[tuple[Any, ...]]:
    conn = sqlite3.connect(path)
    try:
        conn.executescript(_UNKEYED_DDL)
        for id_, seq, subject in (
            (3, SEQ, "relay0"),
            (7, SEQ + 5, "é\u2028"),
            (9, 1, "x"),
        ):
            conn.execute(
                f"INSERT INTO firmware_fault_events ({_OLD_COLUMNS}) "
                "VALUES (?, ?, 41, ?, 'attested', 'sealed_flash', 'h', "
                "'command_rejected', ?, 'replayed', 925000, 17, ?)",
                (id_, SEALED_DEVICE, seq, subject, '{"k":"v"}'),
            )
        # An id spent and then removed must not be reissued.
        conn.execute("DELETE FROM firmware_fault_events WHERE id = 9")
        conn.commit()
        return [
            tuple(r)
            for r in conn.execute(
                f"SELECT {_OLD_COLUMNS} FROM firmware_fault_events ORDER BY id"
            )
        ]
    finally:
        conn.close()


async def _old_rows(store: StateStore) -> list[tuple[Any, ...]]:
    def read(conn: Any) -> list[tuple[Any, ...]]:
        return [
            tuple(r)
            for r in conn.execute(
                f"SELECT {_OLD_COLUMNS} FROM firmware_fault_events ORDER BY id"
            )
        ]

    return await store._run_read(read)


async def test_a_pre_epoch_store_is_rebuilt_keeping_every_row_and_id(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.db"
    before = _unkeyed_store(path)
    store = StateStore(db_path=str(path))
    await store.open()
    try:
        assert await _old_rows(store) == before
        assert [e[0] for e in await _epochs(store)] == ["", ""]

        gate = FirmwareTelemetryGate(store)
        await provision_and_approve(gate, "manifest_full_sealed")
        verification = await gate.ingest_fault(signed_fault_message(seq=SEQ))

        assert verification.accepted, verification.error_detail
        rows = await _old_rows(store)
        assert rows[:2] == before
        assert [r[0] for r in rows] == [3, 7, 10]
        assert [(r[1], r[2], r[3]) for r in rows] == [
            (SEALED_DEVICE, 41, SEQ),
            (SEALED_DEVICE, 41, SEQ + 5),
            (SEALED_DEVICE, 41, SEQ),
        ]
    finally:
        await store.close()


async def test_the_epoch_rebuild_is_a_no_op_when_run_again(tmp_path: Path) -> None:
    path = tmp_path / "state.db"
    _unkeyed_store(path)
    for _ in range(2):
        store = StateStore(db_path=str(path))
        await store.open()
        await store.close()
    conn = sqlite3.connect(path)
    try:
        schema = conn.execute(
            "SELECT sql FROM sqlite_master WHERE name = 'firmware_fault_events'"
        ).fetchone()[0]
        rows = conn.execute(
            "SELECT * FROM firmware_fault_events ORDER BY id"
        ).fetchall()
        StateStore._key_firmware_fault_events_by_epoch(conn)
        assert (
            conn.execute(
                "SELECT sql FROM sqlite_master WHERE name = 'firmware_fault_events'"
            ).fetchone()[0]
            == schema
        )
        assert (
            conn.execute("SELECT * FROM firmware_fault_events ORDER BY id").fetchall()
            == rows
        )
        assert "UNIQUE(device_id, key_epoch_id, boot_id, seq)" in schema
        assert not conn.execute(
            "SELECT name FROM sqlite_master WHERE name LIKE '%unkeyed%'"
        ).fetchall()
    finally:
        conn.close()


async def test_a_read_only_open_leaves_a_pre_epoch_table_as_it_was(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.db"
    _unkeyed_store(path)
    image = path.read_bytes()
    store = StateStore(db_path=str(path), read_only=True)
    await store.open()
    await store.close()

    assert path.read_bytes() == image


def test_a_failed_epoch_rebuild_leaves_the_old_table_whole(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "state.db"
    before = _unkeyed_store(path)
    schema_sql = "SELECT name, sql FROM sqlite_master ORDER BY name"
    conn = sqlite3.connect(path)
    try:
        schema = conn.execute(schema_sql).fetchall()
        monkeypatch.setattr(
            "ori.state.store._FIRMWARE_FAULT_EVENTS_DDL", "CREATE TABLE broken ("
        )
        with pytest.raises(sqlite3.OperationalError):
            StateStore._key_firmware_fault_events_by_epoch(conn)
        assert conn.execute(schema_sql).fetchall() == schema
        assert [
            tuple(r)
            for r in conn.execute(
                f"SELECT {_OLD_COLUMNS} FROM firmware_fault_events ORDER BY id"
            )
        ] == before
    finally:
        conn.close()
