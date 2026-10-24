# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""gateway-api/v2 Producer Time and export row checks, driven through the runtime."""

import ast
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from ori.gateway.export import GatewayExportResponder
from ori.gateway.reasoning import MqttGatewayReasoner
from ori.hal.producer_paths import PRODUCER_PATHS
from ori.network.event_bus import EventBus
from ori.network.events import ActionResult, OriEvent, SensorReading
from ori.network.producer_time import (
    NOT_REPORTED,
    PRODUCER_TIMES,
    REPORTED,
    UNKNOWN,
)
from ori.state.store import StateStore
from ori.utils.time_utils import now_ms

ROOT = Path(__file__).resolve().parent.parent
CORPUS = json.loads(
    (ROOT / "tests" / "vectors" / "gateway_api" / "export-rows-v2.json").read_text()
)
_MAX_RECEIPT = 2**53 - 1
_ABSENT = object()


# ─── the export row checks, from gateway-api/v2's text ────────────────────────


def _receipt_ok(value: Any) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 1 <= value <= _MAX_RECEIPT
    )


def reading_verdict(row: dict[str, Any], where: str) -> str | None:
    """Steps 1 and 2: None when the reading passes."""
    basis = row.get("producer_time", _ABSENT)
    if basis is not _ABSENT and basis not in PRODUCER_TIMES:
        return "producer_time_invalid"
    held_to_receipt = where == "history_point" or (
        where == "sensor_history" and row.get("tier") == "raw"
    )
    if (
        held_to_receipt
        and basis == NOT_REPORTED
        and not _receipt_ok(row.get("received_at_ms", _ABSENT))
    ):
        return "receipt_missing"
    return None


def action_verdict(row: dict[str, Any]) -> str | None:
    """Steps 3 to 7: None when the row passes."""
    kind = row.get("record_kind", _ABSENT)
    if kind is _ABSENT:
        return None
    if kind not in ("dispatch", "contributor", "contributor_legacy"):
        return "record_kind_invalid"
    key = row.get("record_key", _ABSENT)
    if not (key is None or (isinstance(key, str) and key)):
        return "record_key_invalid"
    link = row.get("contributed_to", _ABSENT)
    if kind == "contributor":
        if not (isinstance(link, str) and link and link != key):
            return "contributed_to_invalid"
    elif link is not None:
        return "contributed_to_invalid"
    coalesced = row.get("action_taken") == "coalesced"
    if coalesced != (kind != "dispatch"):
        return "action_taken_mismatch"
    if kind == "contributor" and row.get("executed", _ABSENT) is not False:
        return "contributor_executed"
    return None


@pytest.mark.parametrize("case", CORPUS["readings"], ids=lambda c: c["name"])
def test_the_reading_checks_reach_every_corpus_verdict(case: dict) -> None:
    assert reading_verdict(case["row"], case["where"]) == case["expected"]["verdict"]


@pytest.mark.parametrize("case", CORPUS["action_log"], ids=lambda c: c["name"])
def test_the_action_checks_reach_every_corpus_verdict(case: dict) -> None:
    assert action_verdict(case["row"]) == case["expected"]["verdict"]


# ─── the closed table ─────────────────────────────────────────────────────────


def _reading_constructions() -> list[tuple[str, ast.Call]]:
    found = []
    for path in sorted((ROOT / "ori").rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"SensorReading", "StoredReading"}
            ):
                found.append((f"{path.relative_to(ROOT)}:{node.lineno}", node))
    return found


def test_every_reading_the_runtime_builds_names_its_basis() -> None:
    """A construction that omits producer_time would read unknown, silently.

    This sees direct calls by name; a reading built through an alias or
    dataclasses.replace is outside it and keeps the basis it was copied from.
    """
    constructions = _reading_constructions()
    assert len(constructions) > 20, "the scan stopped finding constructions"
    missing = []
    literal = []
    for where, call in constructions:
        value = next(
            (kw.value for kw in call.keywords if kw.arg == "producer_time"), None
        )
        if value is None:
            missing.append(where)
        elif isinstance(value, ast.Constant):
            literal.append(where)
    assert missing == [], f"readings built with no producer_time: {missing}"
    assert literal == [], (
        f"a basis written as a literal bypasses PRODUCER_PATHS: {literal}"
    )


def test_every_path_named_at_ingest_is_in_the_table() -> None:
    named = set()
    for path in sorted((ROOT / "ori").rglob("*.py")):
        source = path.read_text()
        if "producer_time_for(" not in source:
            continue
        module = ast.parse(source)
        constants = {
            target.id: node.value.value
            for node in ast.walk(
                ast.parse((ROOT / "ori/hal/producer_paths.py").read_text())
            )
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
            for target in node.targets
            if isinstance(target, ast.Name)
        }
        for node in ast.walk(module):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "producer_time_for"
            ):
                args = []
                for arg in node.args:
                    if isinstance(arg, ast.Constant):
                        args.append(arg.value)
                    elif isinstance(arg, ast.Name) and arg.id in constants:
                        args.append(constants[arg.id])
                    else:
                        pytest.fail(
                            f"{path.relative_to(ROOT)}:{node.lineno} names its path "
                            "with something other than a literal or a table constant"
                        )
                named.add(tuple(args))
    assert named, "no ingest path was found"
    assert named <= set(PRODUCER_PATHS), named - set(PRODUCER_PATHS)
    assert set(PRODUCER_PATHS) <= named, (
        f"table entries no ingest path names: {set(PRODUCER_PATHS) - named}"
    )


@pytest.mark.parametrize("value", ["Reported", "", None, 1, "measured"])
def test_a_reading_refuses_a_basis_outside_the_three(value: Any) -> None:
    with pytest.raises(ValueError, match="producer_time"):
        SensorReading("s", "current", 1.0, "ampere", 1, 1.0, producer_time=value)


def test_a_reading_with_no_stated_basis_is_unknown() -> None:
    assert SensorReading("s", "current", 1.0, "ampere", 1, 1.0).producer_time == UNKNOWN


# ─── a firmware reading, through ingest, history and every export ─────────────


@pytest.fixture
async def store(tmp_path):
    state = StateStore(str(tmp_path / "state.db"))
    await state.open()
    try:
        yield state
    finally:
        await state.close()


def _responder(store: StateStore) -> GatewayExportResponder:
    return GatewayExportResponder(
        device_id="dev-01",
        state_store=store,
        health_snapshot_provider=lambda: {},
    )


async def _export(store: StateStore, export_type: str, **fields: Any) -> list[dict]:
    request = {
        "request_id": "req-001",
        "export_type": export_type,
        "device_id": "dev-01",
        "limit": 1000,
        "params": {},
    }
    request.update(fields)
    response = await _responder(store).handle_request(request)
    assert response is not None
    assert response.error is None, response.error
    return response.items


async def test_a_firmware_reading_presents_no_measurement_time_anywhere(
    store: StateStore,
) -> None:
    from ori.runtime._firmware_wiring import _build_firmware_telemetry_subscriber
    from ori.security.firmware.liveness import FirmwareLivenessSupervisor
    from tests.firmware.test_liveness_composition import (
        _cfg,
        _provision,
        _telemetry_message,
    )

    bus = EventBus()
    delivered: list[OriEvent] = []

    async def handler(event: OriEvent) -> None:
        delivered.append(event)

    bus.subscribe("*", handler)
    subscriber = _build_firmware_telemetry_subscriber(
        _cfg(), bus, store, None, FirmwareLivenessSupervisor()
    )
    assert subscriber is not None
    await _provision(store)
    before = now_ms()
    await subscriber._ingest_telemetry(_telemetry_message("telemetry_single_reading"))
    after = now_ms()
    assert len(delivered) == 1
    event = delivered[0]
    assert event.reading is not None
    assert event.reading.producer_time == NOT_REPORTED
    assert before <= event.reading.timestamp <= after, "not the value's arrival"
    sensor_id = event.reading.sensor_id

    await store.history_admission.drain(5.0)  # the subscriber admits the row
    (stored,) = await store.get_history(sensor_id)
    assert stored.producer_time == NOT_REPORTED
    assert stored.timestamp == event.reading.timestamp

    window = {"since_ms": before - 1, "until_ms": after + 1}
    (raw,) = await _export(
        store,
        "sensor_history",
        params={"sensor_id": sensor_id, "bucket_ms": 0},
        **window,
    )
    assert raw["producer_time"] == NOT_REPORTED
    assert raw["tier"] == "raw"
    assert reading_verdict(raw, "sensor_history") is None
    (bucketed,) = await _export(
        store,
        "sensor_history",
        params={"sensor_id": sensor_id, "bucket_ms": 3_600_000},
        **window,
    )
    assert bucketed["producer_time"] == NOT_REPORTED

    request = await MqttGatewayReasoner(
        broker_url="mqtt://broker.local:1883",
        device_id="dev-01",
        request_id_factory=lambda: "req-1",
    )._build_request(prompt="p", event=event, rule_result=None, state_store=store)
    assert request.context["producer_time"] == NOT_REPORTED
    assert reading_verdict(request.context, "reasoning_reading") is None


async def test_a_history_point_carries_its_basis_and_receipt(store: StateStore) -> None:
    for basis in PRODUCER_TIMES:
        reading = SensorReading(
            "s1", "current", 1.0, "ampere", now_ms(), 1.0, producer_time=basis
        )
        await store.append_history(OriEvent.from_reading(reading, "dev-01"))
    event = OriEvent.from_reading(
        SensorReading("s1", "current", 2.0, "ampere", now_ms(), 1.0), "dev-01"
    )
    request = await MqttGatewayReasoner(
        broker_url="mqtt://broker.local:1883",
        device_id="dev-01",
        request_id_factory=lambda: "req-1",
    )._build_request(prompt="p", event=event, rule_result=None, state_store=store)
    points = request.context["history"]
    assert sorted(point["producer_time"] for point in points) == sorted(PRODUCER_TIMES)
    for point in points:
        assert _receipt_ok(point["received_at_ms"])
        assert reading_verdict(point, "history_point") is None


@pytest.mark.parametrize(
    "window",
    [
        [{"value": 1.0, "timestamp": 5, "producer_time": NOT_REPORTED}],
        [
            {
                "value": 1.0,
                "timestamp": 5,
                "producer_time": NOT_REPORTED,
                "received_at_ms": 0,
            }
        ],
        [
            {
                "value": 1.0,
                "timestamp": 5,
                "producer_time": NOT_REPORTED,
                "received_at_ms": 2**53,
            }
        ],
        [
            {
                "value": 1.0,
                "timestamp": 5,
                "producer_time": NOT_REPORTED,
                "received_at_ms": 7.0,
            }
        ],
        [
            {
                "value": 1.0,
                "timestamp": 5,
                "producer_time": "Reported",
                "received_at_ms": 7,
            }
        ],
        [{"value": 1.0, "timestamp": 5, "producer_time": ["reported"]}],
        [{"value": 1.0, "timestamp": 5}],
    ],
)
async def test_a_carried_history_window_never_emits_a_failing_point(
    window: list[dict],
) -> None:
    event = OriEvent.from_reading(
        SensorReading("s1", "current", 2.0, "ampere", 10, 1.0), "dev-01"
    )
    event.context["history_window"] = window
    request = await MqttGatewayReasoner(
        broker_url="mqtt://broker.local:1883",
        device_id="dev-01",
        request_id_factory=lambda: "req-1",
    )._build_request(prompt="p", event=event, rule_result=None, state_store=None)
    (point,) = request.context["history"]
    assert reading_verdict(point, "history_point") is None
    assert point["producer_time"] == UNKNOWN


async def test_an_event_without_a_reading_states_no_basis() -> None:
    event = OriEvent(
        event_id="e",
        event_type="device.heartbeat",
        device_id="dev-01",
        sensor_id="",
        timestamp=10,
        reading=None,
    )
    request = await MqttGatewayReasoner(
        broker_url="mqtt://broker.local:1883",
        device_id="dev-01",
        request_id_factory=lambda: "req-1",
    )._build_request(prompt="p", event=event, rule_result=None, state_store=None)
    assert request.context["producer_time"] == UNKNOWN


# ─── buckets ──────────────────────────────────────────────────────────────────


def _store_corpus_row(conn: sqlite3.Connection, row: dict, index: int) -> None:
    """A single sample as a raw row, a summary as a five-minute row at its timestamp."""
    if row["sample_count"] == 1:
        conn.execute(
            "INSERT INTO sensor_history (sensor_id, sensor_type, value, unit, "
            "timestamp, quality, metadata, received_at_ms, producer_time) "
            "VALUES ('s1', 'current', ?, 'ampere', ?, 1.0, '{}', ?, ?)",
            (
                row["value"],
                row["timestamp"],
                row["received_at_ms"],
                row["producer_time"],
            ),
        )
    else:
        conn.execute(
            "INSERT INTO sensor_history_basis_5min (sensor_id, sensor_type, bucket_ms, "
            "avg_value, unit, sample_count, max_received_at_ms, producer_time) "
            "VALUES ('s1', 'current', ?, ?, 'ampere', ?, ?, ?)",
            (
                row["timestamp"],
                row["value"],
                row["sample_count"],
                row["received_at_ms"],
                row["producer_time"],
            ),
        )


@pytest.mark.parametrize("case", CORPUS["buckets"], ids=lambda c: c["name"])
async def test_the_bucketed_export_reaches_every_corpus_bucket(
    tmp_path: Path, case: dict
) -> None:
    store = StateStore(str(tmp_path / "state.db"))
    await store.open()
    try:
        assert store._conn is not None
        for index, row in enumerate(case["rows"]):
            _store_corpus_row(store._conn, row, index)
        store._conn.commit()
        stamps = [row["timestamp"] for row in case["rows"]]
        items = await _export(
            store,
            "sensor_history",
            since_ms=min(stamps),
            until_ms=max(stamps),
            params={"sensor_id": "s1", "bucket_ms": case["bucket_ms"]},
        )
    finally:
        await store.close()
    got = [
        {key: value for key, value in item.items() if key in case["expected"][0]}
        for item in items
    ]
    assert got == case["expected"]
    for item in items:
        assert reading_verdict(item, "sensor_history") is None


async def test_compaction_keeps_each_basis_in_its_own_bucket(store: StateStore) -> None:
    old = now_ms() - 49 * 3_600_000
    stamp = (old // 300_000) * 300_000 + 10
    assert store._conn is not None
    for value, basis in ((2.0, REPORTED), (4.0, REPORTED), (10.0, NOT_REPORTED)):
        store._conn.execute(
            "INSERT INTO sensor_history (sensor_id, sensor_type, value, unit, "
            "timestamp, quality, metadata, received_at_ms, producer_time) "
            "VALUES ('s1', 'current', ?, 'ampere', ?, 1.0, '{}', ?, ?)",
            (value, stamp, old, basis),
        )
    store._conn.commit()
    await store.compact_history()
    rows = store._conn.execute(
        "SELECT producer_time, avg_value, sample_count FROM sensor_history_basis_5min "
        "ORDER BY producer_time"
    ).fetchall()
    assert [tuple(row) for row in rows] == [
        (NOT_REPORTED, 10.0, 1),
        (REPORTED, 3.0, 2),
    ]
    # A later run merges into its own basis, never the other.
    store._conn.execute(
        "INSERT INTO sensor_history (sensor_id, sensor_type, value, unit, "
        "timestamp, quality, metadata, received_at_ms, producer_time) "
        "VALUES ('s1', 'current', 6.0, 'ampere', ?, 1.0, '{}', ?, 'not_reported')",
        (stamp, old),
    )
    store._conn.commit()
    await store.compact_history()
    rows = store._conn.execute(
        "SELECT producer_time, avg_value, sample_count FROM sensor_history_basis_5min "
        "ORDER BY producer_time"
    ).fetchall()
    assert [tuple(row) for row in rows] == [
        (NOT_REPORTED, 8.0, 2),
        (REPORTED, 3.0, 2),
    ]


async def test_a_raw_row_without_a_usable_receipt_states_no_basis(
    store: StateStore,
) -> None:
    assert store._conn is not None
    store._conn.execute(
        "INSERT INTO sensor_history (sensor_id, sensor_type, value, unit, "
        "timestamp, quality, metadata, received_at_ms, producer_time) "
        "VALUES ('s1', 'current', 1.0, 'ampere', 100, 1.0, '{}', ?, 'not_reported')",
        (2**53,),
    )
    store._conn.commit()
    (item,) = await _export(
        store,
        "sensor_history",
        since_ms=0,
        until_ms=1000,
        params={"sensor_id": "s1", "bucket_ms": 0},
    )
    assert item["producer_time"] == UNKNOWN
    assert reading_verdict(item, "sensor_history") is None


# ─── a store from before the basis ────────────────────────────────────────────

_UNBASED_HISTORY = """
CREATE TABLE sensor_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT, sensor_id TEXT NOT NULL,
    sensor_type TEXT NOT NULL, value REAL NOT NULL, unit TEXT NOT NULL,
    timestamp INTEGER NOT NULL, quality REAL NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}',
    received_at_ms INTEGER NOT NULL CHECK (received_at_ms > 0)
);
""" + "".join(
    f"""
CREATE TABLE sensor_history_{tier} (
    id INTEGER PRIMARY KEY AUTOINCREMENT, sensor_id TEXT NOT NULL,
    sensor_type TEXT NOT NULL, bucket_ms INTEGER NOT NULL, avg_value REAL NOT NULL,
    unit TEXT NOT NULL, sample_count INTEGER NOT NULL,
    max_received_at_ms INTEGER NOT NULL CHECK (max_received_at_ms > 0),
    UNIQUE(sensor_id, bucket_ms)
);
"""
    for tier in ("5min", "hourly", "daily")
)


async def test_history_from_before_the_basis_is_kept_and_reads_unknown(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.db"
    conn = sqlite3.connect(path)
    conn.executescript(_UNBASED_HISTORY)
    # A LoRaWAN network server's received_at, kept by an earlier release.
    conn.execute(
        "INSERT INTO sensor_history (sensor_id, sensor_type, value, unit, timestamp, "
        "quality, received_at_ms) VALUES ('s1', 'current', 1.5, 'ampere', 900, 1.0, 1000)"
    )
    for tier in ("5min", "hourly", "daily"):
        conn.execute(
            f"INSERT INTO sensor_history_{tier} (id, sensor_id, sensor_type, bucket_ms, "
            "avg_value, unit, sample_count, max_received_at_ms) "
            "VALUES (40, 's1', 'current', 600, 2.5, 'ampere', 7, 1000)"
        )
        conn.execute(f"DELETE FROM sensor_history_{tier} WHERE id = 40")
        conn.execute(
            f"INSERT INTO sensor_history_{tier} (id, sensor_id, sensor_type, bucket_ms, "
            "avg_value, unit, sample_count, max_received_at_ms) "
            "VALUES (7, 's1', 'current', 600, 2.5, 'ampere', 7, 1000)"
        )
    conn.commit()
    conn.close()

    for _ in range(2):  # the second open finds nothing to migrate
        store = StateStore(str(path))
        await store.open()
        try:
            items = await _export(
                store,
                "sensor_history",
                since_ms=0,
                until_ms=1000,
                params={"sensor_id": "s1", "bucket_ms": 0},
            )
            assert store._conn is not None
            for tier in ("5min", "hourly", "daily"):
                table = f"sensor_history_{tier}"
                # The shape an earlier release compacts into is left as it was.
                assert "producer_time" not in {
                    row[1] for row in store._conn.execute(f"PRAGMA table_info({table})")
                }
                assert [
                    tuple(r)
                    for r in store._conn.execute(
                        f"SELECT id, sample_count FROM {table}"
                    )
                ] == [(7, 7)]
                (seq,) = store._conn.execute(
                    "SELECT seq FROM sqlite_sequence WHERE name = ?", (table,)
                ).fetchone()
                assert seq == 40
        finally:
            await store.close()
        assert sorted(
            (i["tier"], i["timestamp"], i["producer_time"]) for i in items
        ) == [
            ("5min", 600, UNKNOWN),
            ("daily", 600, UNKNOWN),
            ("hourly", 600, UNKNOWN),
            ("raw", 900, UNKNOWN),
        ]


# ─── action_log records ───────────────────────────────────────────────────────


def _result(action_taken: str, executed: bool) -> ActionResult:
    return ActionResult(
        action_name="trip_relay",
        tier="D",
        executed=executed,
        approved=None,
        action_taken=action_taken,
        timestamp=now_ms(),
    )


def _hostile_rows(conn: sqlite3.Connection) -> None:
    """Rows a store whose columns were added holds, with no CHECK to refuse them."""
    conn.execute("PRAGMA ignore_check_constraints = ON")
    rows = [
        ("dispatch", "", None, "coalesced", 1),  # a rolled-back release's joined row
        ("contributor", "k-self", "k-self", "coalesced", 0),  # names itself
        ("contributor", "k-empty", "", "coalesced", 0),
        ("contributor", "k-exec", "k-holder", "coalesced", 1),
        ("contributor", "k-acted", "k-holder", "trip_relay", 0),
        ("contributor_legacy", "k-linked", "k-holder", "coalesced", 1),
        ("dispatch", "k-linked-dispatch", "k-holder", "trip_relay", 1),
        ("bogus", "k-bogus", None, "trip_relay", 1),
        ("dispatch", "", None, "trip_relay", 1),
    ]
    for kind, key, link, taken, executed in rows:
        conn.execute(
            "INSERT INTO action_log (action_name, tier, executed, approved, "
            "action_taken, trigger_name, timestamp, device_id, record_kind, "
            "record_key, contributed_to) VALUES "
            "('trip_relay', 'D', ?, NULL, ?, 't', ?, 'dev-01', ?, ?, ?)",
            (executed, taken, now_ms(), kind, key, link),
        )
    conn.execute("PRAGMA ignore_check_constraints = OFF")
    conn.commit()


async def test_both_action_readers_emit_only_rows_that_pass_every_check(
    store: StateStore,
) -> None:
    await store.log_action(_result("trip_relay", True), "t", record_key="k-holder")
    await store.log_action(
        _result("coalesced", False),
        "t",
        record_kind="contributor",
        record_key="k-joined",
        contributed_to="k-holder",
    )
    assert store._conn is not None
    store._conn.execute("UPDATE action_log SET device_id = 'dev-01'")
    _hostile_rows(store._conn)

    exported = await _export(store, "action_log")
    local = await store.get_action_log(limit=100)
    assert len(exported) == len(local) == 11
    for row in exported + local:
        assert action_verdict(row) is None, row
        assert set(row) >= {"record_kind", "record_key", "contributed_to"}

    by_key = {row["record_key"]: row for row in exported}
    assert by_key["k-holder"]["record_kind"] == "dispatch"
    assert by_key["k-joined"]["record_kind"] == "contributor"
    assert by_key["k-joined"]["contributed_to"] == "k-holder"
    for key in ("k-self", "k-empty", "k-exec", "k-linked"):
        assert by_key[key]["record_kind"] == "contributor_legacy", key
        assert by_key[key]["contributed_to"] is None
    for key in ("k-acted", "k-linked-dispatch", "k-bogus"):
        assert by_key[key]["record_kind"] == "dispatch", key
        assert by_key[key]["contributed_to"] is None
    unkeyed = [row for row in exported if row["record_key"] is None]
    assert sorted(row["record_kind"] for row in unkeyed) == [
        "contributor_legacy",
        "dispatch",
    ]


# ─── each path's basis, pinned against an independent reading of the contract ─

# Written from gateway-api/v2 Producer Time, not copied from PRODUCER_PATHS: a
# read the runtime requests is reported, a pushed value is not_reported, and a
# time a caller supplies is of unknown basis.
_EXPECTED_BASIS = {
    "i2c": REPORTED,
    "serial": REPORTED,
    "usb_serial": REPORTED,
    "solarman_modbus": REPORTED,
    "psutil": REPORTED,
    "smart": REPORTED,
    "opcua": REPORTED,
    "growatt": REPORTED,
    "http": REPORTED,
    "coap": REPORTED,
    "mqtt": NOT_REPORTED,
    "victron": NOT_REPORTED,
    "lorawan": NOT_REPORTED,
    "zigbee": NOT_REPORTED,
    "mqtt_perception": NOT_REPORTED,
    "firmware": NOT_REPORTED,
    "rule_evaluation": UNKNOWN,
}

# The paths each module may name, so an adapter that names another's is caught.
_MODULE_PATHS = {
    "ori/hal/i2c_adapter.py": {"i2c"},
    "ori/hal/serial_adapter.py": {"serial"},
    "ori/hal/usb_serial_adapter.py": {"usb_serial"},
    "ori/hal/solarman_modbus_adapter.py": {"solarman_modbus"},
    "ori/hal/psutil_adapter.py": {"psutil"},
    "ori/hal/smart_adapter.py": {"smart"},
    "ori/hal/opcua_adapter.py": {"opcua"},
    "ori/hal/growatt_adapter.py": {"growatt"},
    "ori/hal/http_adapter.py": {"http"},
    "ori/hal/coap_adapter.py": {"coap"},
    "ori/hal/mqtt_adapter.py": {"mqtt"},
    "ori/hal/victron_adapter.py": {"victron"},
    "ori/hal/lorawan_adapter.py": {"lorawan"},
    "ori/hal/zigbee_adapter.py": {"zigbee"},
    "ori/hal/mqtt_perception_adapter.py": {"mqtt_perception"},
    "ori/security/firmware/ingest.py": {"firmware"},
    "ori/integration/rule_evaluation.py": {"rule_evaluation"},
}


def test_every_path_has_the_basis_the_contract_gives_it() -> None:
    got = {path: basis for (path, _member), basis in PRODUCER_PATHS.items()}
    assert len(got) == len(PRODUCER_PATHS), "a path keyed by two members"
    assert got == _EXPECTED_BASIS


def test_each_module_names_only_its_own_path() -> None:
    named: dict[str, set[str]] = {}
    for path in sorted((ROOT / "ori").rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "producer_time_for"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                named.setdefault(str(path.relative_to(ROOT)), set()).add(
                    node.args[0].value
                )
    assert named == _MODULE_PATHS


# ─── fixes the review drove ───────────────────────────────────────────────────


async def test_a_tier_3_request_sends_the_readings_own_time_under_its_basis() -> None:
    event = OriEvent.from_reading(
        SensorReading("s1", "current", 2.0, "ampere", 0, 1.0, producer_time=REPORTED),
        "dev-01",
    )
    request = await MqttGatewayReasoner(
        broker_url="mqtt://broker.local:1883",
        device_id="dev-01",
        request_id_factory=lambda: "req-1",
    )._build_request(prompt="p", event=event, rule_result=None, state_store=None)
    assert request.context["timestamp"] == 0
    assert request.context["producer_time"] == REPORTED


async def test_the_decision_history_window_carries_each_basis(
    store: StateStore,
) -> None:
    from ori.reasoning.elevator import IntelligenceElevator

    for basis in PRODUCER_TIMES:
        reading = SensorReading(
            "s1", "current", 1.0, "ampere", now_ms(), 1.0, producer_time=basis
        )
        await store.append_history(OriEvent.from_reading(reading, "dev-01"))
    event = OriEvent.from_reading(
        SensorReading("s1", "current", 2.0, "ampere", now_ms(), 1.0), "dev-01"
    )
    await IntelligenceElevator()._attach_decision_history_window(event, store)
    window = event.context["history_window"]
    assert sorted(row["producer_time"] for row in window) == sorted(PRODUCER_TIMES)


@pytest.mark.parametrize(
    "basis, metadata, expected",
    [
        (REPORTED, {"source": "psutil"}, None),
        (NOT_REPORTED, {"source": "mqtt"}, "not reported by device"),
        (NOT_REPORTED, {"source": "lorawan"}, "not reported by device"),
        (UNKNOWN, {"source": "rule_evaluation"}, "not stated"),
    ],
)
def test_the_measured_line_claims_a_measurement_only_for_a_reported_time(
    basis: str, metadata: dict, expected: str | None
) -> None:
    from ori.reasoning.action_dispatcher import ActionDispatcher
    from ori.reasoning.elevator import ReasoningResult

    stamp = 1_752_537_600_000
    reading = SensorReading(
        "s1",
        "current",
        1.0,
        "ampere",
        stamp,
        1.0,
        metadata=metadata,
        producer_time=basis,
    )
    body = ActionDispatcher()._format_approval_message(
        device_id="dev",
        timestamp_ms=stamp,
        result=ReasoningResult(
            text="t", tier="rule", model="m", tokens_used=0, latency_ms=0
        ),
        action="open_protected_circuit",
        timeout_seconds=30,
        device_timezone="UTC",
        reading=reading,
    )
    line = next(row for row in body.splitlines() if row.startswith("Measured: "))
    if expected is None:
        assert line == "Measured: " + ActionDispatcher._format_local_time(stamp, "UTC")
    else:
        assert line == f"Measured: {expected}"


async def test_compaction_keeps_bases_apart_in_every_tier(store: StateStore) -> None:
    assert store._conn is not None
    current = now_ms()
    # Old enough that each runs through every tier in one compaction.
    received = current - 2 * 365 * 86_400_000
    hour = (received // 86_400_000) * 86_400_000
    for basis, value in ((REPORTED, 2.0), (NOT_REPORTED, 10.0), (REPORTED, 4.0)):
        store._conn.execute(
            "INSERT INTO sensor_history (sensor_id, sensor_type, value, unit, "
            "timestamp, quality, metadata, received_at_ms, producer_time) "
            "VALUES ('s1', 'current', ?, 'ampere', ?, 1.0, '{}', ?, ?)",
            (value, hour + 1, received, basis),
        )
    store._conn.commit()
    for table in ("sensor_history_basis_5min", "sensor_history_basis_hourly"):
        store._conn.execute(
            f"INSERT INTO {table} (sensor_id, sensor_type, bucket_ms, avg_value, "
            "unit, sample_count, max_received_at_ms, producer_time) "
            "VALUES ('s1', 'current', ?, 6.0, 'ampere', 2, ?, 'not_reported')",
            (hour + 600_000, received),
        )
    store._conn.commit()
    await store.compact_history()
    rows = store._conn.execute(
        "SELECT producer_time, avg_value, sample_count FROM sensor_history_basis_daily "
        "ORDER BY producer_time"
    ).fetchall()
    assert [tuple(row) for row in rows] == [
        (NOT_REPORTED, pytest.approx(6.8), 5),  # (10 + 2 x 6 + 2 x 6) / 5
        (REPORTED, pytest.approx(3.0), 2),
    ]


async def test_two_first_opens_of_an_older_store_both_succeed(tmp_path: Path) -> None:
    import asyncio

    for attempt in range(5):
        path = tmp_path / f"race-{attempt}.db"
        # The rest of the schema is in place, so only this migration races.
        fresh = StateStore(str(path))
        await fresh.open()
        await fresh.close()
        conn = sqlite3.connect(path)
        for table in (
            "sensor_history",
            "sensor_history_5min",
            "sensor_history_hourly",
            "sensor_history_daily",
        ):
            conn.execute(f"DROP TABLE {table}")
        conn.executescript(_UNBASED_HISTORY)
        conn.execute(
            "INSERT INTO sensor_history_5min (sensor_id, sensor_type, bucket_ms, "
            "avg_value, unit, sample_count, max_received_at_ms) "
            "VALUES ('s1', 'current', 600, 1.0, 'ampere', 3, 1000)"
        )
        conn.commit()
        conn.close()

        async def open_once() -> None:
            opener = StateStore(str(path), allow_history_rebuild=True)
            try:
                await opener.open()
            finally:
                await opener.close()

        await asyncio.gather(open_once(), open_once())
        conn = sqlite3.connect(path)
        assert "producer_time" in {
            row[1] for row in conn.execute("PRAGMA table_info(sensor_history)")
        }
        assert conn.execute(
            "SELECT sample_count FROM sensor_history_5min"
        ).fetchall() == [(3,)]
        conn.close()


async def test_a_reopened_store_records_each_row_as_every_reader_reads_it(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.db"
    store = StateStore(str(path))
    await store.open()
    assert store._conn is not None
    _hostile_rows(store._conn)
    store._conn.execute("UPDATE action_log SET attestation_status = 'pending'")
    store._conn.commit()
    await store.close()

    store = StateStore(str(path))
    await store.open()
    try:
        assert store._conn is not None
        stored = {
            (row["record_key"], row["record_kind"], row["contributed_to"])
            for row in store._conn.execute(
                "SELECT record_key, record_kind, contributed_to FROM action_log"
            )
        }
        exported = {
            (row["record_key"] or "", row["record_kind"], row["contributed_to"])
            for row in await _export(store, "action_log")
        }
        assert stored == exported
        rewritten = {
            "k-self",
            "k-empty",
            "k-exec",
            "k-acted",
            "k-linked",
            "k-bogus",
            "k-linked-dispatch",
        }
        settled = {
            row["record_key"]: (row["attestation_status"], row["attestation_reason"])
            for row in store._conn.execute(
                "SELECT record_key, attestation_status, attestation_reason "
                "FROM action_log"
            )
        }
        for key in rewritten:
            assert settled[key] == ("refused", "reclassified_record"), key
        pending = await store.get_actions_needing_attestation()
        assert not rewritten & {row.get("record_key") for row in pending}
    finally:
        await store.close()


def test_a_table_another_opener_migrated_first_is_left_as_it_is(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The check before the transaction can be stale; the one inside it decides."""
    from ori.state.store import _table_columns as real

    path = tmp_path / "state.db"
    conn = sqlite3.connect(path)
    conn.executescript(_UNBASED_HISTORY)
    StateStore._add_history_producer_time(conn)  # the other opener, first
    stale: set[str] = set()

    def first_look_is_stale(connection: sqlite3.Connection, table: str) -> set[str]:
        columns = real(connection, table)
        if table not in stale:
            stale.add(table)
            return columns - {"producer_time"}
        return columns

    monkeypatch.setattr("ori.state._migrations._table_columns", first_look_is_stale)
    StateStore._add_history_producer_time(conn)
    assert stale == {"sensor_history"}
    conn.close()


async def test_a_reopen_agrees_with_every_reader_on_hostile_types(
    tmp_path: Path,
) -> None:
    """Stored kind, both readers and the attestation summary read one row alike."""
    path = tmp_path / "state.db"
    store = StateStore(str(path))
    await store.open()
    assert store._conn is not None
    conn = store._conn
    conn.execute("PRAGMA ignore_check_constraints = ON")
    hostile = [
        # (record_kind, record_key, contributed_to, action_taken, executed)
        ("contributor", "b-link", b"k-holder", "coalesced", 0),
        ("contributor", b"k-blob", "k-holder", "coalesced", 0),
        ("contributor", "e-text", "k-holder", "coalesced", "0"),
        ("contributor", "e-real", "k-holder", "coalesced", 0.0),
        ("contributor", "e-blob", "k-holder", "coalesced", b"\x00"),
        ("contributor", "e-empty", "k-holder", "coalesced", ""),
        ("contributor", "a-blob", "k-holder", b"coalesced", 0),
        (b"contributor", "kind-blob", "k-holder", "coalesced", 0),
        ("dispatch", "d-blob-link", b"x", "trip_relay", 1),
        ("contributor", "ok", "k-holder", "coalesced", 0),
        ("dispatch", "k-holder", None, "trip_relay", 1),
    ]
    for kind, key, link, taken, executed in hostile:
        conn.execute(
            "INSERT INTO action_log (action_name, tier, executed, approved, "
            "action_taken, trigger_name, timestamp, device_id, record_kind, "
            "record_key, contributed_to, attestation_status) VALUES "
            "('trip_relay', 'D', ?, NULL, ?, 't', ?, 'dev-01', ?, ?, ?, 'pending')",
            (executed, taken, now_ms(), kind, key, link),
        )
    conn.execute("PRAGMA ignore_check_constraints = OFF")
    conn.commit()
    await store.close()

    store = StateStore(str(path))
    await store.open()
    try:
        assert store._conn is not None
        stored = [
            (row["record_kind"], row["contributed_to"])
            for row in store._conn.execute(
                "SELECT record_kind, contributed_to FROM action_log ORDER BY id"
            )
        ]
        local = await store.get_action_log(limit=100)
        exported = await _export(store, "action_log")
        assert len(stored) == len(local) == len(exported) == len(hostile)
        for row in local + exported:
            assert action_verdict(row) is None, row
        assert sorted(stored, key=repr) == sorted(
            ((row["record_kind"], row["contributed_to"]) for row in local), key=repr
        ), stored
        assert sorted(
            (row["record_kind"], row["contributed_to"]) for row in local
        ) == sorted((row["record_kind"], row["contributed_to"]) for row in exported)
        # INTEGER affinity stores '0' and 0.0 as 0, so those rows are honest.
        contributors = {
            row["record_key"]
            for row in store._conn.execute(
                "SELECT record_key FROM action_log WHERE record_kind = 'contributor'"
            )
        }
        assert contributors == {b"k-blob", "e-text", "e-real", "ok"}
        summary = await store.get_attestation_summary()
        assert summary["contributor_links_unresolved"] == 0
        assert not {
            row.get("record_key")
            for row in await store.get_actions_needing_attestation()
        } & {
            "b-link",
            "e-text",
            "e-real",
            "e-blob",
            "a-blob",
            "kind-blob",
            "d-blob-link",
        }
    finally:
        await store.close()


# ─── a release rolled back to, on a store this release opened ─────────────────

_V250 = json.loads(
    (ROOT / "tests" / "fixtures" / "v2_5_0_history_statements.json").read_text()
)


async def test_the_last_release_still_records_and_compacts_after_this_one(
    tmp_path: Path,
) -> None:
    """The installer restores the previous release on a failed health check."""
    path = tmp_path / "state.db"
    old = now_ms() - 2 * 365 * 86_400_000
    day = (old // 86_400_000) * 86_400_000
    store = StateStore(str(path))
    await store.open()
    assert store._conn is not None
    for basis, value in ((REPORTED, 2.0), (NOT_REPORTED, 10.0)):
        store._conn.execute(
            "INSERT INTO sensor_history (sensor_id, sensor_type, value, unit, "
            "timestamp, quality, metadata, received_at_ms, producer_time) "
            "VALUES ('s1', 'current', ?, 'ampere', ?, 1.0, '{}', ?, ?)",
            (value, day + 1, old, basis),
        )
    store._conn.commit()
    await store.compact_history()  # this release: into the pyramid by basis
    await store.close()

    # The previous release, on the same file: it records and compacts.
    conn = sqlite3.connect(path)
    conn.execute(
        _V250["insert_reading"],
        ("s1", "current", 6.0, "ampere", day + 2, 1.0, "{}", old),
    )
    for statement, cutoff in zip(
        _V250["compaction"],
        (old + 1, old + 1, old + 1, old + 1, old + 1, old + 1),
    ):
        conn.execute(statement, (cutoff,))
    conn.commit()
    assert conn.execute("SELECT COUNT(*) FROM sensor_history").fetchone() == (0,)
    conn.close()

    # This release again: every sample is there, each under the basis it has.
    store = StateStore(str(path))
    await store.open()
    try:
        items = await _export(
            store,
            "sensor_history",
            since_ms=day,
            until_ms=day + 86_400_000,
            params={"sensor_id": "s1", "bucket_ms": 86_400_000},
        )
    finally:
        await store.close()
    assert [(i["producer_time"], i["sample_count"], i["value"]) for i in items] == [
        (REPORTED, 1, 2.0),
        (NOT_REPORTED, 1, 10.0),
        (UNKNOWN, 1, 6.0),
    ]
