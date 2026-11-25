# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""gateway-api/v2 Page Order through the real store and responder.

Every paged export pages by position, not by count: a traversal past the old
source caps returns every row exactly once and ends, a token names a position
bound to its device, export and filters, and a token this runtime did not
issue that way is answered `page_token_invalid`.
"""

from __future__ import annotations

import base64
import json
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import pytest

from ori.gateway.export import ExportResponse, GatewayExportResponder
from ori.gateway.export_paging import PAGE_TOKEN_INVALID, filter_digest, issue, new_key
from ori.state.store import StateStore

CORPUS = json.loads(
    (
        Path(__file__).parent / "vectors" / "gateway_api" / "export-rows-v2.json"
    ).read_text()
)
DEVICE = "dev-01"
SENSOR = "s1"


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[StateStore]:
    state = StateStore(str(tmp_path / "state.db"))
    await state.open()
    try:
        yield state
    finally:
        await state.close()


_RESPONDERS: dict[tuple[int, str], GatewayExportResponder] = {}


def _responder(store: StateStore, device: str = DEVICE) -> GatewayExportResponder:
    """One responder per store and device, as the runtime keeps one per process."""
    key = (id(store), device)
    if key not in _RESPONDERS:
        _RESPONDERS[key] = GatewayExportResponder(
            device_id=device, state_store=store, health_snapshot_provider=dict
        )
    return _RESPONDERS[key]


async def _page(
    store: StateStore,
    export_type: str,
    token: Any = "",
    limit: int = 400,
    device: str = DEVICE,
    **fields: Any,
) -> ExportResponse:
    request: dict[str, Any] = {
        "request_id": "req-001",
        "export_type": export_type,
        "device_id": device,
        "limit": limit,
        "page_token": token,
        "params": {},
    }
    request.update(fields)
    response = await _responder(store, device).handle_request(request)
    assert response is not None
    return response


async def _traverse(
    store: StateStore,
    export_type: str,
    key: Callable[[dict[str, Any]], Any],
    limit: int = 400,
    between: Callable[[int], None] | None = None,
    **fields: Any,
) -> list[list[Any]]:
    pages: list[list[Any]] = []
    token = ""
    for index in range(100_000):
        response = await _page(store, export_type, token, limit, **fields)
        assert response.error is None, response.error
        # As the corpus counts pages: an empty last page, left when rows were
        # removed after the one before it, is not a page.
        if response.items:
            pages.append([key(item) for item in response.items])
        if response.complete:
            assert response.next_page_token == ""
            return pages
        assert response.items, "a page that is not the last holds a row"
        assert response.next_page_token != token, "a token was issued twice"
        token = response.next_page_token
        if between is not None:
            between(index)
    raise AssertionError("the traversal did not end")


def _conn(store: StateStore) -> Any:
    assert store._conn is not None
    return store._conn


def _action_rows(store: StateStore, count: int, *, per_timestamp: int = 3) -> None:
    _conn(store).executemany(
        "INSERT INTO action_log (action_name, tier, executed, action_taken, "
        "trigger_name, timestamp, device_id, correlation_id, record_kind, "
        "record_key) VALUES ('alert_sms', 'A', 1, 'alert_sms', 't', ?, ?, ?, "
        "'dispatch', ?)",
        [
            (1_000 + index // per_timestamp, DEVICE, f"row-{index}", f"key-{index}")
            for index in range(count)
        ],
    )
    _conn(store).commit()


def _reasoning_rows(store: StateStore, count: int) -> None:
    _conn(store).executemany(
        "INSERT INTO reasoning_log (trigger_name, tier_used, response, confidence, "
        "action_tier, timestamp, device_id, correlation_id) "
        "VALUES ('t', 'rule', 'r', 1.0, 'A', ?, ?, ?)",
        [(1_000 + index // 3, DEVICE, f"row-{index}") for index in range(count)],
    )
    _conn(store).commit()


def _tier_c_rows(store: StateStore, count: int) -> None:
    _conn(store).executemany(
        "INSERT INTO tier_c_decision_log (device_id, created_at, proposal_id, "
        "history_window_json, final_action_result_json, later_outcome_json, "
        "safe_default_used, action_executed) VALUES (?, ?, ?, '[]', '{}', '{}', 0, 0)",
        [(DEVICE, 1_000 + index // 3, f"row-{index}") for index in range(count)],
    )
    _conn(store).commit()


def _raw_rows(store: StateStore, count: int) -> None:
    _conn(store).executemany(
        "INSERT INTO sensor_history (sensor_id, sensor_type, value, unit, timestamp, "
        "quality, metadata, received_at_ms, producer_time) "
        "VALUES (?, 'current', ?, 'ampere', ?, 1.0, '{}', ?, 'reported')",
        [
            (SENSOR, float(index), 1_000 + index // 2, 2_000 + index)
            for index in range(count)
        ],
    )
    _conn(store).commit()


# --- every export, past its old source cap -----------------------------------


async def test_action_log_returns_every_row_once_past_the_old_cap(
    store: StateStore,
) -> None:
    _action_rows(store, 1_200)
    pages = await _traverse(store, "action_log", lambda item: item["correlation_id"])
    rows = [row for page in pages for row in page]
    assert sorted(rows) == sorted(f"row-{index}" for index in range(1_200))
    assert len(rows) == len(set(rows))
    assert [len(page) for page in pages] == [400, 400, 400]


async def test_reasoning_log_returns_every_row_once_past_the_old_cap(
    store: StateStore,
) -> None:
    _reasoning_rows(store, 1_200)
    pages = await _traverse(store, "reasoning_log", lambda item: item["correlation_id"])
    rows = [row for page in pages for row in page]
    assert sorted(rows) == sorted(f"row-{index}" for index in range(1_200))
    assert len(rows) == len(set(rows))


async def test_tier_c_decision_log_returns_every_row_once_past_the_old_cap(
    store: StateStore,
) -> None:
    _tier_c_rows(store, 1_200)
    pages = await _traverse(
        store, "tier_c_decision_log", lambda item: item["proposal_id"]
    )
    rows = [row for page in pages for row in page]
    assert sorted(rows) == sorted(f"row-{index}" for index in range(1_200))
    assert len(rows) == len(set(rows))


async def test_unbucketed_sensor_history_returns_every_row_past_the_old_cap(
    store: StateStore,
) -> None:
    _raw_rows(store, 10_300)
    pages = await _traverse(
        store,
        "sensor_history",
        lambda item: item["value"],
        limit=1_000,
        since_ms=0,
        until_ms=10**9,
        params={"sensor_id": SENSOR, "bucket_ms": 0},
    )
    values = [value for page in pages for value in page]
    assert values == [float(index) for index in range(10_300)]


async def test_bucketed_sensor_history_aggregates_every_row_past_the_old_cap(
    store: StateStore,
) -> None:
    _raw_rows(store, 10_300)
    pages = await _traverse(
        store,
        "sensor_history",
        lambda item: (item["start_ms"], item["sample_count"]),
        limit=7,
        since_ms=0,
        until_ms=10**9,
        params={"sensor_id": SENSOR, "bucket_ms": 1_000},
    )
    buckets = [bucket for page in pages for bucket in page]
    assert sum(samples for _, samples in buckets) == 10_300
    starts = [start for start, _ in buckets]
    assert starts == sorted(set(starts))


async def test_a_full_last_page_is_complete(store: StateStore) -> None:
    """`complete` is true exactly when no row remains, a full page included."""
    _action_rows(store, 800)
    first = await _page(store, "action_log", "", 400)
    assert first.complete is False and len(first.items) == 400
    last = await _page(store, "action_log", first.next_page_token, 400)
    assert len(last.items) == 400
    assert last.complete is True and last.next_page_token == ""


# --- position, not count -------------------------------------------------------


async def test_rows_stored_between_pages_do_not_shift_the_traversal(
    store: StateStore,
) -> None:
    _action_rows(store, 9, per_timestamp=1)

    def store_newer(_index: int) -> None:
        _conn(store).execute(
            "INSERT INTO action_log (action_name, tier, executed, action_taken, "
            "trigger_name, timestamp, device_id, correlation_id, record_kind, "
            "record_key) VALUES ('alert_sms', 'A', 1, 'alert_sms', 't', 5000, ?, "
            "'newer', 'dispatch', 'key-newer')",
            (DEVICE,),
        )
        _conn(store).commit()

    pages = await _traverse(
        store,
        "action_log",
        lambda item: item["correlation_id"],
        limit=3,
        between=lambda index: store_newer(index) if index == 0 else None,
    )
    assert [row for page in pages for row in page] == [
        f"row-{index}" for index in reversed(range(9))
    ]


async def test_equal_timestamps_are_ordered_by_stored_order_latest_first(
    store: StateStore,
) -> None:
    _action_rows(store, 6, per_timestamp=6)
    pages = await _traverse(
        store, "action_log", lambda item: item["correlation_id"], limit=4
    )
    assert pages == [
        ["row-5", "row-4", "row-3", "row-2"],
        ["row-1", "row-0"],
    ]


# --- tokens --------------------------------------------------------------------


async def _first_token(store: StateStore, **fields: Any) -> str:
    response = await _page(store, "action_log", "", 2, **fields)
    assert response.error is None and not response.complete
    return response.next_page_token


@pytest.mark.parametrize(
    "token",
    ["2", "0", 400, None.__class__.__name__, "p1.", "p1.!!", "p1." + "A" * 2000],
    ids=[
        "offset",
        "zero-offset",
        "integer",
        "text",
        "empty-body",
        "not-base64",
        "long",
    ],
)
async def test_a_token_this_runtime_did_not_issue_is_refused(
    store: StateStore, token: Any
) -> None:
    _action_rows(store, 5)
    response = await _page(store, "action_log", token, 2)
    assert response.error == PAGE_TOKEN_INVALID
    assert response.items == [] and response.complete is True


async def test_an_empty_token_begins_a_traversal(store: StateStore) -> None:
    _action_rows(store, 5)
    response = await _page(store, "action_log", "", 2)
    assert response.error is None and len(response.items) == 2


async def test_a_token_sent_with_another_window_is_refused(store: StateStore) -> None:
    _action_rows(store, 5)
    token = await _first_token(store, since_ms=0, until_ms=10**9)
    response = await _page(store, "action_log", token, 2, since_ms=1, until_ms=10**9)
    assert response.error == PAGE_TOKEN_INVALID


async def test_a_token_sent_with_other_params_is_refused(store: StateStore) -> None:
    _action_rows(store, 5)
    token = await _first_token(store)
    response = await _page(store, "action_log", token, 2, params={"tier": "A"})
    assert response.error == PAGE_TOKEN_INVALID


async def test_a_token_sent_for_another_export_is_refused(store: StateStore) -> None:
    _action_rows(store, 5)
    _reasoning_rows(store, 5)
    token = await _first_token(store)
    response = await _page(store, "reasoning_log", token, 2)
    assert response.error == PAGE_TOKEN_INVALID


async def test_another_devices_token_is_refused(store: StateStore) -> None:
    _action_rows(store, 5)
    foreign = issue(
        _responder(store)._page_key,
        "dev-02",
        filter_digest("action_log", None, None, {}),
        (1_001, 3),
    )
    response = await _page(store, "action_log", foreign, 2)
    assert response.error == PAGE_TOKEN_INVALID


async def test_a_token_naming_a_position_of_the_wrong_shape_is_refused(
    store: StateStore,
) -> None:
    _action_rows(store, 5)
    digest = filter_digest("action_log", None, None, {})
    for position in ((1_001,), (1_001, 3, 0), (True, 3)):
        token = issue(_responder(store)._page_key, DEVICE, digest, position)  # type: ignore[arg-type]
        response = await _page(store, "action_log", token, 2)
        assert response.error == PAGE_TOKEN_INVALID, position


async def test_a_page_a_limit_change_continues_from_the_same_position(
    store: StateStore,
) -> None:
    """The limit is not a filter: a token keeps its position at another size."""
    _action_rows(store, 9, per_timestamp=1)
    first = await _page(store, "action_log", "", 2)
    rest = await _page(store, "action_log", first.next_page_token, 10)
    assert rest.error is None
    assert [item["correlation_id"] for item in first.items + rest.items] == [
        f"row-{index}" for index in reversed(range(9))
    ]


_EXPORT_FIELDS: dict[str, dict[str, Any]] = {
    "action_log": {},
    "reasoning_log": {},
    "tier_c_decision_log": {},
    "sensor_history": {
        "since_ms": 0,
        "until_ms": 10**9,
        "params": {"sensor_id": SENSOR, "bucket_ms": 0},
    },
    "sensor_history bucketed": {
        "since_ms": 0,
        "until_ms": 10**9,
        "params": {"sensor_id": SENSOR, "bucket_ms": 1_000},
    },
}


@pytest.mark.parametrize("export", sorted(_EXPORT_FIELDS))
async def test_a_token_built_from_the_public_inputs_is_refused(
    store: StateStore, export: str
) -> None:
    """Every input but the key is public: a fabricated position never verifies."""
    _action_rows(store, 5)
    _reasoning_rows(store, 5)
    _tier_c_rows(store, 5)
    _raw_rows(store, 5)
    export_type = export.split()[0]
    fields = _EXPORT_FIELDS[export]
    digest = filter_digest(
        export_type,
        fields.get("since_ms"),
        fields.get("until_ms"),
        fields.get("params", {}),
    )
    arity = 5 if export == "sensor_history" else 2
    forged = issue(new_key(), DEVICE, digest, (0,) * arity)
    response = await _page(store, export_type, forged, 2, **fields)
    assert response.error == PAGE_TOKEN_INVALID
    assert response.items == []


async def test_a_token_whose_position_was_altered_is_refused(store: StateStore) -> None:
    _action_rows(store, 9, per_timestamp=1)
    token = await _first_token(store)
    body, mac = token[len("p1.") :].split(".")
    decoded = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    decoded[2] = [0, 0]
    altered = base64.urlsafe_b64encode(
        json.dumps(decoded, separators=(",", ":")).encode()
    ).decode()
    response = await _page(store, "action_log", f"p1.{altered.rstrip('=')}.{mac}", 2)
    assert response.error == PAGE_TOKEN_INVALID


async def test_another_spelling_of_an_issued_token_is_refused(
    store: StateStore,
) -> None:
    """Flipping a base64 MAC's unused trailing bits decodes to the same MAC."""
    _action_rows(store, 9, per_timestamp=1)
    token = await _first_token(store)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last = alphabet.index(token[-1])
    variant = token[:-1] + alphabet[last ^ 1]
    assert base64.urlsafe_b64decode(variant.split(".")[2] + "==") == (
        base64.urlsafe_b64decode(token.split(".")[2] + "==")
    )
    response = await _page(store, "action_log", variant, 2)
    assert response.error == PAGE_TOKEN_INVALID


async def test_a_null_token_is_refused(store: StateStore) -> None:
    """Only the empty token begins a traversal."""
    _action_rows(store, 5)
    response = await _page(store, "action_log", None, 2)
    assert response.error == PAGE_TOKEN_INVALID


async def test_a_token_from_before_a_restart_is_refused(store: StateStore) -> None:
    _action_rows(store, 9, per_timestamp=1)
    token = await _first_token(store)
    restarted = GatewayExportResponder(
        device_id=DEVICE, state_store=store, health_snapshot_provider=dict
    )
    response = await restarted.handle_request(
        {
            "request_id": "req-001",
            "export_type": "action_log",
            "device_id": DEVICE,
            "limit": 2,
            "page_token": token,
            "params": {},
        }
    )
    assert response is not None and response.error == PAGE_TOKEN_INVALID


# --- the corpus's orders, through the store ------------------------------------

_TIER_TABLE = {
    "5min": "sensor_history_basis_5min",
    "hourly": "sensor_history_basis_hourly",
    "daily": "sensor_history_basis_daily",
}


def _store_ascending(store: StateStore, row: dict[str, Any]) -> None:
    """One corpus row in the table its tier names, its value its stored order.

    Rows are stored in the corpus's stored order, so ids follow it, and the
    value identifies a returned row.
    """
    value = float(row["stored"])
    if row["tier"] == "raw":
        _conn(store).execute(
            "INSERT INTO sensor_history (sensor_id, sensor_type, value, unit, "
            "timestamp, quality, metadata, received_at_ms, producer_time) "
            "VALUES (?, 'current', ?, 'ampere', ?, 1.0, '{}', ?, ?)",
            (
                SENSOR,
                value,
                row["timestamp"],
                row["timestamp"] + 1,
                row["producer_time"],
            ),
        )
    else:
        _conn(store).execute(
            f"INSERT INTO {_TIER_TABLE[row['tier']]} (sensor_id, sensor_type, "
            "bucket_ms, avg_value, unit, sample_count, max_received_at_ms, "
            "producer_time) VALUES (?, 'current', ?, ?, 'ampere', 1, ?, ?)",
            (
                SENSOR,
                row["timestamp"],
                value,
                row["timestamp"] + 1,
                row["producer_time"],
            ),
        )
    _conn(store).commit()


def _remove_ascending(store: StateStore, row: dict[str, Any]) -> None:
    table = "sensor_history" if row["tier"] == "raw" else _TIER_TABLE[row["tier"]]
    column = "value" if row["tier"] == "raw" else "avg_value"
    _conn(store).execute(
        f"DELETE FROM {table} WHERE {column} = ?", (float(row["stored"]),)
    )
    _conn(store).commit()


ASCENDING = [case for case in CORPUS["paging"] if case["order"] == "ascending"]
BUCKETED = [case for case in CORPUS["paging"] if case["order"] == "bucketed"]


@pytest.mark.parametrize("case", ASCENDING, ids=lambda case: case["name"])
async def test_unbucketed_sensor_history_pages_each_ascending_corpus_case(
    store: StateStore, case: dict[str, Any]
) -> None:
    every = case["stored"] + [
        row for change in case["between_pages"] for row in change.get("store", [])
    ]
    by_value = {float(row["stored"]): row for row in every}
    assert len(by_value) == len(every), "each row needs its own stored order"
    for row in sorted(case["stored"], key=lambda row: row["stored"]):
        _store_ascending(store, row)

    def change(index: int) -> None:
        if index >= len(case["between_pages"]):
            return
        step = case["between_pages"][index]
        for gone in step.get("remove", []):
            _remove_ascending(store, next(row for row in every if row["id"] == gone))
        for row in step.get("store", []):
            _store_ascending(store, row)

    pages = await _traverse(
        store,
        "sensor_history",
        lambda item: by_value[item["value"]]["id"],
        limit=case["page_size"],
        between=change,
        since_ms=0,
        until_ms=10**15,
        params={"sensor_id": SENSOR, "bucket_ms": 0},
    )
    assert pages == case["expected_pages"]


def _store_bucket(store: StateStore, row: dict[str, Any]) -> None:
    """One raw reading forming the corpus's bucket row; its receipt keeps its basis."""
    _conn(store).execute(
        "INSERT INTO sensor_history (sensor_id, sensor_type, value, unit, timestamp, "
        "quality, metadata, received_at_ms, producer_time) "
        "VALUES (?, 'current', 1.0, 'ampere', ?, 1.0, ?, ?, ?)",
        (
            SENSOR,
            row["start_ms"],
            json.dumps({"id": row["id"]}),
            row["start_ms"] + 1,
            row["producer_time"],
        ),
    )
    _conn(store).commit()


@pytest.mark.parametrize("case", BUCKETED, ids=lambda case: case["name"])
async def test_bucketed_sensor_history_pages_each_bucketed_corpus_case(
    store: StateStore, case: dict[str, Any]
) -> None:
    every = case["stored"] + [
        row for change in case["between_pages"] for row in change.get("store", [])
    ]
    for row in case["stored"]:
        _store_bucket(store, row)
    live = {row["id"]: row for row in case["stored"]}

    def key(item: dict[str, Any]) -> str:
        named = [
            row
            for row in live.values()
            if (row["start_ms"], row["producer_time"])
            == (item["start_ms"], item["producer_time"])
        ]
        assert len(named) == 1, (item, named)
        return str(named[0]["id"])

    def change(index: int) -> None:
        if index >= len(case["between_pages"]):
            return
        step = case["between_pages"][index]
        for gone in step.get("remove", []):
            _conn(store).execute(
                "DELETE FROM sensor_history WHERE json_extract(metadata, '$.id') = ?",
                (gone,),
            )
            live.pop(gone)
        _conn(store).commit()
        for row in step.get("store", []):
            _store_bucket(store, row)
            live[row["id"]] = row

    widths = {row["start_ms"] for row in every}
    width = 3_600_000
    assert all(start % width == 0 for start in widths)
    pages = await _traverse(
        store,
        "sensor_history",
        key,
        limit=case["page_size"],
        between=change,
        since_ms=0,
        until_ms=10**15,
        params={"sensor_id": SENSOR, "bucket_ms": width},
    )
    assert pages == case["expected_pages"]
