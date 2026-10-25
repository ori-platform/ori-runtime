# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Every action-log row the runtime writes is named, and the export holds A to D."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from ori.network.events import ActionResult
from ori.reasoning.action_dispatcher import ActionDispatcher
from ori.reasoning.resource_gate import ResourceGate
from ori.state.store import StateStore
from tests.test_tier_d_never_waits_on_evidence import (
    BOUND,
    _context,
    _reasoning,
    _Skill,
)
from tests.waiting import drained


async def _rig(tmp_path: Path, *, relay_enabled: bool) -> tuple[StateStore, Any]:
    store = StateStore(str(tmp_path / "state.db"))
    await store.open()
    dispatcher = ActionDispatcher(
        state_store=store,
        config={"relay_enabled": relay_enabled, "operator_contact": "+2348000000000"},
    )
    dispatcher.bind_resource_gate(ResourceGate(), BOUND)

    async def trip(*_args: Any, **_kwargs: Any) -> bool:
        return True

    dispatcher.register_executor("trip_relay", trip)
    return store, dispatcher


def _rows(store: StateStore) -> list[dict[str, Any]]:
    assert store._conn is not None
    store._conn.row_factory = sqlite3.Row
    return [
        dict(r)
        for r in store._conn.execute(
            "SELECT action_taken, tier, record_kind, record_key FROM action_log"
            " ORDER BY id"
        )
    ]


_REFUSALS = [
    # (entry, tier, first party, relay enabled, the refusal's action_taken).
    # The executor's own gates refuse what dispatch would have raised or
    # refused earlier, so they are driven where they stand.
    ("dispatch", "Z", True, True, "refused_unknown_tier"),
    ("dispatch", "C", True, False, "suppressed"),
    ("execute", "D", False, True, "refused_tier_d_without_provenance"),
    ("execute", "A", True, True, "refused_below_minimum_tier"),
]


@pytest.mark.parametrize(
    ("entry", "tier", "first_party", "relay_enabled", "taken"),
    _REFUSALS,
    ids=[case[-1] for case in _REFUSALS],
)
async def test_every_refusal_row_carries_its_own_record_key(
    tmp_path: Path,
    entry: str,
    tier: str,
    first_party: bool,
    relay_enabled: bool,
    taken: str,
) -> None:
    store, dispatcher = await _rig(tmp_path, relay_enabled=relay_enabled)
    try:
        skill = _Skill("protector", tier, ["trip_relay"])
        skill.first_party = first_party
        for _ in range(2):
            if entry == "dispatch":
                await dispatcher.dispatch(
                    action="trip_relay",
                    tier=tier,
                    context=_context(store, skill),
                    result=_reasoning(),
                )
            else:
                await dispatcher._execute_immediately(
                    "trip_relay", tier, _context(store, skill)
                )
        await drained(dispatcher)
        rows = _rows(store)
    finally:
        await store.close()
    refusals = [row for row in rows if row["action_taken"] == taken]
    assert len(refusals) == 2, rows
    keys = [row["record_key"] for row in rows]
    assert all(isinstance(key, str) and key for key in keys), rows
    assert len(set(keys)) == len(keys), rows


@pytest.mark.parametrize("key", ["", None, 7])
async def test_the_writer_refuses_a_row_with_no_record_key(
    tmp_path: Path, key: Any
) -> None:
    store = StateStore(str(tmp_path / "state.db"))
    await store.open()
    result = ActionResult(
        action_name="log_to_dashboard",
        tier="A",
        executed=True,
        approved=None,
        action_taken="log_to_dashboard",
        timestamp=1,
    )
    try:
        with pytest.raises(ValueError, match="record_key"):
            await store.log_action(result, "t", record_key=key)
        with pytest.raises(ValueError, match="record_key"):
            await store.log_action_for_event(result, trigger_name="t", record_key=key)
        assert _rows(store) == []
    finally:
        await store.close()


async def test_the_export_omits_only_unknown_tier_refusals(tmp_path: Path) -> None:
    """gateway-api/v2: a refusal of an unknown tier is omitted; any other row
    outside A to D exports as A, and the store keeps what was recorded."""
    store = StateStore(str(tmp_path / "state.db"))
    await store.open()
    rows = [
        ("A", "", False),
        ("Z", "refused_unknown_tier", False),  # a refusal: omitted
        ("d", "", False),
        ("D", "", False),
        ("", "", False),
    ]
    try:
        for index, (tier, taken, executed) in enumerate(rows):
            await store.log_action(
                ActionResult(
                    action_name="log_to_dashboard",
                    tier=tier,
                    executed=executed,
                    approved=None,
                    action_taken=taken,
                    timestamp=index + 1,
                ),
                "t",
                record_key=f"key-{index}",
            )
        # An act an earlier release ran under an unknown tier, under the name
        # a refusal now carries: only such a release could write it.
        assert store._conn is not None
        store._conn.execute(
            "INSERT INTO action_log (action_name, tier, executed, action_taken, "
            "trigger_name, timestamp, record_key) VALUES "
            "('log_to_dashboard', 'Z', 1, 'refused_unknown_tier', 't', 6, 'key-5')"
        )
        store._conn.commit()
        exported = await store.export_action_log(limit=100)
        filtered = await store.export_action_log(tier="z", limit=100)
        kept = await store.get_action_log(limit=100)
    finally:
        await store.close()
    assert sorted(row["record_key"] for row in exported) == [
        "key-0",
        "key-2",
        "key-3",
        "key-4",
        "key-5",
    ]
    assert sorted(row["tier"] for row in exported) == ["A", "A", "A", "A", "D"]
    assert filtered == []
    assert sorted(row["tier"] for row in kept) == ["", "A", "D", "Z", "Z", "d"]


async def test_a_row_from_before_keys_exports_its_key_as_null(tmp_path: Path) -> None:
    store = StateStore(str(tmp_path / "state.db"))
    await store.open()
    try:
        await store.log_action(
            ActionResult(
                action_name="log_to_dashboard",
                tier="A",
                executed=True,
                approved=None,
                action_taken="log_to_dashboard",
                timestamp=1,
            ),
            "t",
            record_key="named",
        )
        assert store._conn is not None
        # What the migration's default leaves on a row written before keys.
        store._conn.execute("UPDATE action_log SET record_key = ''")
        store._conn.commit()
        exported = await store.export_action_log(limit=10)
    finally:
        await store.close()
    assert [row["record_key"] for row in exported] == [None]
