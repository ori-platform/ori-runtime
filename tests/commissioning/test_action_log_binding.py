# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Every logged physical actuation records the binding in force."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from ori.network.events import ActionResult
from ori.reasoning.action_dispatcher import ActionDispatcher
from ori.state.store import StateStore
from ori.utils.time_utils import now_ms


@pytest.fixture
async def store(tmp_path: Path):
    s = StateStore(db_path=str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


def _result(action: str, tier: str) -> ActionResult:
    return ActionResult(
        action_name=action,
        tier=tier,
        executed=True,
        approved=None,
        action_taken=action,
        timestamp=now_ms(),
    )


async def _rows(store: StateStore) -> list[tuple[str, int | None]]:
    def query(conn: sqlite3.Connection) -> list[Any]:
        return conn.execute(
            "SELECT action_name, binding_seq FROM action_log ORDER BY id"
        ).fetchall()

    return [(str(r[0]), r[1]) for r in await store._run_read(query)]


async def test_physical_actions_carry_the_binding_seq_and_informational_ones_do_not(
    store: StateStore,
) -> None:
    seq = {"value": 4}
    dispatcher = ActionDispatcher(
        state_store=store, binding_seq_in_force=lambda: seq["value"]
    )
    context = cast(Any, SimpleNamespace(state_store=store, event=None))
    await dispatcher._log_action(_result("trip_relay", "D"), context)
    await dispatcher._log_action(_result("alert_sms", "A"), context)
    # A revision between two actions attributes each to its own arrangement.
    seq["value"] = 5
    await dispatcher._log_action(_result("release_relay", "C"), context)
    assert await _rows(store) == [
        ("trip_relay", 4),
        ("alert_sms", None),
        ("release_relay", 5),
    ]


async def test_no_binding_in_force_logs_null_not_a_default(store: StateStore) -> None:
    dispatcher = ActionDispatcher(state_store=store, binding_seq_in_force=lambda: None)
    context = cast(Any, SimpleNamespace(state_store=store, event=None))
    await dispatcher._log_action(_result("trip_relay", "D"), context)
    assert await _rows(store) == [("trip_relay", None)]


async def test_a_failing_lookup_still_logs_the_action(store: StateStore) -> None:
    def broken() -> int | None:
        raise RuntimeError("lookup exploded")

    dispatcher = ActionDispatcher(state_store=store, binding_seq_in_force=broken)
    context = cast(Any, SimpleNamespace(state_store=store, event=None))
    await dispatcher._log_action(_result("trip_relay", "D"), context)
    assert await _rows(store) == [("trip_relay", None)]
