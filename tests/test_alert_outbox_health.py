# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""runtime-health/v4's `alert_outbox` block, read through a real store.

A notice counts by the kind fixed when it was queued: a Tier A notice from a
notify-only Tier D trigger is a Tier D notification, and a safety notice is a
protection-degraded one. The aggregate vectors cannot prove that.
"""

import json
import types
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from ori.actions.alert_delivery import AlertSendReceipt
from ori.runtime import OriRuntime
from ori.runtime._alert_outbox_health import (
    ALERT_OUTBOX_CONDITIONS,
    alert_outbox_conditions,
)
from ori.runtime._alert_text import resolve_notice_kind
from ori.state.store import StateStore

VECTORS = json.loads(
    (
        Path(__file__).resolve().parent
        / "vectors"
        / "runtime_health"
        / "health-vectors-v4.json"
    ).read_text()
)
ALERT_TOKENS = {
    "tier_d_alert_delivery_unconfirmed",
    "protection_degraded_alert_delivery_unconfirmed",
    "alert_delivery_overdue",
}


async def _runtime(tmp_path: Path) -> OriRuntime:
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._device_id = "dev-01"
    runtime._state_store = StateStore(str(tmp_path / "outbox.db"))
    await runtime._state_store.open()
    runtime._operator_contact = "+2340000000000"
    return runtime


async def test_each_mandatory_notice_counts_by_its_queued_kind(tmp_path: Path) -> None:
    runtime = await _runtime(tmp_path)
    store = runtime._state_store
    assert store is not None
    refused = AsyncMock()
    refused.send.return_value = AlertSendReceipt.refused(channel="sms")
    notify_only = types.SimpleNamespace(
        skill=types.SimpleNamespace(
            name="energy-anomaly-detector",
            first_party=True,
            triggers=[{"name": "dangerous_overcurrent", "action_tier": "D"}],
        ),
        trigger_name="dangerous_overcurrent",
        event=None,
    )
    try:
        await runtime._send_or_queue_alert(
            channel="sms",
            message="overcurrent",
            recipient="+2340000000000",
            action_tier="A",
            trigger_name="dangerous_overcurrent",
            original_ts=1,
            received_at_ms=1,
            alert_sender=refused,
            skill_name="energy-anomaly-detector",
            skill_is_first_party=True,
            notice_kind=resolve_notice_kind(notify_only),  # type: ignore[arg-type]
        )
        await runtime._send_or_queue_safety_alert(
            message="SAFETY x", trigger_name="safety_absent", alert_sender=refused
        )

        block = (await runtime._build_health_snapshot())["alert_outbox"]

        assert block["state"] == "available"
        assert block["tier_d_unresolved_count"] == 1
        assert block["protection_degraded_unresolved_count"] == 1
        assert block["backlog_count"] == 2
        assert block["oldest_non_tier_d_age_ms"] is not None

        assert store._conn is not None
        ids = [r[0] for r in store._conn.execute("SELECT alert_id FROM alert_outbox")]
        attempts = {
            i: store._conn.execute(
                "SELECT attempt_count FROM alert_outbox WHERE alert_id = ?", (i,)
            ).fetchone()[0]
            for i in ids
        }
        for alert_id, made in attempts.items():
            for _ in range(block["tier_d_critical_warning_threshold"] - made):
                await store.mark_alert_attempt_failed(alert_id, 2000)
        snapshot = await runtime._build_health_snapshot()

        assert set(alert_outbox_conditions(snapshot["alert_outbox"])) == {
            "tier_d_alert_delivery_unconfirmed",
            "protection_degraded_alert_delivery_unconfirmed",
        }
        assert snapshot["status"] == "critical"
    finally:
        await store.close()


async def test_an_unreadable_outbox_is_unavailable_and_critical(
    tmp_path: Path,
) -> None:
    runtime = await _runtime(tmp_path)
    store = runtime._state_store
    assert store is not None
    await store.close()

    async def _fails() -> Any:
        raise RuntimeError("closed")

    store.get_alert_outbox_summary = _fails  # type: ignore[method-assign]
    snapshot = await runtime._build_health_snapshot()

    assert snapshot["alert_outbox"]["state"] == "unavailable"
    assert "tier_d_unresolved_count" not in snapshot["alert_outbox"]
    assert snapshot["status"] == "critical"


@pytest.mark.parametrize(
    "case",
    [c for c in VECTORS["snapshot_cases"] if "alert_outbox" in c["snapshot"]],
    ids=lambda c: c["name"],
)
def test_the_block_holds_runtime_health_v4s_alert_conditions(
    case: dict[str, Any],
) -> None:
    held = set(alert_outbox_conditions(case["snapshot"]["alert_outbox"]))
    assert held & ALERT_TOKENS == set(case["expected"]["degradation_reasons"]) & (
        ALERT_TOKENS
    )


def test_each_condition_has_runtime_health_v4s_severity() -> None:
    for name, severity in ALERT_OUTBOX_CONDITIONS.items():
        assert VECTORS["conditions"][name] == severity


@pytest.mark.parametrize(
    "case",
    [
        c
        for c in VECTORS["snapshot_cases"]
        if c["snapshot"].get("alert_outbox", {}).get("state")
        in ("starting", "unavailable")
    ],
    ids=lambda c: c["name"],
)
def test_a_block_not_available_holds_its_subsystem_condition(
    case: dict[str, Any],
) -> None:
    held = alert_outbox_conditions(case["snapshot"]["alert_outbox"])
    assert held and set(held) <= set(case["expected"]["degradation_reasons"])


@pytest.mark.parametrize(
    ("elapsed_s", "state", "status"),
    [(299.0, "starting", "degraded"), (300.0, "unavailable", "critical")],
)
async def test_an_unopened_store_is_starting_until_the_startup_deadline(
    monkeypatch: pytest.MonkeyPatch, elapsed_s: float, state: str, status: str
) -> None:
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._device_id = "dev-01"
    started = runtime._process_started_monotonic
    monkeypatch.setattr(
        "ori.runtime._health.time.monotonic", lambda: started + elapsed_s
    )

    snapshot = await runtime._build_health_snapshot()

    assert snapshot["alert_outbox"]["state"] == state
    assert "backlog_count" not in snapshot["alert_outbox"]
    assert snapshot["status"] == status
