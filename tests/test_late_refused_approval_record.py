# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A Tier C decision records a safe default only where one was dispatched."""

from __future__ import annotations

import asyncio
import sqlite3
import time
from typing import Any
from unittest.mock import patch

import pytest

from ori.network.events import OriEvent, ReasoningResult, SensorReading
from ori.reasoning.action_dispatcher import ActionDispatcher
from ori.reasoning.dispatch_plan import resource_identity
from ori.reasoning.elevator import SkillContext
from ori.reasoning.resource_gate import Contributor, ResourceGate
from ori.state.store import StateStore

PROPOSAL = "P0000001"
TARGET = "pid:4242"


class _HostSkill:
    name = "host-guard"
    version = "1.0.0"
    first_party = True
    config: dict[str, Any] = {}
    triggers: list[Any] = [{"name": "t", "requires_approval": True}]

    def __init__(self, tier: str) -> None:
        self.actions: dict[str, Any] = {
            "available": [{"name": "terminate_process", "tier": tier}],
            "defaults": {"t": ["terminate_process"]},
        }


def _event() -> OriEvent:
    return OriEvent.from_reading(
        SensorReading(
            sensor_id="cpu",
            sensor_type="cpu_percent",
            value=99.0,
            unit="percent",
            timestamp=int(time.time() * 1000),
            quality=1.0,
        ),
        "dev-01",
    )


class _Harness:
    def __init__(self, store: StateStore) -> None:
        self.store = store
        self.gate = ResourceGate()
        self.ran: list[str] = []
        self.dispatcher = ActionDispatcher(
            state_store=store, config={"operator_contact": "+2348000000000"}
        )
        self.dispatcher.bind_resource_gate(self.gate)

        async def terminate(*_a: Any, **_k: Any) -> bool:
            self.ran.append("terminate_process")
            return True

        async def log_default(*_a: Any, **_k: Any) -> bool:
            self.ran.append("log_to_dashboard")
            return True

        self.dispatcher.register_executor("terminate_process", terminate)
        self.dispatcher.register_executor("log_to_dashboard", log_default)
        self.dispatcher.register_resource_resolver(
            "terminate_process", lambda _context: {"target": TARGET}
        )

    async def displace(self) -> None:
        """What a Tier D arrival does to the proposal's resource at the gate."""
        identity = resource_identity("terminate_process", target=TARGET)
        assert identity is not None
        await self.gate.request(
            identity,
            "D",
            Contributor(
                skill_name="core",
                trigger_name="safety",
                action="terminate_process",
                dispatch_tier="D",
                tier_d_granted=True,
            ),
        )

    async def run(self, listen: Any, *, timeout: int = 5, tier: str = "C") -> Any:
        with (
            patch.object(self.dispatcher, "_tier_c_comms_available", return_value=True),
            patch.object(self.dispatcher, "_listen_for_response", new=listen),
            patch(
                "ori.reasoning.action_dispatcher._generate_proposal_id",
                return_value=PROPOSAL,
            ),
        ):
            outcome = await self.dispatcher.dispatch(
                action="terminate_process",
                tier=tier,
                context=SkillContext(
                    skill=_HostSkill(tier),
                    event=_event(),
                    state_store=self.store,
                    trigger_name="t",
                ),
                result=ReasoningResult(
                    text="cpu pinned",
                    tier="rule",
                    model="m",
                    tokens_used=0,
                    latency_ms=0,
                ),
                safe_default_action="log_to_dashboard",
                approval_timeout=timeout,
            )
        await self.dispatcher.drain_records(timeout=5)
        return outcome

    async def decision_rows(self) -> list[dict]:
        return await self.store.get_tier_c_decision_log()

    async def action_rows(self) -> list[dict]:
        return [
            row
            for row in await self.store.get_action_log()
            if row["action_name"] == "terminate_process"
        ]


async def _harness(tmp_path: Any) -> _Harness:
    store = StateStore(str(tmp_path / "s.db"))
    await store.open()
    return _Harness(store)


class TestALateRefusalUsesNoSafeDefault:
    @pytest.mark.parametrize("tier", ["C", "B"])
    async def test_a_displaced_approval_records_no_safe_default(self, tmp_path, tier):
        h = await _harness(tmp_path)

        async def listen(**_k: Any) -> str:
            await h.displace()
            return f"YES-{PROPOSAL}"

        try:
            outcome = await h.run(listen, tier=tier)
            decisions = await h.decision_rows()
            actions = await h.action_rows()
        finally:
            await h.store.close()
        assert outcome.tier == tier
        assert outcome.action_taken == "refused_late_approval"
        assert outcome.executed is False
        assert outcome.safe_default_used is False
        assert h.ran == []
        assert len(decisions) == 1
        assert decisions[0]["safe_default_used"] is False
        assert decisions[0]["action_executed"] is False
        assert decisions[0]["action_taken"] == "refused_late_approval"
        assert [row["safe_default_used"] for row in actions] == [False]

    async def test_a_no_records_the_safe_default(self, tmp_path):
        h = await _harness(tmp_path)

        async def listen(**_k: Any) -> str:
            return f"NO-{PROPOSAL}"

        try:
            outcome = await h.run(listen)
            decisions = await h.decision_rows()
            actions = await h.action_rows()
        finally:
            await h.store.close()
        assert outcome.safe_default_used is True
        assert h.ran == ["log_to_dashboard"]
        assert [row["safe_default_used"] for row in decisions] == [True]
        assert [row["safe_default_used"] for row in actions] == [True]

    async def test_no_reply_records_the_safe_default(self, tmp_path):
        h = await _harness(tmp_path)

        async def listen(**_k: Any) -> None:
            return None

        try:
            outcome = await h.run(listen)
            decisions = await h.decision_rows()
        finally:
            await h.store.close()
        assert outcome.safe_default_used is True
        assert h.ran == ["log_to_dashboard"]
        assert [row["safe_default_used"] for row in decisions] == [True]

    async def test_a_displaced_proposal_whose_reply_misses_the_deadline(self, tmp_path):
        # The YES lands after the window closed: the proposal times out and its
        # safe default runs, so that is what the record says.
        h = await _harness(tmp_path)

        async def listen(**_k: Any) -> str:
            await h.displace()
            await asyncio.sleep(2.5)
            return f"YES-{PROPOSAL}"

        try:
            outcome = await h.run(listen, timeout=1)
            decisions = await h.decision_rows()
        finally:
            await h.store.close()
        assert outcome.approved is False
        assert outcome.safe_default_used is True
        assert h.ran == ["log_to_dashboard"]
        assert [row["safe_default_used"] for row in decisions] == [True]
        assert [row["operator_decision"] for row in decisions] == ["timeout"]

    async def test_a_refused_approval_is_not_turned_into_a_safe_default_by_a_busy_store(
        self, tmp_path
    ):
        h = await _harness(tmp_path)
        real = h.store.log_tier_c_decision
        attempts: list[bool] = []

        async def busy_once(**kwargs: Any) -> None:
            attempts.append(bool(kwargs["safe_default_used"]))
            if len(attempts) == 1:
                raise sqlite3.OperationalError("database is locked")
            await real(**kwargs)

        async def listen(**_k: Any) -> str:
            await h.displace()
            return f"YES-{PROPOSAL}"

        try:
            with patch.object(h.store, "log_tier_c_decision", new=busy_once):
                outcome = await h.run(listen)
            decisions = await h.decision_rows()
        finally:
            await h.store.close()
        assert outcome.safe_default_used is False
        assert h.ran == []
        assert len(attempts) >= 2 and not any(attempts)
        assert [row["safe_default_used"] for row in decisions] == [False]

    async def test_a_store_that_refuses_the_decision_leaves_the_result_true_to_the_act(
        self, tmp_path
    ):
        h = await _harness(tmp_path)

        async def refused(**_k: Any) -> None:
            raise sqlite3.IntegrityError("refused")

        async def listen(**_k: Any) -> str:
            await h.displace()
            return f"YES-{PROPOSAL}"

        try:
            with patch.object(h.store, "log_tier_c_decision", new=refused):
                outcome = await h.run(listen)
            decisions = await h.decision_rows()
        finally:
            await h.store.close()
        assert outcome.safe_default_used is False
        assert outcome.action_taken == "refused_late_approval"
        assert h.ran == []
        assert decisions == []
