# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""`safe_default_used` records that the safe default executed, never an attempt.

Every writer is driven through the entry point a caller reaches, with a safe
default that succeeds and one that fails, and the flag is read from the result,
the Tier C decision record and the action_log row.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import time
from typing import Any
from unittest.mock import patch

import pytest

from ori.network.events import OriEvent, ReasoningResult, SensorReading
from ori.reasoning import tier_c_admission as adm
from ori.reasoning.action_dispatcher import ActionDispatcher
from ori.reasoning.elevator import SkillContext
from ori.reasoning.tier_c_admission import TierCAuthorityFacts
from ori.security.evidence.first_party import FirstPartyEvidenceAttestor
from ori.state.store import StateStore
from ori.utils.time_utils import now_ms

DEVICE = "dev-01"
ZONE = "zone-feeder-a"
PROPOSAL = "P0000001"
SAFE_DEFAULT_ENDS = ["executed", "raised", "returned_false"]


def _safe_default(journal: list[str], end: str) -> Any:
    async def run(*_a: Any, **_k: Any) -> bool:
        journal.append("act:log_to_dashboard")
        if end == "raised":
            raise RuntimeError("channel down")
        return end == "executed"

    return run


def _reading_event(sensor_type: str, value: float) -> OriEvent:
    return OriEvent.from_reading(
        SensorReading(
            sensor_id="s1",
            sensor_type=sensor_type,
            value=value,
            unit="u",
            timestamp=int(time.time() * 1000),
            quality=1.0,
        ),
        DEVICE,
    )


def _result() -> ReasoningResult:
    return ReasoningResult(
        text="reasoned", tier="rule", model="m", tokens_used=0, latency_ms=0
    )


async def _rows(store: StateStore, action: str) -> tuple[list[dict], list[dict]]:
    decisions = await store.get_tier_c_decision_log()
    actions = [r for r in await store.get_action_log() if r["action_name"] == action]
    return decisions, actions


def _decided(decisions: list[dict]) -> list[tuple[str, bool, bool, str]]:
    return [
        (
            d["operator_decision"],
            d["safe_default_used"],
            d["action_executed"],
            d["action_taken"],
        )
        for d in decisions
    ]


# ── The host-state approval workflow ─────────────────────────────────────────


class _HostSkill:
    name = "host-guard"
    version = "1.0.0"
    first_party = True
    config: dict[str, Any] = {}
    triggers: list[Any] = [{"name": "t"}]
    actions: dict[str, Any] = {
        "available": [{"name": "terminate_process", "tier": "C"}],
        "defaults": {"t": ["terminate_process"]},
    }


async def _host(tmp_path: Any, end: str) -> tuple[ActionDispatcher, StateStore, list]:
    store = StateStore(str(tmp_path / "s.db"))
    await store.open()
    journal: list[str] = []
    dispatcher = ActionDispatcher(
        state_store=store, config={"operator_contact": "+2348000000000"}
    )

    async def terminate(*_a: Any, **_k: Any) -> bool:
        journal.append("act:terminate_process")
        return True

    dispatcher.register_executor("terminate_process", terminate)
    dispatcher.register_executor("log_to_dashboard", _safe_default(journal, end))
    return dispatcher, store, journal


async def _host_dispatch(dispatcher: ActionDispatcher, store: StateStore) -> Any:
    outcome = await dispatcher.dispatch(
        action="terminate_process",
        tier="C",
        context=SkillContext(
            skill=_HostSkill(),
            event=_reading_event("cpu_percent", 99.0),
            state_store=store,
            trigger_name="t",
        ),
        result=_result(),
        safe_default_action="log_to_dashboard",
        approval_timeout=1,
    )
    await dispatcher.drain_records(timeout=5)
    return outcome


class TestTheHostStateWorkflow:
    @pytest.mark.parametrize("reply", [f"NO-{PROPOSAL}", None, "MAYBE"])
    @pytest.mark.parametrize("end", SAFE_DEFAULT_ENDS)
    async def test_the_flag_is_whether_the_safe_default_executed(
        self, tmp_path: Any, reply: str | None, end: str
    ) -> None:
        dispatcher, store, journal = await _host(tmp_path, end)

        async def listen(**_k: Any) -> str | None:
            return reply

        try:
            with (
                patch.object(dispatcher, "_tier_c_comms_available", return_value=True),
                patch.object(dispatcher, "_listen_for_response", new=listen),
                patch(
                    "ori.reasoning.action_dispatcher._generate_proposal_id",
                    return_value=PROPOSAL,
                ),
            ):
                outcome = await _host_dispatch(dispatcher, store)
            decisions, actions = await _rows(store, "terminate_process")
        finally:
            await store.close()
        ran = end == "executed"
        assert journal == ["act:log_to_dashboard"]
        assert outcome.approved is False
        assert outcome.executed is ran
        assert outcome.safe_default_used is ran
        assert [d["safe_default_used"] for d in decisions] == [ran]
        assert [a["safe_default_used"] for a in actions] == [ran]

    @pytest.mark.parametrize("end", SAFE_DEFAULT_ENDS)
    async def test_a_workflow_that_fails_records_whether_its_safe_default_executed(
        self, tmp_path: Any, end: str
    ) -> None:
        dispatcher, store, journal = await _host(tmp_path, end)

        async def broken(*_a: Any, **_k: Any) -> Any:
            raise RuntimeError("workflow fault")

        try:
            with patch.object(dispatcher, "_run_approval_workflow", new=broken):
                outcome = await _host_dispatch(dispatcher, store)
            decisions, actions = await _rows(store, "terminate_process")
        finally:
            await store.close()
        ran = end == "executed"
        assert journal == ["act:log_to_dashboard"]
        assert outcome.operator_response == "approval_error"
        assert outcome.executed is ran
        assert outcome.safe_default_used is ran
        assert [a["safe_default_used"] for a in actions] == [ran]
        assert _decided(decisions) == [
            ("approval_error", ran, ran, outcome.action_taken)
        ]


# ── The governed workflow for a physical Tier C act ──────────────────────────


class _ZoneSkill:
    name = "protector"
    version = "1.0.0"
    first_party = True
    config: dict[str, Any] = {}
    triggers: list[Any] = []
    actions: dict[str, Any] = {
        "available": [{"name": "trip_relay", "tier": "C"}],
        "defaults": {"t": ["trip_relay"]},
    }
    sensors_required = [{"type": "current_clamp"}]


def _facts() -> TierCAuthorityFacts:
    return TierCAuthorityFacts(
        zone_id=ZONE,
        zone_document={
            "zone_id": ZONE,
            "kind": "local_gpio",
            "identity": {"gpio_pin": 26},
        },
        binding_digest="sha256:" + "b" * 64,
        safety_profile_digest="",
        resource_for={
            "open_protected_circuit": "relay-gpio-26",
            "close_protected_circuit": "relay-gpio-26",
        },
        deployment_inputs={"approval_timeout_seconds": 300, "relay_enabled": True},
    )


class _Operator:
    def __init__(self, reply: str | None) -> None:
        self.reply = reply
        self.proposals: list[str] = []
        self.notices: list[str] = []

    async def send(self, *, alert: Any, to_number: str) -> bool:
        if alert.intent.value == "tier_c_approval":
            self.proposals.append(str(alert.template_variables[3]))
        else:
            self.notices.append(alert.sms_body)
        return True

    async def listen_for_response(
        self, *, from_number: str, timeout_seconds: int
    ) -> str | None:
        while not self.proposals:
            await asyncio.sleep(0)
        if self.reply is None:
            await asyncio.sleep(timeout_seconds + 2)
            return None
        return f"{self.reply}-{self.proposals[-1]}"


def _governed(
    store: StateStore,
    journal: list[str],
    end: str,
    *,
    reply: str | None = "NO",
    facts: TierCAuthorityFacts | None = None,
    evidence_attestor: Any = None,
) -> ActionDispatcher:
    held = facts
    dispatcher = ActionDispatcher(
        state_store=store,
        alert_sender=_Operator(reply),
        evidence_attestor=evidence_attestor,
        config={"operator_contact": "+2348000000000", "relay_enabled": True},
        authority_facts=lambda zone_id=None: held,
    )

    async def trip(*_a: Any, **_k: Any) -> bool:
        journal.append("act:trip_relay")
        return True

    dispatcher.register_executor("trip_relay", trip)
    dispatcher.register_executor("log_to_dashboard", _safe_default(journal, end))
    return dispatcher


def _zone_context(store: StateStore) -> SkillContext:
    return SkillContext(
        skill=_ZoneSkill(),
        event=_reading_event("current_clamp", 9.0),
        state_store=store,
        trigger_name="t",
    )


async def _propose(
    dispatcher: ActionDispatcher, store: StateStore, timeout: int = 30
) -> Any:
    outcome = await dispatcher.dispatch(
        action="trip_relay",
        tier="C",
        context=_zone_context(store),
        result=_result(),
        approval_timeout=timeout,
    )
    await dispatcher.drain_records(timeout=5)
    pending = dispatcher.get_inflight_tier_d_tasks()
    if pending:
        await asyncio.wait(pending, timeout=5)
    return outcome


async def _open(tmp_path: Any) -> StateStore:
    store = StateStore(str(tmp_path / "s.db"))
    await store.open()
    return store


class TestGovernedRefusalsBeforeAProposal:
    @pytest.mark.parametrize("end", SAFE_DEFAULT_ENDS)
    async def test_an_uncommissioned_action(self, tmp_path: Any, end: str) -> None:
        store = await _open(tmp_path)
        journal: list[str] = []
        try:
            dispatcher = _governed(store, journal, end, facts=None)
            outcome = await _propose(dispatcher, store)
            decisions, actions = await _rows(store, "trip_relay")
        finally:
            await store.close()
        ran = end == "executed"
        assert outcome.action_taken == "refused_uncommissioned"
        assert _decided(decisions) == [
            ("refused_uncommissioned", ran, False, "refused_uncommissioned")
        ]
        assert journal == ["act:log_to_dashboard"]
        assert outcome.safe_default_used is ran
        assert [a["safe_default_used"] for a in actions] == [ran]

    @pytest.mark.parametrize("end", SAFE_DEFAULT_ENDS)
    async def test_incomplete_recovery(self, tmp_path: Any, end: str) -> None:
        store = await _open(tmp_path)
        journal: list[str] = []
        try:
            dispatcher = _governed(store, journal, end, facts=_facts())
            dispatcher.mark_tier_c_recovery_failed("store_unreadable")
            outcome = await _propose(dispatcher, store)
            decisions, actions = await _rows(store, "trip_relay")
        finally:
            await store.close()
        ran = end == "executed"
        assert outcome.action_taken == "refused_recovery_incomplete"
        assert _decided(decisions) == [
            ("refused_recovery_incomplete", ran, False, "refused_recovery_incomplete")
        ]
        assert "act:trip_relay" not in journal
        assert outcome.safe_default_used is ran
        assert [a["safe_default_used"] for a in actions] == [ran]

    @pytest.mark.parametrize("end", SAFE_DEFAULT_ENDS)
    async def test_relay_use_withheld(self, tmp_path: Any, end: str) -> None:
        # Dispatch refuses this by class first; the workflow refuses on its own.
        store = await _open(tmp_path)
        journal: list[str] = []
        try:
            dispatcher = _governed(store, journal, end, facts=_facts())
            with patch.object(dispatcher, "permits_relay_action", return_value=False):
                outcome = await dispatcher._governed_approval_workflow(  # type: ignore[attr-defined]
                    "trip_relay",
                    _zone_context(store),
                    _result(),
                    "log_to_dashboard",
                    30,
                    None,
                )
            await dispatcher.drain_records(timeout=5)
            decisions = await store.get_tier_c_decision_log()
        finally:
            await store.close()
        ran = end == "executed"
        assert outcome.action_taken == "refused_policy"
        assert journal == ["act:log_to_dashboard"]
        assert outcome.safe_default_used is ran
        assert _decided(decisions) == [("refused_policy", ran, False, "refused_policy")]


class TestNoProposalWasCreated:
    """No proposal row, so no intent, no decision-log record and no evidence."""

    async def _attestor(self, tmp_path: Any) -> FirstPartyEvidenceAttestor:
        attestor = FirstPartyEvidenceAttestor(
            db_path=str(tmp_path / "evidence.db"),
            key_path=str(tmp_path / "evidence.key"),
            device_secret="install-secret-for-safe-default-tests",
            device_id=DEVICE,
        )
        assert await attestor.start()
        return attestor

    def _sealed(self, tmp_path: Any, attestor: FirstPartyEvidenceAttestor) -> int:
        conn = sqlite3.connect(str(tmp_path / "evidence.db"))
        try:
            (count,) = conn.execute(
                "SELECT COUNT(*) FROM evidence_chain WHERE event_type = ?",
                (attestor.action_event_type,),
            ).fetchone()
        finally:
            conn.close()
        return int(count)

    async def _uncertain(self, store: StateStore) -> None:
        """An earlier approval of the same outcome on the same zone, unresolved."""
        assert (
            await store.create_tier_c_proposal(
                proposal_id="P1",
                device_id=DEVICE,
                action="trip_relay",
                target="relay-gpio-26",
                zone_id=ZONE,
                outcome="open_protected_circuit",
                safe_default_action="log_to_dashboard",
                binding_digest="sha256:" + "b" * 64,
                authority_json="{}",
                created_at_ms=now_ms(),
                expires_at_ms=now_ms() + 300_000,
            )
            == "committed"
        )
        assert (
            await store.admit_tier_c_approval(
                "P1",
                binding_digest="sha256:" + "b" * 64,
                authority_json="{}",
                reservation_ceiling=64,
            )
            == "committed"
        )
        await store.advance_tier_c_proposal(
            "P1", adm.DISPATCH_STARTED, from_states=(adm.APPROVED_PENDING_DISPATCH,)
        )
        await store.advance_tier_c_proposal(
            "P1", adm.DISPATCH_OUTCOME_UNKNOWN, from_states=(adm.DISPATCH_STARTED,)
        )

    @pytest.mark.parametrize("end", SAFE_DEFAULT_ENDS)
    async def test_a_proposal_row_the_store_could_not_commit(
        self, tmp_path: Any, end: str, caplog: Any
    ) -> None:
        store = await _open(tmp_path)
        attestor = await self._attestor(tmp_path)
        journal: list[str] = []

        async def refuse(**_k: Any) -> str:
            raise sqlite3.OperationalError("disk I/O error")

        store.create_tier_c_proposal = refuse  # type: ignore[method-assign]
        try:
            dispatcher = _governed(
                store, journal, end, facts=_facts(), evidence_attestor=attestor
            )
            with caplog.at_level(logging.CRITICAL):
                outcome = await _propose(dispatcher, store)
            decisions, actions = await _rows(store, "trip_relay")
            proposals = await store.get_tier_c_proposals()
            intents = await store.get_tier_c_safe_default_intents()
            sealed = self._sealed(tmp_path, attestor)
        finally:
            await store.close()
            attestor.close()
        operator = dispatcher._alert_sender  # type: ignore[attr-defined]
        assert outcome.action_taken == "proposal_not_committed"
        # Attempted, with no positive claim of its outcome in any record.
        assert journal == ["act:log_to_dashboard"]
        assert outcome.executed is False and outcome.safe_default_used is False
        assert [(a["executed"], a["safe_default_used"]) for a in actions] == [
            (False, False)
        ]
        assert proposals == [] and intents == []
        assert decisions == []
        assert sealed == 0
        assert any(
            r.levelno == logging.CRITICAL
            and "nothing is claimed durable" in r.getMessage()
            for r in caplog.records
        )
        assert operator.proposals == []
        assert any("proposal could not be recorded" in n for n in operator.notices)

    @pytest.mark.parametrize("held", ["durably", "live"])
    @pytest.mark.parametrize("end", SAFE_DEFAULT_ENDS)
    async def test_a_proposal_refused_for_an_unresolved_outcome(
        self, tmp_path: Any, end: str, held: str, caplog: Any
    ) -> None:
        store = await _open(tmp_path)
        attestor = await self._attestor(tmp_path)
        journal: list[str] = []
        try:
            if held == "durably":
                await self._uncertain(store)
            dispatcher = _governed(
                store, journal, end, facts=_facts(), evidence_attestor=attestor
            )
            with (
                patch.object(
                    dispatcher,
                    "tier_c_outcome_held_live",
                    return_value=held == "live",
                ),
                caplog.at_level(logging.CRITICAL),
            ):
                outcome = await _propose(dispatcher, store)
            decisions, actions = await _rows(store, "trip_relay")
            proposals = [
                (r["proposal_id"], r["decision_state"])
                for r in await store.get_tier_c_proposals()
            ]
            intents = await store.get_tier_c_safe_default_intents()
            sealed = self._sealed(tmp_path, attestor)
        finally:
            await store.close()
            attestor.close()
        ran = end == "executed"
        operator = dispatcher._alert_sender  # type: ignore[attr-defined]
        assert outcome.action_taken == "refused_outcome_uncertain"
        assert journal == ["act:log_to_dashboard"]
        assert proposals == (
            [("P1", adm.DISPATCH_OUTCOME_UNKNOWN)] if held == "durably" else []
        )
        assert intents == [] and decisions == []
        assert sealed == 0
        assert outcome.safe_default_used is ran
        assert [a["safe_default_used"] for a in actions] == [ran]
        assert any(
            r.levelno == logging.CRITICAL and "unresolved outcome" in r.getMessage()
            for r in caplog.records
        )
        assert operator.proposals == []
        assert any("an earlier outcome is unresolved" in n for n in operator.notices)


class TestGovernedRejectionAndExpiry:
    @pytest.mark.parametrize(
        ("reply", "timeout", "decision"),
        [("NO", 30, "rejected"), (None, 1, "timeout")],
    )
    @pytest.mark.parametrize("end", SAFE_DEFAULT_ENDS)
    async def test_the_flag_is_whether_the_safe_default_executed(
        self, tmp_path: Any, reply: str | None, timeout: int, decision: str, end: str
    ) -> None:
        store = await _open(tmp_path)
        journal: list[str] = []
        try:
            dispatcher = _governed(store, journal, end, reply=reply, facts=_facts())
            outcome = await _propose(dispatcher, store, timeout=timeout)
            decisions, actions = await _rows(store, "trip_relay")
            intents = await store.get_tier_c_safe_default_intents()
        finally:
            await store.close()
        ran = end == "executed"
        assert journal == ["act:log_to_dashboard"]
        assert outcome.approved is False and outcome.executed is ran
        assert outcome.safe_default_used is ran
        assert [d["operator_decision"] for d in decisions] == [decision]
        assert [d["safe_default_used"] for d in decisions] == [ran]
        assert [a["safe_default_used"] for a in actions] == [ran]
        assert [i["outcome"] for i in intents] == ["executed" if ran else "failed"]

    @pytest.mark.parametrize("attempted", ["executed", "failed"])
    async def test_an_intent_already_attempted_is_not_claimed_by_this_record(
        self, tmp_path: Any, attempted: str
    ) -> None:
        store = await _open(tmp_path)
        journal: list[str] = []

        async def already(proposal_id: str, *_a: Any, **_k: Any) -> str:
            return attempted

        store.ensure_tier_c_safe_default_intent = already  # type: ignore[method-assign]
        try:
            dispatcher = _governed(store, journal, "executed", facts=_facts())
            outcome = await _propose(dispatcher, store)
            decisions, actions = await _rows(store, "trip_relay")
        finally:
            await store.close()
        assert journal == []
        assert outcome.executed is False
        assert outcome.safe_default_used is False
        assert [d["safe_default_used"] for d in decisions] == [False]
        assert [a["safe_default_used"] for a in actions] == [False]


class _RefusingGate:
    async def reply_admitted(self, _token: Any) -> bool:
        return False


class TestGovernedAfterApproval:
    async def _admitted(self, store: StateStore) -> None:
        assert (
            await store.create_tier_c_proposal(
                proposal_id="P9",
                device_id=DEVICE,
                action="trip_relay",
                target="relay-gpio-26",
                zone_id=ZONE,
                outcome="open_protected_circuit",
                safe_default_action="log_to_dashboard",
                binding_digest="sha256:" + "b" * 64,
                authority_json="{}",
                created_at_ms=now_ms(),
                expires_at_ms=now_ms() + 300_000,
            )
            == "committed"
        )
        assert (
            await store.admit_tier_c_approval(
                "P9",
                binding_digest="sha256:" + "b" * 64,
                authority_json="{}",
                reservation_ceiling=64,
            )
            == "committed"
        )

    @pytest.mark.parametrize("why", ["contention", "expired"])
    @pytest.mark.parametrize("end", SAFE_DEFAULT_ENDS)
    async def test_an_approval_not_carried_out(
        self, tmp_path: Any, why: str, end: str
    ) -> None:
        store = await _open(tmp_path)
        journal: list[str] = []
        try:
            await self._admitted(store)
            dispatcher = _governed(store, journal, end, facts=_facts())
            dispatcher._resource_gate = _RefusingGate()  # type: ignore[assignment]
            loop_now = asyncio.get_running_loop().time()
            outcome = await dispatcher._dispatch_admitted(  # type: ignore[attr-defined]
                "trip_relay",
                _zone_context(store),
                store,
                {
                    "proposal_id": "P9",
                    "device_id": DEVICE,
                    "safe_default_action": "log_to_dashboard",
                },
                object(),
                loop_now - 1 if why == "expired" else loop_now + 30,
                "YES-P9",
            )
            intents = await store.get_tier_c_safe_default_intents("P9")
        finally:
            await store.close()
        ran = end == "executed"
        assert journal == ["act:log_to_dashboard"]
        assert outcome.approved is True and outcome.executed is False
        assert outcome.action_taken == (
            "approval_expired_undispatched"
            if why == "expired"
            else "dispatch_refused_contention"
        )
        assert outcome.safe_default_used is ran
        assert [i["outcome"] for i in intents] == ["executed" if ran else "failed"]

    async def test_an_approval_that_outlives_its_window_in_the_commit(
        self, tmp_path: Any
    ) -> None:
        store = await _open(tmp_path)
        journal: list[str] = []
        admit = store.admit_tier_c_approval

        async def slow(*a: Any, **k: Any) -> str:
            await asyncio.sleep(1.3)
            return await admit(*a, **k)

        store.admit_tier_c_approval = slow  # type: ignore[method-assign]
        try:
            dispatcher = _governed(
                store, journal, "raised", reply="YES", facts=_facts()
            )
            outcome = await _propose(dispatcher, store, timeout=1)
            decisions, actions = await _rows(store, "trip_relay")
        finally:
            await store.close()
        assert outcome.action_taken == "approval_expired_undispatched"
        assert journal == ["act:log_to_dashboard"]
        assert outcome.safe_default_used is False
        assert [d["safe_default_used"] for d in decisions] == [False]
        assert [a["safe_default_used"] for a in actions] == [False]


class TestAResumedIntent:
    @pytest.mark.parametrize("end", SAFE_DEFAULT_ENDS)
    async def test_the_intent_ends_as_the_executor_did(
        self, tmp_path: Any, end: str
    ) -> None:
        store = await _open(tmp_path)
        journal: list[str] = []
        try:
            assert (
                await store.create_tier_c_proposal(
                    proposal_id="P1",
                    device_id=DEVICE,
                    action="trip_relay",
                    target="relay-gpio-26",
                    zone_id=ZONE,
                    outcome="open_protected_circuit",
                    safe_default_action="log_to_dashboard",
                    binding_digest="sha256:" + "b" * 64,
                    authority_json="{}",
                    created_at_ms=now_ms(),
                    expires_at_ms=now_ms() + 300_000,
                )
                == "committed"
            )
            # A rejection recorded with its intent pending, and never attempted.
            assert await store.advance_tier_c_proposal(
                "P1",
                adm.REJECTED,
                from_states=(adm.PROPOSED,),
                safe_default_action="log_to_dashboard",
            )
            pending = await store.get_tier_c_safe_default_intents("P1")
            assert [i["outcome"] for i in pending] == ["pending"]
            dispatcher = _governed(store, journal, end, facts=_facts())
            counts = await dispatcher.recover_tier_c_at_start(store)
            intents = await store.get_tier_c_safe_default_intents("P1")
        finally:
            await store.close()
        assert journal == ["act:log_to_dashboard"]
        assert counts["safe_defaults_resumed"] == 1
        assert [i["outcome"] for i in intents] == [
            "executed" if end == "executed" else "failed"
        ]
