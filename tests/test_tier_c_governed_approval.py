# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""A physical Tier C act is admitted under tier-c-approval/v1.

Every test runs the real dispatcher against a real SQLite store with the
commissioned facts a zone provides. The proposal row exists before the
operator is asked; a reply is an approval only once its commit answers;
nothing is written between that commit and the executor; the outcome is
appended afterwards; and a restart replays nothing.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from typing import Any

import pytest

from ori.network.events import OriEvent, ReasoningResult, SensorReading
from ori.reasoning import tier_c_admission as adm
from ori.reasoning.action_dispatcher import (
    ACTUATION_NOT_PERFORMED,
    ActionDispatcher,
)
from ori.reasoning.elevator import SkillContext
from ori.reasoning.tier_c_admission import TierCAuthorityFacts
from ori.state.store import StateStore
from ori.utils.time_utils import now_ms

DEVICE = "energy-monitor-ikeja-01"
ZONE = "zone-feeder-a"
_WRITES = (
    "create_tier_c_proposal",
    "admit_tier_c_approval",
    "advance_tier_c_proposal",
    "log_action_for_event",
    "log_tier_c_decision",
    "log_override",
    "store_rejection",
    "log_offline_token_attempt",
    "set_action_attestation",
    "create_tier_c_safe_default_intent",
    "mark_tier_c_safe_default_intent",
)


class _Skill:
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


def _event() -> OriEvent:
    reading = SensorReading(
        sensor_id="load-current",
        sensor_type="current_clamp",
        value=9.0,
        unit="ampere",
        timestamp=now_ms(),
        quality=1.0,
    )
    return OriEvent.from_reading(reading, DEVICE)


def _facts(binding: str = "sha256:" + "b" * 64) -> TierCAuthorityFacts:
    return TierCAuthorityFacts(
        zone_id=ZONE,
        zone_document={
            "zone_id": ZONE,
            "kind": "local_gpio",
            "identity": {"gpio_pin": 26},
        },
        binding_digest=binding,
        safety_profile_digest="",
        resource_for={
            "open_protected_circuit": "relay-gpio-26",
            "close_protected_circuit": "relay-gpio-26",
        },
        deployment_inputs={"approval_timeout_seconds": 300, "relay_enabled": True},
    )


def _recording_store(path: str, journal: list[str], **delays: float) -> StateStore:
    """A real store that notes each write as it begins and the commit as it ends."""

    class Recording(StateStore):
        pass

    for name in _WRITES:
        original = getattr(StateStore, name)

        def wrap(original: Any = original, name: str = name) -> Any:
            async def call(self: StateStore, *args: Any, **kwargs: Any) -> Any:
                journal.append(f"write:{name}")
                if delays.get(name):
                    await asyncio.sleep(delays[name])
                answer = await original(self, *args, **kwargs)
                if name == "admit_tier_c_approval":
                    journal.append(f"admitted:{answer}")
                return answer

            return call

        setattr(Recording, name, wrap())
    return Recording(path)


class _Operator:
    """Sends the approval request and answers it, after *delay_s*."""

    def __init__(self, reply: str | None = "YES", delay_s: float = 0.0) -> None:
        self.reply = reply
        self.delay_s = delay_s
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
        await asyncio.sleep(self.delay_s)
        if self.reply is None:
            await asyncio.sleep(timeout_seconds + 2)
            return None
        return f"{self.reply}-{self.proposals[-1]}"


def _dispatcher(
    store: Any,
    operator: Any,
    journal: list[str],
    *,
    facts: TierCAuthorityFacts | None = None,
    executor: Any = None,
) -> ActionDispatcher:
    holder = {"facts": facts if facts is not None else _facts()}
    dispatcher = ActionDispatcher(
        state_store=store,
        alert_sender=operator,
        config={"operator_contact": "+2348000000000", "relay_enabled": True},
        authority_facts=lambda zone_id=None: holder["facts"],
    )
    dispatcher.facts_holder = holder  # type: ignore[attr-defined]

    async def act(*_args: Any, **_kwargs: Any) -> Any:
        journal.append("act:trip_relay")
        return True

    async def safe_default(*_args: Any, **_kwargs: Any) -> bool:
        journal.append("act:log_to_dashboard")
        return True

    dispatcher.register_executor("trip_relay", executor or act)
    dispatcher.register_executor("log_to_dashboard", safe_default)
    return dispatcher


async def _propose(dispatcher: ActionDispatcher, store: Any, timeout: int = 30) -> Any:
    return await dispatcher.dispatch(
        action="trip_relay",
        tier="C",
        context=SkillContext(
            skill=_Skill(), event=_event(), state_store=store, trigger_name="t"
        ),
        result=ReasoningResult(
            text="", tier="rule", model="m", tokens_used=0, latency_ms=0
        ),
        approval_timeout=timeout,
    )


async def _states(store: StateStore) -> list[tuple[str, str]]:
    return [
        (row["proposal_id"], row["decision_state"])
        for row in await store.get_tier_c_proposals()
    ]


async def _settle(dispatcher: ActionDispatcher) -> None:
    await dispatcher.drain_records(timeout=5)
    pending = dispatcher.get_inflight_tier_d_tasks()
    if pending:
        await asyncio.wait(pending, timeout=5)


class TestTheProposalIsCommittedBeforeTheAsk:
    async def test_the_row_exists_when_the_operator_is_asked(
        self, tmp_path: Any
    ) -> None:
        journal: list[str] = []
        store = _recording_store(str(tmp_path / "s.db"), journal)
        await store.open()
        operator = _Operator()
        try:
            dispatcher = _dispatcher(store, operator, journal)
            outcome = await _propose(dispatcher, store)
            await _settle(dispatcher)
            records = await store.get_tier_c_proposal_records(outcome.proposal_id)
        finally:
            await store.close()
        assert journal.index("write:create_tier_c_proposal") < journal.index(
            "write:admit_tier_c_approval"
        )
        assert operator.proposals == [outcome.proposal_id]
        assert records == [
            adm.PROPOSED,
            adm.APPROVED_PENDING_DISPATCH,
            adm.DISPATCH_STARTED,
            adm.EXECUTED,
        ]

    async def test_a_row_the_store_cannot_commit_is_no_proposal(
        self, tmp_path: Any, caplog: Any
    ) -> None:
        journal: list[str] = []
        store = _recording_store(str(tmp_path / "s.db"), journal)
        await store.open()
        operator = _Operator()

        async def refuse(**_kwargs: Any) -> str:
            raise sqlite3.OperationalError("disk I/O error")

        store.create_tier_c_proposal = refuse  # type: ignore[method-assign]
        try:
            dispatcher = _dispatcher(store, operator, journal)
            with caplog.at_level(logging.CRITICAL):
                outcome = await _propose(dispatcher, store)
            await _settle(dispatcher)
            rows = await store.get_tier_c_proposals()
            intents = await store.get_tier_c_safe_default_intents()
        finally:
            await store.close()
        assert operator.proposals == []
        assert outcome.approved is None
        assert outcome.action_taken == "proposal_not_committed"
        assert "act:trip_relay" not in journal
        assert "act:log_to_dashboard" in journal
        assert rows == [] and intents == []
        assert any(
            "nothing is claimed durable" in r.getMessage() for r in caplog.records
        )

    async def test_a_physical_action_with_no_zone_is_refused_not_asked(
        self, tmp_path: Any
    ) -> None:
        journal: list[str] = []
        store = StateStore(str(tmp_path / "s.db"))
        await store.open()
        operator = _Operator()
        try:
            dispatcher = _dispatcher(store, operator, journal)
            dispatcher.facts_holder["facts"] = None  # type: ignore[attr-defined]
            outcome = await _propose(dispatcher, store)
            await _settle(dispatcher)
            rows = await store.get_tier_c_proposals()
        finally:
            await store.close()
        assert outcome.action_taken == "refused_uncommissioned"
        assert operator.proposals == [] and rows == []
        assert journal == ["act:log_to_dashboard"]


class TestLiveImmediateDispatch:
    async def test_nothing_is_written_between_the_commit_and_the_act(
        self, tmp_path: Any
    ) -> None:
        journal: list[str] = []
        store = _recording_store(str(tmp_path / "s.db"), journal)
        await store.open()
        try:
            dispatcher = _dispatcher(store, _Operator(), journal)
            outcome = await _propose(dispatcher, store)
            await _settle(dispatcher)
            states = await _states(store)
        finally:
            await store.close()
        assert outcome.approved is True and outcome.executed is True
        committed = journal.index("admitted:committed")
        acted = journal.index("act:trip_relay")
        # The act follows the commit, and nothing is written between them.
        assert committed < acted, journal
        between = journal[committed + 1 : acted]
        assert all(not step.startswith("write:") for step in between), journal
        assert states == [(outcome.proposal_id, adm.EXECUTED)]

    async def test_a_reply_the_store_cannot_admit_is_retried_by_a_later_reply(
        self, tmp_path: Any
    ) -> None:
        journal: list[str] = []
        store = _recording_store(str(tmp_path / "s.db"), journal)
        failures = {"left": 1}
        original = store.admit_tier_c_approval

        async def flaky(*args: Any, **kwargs: Any) -> str:
            if failures["left"]:
                failures["left"] -= 1
                raise sqlite3.OperationalError("database is locked")
            return await original(*args, **kwargs)

        store.admit_tier_c_approval = flaky  # type: ignore[method-assign]
        await store.open()
        operator = _Operator()
        try:
            dispatcher = _dispatcher(store, operator, journal)
            outcome = await asyncio.wait_for(_propose(dispatcher, store), 10)
            await _settle(dispatcher)
        finally:
            await store.close()
        assert outcome.approved is True and journal.count("act:trip_relay") == 1
        assert any("reply again" in n for n in operator.notices)

    async def test_a_duplicate_reply_is_one_approval(self, tmp_path: Any) -> None:
        journal: list[str] = []
        store = StateStore(str(tmp_path / "s.db"))
        await store.open()
        try:
            dispatcher = _dispatcher(store, _Operator(), journal)
            outcome = await _propose(dispatcher, store)
            await _settle(dispatcher)
            again = await store.admit_tier_c_approval(
                outcome.proposal_id,
                binding_digest="x",
                authority_json="y",
                reservation_ceiling=64,
            )
        finally:
            await store.close()
        assert again == "duplicate"
        assert journal.count("act:trip_relay") == 1

    async def test_an_affirmed_refusal_is_dispatch_failed_and_a_bare_false_is_unknown(
        self, tmp_path: Any
    ) -> None:
        for answer, expected in (
            (ACTUATION_NOT_PERFORMED, adm.DISPATCH_FAILED),
            (False, adm.DISPATCH_OUTCOME_UNKNOWN),
        ):
            journal: list[str] = []
            store = StateStore(str(tmp_path / f"{expected}.db"))
            await store.open()

            async def executor(*_a: Any, _answer: Any = answer, **_k: Any) -> Any:
                return _answer

            try:
                dispatcher = _dispatcher(store, _Operator(), journal, executor=executor)
                outcome = await _propose(dispatcher, store)
                await _settle(dispatcher)
                states = await _states(store)
                records = dispatcher.action_records()
            finally:
                await store.close()
            assert outcome.approved is True and outcome.executed is False
            assert states == [(outcome.proposal_id, expected)]
            if expected == adm.DISPATCH_OUTCOME_UNKNOWN:
                assert records["outcome_unknown"] == 1 and records["lost"] == 1
            else:
                assert records["lost"] == 0

    async def test_an_executor_that_raises_leaves_the_outcome_unknown(
        self, tmp_path: Any
    ) -> None:
        journal: list[str] = []
        store = StateStore(str(tmp_path / "s.db"))
        await store.open()

        async def executor(*_a: Any, **_k: Any) -> bool:
            raise RuntimeError("driver lost")

        try:
            dispatcher = _dispatcher(store, _Operator(), journal, executor=executor)
            outcome = await _propose(dispatcher, store)
            await _settle(dispatcher)
            states = await _states(store)
        finally:
            await store.close()
        assert outcome.approved is True and outcome.executed is False
        assert states == [(outcome.proposal_id, adm.DISPATCH_OUTCOME_UNKNOWN)]


class TestExpiry:
    async def test_a_reply_after_the_deadline_is_not_an_approval(
        self, tmp_path: Any
    ) -> None:
        journal: list[str] = []
        store = _recording_store(str(tmp_path / "s.db"), journal)
        await store.open()
        operator = _Operator(delay_s=1.3)
        try:
            dispatcher = _dispatcher(store, operator, journal)
            outcome = await _propose(dispatcher, store, timeout=1)
            await _settle(dispatcher)
            states = await _states(store)
            intents = await store.get_tier_c_safe_default_intents()
        finally:
            await store.close()
        assert outcome.approved is False
        assert "act:trip_relay" not in journal
        assert "write:admit_tier_c_approval" not in journal
        assert states == [(outcome.proposal_id, adm.PROPOSAL_EXPIRED)]
        assert [i["proposal_id"] for i in intents] == [outcome.proposal_id]

    async def test_an_approval_that_outlives_its_window_in_the_commit_grants_nothing(
        self, tmp_path: Any, caplog: Any
    ) -> None:
        journal: list[str] = []
        store = _recording_store(
            str(tmp_path / "s.db"), journal, admit_tier_c_approval=1.3
        )
        await store.open()
        try:
            dispatcher = _dispatcher(store, _Operator(), journal)
            with caplog.at_level(logging.CRITICAL):
                outcome = await _propose(dispatcher, store, timeout=1)
            await _settle(dispatcher)
            states = await _states(store)
        finally:
            await store.close()
        assert "act:trip_relay" not in journal
        assert "act:log_to_dashboard" in journal
        assert outcome.approved is True and outcome.executed is False
        assert outcome.action_taken == "approval_expired_undispatched"
        assert states == [(outcome.proposal_id, adm.APPROVAL_EXPIRED_UNDISPATCHED)]


class TestRestart:
    async def _left_behind(self, path: str, state: str) -> None:
        store = StateStore(path)
        await store.open()
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
            if state != adm.PROPOSED:
                assert (
                    await store.admit_tier_c_approval(
                        "P1",
                        binding_digest="sha256:" + "b" * 64,
                        authority_json="{}",
                        reservation_ceiling=64,
                    )
                    == "committed"
                )
            if state == adm.DISPATCH_STARTED:
                await store.advance_tier_c_proposal(
                    "P1", state, from_states=(adm.APPROVED_PENDING_DISPATCH,)
                )
        finally:
            await store.close()

    @pytest.mark.parametrize(
        ("left", "expected"),
        [
            (adm.PROPOSED, adm.PROPOSAL_ABORTED_RESTART),
            (adm.APPROVED_PENDING_DISPATCH, adm.DISPATCH_NOT_PROVEN),
            (adm.DISPATCH_STARTED, adm.DISPATCH_OUTCOME_UNKNOWN),
        ],
    )
    async def test_a_restart_replays_nothing(
        self, tmp_path: Any, left: str, expected: str, caplog: Any
    ) -> None:
        path = str(tmp_path / "s.db")
        await self._left_behind(path, left)
        journal: list[str] = []
        store = StateStore(path)
        await store.open()
        operator = _Operator()
        try:
            dispatcher = _dispatcher(store, operator, journal)
            with caplog.at_level(logging.WARNING):
                counts = await dispatcher.recover_tier_c_at_start(store)
            await _settle(dispatcher)
            states = await _states(store)
            intents = await store.get_tier_c_safe_default_intents()
            records = dispatcher.action_records()
        finally:
            await store.close()
        assert "act:trip_relay" not in journal
        assert states == [("P1", expected)]
        if expected == adm.PROPOSAL_ABORTED_RESTART:
            assert counts["aborted_proposals"] == 1
            assert journal == ["act:log_to_dashboard"]
            assert [i["proposal_id"] for i in intents] == ["P1"]
            assert records["lost"] == 0
        else:
            # No safe default: the approval stands, and its act may have run.
            assert journal == [] and intents == []
            assert records["lost"] == 1
            key = (
                "dispatch_unproven"
                if expected == adm.DISPATCH_NOT_PROVEN
                else "outcome_unknown"
            )
            assert records[key] == 1
            assert any(
                r.levelno == logging.CRITICAL and "never replayed" in r.getMessage()
                for r in caplog.records
            )
            # The operator event beside the audit record: the operator is told
            # the act may have run and what is blocked until they reconcile.
            told = [n for n in operator.notices if "P1" in n]
            assert len(told) == 1, operator.notices
            assert "open_protected_circuit" in told[0] and ZONE in told[0]
            assert expected.replace("_", " ") in told[0]

    async def test_a_repeated_restart_creates_one_safe_default_intent(
        self, tmp_path: Any
    ) -> None:
        path = str(tmp_path / "s.db")
        await self._left_behind(path, adm.PROPOSED)
        intents: list[dict] = []
        for _ in range(2):
            journal: list[str] = []
            store = StateStore(path)
            await store.open()
            try:
                dispatcher = _dispatcher(store, _Operator(), journal)
                await dispatcher.recover_tier_c_at_start(store)
                await _settle(dispatcher)
                intents = await store.get_tier_c_safe_default_intents()
            finally:
                await store.close()
        assert len(intents) == 1

    async def test_an_uncertain_dispatch_blocks_the_same_outcome_until_reconciled(
        self, tmp_path: Any
    ) -> None:
        path = str(tmp_path / "s.db")
        await self._left_behind(path, adm.DISPATCH_STARTED)
        journal: list[str] = []
        store = StateStore(path)
        await store.open()
        operator = _Operator()
        try:
            dispatcher = _dispatcher(store, operator, journal)
            await dispatcher.recover_tier_c_at_start(store)
            refused = await _propose(dispatcher, store)
            await _settle(dispatcher)
            assert refused.action_taken == "refused_outcome_uncertain"
            assert "act:trip_relay" not in journal
            answer = await dispatcher.reconcile_tier_c(
                store,
                proposal_id="P1",
                device_id=DEVICE,
                runtime_device_id=DEVICE,
                zone_id=ZONE,
                outcome="executed",
                reason="site_inspection",
                note=None,
                principal_uid=1001,
                principal_account="installer",
                principal_login_uid=1001,
            )
            assert answer["ok"] is True
            assert dispatcher.action_records()["lost"] == 0
            fresh = await _propose(dispatcher, store)
            await _settle(dispatcher)
            states = await _states(store)
        finally:
            await store.close()
        assert fresh.approved is True and journal.count("act:trip_relay") == 1
        assert dict(states)["P1"] == adm.RECONCILED_EXECUTED
        assert dict(states)[fresh.proposal_id] == adm.EXECUTED

    async def test_a_reconcile_request_is_refused_in_the_contracts_order(
        self, tmp_path: Any
    ) -> None:
        store = StateStore(str(tmp_path / "s.db"))
        await store.open()
        try:
            dispatcher = _dispatcher(store, _Operator(), [])
            base: dict[str, Any] = dict(
                proposal_id="P1",
                device_id=DEVICE,
                runtime_device_id=DEVICE,
                zone_id=ZONE,
                outcome="executed",
                reason="site_inspection",
                note=None,
                principal_uid=1001,
                principal_account="installer",
                principal_login_uid=1001,
            )
            for bad in (
                {"outcome": "maybe"},
                {"reason": "guess"},
                {"note": "x" * 281},
                {"note": "a\tb"},
            ):
                answer = await dispatcher.reconcile_tier_c(store, **{**base, **bad})
                assert answer == {"ok": False, "error": "invalid_arguments"}, bad
            answer = await dispatcher.reconcile_tier_c(
                store, **{**base, "device_id": "other"}
            )
            assert answer["error"] == "device_mismatch"
            answer = await dispatcher.reconcile_tier_c(store, **base)
            assert answer["error"] == "unknown_proposal"
        finally:
            await store.close()


class TestGracefulStop:
    async def test_a_stop_during_a_pending_approval_closes_the_proposal(
        self, tmp_path: Any
    ) -> None:
        journal: list[str] = []
        store = StateStore(str(tmp_path / "s.db"))
        await store.open()
        operator = _Operator(reply=None)
        try:
            dispatcher = _dispatcher(store, operator, journal)
            task = asyncio.create_task(_propose(dispatcher, store, timeout=300))
            for _ in range(200):
                if operator.proposals:
                    break
                await asyncio.sleep(0.01)
            assert operator.proposals
            closed = await dispatcher.close_open_proposals(
                store, reason="graceful_shutdown"
            )
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await _settle(dispatcher)
            states = await _states(store)
            intents = await store.get_tier_c_safe_default_intents()
            row = await store.get_tier_c_proposal(operator.proposals[0])
        finally:
            await store.close()
        assert closed == 1
        assert states == [(operator.proposals[0], adm.PROPOSAL_ABORTED_RESTART)]
        assert row is not None
        assert row["state_reason"] == "graceful_shutdown"
        assert [i["proposal_id"] for i in intents] == [operator.proposals[0]]
        assert journal == ["act:log_to_dashboard"]
        assert "act:trip_relay" not in journal
        assert any("graceful shutdown" in n for n in operator.notices)

    async def test_a_stale_yes_after_the_stop_approves_nothing(
        self, tmp_path: Any
    ) -> None:
        path = str(tmp_path / "s.db")
        await TestRestart()._left_behind(path, adm.PROPOSED)
        store = StateStore(path)
        await store.open()
        try:
            dispatcher = _dispatcher(store, _Operator(), [])
            await dispatcher.close_open_proposals(store, reason="graceful_shutdown")
            late = await store.admit_tier_c_approval(
                "P1",
                binding_digest="sha256:" + "b" * 64,
                authority_json="{}",
                reservation_ceiling=64,
            )
        finally:
            await store.close()
        assert late == f"closed:{adm.PROPOSAL_ABORTED_RESTART}"


class TestBindingAndBlocking:
    async def test_a_changed_binding_makes_the_reply_no_approval(
        self, tmp_path: Any, caplog: Any
    ) -> None:
        journal: list[str] = []
        store = StateStore(str(tmp_path / "s.db"))
        await store.open()
        operator = _Operator(delay_s=0.05)
        try:
            dispatcher = _dispatcher(store, operator, journal)
            task = asyncio.create_task(_propose(dispatcher, store))
            for _ in range(200):
                if operator.proposals:
                    break
                await asyncio.sleep(0.01)
            dispatcher.facts_holder["facts"] = _facts(binding="sha256:" + "c" * 64)  # type: ignore[attr-defined]
            with caplog.at_level(logging.CRITICAL):
                outcome = await asyncio.wait_for(task, 10)
            await _settle(dispatcher)
            states = await _states(store)
        finally:
            await store.close()
        assert outcome.approved is False
        assert "act:trip_relay" not in journal
        assert "act:log_to_dashboard" in journal
        assert states == [(outcome.proposal_id, adm.APPROVAL_BINDING_CHANGED)]
        assert any("binding or authority changed" in n for n in operator.notices)

    async def test_a_contended_resource_refuses_the_approved_act(
        self, tmp_path: Any, caplog: Any
    ) -> None:
        class _Gate:
            async def request(self, *_a: Any, **_k: Any) -> Any:
                raise AssertionError("not reached: no identity resolves here")

            async def reply_admitted(self, _token: Any) -> bool:
                return False

        journal: list[str] = []
        store = StateStore(str(tmp_path / "s.db"))
        await store.open()
        try:
            # An admitted approval, as the store holds one when dispatch begins.
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
            dispatcher = _dispatcher(store, _Operator(), journal)
            dispatcher._resource_gate = _Gate()  # type: ignore[assignment]
            # The gate is consulted through the token the admission handed out;
            # here the refusal is driven directly.
            outcome = await dispatcher._dispatch_admitted(  # type: ignore[attr-defined]
                "trip_relay",
                SkillContext(
                    skill=_Skill(), event=_event(), state_store=store, trigger_name="t"
                ),
                store,
                {
                    "proposal_id": "P9",
                    "device_id": DEVICE,
                    "safe_default_action": "log_to_dashboard",
                },
                object(),
                asyncio.get_running_loop().time() + 30,
                "YES-P9",
            )
            await _settle(dispatcher)
            states = await _states(store)
            intents = await store.get_tier_c_safe_default_intents("P9")
        finally:
            await store.close()
        assert outcome.approved is True and outcome.executed is False
        assert outcome.action_taken == "dispatch_refused_contention"
        assert outcome.safe_default_used is True
        assert states == [("P9", adm.DISPATCH_REFUSED_CONTENTION)]
        assert [i["outcome"] for i in intents] == ["executed"]
        assert journal == ["act:log_to_dashboard"]


class TestOfflineTokensV2:
    async def test_a_v2_token_bound_to_the_proposal_is_admitted_and_claimed_once(
        self, tmp_path: Any
    ) -> None:
        import base64
        import json

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from ori.security.offline_tokens import (
            V2_SIGNATURE_DOMAIN,
            OfflineTierCTokenVerifier,
        )
        from ori.skills.signing import canonical_signed_payload

        key = Ed25519PrivateKey.generate()
        public = base64.b64encode(
            key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).decode("ascii")
        journal: list[str] = []
        store = StateStore(str(tmp_path / "s.db"))
        await store.open()
        replies: list[str] = []

        class Console(_Operator):
            async def send(
                self, *, alert: Any, to_number: str
            ) -> bool:  # pragma: no cover
                return True

        dispatcher = _dispatcher(store, Console(), journal)
        dispatcher._offline_token_verifier = OfflineTierCTokenVerifier(
            public_key_b64=public
        )
        dispatcher._local_console_enabled = True
        dispatcher._tier_c_comms_available = lambda: False  # type: ignore[method-assign]

        async def listen(**kwargs: Any) -> str | None:
            proposal_id = kwargs["proposal_id"]
            now_s = now_ms() // 1000
            payload = {
                "token_version": 2,
                "token_id": "tok-1",
                "device_id": DEVICE,
                "proposal_id": proposal_id,
                "action_scope": "trip_relay",
                "target": "relay-gpio-26",
                "zone_id": ZONE,
                "issued_at": now_s - 5,
                "expires_at": now_s + 120,
                "nonce": "n1",
            }
            signature = key.sign(
                V2_SIGNATURE_DOMAIN + b"\x00" + canonical_signed_payload(payload)
            )
            payload["signature"] = "ed25519:" + base64.b64encode(signature).decode(
                "ascii"
            )
            replies.append(proposal_id)
            return "TOKEN:" + json.dumps(payload)

        dispatcher._listen_for_local_console_response = listen  # type: ignore[method-assign]
        try:
            outcome = await _propose(dispatcher, store)
            await _settle(dispatcher)
            row = await store.get_tier_c_proposal(outcome.proposal_id)
            with sqlite3.connect(str(tmp_path / "s.db")) as reader:
                claimed = reader.execute(
                    "SELECT token_id FROM offline_token_consumption"
                ).fetchall()
        finally:
            await store.close()
        assert outcome.approved is True and outcome.executed is True
        assert row is not None
        assert row["decision_state"] == adm.EXECUTED
        assert row["offline_token_id"] == "tok-1"
        assert row["ingress_channel"] == "local_console"
        assert claimed == [("tok-1",)]


class TestHealth:
    async def test_action_records_follow_the_outcome(self, tmp_path: Any) -> None:
        journal: list[str] = []
        store = StateStore(str(tmp_path / "s.db"))
        await store.open()
        try:
            dispatcher = _dispatcher(store, _Operator(), journal)
            assert dispatcher.action_records() == {
                "pending": 0,
                "outcome_unknown": 0,
                "dispatch_unproven": 0,
                "lost": 0,
                "ceiling": 64,
                "unknown_live": 0,
                "oldest_pending_age_ms": None,
            }
            assert dispatcher.action_records_degrade_health() is False
            outcome = await _propose(dispatcher, store)
            await _settle(dispatcher)
            assert outcome.executed is True
            assert dispatcher.action_records()["pending"] == 0
            dispatcher._uncertain["X"] = adm.DISPATCH_NOT_PROVEN
            assert dispatcher.action_records()["dispatch_unproven"] == 1
            assert dispatcher.action_records_degrade_health() is True
        finally:
            await store.close()


class TestRelayPolicyIsDecidedByClass:
    """Every action that drives the protected circuit answers to relay policy.

    Suppression by name let `close_gas_valve`, registered to the same
    executor and outcome as `trip_relay`, reach the relay with the relay
    disabled for Tier C.
    """

    @pytest.mark.parametrize("withheld_by", ["relay_enabled", "device_policy"], ids=str)
    async def test_no_protected_circuit_action_is_proposed_when_withheld(
        self, tmp_path: Any, withheld_by: str
    ) -> None:
        import dataclasses

        from ori.policy.device_policy import DevicePolicy
        from ori.reasoning.action_registry import ACTION_REGISTRY
        from ori.reasoning.tier_c_admission import governed_outcome

        actions = sorted(
            name
            for name, entry in ACTION_REGISTRY.items()
            if entry.physical and governed_outcome(name) is not None
        )
        assert "close_gas_valve" in actions
        for action in actions:
            journal: list[str] = []
            store = StateStore(str(tmp_path / f"{withheld_by}-{action}.db"))
            await store.open()
            operator = _Operator()
            try:
                dispatcher = _dispatcher(store, operator, journal)
                if withheld_by == "relay_enabled":
                    dispatcher._relay_b_c_enabled = False
                else:
                    dispatcher.update_policy(
                        dataclasses.replace(
                            DevicePolicy.unrestricted(), relay_c_enabled=False
                        )
                    )
                dispatcher.register_executor(
                    action, lambda *_a, _own=action, **_k: journal.append(f"act:{_own}")
                )
                outcome = await dispatcher.dispatch(
                    action=action,
                    tier="C",
                    context=SkillContext(
                        skill=_Skill(),
                        event=_event(),
                        state_store=store,
                        trigger_name="t",
                    ),
                    result=ReasoningResult(
                        text="", tier="rule", model="m", tokens_used=0, latency_ms=0
                    ),
                    approval_timeout=30,
                )
                await _settle(dispatcher)
                rows = await store.get_tier_c_proposals()
                log = await store.get_action_log(limit=50)
            finally:
                await store.close()
            assert not any(step.startswith(f"act:{action}") for step in journal), (
                action,
                journal,
            )
            assert rows == [], (action, rows)
            assert operator.proposals == [], (action, operator.proposals)
            assert outcome.approved is not True, (action, outcome)
            # Dispatch itself suppressed it and wrote that audit, so the
            # action never reached the proposal path at all.
            assert any(
                r["action_name"] == action and r["action_taken"] == "suppressed"
                for r in log
            ), (action, log)

    async def test_the_governed_path_refuses_on_its_own_when_dispatch_did_not(
        self, tmp_path: Any
    ) -> None:
        """The second layer: reached directly, with relay use withheld."""
        journal: list[str] = []
        store = StateStore(str(tmp_path / "s.db"))
        await store.open()
        operator = _Operator()
        try:
            dispatcher = _dispatcher(store, operator, journal)
            dispatcher._relay_b_c_enabled = False
            outcome = await dispatcher._governed_approval_workflow(  # type: ignore[attr-defined]
                "trip_relay",
                SkillContext(
                    skill=_Skill(), event=_event(), state_store=store, trigger_name="t"
                ),
                ReasoningResult(
                    text="", tier="rule", model="m", tokens_used=0, latency_ms=0
                ),
                "log_to_dashboard",
                30,
                None,
            )
            await _settle(dispatcher)
            rows = await store.get_tier_c_proposals()
        finally:
            await store.close()
        assert outcome.action_taken == "refused_policy"
        assert rows == [] and operator.proposals == []
        assert journal == ["act:log_to_dashboard"]


class TestNoiseNeverClosesAProposal:
    async def test_replies_that_decide_nothing_leave_the_proposal_open_to_its_deadline(
        self, tmp_path: Any
    ) -> None:
        journal: list[str] = []
        store = StateStore(str(tmp_path / "s.db"))
        await store.open()
        clock = {"now": 1000.0}

        class Noisy(_Operator):
            def __init__(self) -> None:
                super().__init__()
                self.heard = 0

            async def listen_for_response(
                self, *, from_number: str, timeout_seconds: int
            ) -> str | None:
                while not self.proposals:
                    await asyncio.sleep(0)
                self.heard += 1
                if self.heard > 24:
                    # The channel goes quiet; the deadline then passes.
                    clock["now"] += 10_000
                    return None
                return f"BLAH-{self.proposals[-1]}"

        operator = Noisy()
        try:
            dispatcher = _dispatcher(store, operator, journal)
            dispatcher._clock = lambda: clock["now"]
            from ori.reasoning import action_dispatcher as module

            original = module.asyncio.sleep

            async def quick(delay: float, *args: Any) -> None:
                # The one-second breather per noisy reply, without the second.
                await original(0 if delay == 1.0 else delay, *args)

            module.asyncio.sleep = quick  # type: ignore[assignment]
            try:
                outcome = await asyncio.wait_for(
                    _propose(dispatcher, store, timeout=300), 20
                )
            finally:
                module.asyncio.sleep = original  # type: ignore[assignment]
            await _settle(dispatcher)
            row = await store.get_tier_c_proposal(outcome.proposal_id)
        finally:
            await store.close()
        assert operator.heard > 20
        assert "act:trip_relay" not in journal
        assert row is not None
        assert row["decision_state"] == adm.PROPOSAL_EXPIRED
        assert row["state_reason"] != "reply_limit"


class TestTheRuntimeFactsProvider:
    """The commissioned facts the runtime hands the dispatcher, with real types.

    A renamed attribute on the zone, the binding or the profile set would make
    every governed proposal `refused_uncommissioned` through the provider's
    guard; this holds the join with the objects the runtime actually holds.
    """

    def test_the_facts_come_from_the_zone_the_binding_and_the_profile_set(self) -> None:
        from ori.actions.commissioned_actuator import CommissionedActuator
        from ori.reasoning.tier_c_admission import AuthorityInputs, build_snapshot
        from ori.runtime import OriRuntime
        from ori.security.commissioning.binding import AcceptedBinding, AcceptedZone
        from ori.security.commissioning.loader import CommissioningState

        zone = AcceptedZone(
            zone_id="zone-feeder-a",
            sensor_id="clamp",
            quantity="current",
            unit="ampere",
            direction="positive_is_load_draw",
            range_min=0.0,
            range_max=100.0,
            noise_floor=0.05,
            calibration_ref="bench",
            rated_capacity_parameter="rated_capacity_amps",
            rated_capacity_value=10.0,
            kind="local_gpio",
            identity={"gpio_pin": 26, "active_high": True},
            mapping={
                "open_protected_circuit": "de_energised",
                "close_protected_circuit": "energised",
                "de_energised_terminal_state": "open",
            },
            proof_method="actuate_and_observe",
            proof_performed_at_ms=1,
            control_proof_method="actuate_and_observe",
            control_proof_performed_at_ms=2,
        )
        binding = AcceptedBinding(
            binding_seq=7,
            canonical_hash="sha256:" + "b" * 64,
            inventory_generation=1,
            device_id=DEVICE,
            signer_id="signer",
            issued_at_ms=1,
            supersedes=None,
            zones=(zone,),
            canonical_bytes=b"{}",
            signature="ed25519:x",
        )

        class _Driver:
            connected = True

            async def acquire_at(self, *_a: Any, **_k: Any) -> None:
                return None

            async def trigger(self, duration_seconds: float | None = None) -> bool:
                return True

            async def release(self) -> bool:
                return True

            @property
            def is_simulated(self) -> bool:
                return True

            @property
            def is_active(self) -> bool:
                return False

        runtime: Any = object.__new__(OriRuntime)
        runtime._commissioned_actuator = CommissionedActuator(
            driver=_Driver(), zone=zone, binding_seq=7
        )
        runtime._commissioning_state = CommissioningState.__new__(CommissioningState)
        runtime._commissioning_state.in_force = binding
        runtime._safety_registry = None
        runtime._shipped_profile_digest = "c" * 64
        runtime._tier_c_deployment_inputs = {"approval_timeout_seconds": 300}

        facts = runtime._tier_c_authority_facts()
        assert facts is not None
        assert facts.zone_id == "zone-feeder-a"
        assert facts.binding_digest == "sha256:" + "b" * 64
        assert facts.safety_profile_digest == ""  # no active pair on the zone
        assert facts.resource_for["open_protected_circuit"] == "relay-gpio-26"
        assert runtime._tier_c_authority_facts("zone-feeder-a") == facts
        assert runtime._tier_c_authority_facts("zone-other") is None
        snapshot = build_snapshot(
            AuthorityInputs(
                action="trip_relay",
                outcome="open_protected_circuit",
                resource=facts.resource_for["open_protected_circuit"],
                zone_id=facts.zone_id,
                zone_document=facts.zone_document,
                binding_canonical_hash=facts.binding_digest,
                safety_profile_digest=facts.safety_profile_digest,
                policy_inputs={"deployment": facts.deployment_inputs},
            )
        )
        assert snapshot["zone_id"] == "zone-feeder-a" and snapshot["v"] == 1

        class _Registry:
            zones_with_active_pairs = frozenset({"zone-feeder-a"})

        runtime._safety_registry = _Registry()
        with_profile = runtime._tier_c_authority_facts()
        assert with_profile is not None
        assert with_profile.safety_profile_digest == "sha256:" + "c" * 64


class TestSafeDefaultIntentsAreObligations:
    """A pending intent is work owed, never a record that the work was done."""

    async def _closed_with_pending_intent(self, path: str) -> None:
        store = StateStore(path)
        await store.open()
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
            # The process died after the close and its intent landed, before
            # the safe default ran or before its outcome was marked.
            assert await store.advance_tier_c_proposal(
                "P1",
                adm.REJECTED,
                from_states=(adm.PROPOSED,),
                reason="operator_no",
                safe_default_action="log_to_dashboard",
            )
        finally:
            await store.close()

    async def test_a_restart_attempts_a_pending_intent_once_and_then_never_again(
        self, tmp_path: Any
    ) -> None:
        path = str(tmp_path / "s.db")
        await self._closed_with_pending_intent(path)
        runs: list[list[str]] = []
        counts: dict[str, int] = {}
        intents: list[dict] = []
        states: list[tuple[str, str]] = []
        for _ in range(2):
            journal: list[str] = []
            store = StateStore(path)
            await store.open()
            try:
                dispatcher = _dispatcher(store, _Operator(), journal)
                counts = await dispatcher.recover_tier_c_at_start(store)
                await _settle(dispatcher)
                intents = await store.get_tier_c_safe_default_intents("P1")
                states = await _states(store)
            finally:
                await store.close()
            runs.append(journal)
        assert runs == [["act:log_to_dashboard"], []], runs
        assert counts["safe_defaults_resumed"] == 0
        assert [(i["outcome"], i["reason"]) for i in intents] == [
            ("executed", "operator_no")
        ]
        assert states == [("P1", adm.REJECTED)]
        assert "act:trip_relay" not in runs[0]

    async def test_a_rejection_whose_close_cannot_land_is_a_lost_decision(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        """The close and its intent are one transaction; neither lands alone."""
        journal: list[str] = []
        store = StateStore(str(tmp_path / "s.db"))
        await store.open()
        operator = _Operator(reply="NO")

        def _refuse(*_a: Any, **_k: Any) -> bool:
            raise sqlite3.OperationalError("intents table unavailable")

        try:
            dispatcher = _dispatcher(store, operator, journal)
            monkeypatch.setattr(
                StateStore, "_insert_tier_c_intent", staticmethod(_refuse)
            )
            outcome = await _propose(dispatcher, store)
            await _settle(dispatcher)
            states = await _states(store)
            records = await store.get_tier_c_proposal_records(states[0][0])
            intents = await store.get_tier_c_safe_default_intents()
        finally:
            await store.close()
        assert outcome.approved is False and "act:trip_relay" not in journal
        # The row says what it can answer for: nothing was closed, no intent
        # exists, the lost decision is counted, and the safe default was still
        # attempted without being claimed durable.
        assert [state for _, state in states] == [adm.PROPOSED]
        assert records == [adm.PROPOSED] and intents == []
        assert dispatcher._decision_records_lost >= 1
        assert journal == ["act:log_to_dashboard"]


class TestTerminalDecisionsAreDurableBeforeTheyAreReported:
    async def test_a_rejection_is_not_reported_until_its_row_has_moved(
        self, tmp_path: Any
    ) -> None:
        released = asyncio.Event()
        held: list[str] = []

        class _Holding(StateStore):
            async def advance_tier_c_proposal(
                self, proposal_id: str, state: str, **kwargs: Any
            ) -> bool:
                if state == adm.REJECTED:
                    held.append(proposal_id)
                    await released.wait()
                return await super().advance_tier_c_proposal(
                    proposal_id, state, **kwargs
                )

        journal: list[str] = []
        store = _Holding(str(tmp_path / "s.db"))
        await store.open()
        operator = _Operator(reply="NO")
        try:
            dispatcher = _dispatcher(store, operator, journal)
            task = asyncio.create_task(_propose(dispatcher, store))
            for _ in range(400):
                if held:
                    break
                await asyncio.sleep(0.005)
            assert held, "the rejection never reached the store"
            await asyncio.sleep(0.05)
            # The decision is not reported while its row has not moved.
            assert not task.done()
            assert journal == []
            released.set()
            outcome = await asyncio.wait_for(task, 5)
            await _settle(dispatcher)
            states = await _states(store)
            intents = await store.get_tier_c_safe_default_intents()
        finally:
            released.set()
            await store.close()
        assert outcome.approved is False
        assert states == [(held[0], adm.REJECTED)]
        assert [i["outcome"] for i in intents] == ["executed"]
        assert journal == ["act:log_to_dashboard"]


class TestRecoveryThatDidNotComplete:
    async def test_no_proposal_is_raised_and_health_degrades(
        self, tmp_path: Any
    ) -> None:
        journal: list[str] = []
        store = StateStore(str(tmp_path / "s.db"))
        await store.open()
        operator = _Operator()
        try:
            dispatcher = _dispatcher(store, operator, journal)
            assert not dispatcher.action_records_degrade_health()
            dispatcher.mark_tier_c_recovery_failed("OperationalError: locked")
            outcome = await _propose(dispatcher, store)
            await _settle(dispatcher)
            rows = await store.get_tier_c_proposals()
        finally:
            await store.close()
        assert outcome.action_taken == "refused_recovery_incomplete"
        assert outcome.approved is None and not outcome.executed
        assert rows == [] and operator.proposals == []
        assert journal == ["act:log_to_dashboard"]
        assert any("could not settle" in n for n in operator.notices)
        assert dispatcher.action_records_degrade_health()


class TestARefusedTransitionIsNeverReportedAsRecorded:
    async def _rejected_through(self, store: Any) -> tuple[Any, ActionDispatcher, list]:
        journal: list[str] = []
        dispatcher = _dispatcher(store, _Operator(reply="NO"), journal)
        outcome = await _propose(dispatcher, store)
        await _settle(dispatcher)
        return outcome, dispatcher, journal

    async def test_a_transition_the_store_refuses_is_a_lost_decision(
        self, tmp_path: Any
    ) -> None:
        class _Refusing(StateStore):
            async def advance_tier_c_proposal(
                self, proposal_id: str, state: str, **kwargs: Any
            ) -> bool:
                # The store answers, and says no: the row is not moved.
                if state == adm.REJECTED:
                    return False
                return await super().advance_tier_c_proposal(
                    proposal_id, state, **kwargs
                )

        store = _Refusing(str(tmp_path / "s.db"))
        await store.open()
        try:
            outcome, dispatcher, journal = await self._rejected_through(store)
            states = await _states(store)
            decisions = await store.get_tier_c_decision_log()
        finally:
            await store.close()
        assert outcome.approved is False and "act:trip_relay" not in journal
        assert states == [(states[0][0], adm.PROPOSED)]
        assert outcome.action_taken == "rejected_unrecorded"
        assert dispatcher._decision_records_lost >= 1
        assert [d["operator_decision"] for d in decisions] == ["rejected_unrecorded"]
        assert journal == ["act:log_to_dashboard"]

    async def test_a_row_already_holding_the_state_is_the_same_decision_once(
        self, tmp_path: Any
    ) -> None:
        class _AlreadyThere(StateStore):
            async def advance_tier_c_proposal(
                self, proposal_id: str, state: str, **kwargs: Any
            ) -> bool:
                moved = await super().advance_tier_c_proposal(
                    proposal_id, state, **kwargs
                )
                # A second writer got there first with the same decision.
                return False if state == adm.REJECTED else moved

        store = _AlreadyThere(str(tmp_path / "s.db"))
        await store.open()
        try:
            outcome, dispatcher, journal = await self._rejected_through(store)
            states = await _states(store)
            decisions = await store.get_tier_c_decision_log()
        finally:
            await store.close()
        assert states == [(states[0][0], adm.REJECTED)]
        assert outcome.action_taken == "log_to_dashboard"
        assert dispatcher._decision_records_lost == 0
        assert [d["operator_decision"] for d in decisions] == ["rejected"]


class TestAJoinedContributorReportsTheProposedAct:
    """A second Tier C dispatch of the same outcome joins the open proposal.

    What it reports is what the proposed act did. After a NO or a timeout the
    act never ran, so the joiner is not executed, even though the safe default
    succeeded; the safe default's success is the holder's own record, never the
    joiner's. After a YES the act ran once, and the joiner says so.
    """

    @pytest.mark.parametrize(
        ("reply", "executor_succeeds", "proposed_ran"),
        [
            pytest.param("NO", True, False, id="no"),
            pytest.param(None, True, False, id="timeout"),
            pytest.param("YES", True, True, id="yes"),
            pytest.param("YES", False, False, id="yes-but-the-executor-failed"),
        ],
    )
    async def test_a_joiner_reports_what_the_proposed_act_did(
        self,
        tmp_path: Any,
        reply: str | None,
        executor_succeeds: bool,
        proposed_ran: bool,
    ) -> None:
        from ori.reasoning.dispatch_plan import (
            CLOSE_PROTECTED_CIRCUIT,
            OPEN_PROTECTED_CIRCUIT,
            BindingView,
        )
        from ori.reasoning.resource_gate import ResourceGate

        journal: list[str] = []
        store = StateStore(str(tmp_path / "s.db"))
        await store.open()
        operator = _Operator(reply=reply, delay_s=0.2)
        try:

            async def act(*_args: Any, **_kwargs: Any) -> bool:
                journal.append("act:trip_relay")
                return executor_succeeds

            dispatcher = _dispatcher(store, operator, journal, executor=act)
            dispatcher.bind_resource_gate(
                ResourceGate(),
                BindingView(
                    zone_identity_key=("local_gpio", "pin:26"),
                    binding_revision="7",
                    consequence_by_outcome={
                        OPEN_PROTECTED_CIRCUIT: "hard",
                        CLOSE_PROTECTED_CIRCUIT: "hard",
                    },
                ),
            )
            holder_task = asyncio.create_task(_propose(dispatcher, store, timeout=1))
            while not operator.proposals:
                await asyncio.sleep(0)
            joiner = await asyncio.wait_for(_propose(dispatcher, store, timeout=1), 10)
            holder = await asyncio.wait_for(holder_task, 10)
            await _settle(dispatcher)
            rows = await store.get_action_log(limit=50)
        finally:
            await store.close()

        assert joiner.action_taken == "coalesced"
        assert joiner.executed is proposed_ran, joiner
        approved = reply == "YES"
        assert journal.count("act:trip_relay") == (1 if approved else 0), journal
        executed_proposed = [
            row
            for row in rows
            if row["executed"] and row["action_taken"] in ("trip_relay", "coalesced")
        ]
        if approved:
            assert holder.approved is True
            assert holder.executed is proposed_ran
            if not proposed_ran:
                assert executed_proposed == [], rows
        else:
            # The safe default ran and is the holder's record; nothing records
            # the proposed act as executed.
            assert "act:log_to_dashboard" in journal, journal
            assert holder.approved is not True and holder.safe_default_used is True
            assert executed_proposed == [], rows

    async def test_an_uncertain_command_settles_on_the_proposed_act(self) -> None:
        """The uncertain-command settle applies the same rule, defensively.

        Only a Tier D act is shielded and settled this way today, and it never
        has a safe default, so this result is synthetic. It holds the settle to
        the same rule as retirement, so a future path that settles an attempt
        ended by its safe default cannot report the proposed act as accepted.
        """
        from ori.network.events import ActionResult
        from ori.reasoning.dispatch_plan import resource_identity
        from ori.reasoning.resource_gate import Contributor, ResourceGate

        gate = ResourceGate()
        dispatcher = ActionDispatcher(config={})
        dispatcher.bind_resource_gate(gate)
        identity = resource_identity(
            "trip_relay", zone_identity_key=("local_gpio", "pin:26")
        )
        assert identity is not None
        decision = await gate.request(
            identity,
            "C",
            Contributor(
                skill_name="s", trigger_name="t", action="trip_relay", dispatch_tier="C"
            ),
        )
        token = decision.token
        assert token is not None
        await gate.mark_uncertain(token)
        settled: asyncio.Future[ActionResult] = (
            asyncio.get_running_loop().create_future()
        )
        settled.set_result(
            ActionResult(
                action_name="trip_relay",
                tier="C",
                executed=True,
                approved=False,
                action_taken="log_to_dashboard",
                timestamp=now_ms(),
                safe_default_used=True,
            )
        )
        dispatcher._retire_when_settled(token, settled)
        await asyncio.wait(dispatcher.get_inflight_tier_d_tasks(), timeout=5)
        assert token.done.is_set()
        assert token.result is False


class _HostSkill:
    name = "host-guard"
    version = "1.0.0"
    first_party = True
    config: dict[str, Any] = {}
    triggers: list[Any] = []
    actions: dict[str, Any] = {
        "available": [{"name": "terminate_process", "tier": "C"}],
        "defaults": {"t": ["terminate_process"]},
    }
    sensors_required = [{"type": "cpu_percent"}]


async def test_a_joiner_on_the_host_state_workflow_is_not_executed_after_a_no(
    tmp_path: Any,
) -> None:
    """The same rule on the other approval workflow a joiner can wait on."""
    from ori.reasoning.resource_gate import ResourceGate

    store = StateStore(str(tmp_path / "s.db"))
    await store.open()
    operator = _Operator(reply="NO", delay_s=0.2)
    ran: list[str] = []
    try:
        dispatcher = ActionDispatcher(
            state_store=store,
            alert_sender=operator,
            config={"operator_contact": "+2348000000000"},
        )
        dispatcher.bind_resource_gate(ResourceGate())

        async def terminate(*_args: Any, **_kwargs: Any) -> bool:
            ran.append("terminate_process")
            return True

        dispatcher.register_executor("terminate_process", terminate)
        dispatcher.register_resource_resolver(
            "terminate_process", lambda _context: {"target": "pid:4242"}
        )

        async def propose() -> Any:
            return await dispatcher.dispatch(
                action="terminate_process",
                tier="C",
                context=SkillContext(
                    skill=_HostSkill(),
                    event=_event(),
                    state_store=store,
                    trigger_name="t",
                ),
                result=ReasoningResult(
                    text="", tier="rule", model="m", tokens_used=0, latency_ms=0
                ),
                approval_timeout=1,
            )

        holder_task = asyncio.create_task(propose())
        while not operator.proposals:
            await asyncio.sleep(0)
        joiner = await asyncio.wait_for(propose(), 10)
        holder = await asyncio.wait_for(holder_task, 10)
        await _settle(dispatcher)
        rows = await store.get_action_log(limit=50)
    finally:
        await store.close()

    assert ran == []
    assert holder.safe_default_used is True
    assert joiner.action_taken == "coalesced"
    assert joiner.executed is False, joiner
    assert [
        row
        for row in rows
        if row["executed"] and row["action_taken"] in ("terminate_process", "coalesced")
    ] == [], rows
