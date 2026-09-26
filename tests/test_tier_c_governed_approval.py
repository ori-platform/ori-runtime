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
            assert any("never replayed" in r.getMessage() for r in caplog.records)

    async def test_a_repeated_restart_creates_one_safe_default_intent(
        self, tmp_path: Any
    ) -> None:
        path = str(tmp_path / "s.db")
        await self._left_behind(path, adm.PROPOSED)
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
        finally:
            await store.close()
        assert outcome.approved is True and outcome.executed is False
        assert outcome.action_taken == "dispatch_refused_contention"
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
