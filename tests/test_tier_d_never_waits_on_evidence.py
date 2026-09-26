# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Nothing that records an act runs ahead of a Tier D act, or of an approved one.

Evidence attests the licence after the action and never supplies it, so a
store that is busy, locked or failing, and a signer that never returns, must
not hold a protective act — including one that follows another act of the same
event. The record of every attempt still lands afterwards, in order.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from ori.network.events import OriEvent, SensorReading
from ori.reasoning.action_dispatcher import ActionDispatcher
from ori.reasoning.dispatch_coordinator import DispatchCoordinator
from ori.reasoning.dispatch_plan import (
    CLOSE_PROTECTED_CIRCUIT,
    OPEN_PROTECTED_CIRCUIT,
    BindingView,
)
from ori.reasoning.elevator import IntelligenceElevator
from ori.reasoning.resource_gate import ResourceGate
from ori.state.store import StateStore
from ori.utils.time_utils import now_ms

ZONE = ("local_gpio", "pin:26")
BOUND = BindingView(
    zone_identity_key=ZONE,
    binding_revision="7",
    consequence_by_outcome={
        OPEN_PROTECTED_CIRCUIT: "hard",
        CLOSE_PROTECTED_CIRCUIT: "hard",
    },
)

# How long a test waits for an executor that should already have run. A
# blocked record never releases, so the bound is what turns a hang into a
# failure rather than what the property depends on.
_PROMPT = 2.0


class _Skill:
    def __init__(self, name: str, tier: str, actions: list[str]) -> None:
        from ori.skills.loader import Trigger

        self.name = name
        self.version = "1.0.0"
        self.triggers: list[Any] = [
            Trigger(
                name="t",
                condition="value > 3.0",
                action_tier=tier,
                bypass_llm=tier == "D",
                cooldown_seconds=0,
            )
        ]
        self.actions = {
            "available": [{"name": a, "tier": tier} for a in actions],
            "defaults": {"t": actions},
        }
        self.config: dict[str, Any] = {}
        self.hooks: Any = None
        self.first_party = True
        self.sensors_required = [{"type": "current_clamp"}]

    def get_default_actions(self, _sensor_type: str) -> list[str]:
        return []


def _firmware_event() -> OriEvent:
    """A firmware-sourced reading, so logging reaches the confirmation read."""
    reading = SensorReading(
        sensor_id="load-current",
        sensor_type="current_clamp",
        value=5.0,
        unit="ampere",
        timestamp=now_ms(),
        quality=1.0,
        metadata={
            "source": "firmware",
            "firmware_device_id": "fw-1",
            "boot_id": 1,
            "seq": 7,
        },
    )
    return OriEvent.from_reading(reading, "test-device")


class _RecordStore:
    """The store surface the dispatcher records through, one method blockable."""

    def __init__(
        self, *, block: str = "", fail: bool = False, locked_for: int = 0
    ) -> None:
        self.block = block
        self.fail = fail
        # Writes answered "database is locked" before the store takes one.
        self.locked_for = locked_for
        self.release = asyncio.Event()
        self.rows: list[tuple[str, str, bool, str]] = []
        self.overrides: list[str] = []
        self.attestations: dict[int, str] = {}
        self.confirmation_reads = 0
        self.registrations: list[str] = []
        self.snapshot_locked_for = 0

    async def _gate(self, name: str) -> None:
        if self.block == name:
            await self.release.wait()
        if self.fail:
            raise RuntimeError(f"store unavailable: {name}")
        if self.locked_for and name != "get_firmware_confirmation_status":
            self.locked_for -= 1
            import sqlite3

            raise sqlite3.OperationalError("database is locked")

    async def log_override(self, **kwargs: Any) -> None:
        await self._gate("log_override")
        self.overrides.append(str(kwargs.get("action")))

    async def log_action_for_event(self, result: Any, **kwargs: Any) -> int:
        await self._gate("log_action_for_event")
        self.rows.append(
            (
                result.action_name,
                result.tier,
                bool(result.executed),
                str(kwargs.get("attestation_pending")),
            )
        )
        self.registrations.append(str(kwargs.get("input_firmware_registration")))
        return len(self.rows)

    async def get_firmware_device(self, device_id: str) -> dict[str, Any]:
        if self.snapshot_locked_for:
            self.snapshot_locked_for -= 1
            import sqlite3

            raise sqlite3.OperationalError("database is locked")
        return {"device_id": device_id, "anchor_epoch_id": "epoch-1"}

    async def firmware_active_promotion_attribution(self, _device_id: str) -> None:
        return None

    async def get_firmware_confirmation_status(self, _device: str, _epoch: str) -> str:
        self.confirmation_reads += 1
        await self._gate("get_firmware_confirmation_status")
        return "confirmed"

    async def set_action_attestation(
        self, row_id: int, *, status: str, attestation_seq: Any, reason: Any = None
    ) -> None:
        self.attestations[row_id] = status


class _Signer:
    def __init__(self, *, block: bool = False) -> None:
        self.block = block
        self.release = asyncio.Event()
        self.signed: list[int] = []

    async def attest_action(self, row: dict, *, reconciled: bool = False) -> int:
        if self.block:
            await self.release.wait()
        self.signed.append(int(row["id"]))
        return len(self.signed)


class _Approver:
    """The alert sender the approval workflow sends through and listens on.

    Answers the proposal it was sent with a scoped YES, as an operator does.
    """

    def __init__(self) -> None:
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
        return f"YES-{self.proposals[-1]}"


def _executor(ran: dict[str, asyncio.Event], name: str) -> Any:
    ran[name] = asyncio.Event()

    async def run(*_args: Any, **_kwargs: Any) -> bool:
        ran[name].set()
        return True

    return run


def _build(
    store: Any,
    *,
    signer: Any = None,
    gate: bool = True,
    approver: Any = None,
) -> tuple[DispatchCoordinator, ActionDispatcher, dict[str, asyncio.Event]]:
    config: dict[str, Any] = {"relay_enabled": True}
    if approver is not None:
        config["operator_contact"] = "+2348000000000"
    dispatcher = ActionDispatcher(
        state_store=store,
        alert_sender=approver,
        evidence_attestor=signer,
        config=config,
    )
    shared = ResourceGate()
    if gate:
        dispatcher.bind_resource_gate(shared, BOUND)
    ran: dict[str, asyncio.Event] = {}
    for action in ("trip_relay", "close_gas_valve", "terminate_process"):
        dispatcher.register_executor(action, _executor(ran, action))
    dispatcher.register_resource_resolver(
        "terminate_process", lambda _context: {"target": "pid:4242"}
    )
    coordinator = DispatchCoordinator(
        elevator=IntelligenceElevator(),
        dispatcher=dispatcher,
        state_store=None,
        gate=shared,
    )
    coordinator.set_binding(BOUND)
    return coordinator, dispatcher, ran


async def _settle(
    coordinator: DispatchCoordinator,
    dispatcher: ActionDispatcher,
    *releases: asyncio.Event,
) -> None:
    """Release the held step and drain the records of acts that have settled.

    No record exists until its act settles, so the event's dispatch is awaited
    before this, or the drain finds nothing to wait for.
    """
    for release in releases:
        release.set()
    await coordinator.drain(timeout=_PROMPT)
    await dispatcher.drain_records(timeout=_PROMPT)


_BLOCKED_STEPS = [
    pytest.param({"block": "log_action_for_event"}, False, id="action-log-insert"),
    pytest.param(
        {"block": "get_firmware_confirmation_status"},
        False,
        id="confirmation-read",
    ),
    pytest.param({}, True, id="attestation-signer"),
    pytest.param({"block": "log_override"}, False, id="override-log"),
]


class TestASecondTierDActDoesNotWaitOnTheFirstActsRecord:
    @pytest.mark.parametrize(("store_kwargs", "block_signer"), _BLOCKED_STEPS)
    async def test_both_protective_acts_run_while_the_first_record_is_held(
        self, store_kwargs: dict[str, Any], block_signer: bool
    ) -> None:
        """Two Tier D acts on different resources, one discovery set.

        One commissioned zone carries every protective outcome today, so two
        granted acts in one event coalesce at the gate; the dispatcher here has
        no gate bound, which is the shape a second zone produces. What is under
        test is only whether the second act waits on the first act's record.
        """
        store = _RecordStore(**store_kwargs)
        signer = _Signer(block=block_signer)
        coordinator, dispatcher, ran = _build(store, signer=signer, gate=False)
        coordinator.add_skill(_Skill("protector-a", "D", ["trip_relay"]))
        coordinator.add_skill(_Skill("protector-b", "D", ["close_gas_valve"]))

        event_task = asyncio.create_task(coordinator.dispatch_event(_firmware_event()))
        try:
            await asyncio.wait_for(ran["trip_relay"].wait(), _PROMPT)
            await asyncio.wait_for(ran["close_gas_valve"].wait(), _PROMPT)
        finally:
            await asyncio.wait_for(event_task, _PROMPT)
            await _settle(coordinator, dispatcher, store.release, signer.release)
        # The firmware-sourced reading reached the confirmation read, came back
        # confirmed, and both rows were signed: the held step was on the path.
        assert store.confirmation_reads == 2
        assert store.attestations == {1: "signed", 2: "signed"}

    @pytest.mark.parametrize(("store_kwargs", "block_signer"), _BLOCKED_STEPS)
    async def test_one_zone_coalesces_without_waiting_on_the_record(
        self, store_kwargs: dict[str, Any], block_signer: bool
    ) -> None:
        """The gate-bound shape a device has today: the second act joins the first.

        Its outcome is known as soon as the first act is, and the event goes on
        to its notices, rather than both waiting for the first act's record.
        """
        store = _RecordStore(**store_kwargs)
        signer = _Signer(block=block_signer)
        coordinator, dispatcher, ran = _build(store, signer=signer)
        coordinator.add_skill(_Skill("protector-a", "D", ["trip_relay"]))
        coordinator.add_skill(_Skill("protector-b", "D", ["close_gas_valve"]))

        event_task = asyncio.create_task(coordinator.dispatch_event(_firmware_event()))
        try:
            done, _ = await asyncio.wait({event_task}, timeout=_PROMPT)
            assert done, "the event never passed its Tier D phase"
            assert ran["trip_relay"].is_set() != ran["close_gas_valve"].is_set()
        finally:
            await asyncio.wait_for(event_task, _PROMPT)
            await _settle(coordinator, dispatcher, store.release, signer.release)


class TestAnApprovedTierCActAfterATripDoesNotWaitOnTheTripsRecord:
    @pytest.mark.parametrize(("store_kwargs", "block_signer"), _BLOCKED_STEPS)
    async def test_the_approved_act_runs_while_the_trip_record_is_held(
        self, store_kwargs: dict[str, Any], block_signer: bool
    ) -> None:
        store = _RecordStore(**store_kwargs)
        signer = _Signer(block=block_signer)
        approver = _Approver()
        coordinator, dispatcher, ran = _build(store, signer=signer, approver=approver)
        coordinator.add_skill(_Skill("protector", "D", ["trip_relay"]))
        coordinator.add_skill(_Skill("operator-asked", "C", ["terminate_process"]))

        event_task = asyncio.create_task(coordinator.dispatch_event(_firmware_event()))
        try:
            await asyncio.wait_for(ran["trip_relay"].wait(), _PROMPT)
            await asyncio.wait_for(ran["terminate_process"].wait(), _PROMPT)
            assert approver.proposals, "the Tier C act ran without an approval"
        finally:
            await asyncio.wait_for(event_task, _PROMPT)
            await _settle(coordinator, dispatcher, store.release, signer.release)


class TestABusyStoreDoesNotHoldATrip:
    async def test_a_trip_runs_while_another_writer_holds_the_store(
        self, tmp_path: Any
    ) -> None:
        """The real store, busy with an unrelated write for as long as it likes."""
        store = StateStore(str(tmp_path / "busy.db"))
        await store.open()
        coordinator, dispatcher, ran = _build(store)
        coordinator.add_skill(_Skill("protector", "D", ["trip_relay"]))
        event_task: asyncio.Task[Any] | None = None
        try:
            async with store._write_lock:
                event_task = asyncio.create_task(
                    coordinator.dispatch_event(_firmware_event())
                )
                await asyncio.wait_for(ran["trip_relay"].wait(), _PROMPT)
            await asyncio.wait_for(event_task, _PROMPT)
            await coordinator.drain(timeout=_PROMPT)
            await dispatcher.drain_records(timeout=_PROMPT)
            rows = await store.get_action_log(limit=10)
            assert [(r["action_name"], r["tier"]) for r in rows] == [
                ("trip_relay", "D")
            ]
        finally:
            if event_task is not None and not event_task.done():
                event_task.cancel()
            await store.close()


class TestTheRecordLandsAfterTheAct:
    async def test_the_row_and_its_attestation_land_once_the_store_answers(
        self,
    ) -> None:
        store = _RecordStore(block="log_action_for_event")
        signer = _Signer()
        coordinator, dispatcher, ran = _build(store, signer=signer)
        coordinator.add_skill(_Skill("protector", "D", ["trip_relay"]))

        await asyncio.wait_for(coordinator.dispatch_event(_firmware_event()), _PROMPT)
        assert ran["trip_relay"].is_set()
        assert store.rows == []
        assert dispatcher.pending_record_count() > 0

        await _settle(coordinator, dispatcher, store.release)
        assert store.rows == [("trip_relay", "D", True, "True")]
        assert store.attestations == {1: "signed"}
        assert store.overrides == ["trip_relay"]
        assert dispatcher.pending_record_count() == 0

    async def test_a_failing_store_never_prevents_the_trip(self) -> None:
        store = _RecordStore(fail=True)
        coordinator, dispatcher, ran = _build(store, signer=_Signer())
        coordinator.add_skill(_Skill("protector", "D", ["trip_relay"]))
        coordinator.add_skill(_Skill("operator-asked", "C", ["terminate_process"]))
        dispatcher._alert_sender = _Approver()
        dispatcher._config["operator_contact"] = "+2348000000000"

        await asyncio.wait_for(coordinator.dispatch_event(_firmware_event()), _PROMPT)
        await _settle(coordinator, dispatcher)
        assert ran["trip_relay"].is_set()
        assert ran["terminate_process"].is_set()
        assert store.rows == []
        assert dispatcher.pending_record_count() == 0

    async def test_a_locked_store_is_retried_until_it_takes_the_records(
        self,
    ) -> None:
        store = _RecordStore(locked_for=4)
        coordinator, dispatcher, ran = _build(store, signer=_Signer())
        coordinator.add_skill(_Skill("protector", "D", ["trip_relay"]))

        await asyncio.wait_for(coordinator.dispatch_event(_firmware_event()), _PROMPT)
        assert ran["trip_relay"].is_set()
        await _settle(coordinator, dispatcher)
        assert store.locked_for == 0
        assert store.overrides == ["trip_relay"]
        assert store.rows == [("trip_relay", "D", True, "True")]
        assert store.attestations == {1: "signed"}

    async def test_no_record_begins_before_the_executor_has_run(self) -> None:
        """Every record of a Tier D act starts after its executor returned.

        A record queued before admission would race the executor for the
        store; the writer is asynchronous, so an `await` placed before the act
        is not the only way a record can run ahead of it.
        """
        store = _RecordStore()
        coordinator, dispatcher, ran = _build(store, signer=_Signer())
        coordinator.add_skill(_Skill("protector", "D", ["trip_relay"]))

        async def drives_the_coil(*_args: Any, **_kwargs: Any) -> bool:
            # A real executor yields to the loop while the hardware answers;
            # a record queued before admission gets the store in that gap.
            for _ in range(3):
                await asyncio.sleep(0)
            ran["trip_relay"].set()
            return True

        dispatcher.register_executor("trip_relay", drives_the_coil)
        began: list[tuple[str, bool]] = []
        original_override = store.log_override
        original_row = store.log_action_for_event

        async def override(**kwargs: Any) -> None:
            began.append(("override", ran["trip_relay"].is_set()))
            await original_override(**kwargs)

        async def row(result: Any, **kwargs: Any) -> int:
            began.append(("action_log", ran["trip_relay"].is_set()))
            return await original_row(result, **kwargs)

        store.log_override = override  # type: ignore[method-assign]
        store.log_action_for_event = row  # type: ignore[method-assign]

        await asyncio.wait_for(coordinator.dispatch_event(_firmware_event()), _PROMPT)
        await _settle(coordinator, dispatcher)
        assert ran["trip_relay"].is_set()
        # Each began after the act, the override entry ahead of the row.
        assert began == [("override", True), ("action_log", True)]
        assert store.overrides == ["trip_relay"]
        assert store.rows == [("trip_relay", "D", True, "True")]

    async def test_rows_land_in_the_order_the_acts_settled(self) -> None:
        store = _RecordStore(block="log_action_for_event")
        coordinator, dispatcher, ran = _build(store, signer=_Signer(), gate=False)
        coordinator.add_skill(_Skill("protector-a", "D", ["trip_relay"]))
        coordinator.add_skill(_Skill("protector-b", "D", ["close_gas_valve"]))

        await asyncio.wait_for(coordinator.dispatch_event(_firmware_event()), _PROMPT)
        assert ran["trip_relay"].is_set() and ran["close_gas_valve"].is_set()
        await _settle(coordinator, dispatcher, store.release)
        assert [row[0] for row in store.rows] == ["trip_relay", "close_gas_valve"]


class TestAnApprovedTierCActIsRecordedThroughATrackedRecord:
    async def test_the_operator_decision_is_held_until_the_store_takes_it(
        self,
    ) -> None:
        """Deferred like a trip's record, and held by the drain until written."""
        from ori.network.events import ReasoningResult
        from ori.reasoning.elevator import SkillContext

        store = _RecordStore()
        _, dispatcher, ran = _build(store, signer=_Signer(), approver=_Approver())
        skill = _Skill("operator-asked", "C", ["terminate_process"])
        context = SkillContext(
            skill=skill, event=_firmware_event(), state_store=None, trigger_name="t"
        )
        outcome = await dispatcher.dispatch(
            action="terminate_process",
            tier="C",
            context=context,
            result=ReasoningResult(
                text="", tier="rule", model="m", tokens_used=0, latency_ms=0
            ),
            approval_timeout=5,
        )
        assert outcome.approved is True and ran["terminate_process"].is_set()
        await dispatcher.drain_records(timeout=_PROMPT)
        assert store.rows == [("terminate_process", "C", True, "True")]
        assert store.attestations == {1: "signed"}
        assert dispatcher.pending_record_count() == 0


def _table_rows(path: str, query: str) -> list[tuple[Any, ...]]:
    import sqlite3

    with sqlite3.connect(path) as conn:
        return list(conn.execute(query))


class TestAnotherConnectionHoldingTheDatabase:
    """A second process holding a write transaction past SQLite's busy timeout.

    Each write the store attempts meanwhile waits out that timeout and fails
    with "database is locked". Nothing it would have recorded is allowed to sit
    ahead of the act, and nothing it would have recorded is lost: the records
    land once the other connection lets go.
    """

    # Past the store connection's five-second busy timeout, so at least one
    # write attempt fails outright rather than merely waiting.
    _HOLD_S = 5.6

    async def _dispatch_while_held(
        self,
        tmp_path: Any,
        action: str,
        tier: str,
        approver: Any = None,
    ) -> tuple[str, float, Any]:
        import sqlite3
        import time

        from ori.network.events import ReasoningResult
        from ori.reasoning.elevator import SkillContext

        path = str(tmp_path / "state.db")
        store = StateStore(path)
        await store.open()
        _, dispatcher, ran = _build(store, signer=_Signer(), approver=approver)
        holder = sqlite3.connect(path, isolation_level=None)
        holder.execute("BEGIN IMMEDIATE")
        started = time.monotonic()
        fired_after = -1.0
        try:
            context = SkillContext(
                skill=_Skill("protector", tier, [action]),
                event=_firmware_event(),
                state_store=store,
                trigger_name="t",
            )
            dispatch = asyncio.create_task(
                dispatcher.dispatch(
                    action=action,
                    tier=tier,
                    context=context,
                    result=ReasoningResult(
                        text="", tier="rule", model="m", tokens_used=0, latency_ms=0
                    ),
                    approval_timeout=10,
                )
            )
            await asyncio.wait_for(ran[action].wait(), 1.0)
            fired_after = time.monotonic() - started
            outcome = await asyncio.wait_for(dispatch, 15.0)
            await asyncio.sleep(max(0.0, self._HOLD_S - (time.monotonic() - started)))
        finally:
            holder.execute("ROLLBACK")
            holder.close()
        try:
            await dispatcher.drain_records(timeout=15.0)
            assert dispatcher.pending_record_count() == 0
        finally:
            await store.close()
        return path, fired_after, outcome

    async def test_a_trip_fires_at_once_and_its_records_land_afterwards(
        self, tmp_path: Any
    ) -> None:
        path, fired_after, outcome = await self._dispatch_while_held(
            tmp_path, "trip_relay", "D"
        )
        assert fired_after < 1.0
        assert outcome.executed is True
        assert _table_rows(
            path, "SELECT action_name, tier, executed FROM action_log"
        ) == [("trip_relay", "D", 1)]
        assert _table_rows(path, "SELECT action, override_type FROM override_log") == [
            ("trip_relay", "autonomous_tier_d")
        ]


def _override_rows(path: str) -> list[tuple[str, str]]:
    import sqlite3

    with sqlite3.connect(path) as conn:
        return [
            (str(action), str(kind))
            for action, kind in conn.execute(
                "SELECT action, override_type FROM override_log ORDER BY id"
            )
        ]


class TestAStopBetweenTheActAndItsRecord:
    """What a process that dies after a trip leaves behind, on the real store."""

    async def test_a_row_left_unsigned_is_found_by_reconciliation(
        self, tmp_path: Any
    ) -> None:
        path = str(tmp_path / "stop.db")
        store = StateStore(path)
        await store.open()
        signer = _Signer(block=True)
        coordinator, dispatcher, ran = _build(store, signer=signer)
        coordinator.add_skill(_Skill("protector", "D", ["trip_relay"]))

        await asyncio.wait_for(coordinator.dispatch_event(_firmware_event()), _PROMPT)
        assert ran["trip_relay"].is_set()
        # The row is written and the signature never arrives: the process stops.
        loop = asyncio.get_running_loop()
        deadline = loop.time() + _PROMPT
        while not await store.get_action_log(limit=10):
            assert loop.time() < deadline, "the action row never landed"
            await asyncio.sleep(0.01)
        await dispatcher.abandon_records()
        await store.close()

        restarted = StateStore(path)
        await restarted.open()
        try:
            needing = await restarted.get_actions_needing_attestation()
            assert [(r["action_name"], r["tier"]) for r in needing] == [
                ("trip_relay", "D")
            ]
            assert needing[0]["attestation_status"] == "pending"
        finally:
            await restarted.close()

    async def test_the_override_entry_lands_while_the_action_row_is_held(
        self, tmp_path: Any
    ) -> None:
        """A row never written is not reconciled; the override entry is what remains."""
        path = str(tmp_path / "held.db")
        release = asyncio.Event()

        class HeldInsert(StateStore):
            async def log_action_for_event(self, *args: Any, **kwargs: Any) -> int:
                await release.wait()
                return await super().log_action_for_event(*args, **kwargs)

        store = HeldInsert(path)
        await store.open()
        coordinator, dispatcher, ran = _build(store, signer=_Signer())
        coordinator.add_skill(_Skill("protector", "D", ["trip_relay"]))
        try:
            await asyncio.wait_for(
                coordinator.dispatch_event(_firmware_event()), _PROMPT
            )
            assert ran["trip_relay"].is_set()
            loop = asyncio.get_running_loop()
            deadline = loop.time() + _PROMPT
            while not _override_rows(path):
                assert loop.time() < deadline, "the override entry never landed"
                await asyncio.sleep(0.01)
            assert _override_rows(path) == [("trip_relay", "autonomous_tier_d")]
            assert await store.get_action_log(limit=10) == []
        finally:
            release.set()
            await dispatcher.drain_records(timeout=_PROMPT)
            await store.close()


class _HeldSender:
    """An emergency SMS channel that does not answer until released."""

    def __init__(self) -> None:
        self.release = asyncio.Event()
        self.sent: list[str] = []

    async def send(self, message: str, *, to_number: str) -> bool:
        await self.release.wait()
        self.sent.append(message)
        return True


class TestAFailedTripsNoticeDoesNotHoldTheNextTrip:
    async def test_the_second_act_runs_while_the_first_acts_notice_is_held(
        self,
    ) -> None:
        """Neither the other trip nor the event's approved act waits on the notice."""
        store = _RecordStore()
        coordinator, dispatcher, ran = _build(
            store, signer=_Signer(), gate=False, approver=_Approver()
        )
        sender = _HeldSender()
        dispatcher._emergency_sms_sender = sender

        async def failing(*_args: Any, **_kwargs: Any) -> bool:
            return False

        dispatcher.register_executor("trip_relay", failing)
        coordinator.add_skill(_Skill("protector-a", "D", ["trip_relay"]))
        coordinator.add_skill(_Skill("protector-b", "D", ["close_gas_valve"]))
        coordinator.add_skill(_Skill("operator-asked", "C", ["terminate_process"]))

        event_task = asyncio.create_task(coordinator.dispatch_event(_firmware_event()))
        try:
            await asyncio.wait_for(ran["close_gas_valve"].wait(), _PROMPT)
            await asyncio.wait_for(ran["terminate_process"].wait(), _PROMPT)
            assert sender.sent == []
        finally:
            sender.release.set()
            await asyncio.wait_for(event_task, _PROMPT)
            if pending := dispatcher.get_inflight_tier_d_tasks():
                await asyncio.wait(pending, timeout=_PROMPT)
        assert len(sender.sent) == 1 and "trip_relay" in sender.sent[0]


class TestABacklogOfRecordsIsBounded:
    async def test_records_past_the_ceiling_are_counted_lost_and_acts_still_run(
        self, caplog: Any
    ) -> None:
        """A store that never answers cannot grow the backlog without limit."""
        import logging

        from ori.network.events import ReasoningResult
        from ori.reasoning.elevator import SkillContext

        store = _RecordStore(locked_for=10_000)
        _, dispatcher, ran = _build(store, signer=_Signer(), gate=False)
        dispatcher._records.ceiling = 4
        executed = 0

        async def trip(*_args: Any, **_kwargs: Any) -> bool:
            nonlocal executed
            executed += 1
            return True

        dispatcher.register_executor("trip_relay", trip)
        context = SkillContext(
            skill=_Skill("protector", "D", ["trip_relay"]),
            event=_firmware_event(),
            state_store=None,
            trigger_name="t",
        )
        with caplog.at_level(logging.CRITICAL):
            for _ in range(10):
                outcome = await asyncio.wait_for(
                    dispatcher.dispatch(
                        action="trip_relay",
                        tier="D",
                        context=context,
                        result=ReasoningResult(
                            text="", tier="rule", model="m", tokens_used=0, latency_ms=0
                        ),
                    ),
                    _PROMPT,
                )
                assert outcome.executed is True
        assert executed == 10
        # The last act's row becomes writable one loop turn after it returns.
        await asyncio.sleep(0)
        backlog = dispatcher.record_backlog()
        # Ten acts, two records each: the ceiling is held and the rest counted.
        assert backlog["pending"] == 4
        assert backlog["lost"] == 16
        assert any("lost" in r.getMessage() for r in caplog.records)

        store.locked_for = 0
        await dispatcher.drain_records(timeout=_PROMPT)
        assert dispatcher.pending_record_count() == 0
        assert len(store.overrides) + len(store.rows) == 4
        assert dispatcher.record_backlog()["lost"] == 16


# ── the real store, one method at a time ─────────────────────────────────────


def _locked_store(path: str, method: str, times: int) -> StateStore:
    """A real store whose *method* answers "database is locked" *times* times."""
    import sqlite3

    remaining = {"n": times}

    class Locked(StateStore):
        pass

    original = getattr(StateStore, method)

    async def locked(self: StateStore, *args: Any, **kwargs: Any) -> Any:
        if remaining["n"] > 0:
            remaining["n"] -= 1
            raise sqlite3.OperationalError("database is locked")
        return await original(self, *args, **kwargs)

    setattr(Locked, method, locked)
    store = Locked(path)
    store.locked_remaining = remaining  # type: ignore[attr-defined]
    return store


def _reasoning() -> Any:
    from ori.network.events import ReasoningResult

    return ReasoningResult(text="", tier="rule", model="m", tokens_used=0, latency_ms=0)


def _context(store: Any, skill: Any) -> Any:
    from ori.reasoning.elevator import SkillContext

    return SkillContext(
        skill=skill, event=_firmware_event(), state_store=store, trigger_name="t"
    )


class _Replying:
    """An alert sender whose operator answers each proposal with *reply*."""

    def __init__(self, reply: str) -> None:
        self.reply = reply
        self.proposals: list[str] = []

    async def send(self, *, alert: Any, to_number: str) -> bool:
        if alert.intent.value == "tier_c_approval":
            self.proposals.append(str(alert.template_variables[3]))
        return True

    async def listen_for_response(
        self, *, from_number: str, timeout_seconds: int
    ) -> str | None:
        while not self.proposals:
            await asyncio.sleep(0)
        return f"{self.reply}-{self.proposals[-1]}"


class TestEveryRecordSurvivesALockedStore:
    """Each record path, locked on its own, still lands once the store answers."""

    @pytest.mark.parametrize(
        ("method", "reply"),
        [
            ("log_action_for_event", "YES"),
            ("log_tier_c_decision", "YES"),
            ("log_override", "NO"),
            ("store_rejection", "NO"),
        ],
    )
    async def test_the_operator_decision_and_its_act_land(
        self, tmp_path: Any, method: str, reply: str
    ) -> None:
        path = str(tmp_path / "state.db")
        store = _locked_store(path, method, 3)
        await store.open()
        try:
            _, dispatcher, ran = _build(
                store, signer=_Signer(), approver=_Replying(reply)
            )
            outcome = await dispatcher.dispatch(
                action="terminate_process",
                tier="C",
                context=_context(store, _Skill("asked", "C", ["terminate_process"])),
                result=_reasoning(),
                approval_timeout=5,
            )
            await dispatcher.drain_records(timeout=_PROMPT)
            assert store.locked_remaining["n"] == 0  # type: ignore[attr-defined]
            assert dispatcher.record_backlog()["lost"] == 0
            decisions = await store.get_tier_c_decision_log()
            rows = await store.get_action_log()
        finally:
            await store.close()
        approved = reply == "YES"
        assert outcome.approved is approved
        assert ran["terminate_process"].is_set() is approved
        assert [(r["action_name"], r["tier"]) for r in rows] == [
            ("terminate_process", "C")
        ]
        assert [(d["proposal_id"], d["operator_decision"]) for d in decisions] == [
            (outcome.proposal_id, "approved" if approved else "rejected")
        ]
        overrides = _override_rows(path)
        assert overrides == ([] if approved else [("terminate_process", "rejection")])
        if not approved:
            import sqlite3

            with sqlite3.connect(path) as conn:
                patterns = conn.execute(
                    "SELECT proposed_action FROM causal_memory_rejections"
                ).fetchall()
            assert patterns == [("terminate_process",)]

    async def test_the_firmware_snapshot_is_retried_with_its_row(self) -> None:
        store = _RecordStore()
        store.snapshot_locked_for = 2
        coordinator, dispatcher, ran = _build(store, signer=_Signer())
        coordinator.add_skill(_Skill("protector", "D", ["trip_relay"]))
        await asyncio.wait_for(coordinator.dispatch_event(_firmware_event()), _PROMPT)
        await _settle(coordinator, dispatcher)
        assert store.snapshot_locked_for == 0
        assert len(store.registrations) == 1
        assert "epoch-1" in store.registrations[0]


class TestAStoreThatWillNotAnswerIsReported:
    async def test_a_permanent_store_error_is_counted_lost_not_retried(self) -> None:
        import sqlite3

        store = _RecordStore()

        async def readonly(**_kwargs: Any) -> None:
            raise sqlite3.OperationalError("attempt to write a readonly database")

        store.log_override = readonly  # type: ignore[method-assign]
        coordinator, dispatcher, ran = _build(store, signer=_Signer())
        coordinator.add_skill(_Skill("protector", "D", ["trip_relay"]))
        for _ in range(3):
            await asyncio.wait_for(
                coordinator.dispatch_event(_firmware_event()), _PROMPT
            )
        await _settle(coordinator, dispatcher)
        assert dispatcher.record_backlog()["lost"] == 3
        # The rows behind the refused entries are not held by them.
        assert [row[0] for row in store.rows] == ["trip_relay"] * 3

    async def test_a_signer_that_never_answers_leaves_its_row_pending(
        self, monkeypatch: Any
    ) -> None:
        import ori.reasoning.action_dispatcher as dispatcher_module

        monkeypatch.setattr(dispatcher_module, "_ATTESTATION_BOUND_S", 0.2)
        store = _RecordStore()
        signer = _Signer(block=True)
        _, dispatcher, ran = _build(store, signer=signer, approver=_Approver())
        await dispatcher.dispatch(
            action="trip_relay",
            tier="D",
            context=_context(None, _Skill("protector", "D", ["trip_relay"])),
            result=_reasoning(),
        )
        await dispatcher.dispatch(
            action="terminate_process",
            tier="C",
            context=_context(None, _Skill("asked", "C", ["terminate_process"])),
            result=_reasoning(),
            approval_timeout=5,
        )
        await dispatcher.drain_records(timeout=_PROMPT)
        try:
            assert [row[0] for row in store.rows] == ["trip_relay", "terminate_process"]
            # Neither row was marked: both stay pending for reconciliation.
            assert store.attestations == {}
            assert dispatcher.pending_record_count() == 0
        finally:
            signer.release.set()

    async def test_a_record_queue_that_stalls_ages_in_health(self) -> None:
        store = _RecordStore(block="log_override")
        _, dispatcher, ran = _build(store, signer=_Signer())
        await asyncio.wait_for(
            dispatcher.dispatch(
                action="trip_relay",
                tier="D",
                context=_context(None, _Skill("protector", "D", ["trip_relay"])),
                result=_reasoning(),
            ),
            _PROMPT,
        )
        await asyncio.sleep(0.05)
        try:
            assert dispatcher.record_backlog()["oldest_pending_age_ms"] >= 40
        finally:
            store.release.set()
            await dispatcher.drain_records(timeout=_PROMPT)
        assert dispatcher.record_backlog()["oldest_pending_age_ms"] == 0


class TestARecordWithNothingToRecordLeavesTheQueueWorking:
    async def test_a_dispatch_cancelled_before_its_act_does_not_wedge_the_writer(
        self,
    ) -> None:
        """A joined trip cancelled while it waits: its record has no result."""
        store = _RecordStore()
        _, dispatcher, ran = _build(store, signer=_Signer())
        release = asyncio.Event()

        async def slow(*_args: Any, **_kwargs: Any) -> bool:
            await release.wait()
            return True

        dispatcher.register_executor("trip_relay", slow)
        skill = _Skill("protector", "D", ["trip_relay"])
        first = asyncio.create_task(
            dispatcher.dispatch(
                action="trip_relay",
                tier="D",
                context=_context(None, skill),
                result=_reasoning(),
            )
        )
        await asyncio.sleep(0.02)
        joiner = asyncio.create_task(
            dispatcher.dispatch(
                action="trip_relay",
                tier="D",
                context=_context(None, skill),
                result=_reasoning(),
            )
        )
        await asyncio.sleep(0.02)
        joiner.cancel()
        await asyncio.gather(joiner, return_exceptions=True)
        release.set()
        await asyncio.wait_for(first, _PROMPT)
        await dispatcher.drain_records(timeout=_PROMPT)
        assert dispatcher.record_backlog()["lost"] == 0
        assert [row[0] for row in store.rows] == ["trip_relay"]
        # The joiner never acted, so nothing says it dispatched autonomously.
        assert store.overrides == ["trip_relay"]

    async def test_an_interrupted_act_records_what_its_executor_reported(
        self,
    ) -> None:
        store = _RecordStore()
        _, dispatcher, ran = _build(store, signer=_Signer())
        started = asyncio.Event()
        release = asyncio.Event()

        async def slow(*_args: Any, **_kwargs: Any) -> bool:
            started.set()
            await release.wait()
            return True

        dispatcher.register_executor("trip_relay", slow)
        task = asyncio.create_task(
            dispatcher.dispatch(
                action="trip_relay",
                tier="D",
                context=_context(None, _Skill("protector", "D", ["trip_relay"])),
                result=_reasoning(),
            )
        )
        await started.wait()
        task.cancel()
        interrupted = (await asyncio.gather(task, return_exceptions=True))[0]
        assert getattr(interrupted, "executed", None) is False
        await dispatcher.drain_records(timeout=_PROMPT)
        assert store.rows == []
        release.set()
        pending = dispatcher.get_inflight_tier_d_tasks()
        if pending:
            await asyncio.wait(pending, timeout=_PROMPT)
        await dispatcher.drain_records(timeout=_PROMPT)
        assert store.rows == [("trip_relay", "D", True, "True")]


class TestShutdownWithAnApprovalOpen:
    async def test_an_open_approval_is_reported_once_and_never_waited_for(
        self, caplog: Any
    ) -> None:
        import logging
        import time

        class Silent:
            async def send(self, **_kwargs: Any) -> bool:
                return True

            async def listen_for_response(self, **_kwargs: Any) -> None:
                await asyncio.sleep(3600)

        store = _RecordStore()
        _, dispatcher, ran = _build(store, approver=Silent())
        task = asyncio.create_task(
            dispatcher.dispatch(
                action="terminate_process",
                tier="C",
                context=_context(None, _Skill("asked", "C", ["terminate_process"])),
                result=_reasoning(),
                approval_timeout=300,
            )
        )
        await asyncio.sleep(0.05)
        started = time.monotonic()
        await dispatcher.drain_records(timeout=2.0)
        assert time.monotonic() - started < 0.5
        with caplog.at_level(logging.CRITICAL):
            assert await dispatcher.abandon_records() == 0
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await asyncio.sleep(0)
        assert dispatcher.record_backlog()["lost"] == 0
        messages = [r.getMessage() for r in caplog.records]
        assert any("had not settled at shutdown" in m for m in messages)
        assert any("settled after shutdown" in m for m in messages)


class TestAHungExecutorHoldsNoOtherProtectiveAct:
    async def test_a_second_resource_is_attempted_while_the_first_hangs(
        self,
    ) -> None:
        store = _RecordStore()
        coordinator, dispatcher, ran = _build(store, signer=_Signer(), gate=False)
        hang = asyncio.Event()

        async def hung(*_args: Any, **_kwargs: Any) -> bool:
            await hang.wait()
            return True

        dispatcher.register_executor("trip_relay", hung)
        coordinator.add_skill(_Skill("protector-a", "D", ["trip_relay"]))
        coordinator.add_skill(_Skill("protector-b", "D", ["close_gas_valve"]))
        event_task = asyncio.create_task(coordinator.dispatch_event(_firmware_event()))
        try:
            await asyncio.wait_for(ran["close_gas_valve"].wait(), _PROMPT)
        finally:
            hang.set()
            await asyncio.wait_for(event_task, _PROMPT)
            await _settle(coordinator, dispatcher)


# ── the local console and its offline token ──────────────────────────────────
