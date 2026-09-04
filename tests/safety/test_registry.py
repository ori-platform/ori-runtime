# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The registry orchestration: activation to actuation, with a fake seam."""

import asyncio
from pathlib import Path

import pytest

from ori.safety.registry import (
    SafetyRegistry,
    _RegistryAuthority,
)
from ori.security.commissioning.binding import AcceptedZone
from ori.security.commissioning.profiles import (
    load_profile_set,
    load_shipped_profile_set,
)
from ori.state.store import StateStore, TripJournal

RATIFIED = load_profile_set(
    [
        {
            "v": 1,
            "id": "fixture.overcurrent.v1",
            "status": "ratified",
            "observes": {"quantity": "current", "unit": "ampere"},
            "condition": {
                "kind": "upper_capacity_multiplier",
                "capacity_parameter": "rated_capacity_amps",
                "multiplier": 2.0,
            },
            "outcome": "open_protected_circuit",
        }
    ]
)


def zone(zone_id: str = "main-distribution", *, terminal: str = "open") -> AcceptedZone:
    return AcceptedZone(
        zone_id=zone_id,
        sensor_id=f"{zone_id}-current",
        quantity="current",
        unit="ampere",
        direction="positive_is_load_draw",
        range_min=0.0,
        range_max=30.0,
        noise_floor=0.05,
        calibration_ref="cal-2026-08",
        rated_capacity_parameter="rated_capacity_amps",
        rated_capacity_value=10.0,
        kind="local_gpio",
        identity={"chip": "gpiochip0", "line": 26, "active_high": True},
        mapping={
            "open_protected_circuit": "energised",
            "close_protected_circuit": "de_energised",
            "de_energised_terminal_state": terminal,
        },
        proof_method="actuate_and_observe",
        proof_performed_at_ms=1756684800000,
        control_proof_method="commanded_and_observed",
        control_proof_performed_at_ms=1756684900000,
    )


class FakeCommander:
    def __init__(self) -> None:
        self.outcome_calls: list[tuple[str, str]] = []
        self.startup_calls: list[str] = []
        self.accept = True

    async def command_outcome(self, zone_id: str, outcome: str) -> bool:
        self.outcome_calls.append((zone_id, outcome))
        return self.accept

    async def command_startup_de_energised(self, zone_id: str) -> bool:
        self.startup_calls.append(zone_id)
        return True


@pytest.fixture
async def store(tmp_path: Path):
    s = StateStore(db_path=str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


def build(
    store: StateStore, *zones: AcceptedZone, profile_set=None
) -> tuple[SafetyRegistry, FakeCommander]:
    commander = FakeCommander()
    registry = SafetyRegistry(
        profile_set if profile_set is not None else RATIFIED,
        zones or (zone(),),
        TripJournal(store),
        commander,
        binding_seq=4,
    )
    return registry, commander


async def test_shipped_set_is_dormant_everywhere(store: StateStore) -> None:
    """Every shipped profile is a candidate: a fully commissioned zone gets
    pending, never activation, and no reading reaches a machine."""
    registry, commander = build(store, profile_set=load_shipped_profile_set())
    assert registry.activation.activated == ()
    await registry.start()
    decisions = await registry.observe_reading(
        "main-distribution-current", 500.0, "ampere", 1.0
    )
    assert decisions == []
    assert commander.outcome_calls == []


async def test_startup_commands_de_energised_on_open_terminal(
    store: StateStore,
) -> None:
    registry, commander = build(store)
    await registry.start()
    assert commander.startup_calls == ["main-distribution"]


async def test_closed_terminal_defers_until_a_clear_reading(store: StateStore) -> None:
    registry, commander = build(store, zone(terminal="closed"))
    await registry.start()
    assert commander.startup_calls == []
    await registry.observe_reading("main-distribution-current", 5.0, "ampere", 1.0)
    assert commander.startup_calls == ["main-distribution"]


async def test_closed_terminal_hazard_first_never_closes(store: StateStore) -> None:
    registry, commander = build(store, zone(terminal="closed"))
    await registry.start()
    await registry.observe_reading("main-distribution-current", 25.0, "ampere", 1.0)
    await registry.observe_reading("main-distribution-current", 5.0, "ampere", 1.0)
    assert commander.startup_calls == []
    assert commander.outcome_calls == [("main-distribution", "open_protected_circuit")]


async def test_trip_runs_the_full_contract_sequence(store: StateStore) -> None:
    """Intent, leased command, record, mark — visible in the journal and in
    the machine the next start loads."""
    registry, commander = build(store)
    await registry.start()
    decisions = await registry.observe_reading(
        "main-distribution-current", 25.0, "ampere", 1.0
    )
    assert [d.tripped for d in decisions] == [True]
    assert commander.outcome_calls == [("main-distribution", "open_protected_circuit")]
    journal = TripJournal(store)
    durable_state, entries = await journal.load(
        "main-distribution", "fixture.overcurrent.v1"
    )
    assert durable_state == "tripped"
    kinds = [next(iter(e)) for e in entries]
    assert kinds == ["intent", "record"]
    assert entries[0]["intent"]["resolved"] is True
    assert entries[1]["record"]["command_status"] == "command_issued"

    registry2, commander2 = build(store)
    await registry2.start()
    snapshot = registry2.health_snapshot()
    pair = snapshot["pairs"]["main-distribution/fixture.overcurrent.v1"]
    assert pair["state"] == "tripped"
    assert pair["command_status"] == "command_issued"
    assert commander2.startup_calls == []


async def test_driver_refusal_retries_without_a_reading(store: StateStore) -> None:
    registry, commander = build(store)
    await registry.start()
    commander.accept = False
    await registry.observe_reading("main-distribution-current", 25.0, "ampere", 1.0)
    snapshot = registry.health_snapshot()
    assert (
        snapshot["pairs"]["main-distribution/fixture.overcurrent.v1"]["command_status"]
        == "driver_refused"
    )
    commander.accept = True
    assert await registry.retry_pending_once() == 1
    assert len(commander.outcome_calls) == 2
    assert await registry.retry_pending_once() == 0
    assert len(commander.outcome_calls) == 2


async def test_restart_with_unresolved_intent_retries_the_command(
    store: StateStore,
) -> None:
    """The crash path end to end: intent persisted, record missing, restart
    loads command_pending and the reading-free retry commands the outcome."""
    journal = TripJournal(store)
    await journal.append_intent(
        "main-distribution",
        "fixture.overcurrent.v1",
        attempt_id="crashed-1",
        binding_seq=4,
        outcome="open_protected_circuit",
        created_at_ms=1756684800000,
    )
    registry, commander = build(store)
    await registry.start()
    assert commander.startup_calls == []
    assert await registry.retry_pending_once() == 1
    assert commander.outcome_calls == [("main-distribution", "open_protected_circuit")]


async def test_orphaned_journal_pair_is_retained_and_never_actuated(
    store: StateStore,
) -> None:
    journal = TripJournal(store)
    await journal.append_intent(
        "decommissioned-zone",
        "fixture.overcurrent.v1",
        attempt_id="orphan-1",
        binding_seq=4,
        outcome="open_protected_circuit",
        created_at_ms=1756684800000,
    )
    registry, commander = build(store)
    await registry.start()
    snapshot = registry.health_snapshot()
    pair = snapshot["pairs"]["decommissioned-zone/fixture.overcurrent.v1"]
    assert pair["state"] == "tripped"
    assert pair["orphaned"] is True
    assert await registry.retry_pending_once() == 0
    assert commander.outcome_calls == []


async def test_executor_refuses_a_foreign_authority(store: StateStore) -> None:
    registry, _ = build(store)
    await registry.start()
    with pytest.raises(PermissionError):
        await registry._executor.execute(
            _RegistryAuthority(),
            ("main-distribution", "fixture.overcurrent.v1"),
            "open_protected_circuit",
            binding_seq=4,
            actuator_identity=zone().identity_key,
        )


async def test_executor_refuses_an_inactive_pair_and_a_drifted_identity(
    store: StateStore,
) -> None:
    registry, _ = build(store)
    await registry.start()
    with pytest.raises(PermissionError):
        await registry._executor.execute(
            registry._authority,
            ("main-distribution", "not-active"),
            "open_protected_circuit",
            binding_seq=4,
            actuator_identity=zone().identity_key,
        )
    with pytest.raises(PermissionError):
        await registry._executor.execute(
            registry._authority,
            ("main-distribution", "fixture.overcurrent.v1"),
            "open_protected_circuit",
            binding_seq=9,
            actuator_identity=zone().identity_key,
        )


async def test_intent_append_failure_never_delays_the_command(
    store: StateStore,
) -> None:
    """The deadline rule: a journal that hangs past the bound loses the
    intent, and the command proceeds regardless."""

    class HangingJournal(TripJournal):
        async def append_intent(self, *args, **kwargs) -> None:
            await asyncio.sleep(3600)

    commander = FakeCommander()
    registry = SafetyRegistry(
        RATIFIED, (zone(),), HangingJournal(store), commander, binding_seq=4
    )
    await registry.start()
    before = asyncio.all_tasks()
    decisions = await asyncio.wait_for(
        registry.observe_reading("main-distribution-current", 25.0, "ampere", 1.0),
        timeout=10.0,
    )
    assert [d.tripped for d in decisions] == [True]
    assert commander.outcome_calls == [("main-distribution", "open_protected_circuit")]
    # The record is deferred to recovery rather than racing the stuck write.
    pair_view = registry.health_snapshot()["pairs"][
        "main-distribution/fixture.overcurrent.v1"
    ]
    assert pair_view["command_status"] == "command_issued"
    assert pair_view["record"] == "pending"
    for task in asyncio.all_tasks() - before:
        task.cancel()


async def test_record_write_failure_is_recovered_by_persistence_alone(
    store: StateStore,
) -> None:
    class FlakyJournal(TripJournal):
        def __init__(self, store: StateStore) -> None:
            super().__init__(store)
            self.fail_records = True

        async def append_record(self, *args, **kwargs) -> None:
            if self.fail_records:
                raise OSError("disk says no")
            await super().append_record(*args, **kwargs)

    commander = FakeCommander()
    flaky = FlakyJournal(store)
    registry = SafetyRegistry(RATIFIED, (zone(),), flaky, commander, binding_seq=4)
    await registry.start()
    await registry.observe_reading("main-distribution-current", 25.0, "ampere", 1.0)
    pair_view = registry.health_snapshot()["pairs"][
        "main-distribution/fixture.overcurrent.v1"
    ]
    assert pair_view["command_status"] == "command_issued"
    assert pair_view["record"] == "pending"
    assert await registry.retry_pending_once() == 0  # never re-issues the command
    flaky.fail_records = False
    assert await registry.retry_records_once() == 1
    assert (
        registry.health_snapshot()["pairs"]["main-distribution/fixture.overcurrent.v1"][
            "record"
        ]
        == "committed"
    )
    assert len(commander.outcome_calls) == 1


async def test_rejected_reading_does_not_settle_the_deferred_gate(
    store: StateStore,
) -> None:
    """Only a credible reading licenses the deferred closing command."""
    registry, commander = build(store, zone(terminal="closed"))
    await registry.start()
    await registry.observe_reading("main-distribution-current", 5.0, "ampere", 0.0)
    assert commander.startup_calls == []
    await registry.observe_reading("main-distribution-current", 5.0, "ampere", 1.0)
    assert commander.startup_calls == ["main-distribution"]


async def test_executor_refuses_an_outcome_the_profile_does_not_authorise(
    store: StateStore,
) -> None:
    """v1 profiles only open. A close through the executor is a second path
    to reconnecting a load, refused before the commander is touched."""
    registry, commander = build(store)
    await registry.start()
    with pytest.raises(PermissionError):
        await registry._executor.execute(
            registry._authority,
            ("main-distribution", "fixture.overcurrent.v1"),
            "close_protected_circuit",
            binding_seq=4,
            actuator_identity=zone().identity_key,
        )
    assert commander.outcome_calls == []


async def test_every_retry_carries_its_own_intent(store: StateStore) -> None:
    """A retry is a new physical attempt: the journal shows intent, record,
    intent, record with distinct attempt ids, and the reload agrees."""
    registry, commander = build(store)
    await registry.start()
    commander.accept = False
    await registry.observe_reading("main-distribution-current", 25.0, "ampere", 1.0)
    commander.accept = True
    assert await registry.retry_pending_once() == 1
    journal = TripJournal(store)
    _, entries = await journal.load("main-distribution", "fixture.overcurrent.v1")
    kinds = [next(iter(e)) for e in entries]
    assert kinds == ["intent", "record", "intent", "record"]
    attempts = {e["intent"]["attempt_id"] for e in entries if "intent" in e}
    assert len(attempts) == 2
    assert entries[3]["record"]["command_status"] == "command_issued"
    registry2, _ = build(store)
    await registry2.start()
    assert (
        registry2.health_snapshot()["pairs"][
            "main-distribution/fixture.overcurrent.v1"
        ]["command_status"]
        == "command_issued"
    )


async def test_uncancellable_slow_intent_cannot_land_after_the_record(
    store: StateStore,
) -> None:
    """The reorder attack: an intent whose SQLite work outlives the deadline
    must still commit before the record, because the record queues behind it
    rather than racing a cancelled coroutine's orphaned thread."""
    import time as _time

    class SlowJournal(TripJournal):
        async def append_intent(self, *args, **kwargs) -> None:
            await asyncio.to_thread(_time.sleep, 0.6)
            await super().append_intent(*args, **kwargs)

    commander = FakeCommander()
    registry = SafetyRegistry(
        RATIFIED, (zone(),), SlowJournal(store), commander, binding_seq=4
    )
    await registry.start()
    started = asyncio.get_event_loop().time()
    await registry.observe_reading("main-distribution-current", 25.0, "ampere", 1.0)
    assert commander.outcome_calls == [("main-distribution", "open_protected_circuit")]
    assert asyncio.get_event_loop().time() - started < 5.0
    journal = TripJournal(store)
    _, entries = await journal.load("main-distribution", "fixture.overcurrent.v1")
    kinds = [next(iter(e)) for e in entries]
    assert kinds == ["intent", "record"]
    assert entries[0]["intent"]["resolved"] is True


async def test_deferred_gate_is_zonal_across_a_shared_sensor(store: StateStore) -> None:
    """A trip in one zone must not suppress another zone's deferred closing
    command when both hear the same sensor."""
    hungry = zone("hungry-zone", terminal="closed")
    calm = AcceptedZone(
        **{
            **hungry.__dict__,
            "zone_id": "calm-zone",
            "sensor_id": hungry.sensor_id,
            "rated_capacity_value": 14.0,
        }
    )
    registry, commander = build(store, hungry, calm)
    await registry.start()
    assert commander.startup_calls == []
    await registry.observe_reading(hungry.sensor_id, 25.0, "ampere", 1.0)
    assert commander.outcome_calls == [("hungry-zone", "open_protected_circuit")]
    assert commander.startup_calls == ["calm-zone"]


async def test_recovery_never_crosses_an_intent_slower_than_the_grace(
    store: StateStore,
) -> None:
    """The grace-expired path: the record defers, and recovery called while
    the intent write is still in flight must not write either — the durable
    order stays intent-then-record however slow the intent."""
    import time as _time

    class VerySlowJournal(TripJournal):
        async def append_intent(self, *args, **kwargs) -> None:
            await asyncio.to_thread(_time.sleep, 1.0)
            await super().append_intent(*args, **kwargs)

    commander = FakeCommander()
    registry = SafetyRegistry(
        RATIFIED,
        (zone(),),
        VerySlowJournal(store),
        commander,
        binding_seq=4,
        record_order_grace_s=0.1,
    )
    await registry.start()
    await registry.observe_reading("main-distribution-current", 25.0, "ampere", 1.0)
    pair_view = registry.health_snapshot()["pairs"][
        "main-distribution/fixture.overcurrent.v1"
    ]
    assert pair_view["command_status"] == "command_issued"
    assert pair_view["record"] == "pending"
    # Recovery before the intent settles writes nothing.
    assert await registry.retry_records_once() == 0
    journal = TripJournal(store)
    _, entries = await journal.load("main-distribution", "fixture.overcurrent.v1")
    assert entries == []
    # Once the intent lands, recovery persists in append order.
    await asyncio.sleep(1.2)
    assert await registry.retry_records_once() == 1
    _, entries = await journal.load("main-distribution", "fixture.overcurrent.v1")
    assert [next(iter(e)) for e in entries] == ["intent", "record"]
    assert entries[0]["intent"]["resolved"] is True


async def test_outcome_retry_never_crosses_an_unsettled_intent(
    store: StateStore,
) -> None:
    """A refused command with its intent still in flight: the reading-free
    retry waits for the intent to settle before commanding again."""
    import time as _time

    class VerySlowJournal(TripJournal):
        async def append_intent(self, *args, **kwargs) -> None:
            await asyncio.to_thread(_time.sleep, 1.0)
            await super().append_intent(*args, **kwargs)

    commander = FakeCommander()
    registry = SafetyRegistry(
        RATIFIED,
        (zone(),),
        VerySlowJournal(store),
        commander,
        binding_seq=4,
        record_order_grace_s=0.1,
    )
    await registry.start()
    commander.accept = False
    await registry.observe_reading("main-distribution-current", 25.0, "ampere", 1.0)
    commander.accept = True
    assert await registry.retry_pending_once() == 0
    assert len(commander.outcome_calls) == 1
    await asyncio.sleep(1.2)
    assert await registry.retry_pending_once() == 1
    assert len(commander.outcome_calls) == 2


class FakeSink:
    def __init__(self) -> None:
        self.notices: list[tuple[str, str]] = []

    async def send(self, *, kind, zone_id, profile_id, message) -> bool:
        self.notices.append((kind, zone_id))
        return True


class FakeClock:
    def __init__(self) -> None:
        self.now = 1_756_684_800_000

    def __call__(self) -> int:
        return self.now


def build_watched(store: StateStore, **over):
    commander = FakeCommander()
    sink = FakeSink()
    clock = FakeClock()
    registry = SafetyRegistry(
        RATIFIED,
        (zone(),),
        TripJournal(store),
        commander,
        binding_seq=4,
        alert_sink=sink,
        poll_intervals_ms=over.pop(
            "poll_intervals_ms", {"main-distribution-current": 1000}
        ),
        clock=clock,
    )
    return registry, commander, sink, clock


async def test_rejected_reading_alerts_once_under_suppression(
    store: StateStore,
) -> None:
    """An immediate Tier A notice, bounded so a persistent fault is not a
    flood, resending only after the suppression window."""
    registry, _, sink, clock = build_watched(store)
    await registry.start()
    for _ in range(3):
        await registry.observe_reading("main-distribution-current", 5.0, "volt", 1.0)
    assert sink.notices == [("rejected_input", "main-distribution")]
    assert registry.health_snapshot()["suppressed_alerts"] == 2
    pair_view = registry.health_snapshot()["pairs"][
        "main-distribution/fixture.overcurrent.v1"
    ]
    assert pair_view["rejected_input_active"] is True
    clock.now += 301_000
    await registry.observe_reading("main-distribution-current", 5.0, "volt", 1.0)
    assert len(sink.notices) == 2
    await registry.observe_reading("main-distribution-current", 5.0, "ampere", 1.0)
    assert (
        registry.health_snapshot()["pairs"]["main-distribution/fixture.overcurrent.v1"][
            "rejected_input_active"
        ]
        is False
    )


async def test_measurement_loss_degrades_alerts_and_holds_the_state(
    store: StateStore,
) -> None:
    """No credible reading past the documented bound — the 60 s floor for a
    fast poller: degraded, one notice, trip state held, and a credible
    reading recovers it."""
    registry, commander, sink, clock = build_watched(store)
    await registry.start()
    await registry.observe_reading("main-distribution-current", 25.0, "ampere", 1.0)
    assert commander.outcome_calls  # tripped and latched

    def _degraded() -> bool:
        return registry.health_snapshot()["pairs"][
            "main-distribution/fixture.overcurrent.v1"
        ]["measurement_degraded"]

    # A 1 s poller must not degrade at five intervals: the 60 s floor is a
    # floor, not five-times-interval. Well past five intervals, still silent.
    clock.now += 30_000
    await registry.watch_measurement_loss()
    assert not _degraded() and sink.notices == []
    clock.now += 29_999
    await registry.watch_measurement_loss()
    assert not _degraded() and sink.notices == []
    clock.now += 2
    await registry.watch_measurement_loss()
    assert _degraded()
    assert ("measurement_loss", "main-distribution") in sink.notices
    view = registry.health_snapshot()["pairs"][
        "main-distribution/fixture.overcurrent.v1"
    ]
    assert view["measurement_degraded"] is True
    assert view["state"] == "tripped"  # loss never moves the latch
    await registry.observe_reading("main-distribution-current", 25.0, "ampere", 1.0)
    assert (
        registry.health_snapshot()["pairs"]["main-distribution/fixture.overcurrent.v1"][
            "measurement_degraded"
        ]
        is False
    )


async def test_loss_watch_covers_a_sensor_that_never_connected(
    store: StateStore,
) -> None:
    """No reading ever arrives — the watch runs from the configured interval
    and the started baseline, not from adapter state."""
    registry, _, sink, clock = build_watched(store)
    await registry.start()
    clock.now += 60_001
    await registry.watch_measurement_loss()
    assert ("measurement_loss", "main-distribution") in sink.notices


async def test_retry_loop_runs_the_loss_watch(store: StateStore) -> None:
    registry, _, sink, clock = build_watched(store)
    await registry.start()
    clock.now += 60_001
    shutdown = asyncio.Event()

    async def _stop_soon():
        await asyncio.sleep(0.05)
        shutdown.set()

    await asyncio.gather(registry.run_retry_loop(shutdown), _stop_soon())
    await asyncio.sleep(0)
    assert ("measurement_loss", "main-distribution") in sink.notices


# ─── The protection claim (runtime-health/v2 safety_zones[]) ──────────────────


PAIR = ("main-distribution", "fixture.overcurrent.v1")


def _entry(registry, zone_id: str = "main-distribution") -> dict:
    return next(z for z in registry.safety_zones() if z["zone_id"] == zone_id)


def _backend_answers_drivable(monkeypatch) -> None:
    """Stand in for the non-actuating seam member tracked on #482.

    Everything else in the conjunction is live code today. Without this the
    claim would be `unprotected` for one reason in every case and the other
    conditions could be deleted unnoticed.
    """
    monkeypatch.setattr(SafetyRegistry, "_backend_drivable", lambda self, zone: True)


async def test_no_pair_claims_protection_while_the_backend_cannot_be_asked(
    store: StateStore,
) -> None:
    """The shipped producer never emits `protected`.

    `runtime-health/v2` puts a drivable actuator backend among the conjuncts,
    and the actuation seam carries commands and no status, so the only way to
    answer it would be to drive a coil. Nothing may move one in order to
    describe itself. `unprotected` says this side lacks the evidence for the
    positive claim; it does not assert that any backend is broken.
    """
    registry, _ = build(store)
    await registry.start()
    await registry.observe_reading("main-distribution-current", 5.0, "ampere", 1.0)

    entry = _entry(registry)
    assert entry["activation"] == "active"
    assert entry["measurement_degraded"] is False
    assert entry["rejected_input_active"] is False
    assert entry["trip_state"] != "tripped"
    assert entry["protection_claim"] == "unprotected"


async def test_a_clean_pair_claims_protection_once_the_backend_can_be_asked(
    store: StateStore, monkeypatch
) -> None:
    _backend_answers_drivable(monkeypatch)
    registry, _ = build(store)
    await registry.start()
    await registry.observe_reading("main-distribution-current", 5.0, "ampere", 1.0)

    assert _entry(registry)["protection_claim"] == "protected"


async def test_a_degraded_measurement_withdraws_the_claim_for_its_pair_only(
    store: StateStore, monkeypatch
) -> None:
    """Per affected pair, never global: a pair with nothing to evaluate is not
    watching anything, and every other pair carries on."""
    _backend_answers_drivable(monkeypatch)
    commander = FakeCommander()
    clock = FakeClock()
    registry = SafetyRegistry(
        RATIFIED,
        (zone("zone-a"), zone("zone-b")),
        TripJournal(store),
        commander,
        binding_seq=4,
        poll_intervals_ms={"zone-a-current": 1000, "zone-b-current": 1000},
        clock=clock,
    )
    await registry.start()
    for zone_id in ("zone-a", "zone-b"):
        await registry.observe_reading(f"{zone_id}-current", 5.0, "ampere", 1.0)
    assert _entry(registry, "zone-a")["protection_claim"] == "protected"

    # Only zone-a goes quiet; zone-b keeps reporting.
    clock.now += 60_001
    await registry.observe_reading("zone-b-current", 5.0, "ampere", 1.0)
    await registry.watch_measurement_loss()

    quiet, reporting = _entry(registry, "zone-a"), _entry(registry, "zone-b")
    assert quiet["measurement_degraded"] is True
    assert quiet["protection_claim"] == "unprotected"
    assert reporting["measurement_degraded"] is False
    assert reporting["protection_claim"] == "protected"


async def test_a_rejected_reading_withdraws_the_claim_and_names_the_reason(
    store: StateStore, monkeypatch
) -> None:
    """A pair whose readings are rejected is evaluating nothing credible.

    The reason comes from the contract's closed vocabulary, so an operator is
    told which rejection it was rather than that one happened.
    """
    _backend_answers_drivable(monkeypatch)
    registry, _ = build(store)
    await registry.start()
    await registry.observe_reading("main-distribution-current", 5.0, "volt", 1.0)

    entry = _entry(registry)
    assert entry["rejected_input_active"] is True
    assert entry["last_rejected_reason"] == "unit_mismatch"
    assert entry["protection_claim"] == "unprotected"

    await registry.observe_reading("main-distribution-current", 5.0, "ampere", 1.0)
    recovered = _entry(registry)
    assert recovered["rejected_input_active"] is False
    assert recovered["last_rejected_reason"] == ""
    assert recovered["protection_claim"] == "protected"


async def test_a_trip_whose_effect_is_unverified_does_not_claim_protection(
    store: StateStore, monkeypatch
) -> None:
    """It has decided to open a circuit that may still be closed."""
    _backend_answers_drivable(monkeypatch)
    registry, commander = build(store)
    await registry.start()
    await registry.observe_reading("main-distribution-current", 25.0, "ampere", 1.0)
    assert commander.outcome_calls

    entry = _entry(registry)
    assert entry["trip_state"] == "tripped"
    assert entry["effect_verified"] == "unknown"
    assert entry["protection_claim"] == "unprotected"


async def test_a_pair_held_for_ratification_is_reported_and_never_protected(
    store: StateStore, monkeypatch
) -> None:
    """Absence would read as unknown, so a pending pair is named, not omitted."""
    _backend_answers_drivable(monkeypatch)
    registry, _ = build(store, profile_set=load_shipped_profile_set())
    await registry.start()

    zones = registry.safety_zones()
    assert zones, "an eligible pair must be reported even when it did not activate"
    for entry in zones:
        assert entry["activation"] == "pending_ratification"
        assert entry["protection_claim"] == "unprotected"
        assert entry["qualification"]["state"] == "none"


async def test_a_pair_under_qualification_is_unavailable_before_anything_else(
    store: StateStore, monkeypatch
) -> None:
    """The contract decides this first, in every posture.

    Asserted against a tripped pair as well as a clean one: a check that only
    ever runs on an otherwise-perfect pair proves the value, not the ordering,
    and the ordering is the normative part.
    """
    _backend_answers_drivable(monkeypatch)
    monkeypatch.setattr(
        SafetyRegistry,
        "_qualification",
        lambda self: {
            "state": "session_open",
            "fixture_hash": "sha256:" + "0" * 64,
            "expires_at_ms": 1,
            "sessions_used": 1,
            "sessions_remaining": 0,
            "min_acceptable_seq": 1,
        },
    )
    registry, commander = build(store)
    await registry.start()
    await registry.observe_reading("main-distribution-current", 5.0, "ampere", 1.0)
    assert _entry(registry)["protection_claim"] == "unavailable"

    await registry.observe_reading("main-distribution-current", 25.0, "ampere", 1.0)
    tripped = _entry(registry)
    assert tripped["trip_state"] == "tripped"
    assert tripped["protection_claim"] == "unavailable"


async def test_a_refused_pair_is_reported_with_its_verdict_and_binding(
    store: StateStore, monkeypatch
) -> None:
    """A refused pair omitted from the array would read as unknown."""
    _backend_answers_drivable(monkeypatch)
    import dataclasses

    mismatched = dataclasses.replace(zone(), unit="milliampere")
    registry, _ = build(store, mismatched)
    await registry.start()

    entry = _entry(registry)
    assert entry["activation"] == "unit_mismatch"
    assert entry["binding_seq"] == 4
    assert entry["protection_claim"] == "unprotected"


async def test_a_trip_whose_command_was_refused_does_not_claim_protection(
    store: StateStore, monkeypatch
) -> None:
    """A verified effect is not enough when the driver never took the command.

    Both halves of the contract's exception are required: the command must
    have been issued *and* the effect matched. This pair has the second
    without the first, and has decided to open a circuit that may still be
    closed.
    """
    _backend_answers_drivable(monkeypatch)
    registry, commander = build(store)
    commander.accept = False
    await registry.start()
    await registry.observe_reading("main-distribution-current", 25.0, "ampere", 1.0)
    registry._machines[PAIR].effect_report("matched")

    entry = _entry(registry)
    assert entry["command_status"] == "driver_refused"
    assert entry["effect_verified"] == "matched"
    assert entry["protection_claim"] == "unprotected"


async def test_a_trip_that_was_issued_and_verified_still_claims_protection(
    store: StateStore, monkeypatch
) -> None:
    """Its outcome is resolved and the circuit is isolated."""
    _backend_answers_drivable(monkeypatch)
    registry, commander = build(store)
    await registry.start()
    await registry.observe_reading("main-distribution-current", 25.0, "ampere", 1.0)
    assert commander.outcome_calls
    registry._machines[PAIR].effect_report("matched")

    entry = _entry(registry)
    assert entry["trip_state"] == "tripped"
    assert entry["command_status"] == "command_issued"
    assert entry["protection_claim"] == "protected"


async def test_a_sensor_known_unavailable_degrades_its_pairs_at_once(
    store: StateStore, monkeypatch
) -> None:
    """A failed connect is not silence to be waited out.

    The loss watch infers unavailability from absent readings, so it cannot
    conclude anything before its bound — at least the documented floor. When
    the runtime already knows no reading will arrive, the pair is told
    immediately, and the clock is not moved here to prove it.
    """
    _backend_answers_drivable(monkeypatch)
    commander = FakeCommander()
    sink = FakeSink()
    clock = FakeClock()
    registry = SafetyRegistry(
        RATIFIED,
        (zone("zone-a"), zone("zone-b")),
        TripJournal(store),
        commander,
        binding_seq=4,
        alert_sink=sink,
        poll_intervals_ms={"zone-a-current": 1000, "zone-b-current": 1000},
        clock=clock,
    )
    await registry.start()
    for zone_id in ("zone-a", "zone-b"):
        await registry.observe_reading(f"{zone_id}-current", 5.0, "ampere", 1.0)
    assert _entry(registry, "zone-a")["protection_claim"] == "protected"

    await registry.note_sensor_unavailable("zone-a-current", "could not be connected")

    down = _entry(registry, "zone-a")
    assert down["measurement_degraded"] is True
    assert down["protection_claim"] == "unprotected"
    assert ("measurement_loss", "zone-a") in sink.notices

    # Per affected pair, never global: the other zone is untouched and still
    # evaluates, up to and including a trip.
    other = _entry(registry, "zone-b")
    assert other["measurement_degraded"] is False
    assert other["protection_claim"] == "protected"
    await registry.observe_reading("zone-b-current", 25.0, "ampere", 1.0)
    assert commander.outcome_calls == [("zone-b", "open_protected_circuit")]


async def test_an_unavailable_sensor_with_no_pair_is_not_an_error(
    store: StateStore,
) -> None:
    """Most sensors carry no safety pair; the runtime tells the registry anyway."""
    registry, _ = build(store)
    await registry.start()

    told = await registry.note_sensor_unavailable(
        "some-other-sensor", "could not be connected"
    )

    # Nothing was said about any pair, so the caller must speak for itself.
    assert told is False
    assert _entry(registry)["measurement_degraded"] is False
