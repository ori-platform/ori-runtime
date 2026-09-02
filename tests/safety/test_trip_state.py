# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The trip-state machine held to the vendored lifecycle corpus, event by event."""

import json
import math
from pathlib import Path
from typing import Any

import pytest

from ori.safety.evaluation import EvaluationVerdict, evaluate_reading
from ori.safety.trip_state import (
    CommandSequenceError,
    DeferredStartupGate,
    DurableStateError,
    VerdictError,
    ZoneTripState,
)

CORPUS = json.loads(
    (Path(__file__).parent.parent / "vectors/safety_profile/lifecycle.json").read_text()
)
FIXTURES = {f["id"]: f for f in CORPUS["fixtures"]}
NON_FINITE = {"nan": math.nan, "+inf": math.inf, "-inf": -math.inf}


def _decode_value(raw: Any) -> Any:
    if isinstance(raw, dict) and set(raw) == {"non_finite"}:
        return NON_FINITE[raw["non_finite"]]
    return raw


def _trip_point(profile: dict, zone: dict) -> float:
    condition = profile["condition"]
    if condition["kind"] == "upper_capacity_multiplier":
        return condition["multiplier"] * zone["rated_capacity"]["value"]
    return condition["threshold"]


def _machine(case: dict, profile_id: str) -> ZoneTripState:
    return ZoneTripState(
        case["zone"].get("zone_id", "protected-zone"),
        profile_id,
        terminal_state=case["zone"].get("de_energised_terminal_state", "open"),
    )


def _verdict(case: dict, profile_id: str, event: dict) -> EvaluationVerdict:
    sensor = case["zone"]["sensor"]
    return evaluate_reading(
        _decode_value(event["value"]),
        sensor["unit"],
        event.get("quality", 1.0),
        expected_unit=sensor["unit"],
        trip_point=_trip_point(FIXTURES[profile_id], case["zone"]),
        range_min=sensor["range_min"],
        range_max=sensor["range_max"],
    )


def _startup(machine: ZoneTripState, case: dict, event: dict):
    return machine.startup(
        event["durable_state"] if event["durable_state"] != "none" else None,
        event.get("durable_journal", []),
        durable_command_status=event.get("durable_command_status"),
        binding_seq_in_force=case.get("binding_seq_in_force", 1),
    )


SINGLE = [c for c in CORPUS["cases"] if "profiles" not in c]
MULTI = [c for c in CORPUS["cases"] if "profiles" in c]


@pytest.mark.parametrize("case", SINGLE, ids=lambda c: c["name"])
def test_lifecycle_case(case: dict) -> None:
    machine = _machine(case, case["profile"])
    gate = DeferredStartupGate(deferred=False)
    for index, event in enumerate(case["events"]):
        kind = event["event"]
        where = f"event {index} ({kind})"
        startup_command = None
        retry = None
        if kind in ("startup", "restart"):
            transition = _startup(machine, case, event)
            startup_command = transition.startup_command
            gate = DeferredStartupGate(deferred=startup_command == "deferred")
        elif kind == "safety_path_confirmed":
            transition = machine.confirm_safety_path()
        elif kind == "reading":
            transition = machine.observe(_verdict(case, case["profile"], event))
            if transition.outcome == "open_protected_circuit":
                # The evidence sequence the contract requires: pending before
                # any driver call, then the driver's answer.
                assert machine.command_status == "command_pending", where
                machine.begin_driver_attempt()
                machine.record_driver_result(
                    accepted=event.get("driver_result", "accepted") == "accepted"
                )
                if event.get("record_result", "committed") == "write_failed":
                    machine.record_write_failed()
                gate.note_trip()
            elif transition.rejected is None:
                startup_command = gate.note_credible_reading(
                    any_pair_tripped=machine.state == "tripped"
                )
        elif kind == "arm_attempt":
            transition = machine.arm()
        elif kind == "reset_attempt":
            transition = machine.reset()
        elif kind == "retry_tick":
            transition = machine.outcome_retry()
            retry = transition.retry
            if retry == "attempted":
                machine.begin_driver_attempt()
                machine.record_driver_result(
                    accepted=event.get("driver_result", "accepted") == "accepted"
                )
        elif kind == "record_retry_tick":
            transition = machine.record_retry(
                committed=event.get("record_result", "committed") == "committed"
            )
        elif kind == "effect_report":
            transition = machine.effect_report(event["result"])
        elif kind == "binding_removed":
            transition = machine.binding_removed()
        elif kind == "orphan_retirement":
            transition = machine.retire_orphan()
        elif kind == "external":
            transition = machine.external(event["source"])
        else:
            raise AssertionError(f"unknown corpus event {kind}")

        assert transition.state == event["expect_state"], where
        assert transition.refusal == event.get("expect_refusal"), where
        assert transition.outcome == event.get("expect_outcome"), where
        assert transition.rejected == event.get("expect_rejected"), where
        if "expect_command_status" in event:
            assert machine.command_status == event["expect_command_status"], where
        if "expect_startup_command" in event:
            assert startup_command == event["expect_startup_command"], where
        if "expect_retry" in event:
            assert retry == event["expect_retry"], where
        if "expect_orphaned" in event:
            assert machine.orphaned == event["expect_orphaned"], where
        if "expect_retired" in event:
            assert machine.retired == event["expect_retired"], where
        if "expect_record" in event:
            assert machine.record_state == event["expect_record"], where
        if "expect_effect" in event:
            assert machine.effect == event["expect_effect"], where


@pytest.mark.parametrize("case", MULTI, ids=lambda c: c["name"])
def test_multi_profile_case(case: dict) -> None:
    machines = {pid: _machine(case, pid) for pid in case["profiles"]}
    gate = DeferredStartupGate(deferred=False)
    for index, event in enumerate(case["events"]):
        kind = event["event"]
        where = f"event {index} ({kind})"
        startup_command = None
        if kind == "startup":
            commands = {
                pid: _startup(machine, case, event).startup_command
                for pid, machine in machines.items()
            }
            assert len(set(commands.values())) == 1, where
            startup_command = next(iter(commands.values()))
            gate = DeferredStartupGate(deferred=startup_command == "deferred")
        elif kind == "reading":
            outcomes = {}
            for pid in case["profiles"]:
                outcomes[pid] = (
                    machines[pid].observe(_verdict(case, pid, event)).outcome
                )
                if outcomes[pid] is not None:
                    machines[pid].begin_driver_attempt()
                    machines[pid].record_driver_result(accepted=True)
            if any(outcomes.values()):
                gate.note_trip()
            else:
                startup_command = gate.note_credible_reading(
                    any_pair_tripped=any(
                        m.state == "tripped" for m in machines.values()
                    )
                )
            for pid, outcome in event.get("expect_outcomes", {}).items():
                assert outcomes[pid] == outcome, where
        else:
            raise AssertionError("multi-profile cases carry only startup and reading")
        for pid, machine in machines.items():
            assert machine.state == event["expect_states"][pid], where
        if "expect_startup_command" in event:
            assert startup_command == event["expect_startup_command"], where


@pytest.mark.parametrize(
    "case", CORPUS["durable_reject_cases"], ids=lambda c: c["name"]
)
def test_durable_reject_case(case: dict) -> None:
    machine = _machine(case, case["profile"])
    with pytest.raises(DurableStateError):
        machine.startup(
            case["durable_state"] if case["durable_state"] != "none" else None,
            case.get("durable_journal", []),
            durable_command_status=case.get("durable_command_status"),
            binding_seq_in_force=case.get("binding_seq_in_force", 1),
        )


def test_refusal_vocabularies_match_the_corpus() -> None:
    assert CORPUS["arm_refusals"] == [
        "tripped",
        "safety_path_unconfirmed",
        "no_credible_reading",
    ]
    assert CORPUS["reset_refusals"] == [
        "not_tripped",
        "no_credible_reading",
        "condition_active",
    ]
    assert CORPUS["external_refusal"] == "no_authority"


def test_every_external_source_is_refused_in_every_state() -> None:
    """One machine walked through inactive, armed, and tripped, with every
    external source refused in each state and nothing reset in between."""
    sources = (
        "remote_command",
        "skill",
        "configuration",
        "device_policy",
        "binding_revision",
    )
    machine = ZoneTripState("protected-zone", "fixture.overcurrent.v1")
    machine.startup(None)
    for expected_state, advance in (
        ("inactive", lambda: None),
        (
            "armed",
            lambda: (
                machine.confirm_safety_path(),
                machine.observe(EvaluationVerdict("no_trip")),
                machine.arm(),
            ),
        ),
        ("tripped", lambda: machine.observe(EvaluationVerdict("trip"))),
    ):
        advance()
        assert machine.state == expected_state
        for source in sources:
            assert machine.external(source).refusal == "no_authority"
            assert machine.state == expected_state


def test_deferred_gate_never_licenses_closing_on_a_tripped_zone() -> None:
    """A credible clear reading after a trip must not license the deferred
    de_energised command: a latched zone's circuit is closed only by reset.
    The specs corpus does not yet carry this case; the rule is held here."""
    gate = DeferredStartupGate(deferred=True)
    gate.note_trip()
    assert gate.note_credible_reading(any_pair_tripped=True) is None
    assert gate.note_credible_reading(any_pair_tripped=False) is None
    gate2 = DeferredStartupGate(deferred=True)
    assert gate2.note_credible_reading(any_pair_tripped=True) is None
    assert not gate2.pending
    assert gate2.note_credible_reading(any_pair_tripped=False) is None


def test_arm_refusal_order_tripped_before_unconfirmed_path() -> None:
    machine = ZoneTripState("protected-zone", "fixture.overcurrent.v1")
    machine.startup("tripped")
    assert machine.arm().refusal == "tripped"


@pytest.mark.parametrize("durable", ["trippped", "future_state", "", "TRIPPED"])
def test_unknown_durable_state_refuses_startup(durable: str) -> None:
    machine = ZoneTripState("protected-zone", "fixture.overcurrent.v1")
    machine.startup("tripped")
    with pytest.raises(DurableStateError):
        machine.startup(durable)


def test_unknown_verdict_cannot_authorize_reset() -> None:
    machine = ZoneTripState("protected-zone", "fixture.overcurrent.v1")
    machine.startup("tripped")
    with pytest.raises(VerdictError):
        machine.observe(EvaluationVerdict("future_verdict"))
    assert machine.state == "tripped"
    assert machine.reset().refusal == "no_credible_reading"


@pytest.mark.parametrize(
    "verdict",
    [
        EvaluationVerdict("rejected_input", "future_reason"),
        EvaluationVerdict("rejected_input"),
        EvaluationVerdict("trip", "out_of_range"),
        EvaluationVerdict("no_trip", "boolean"),
    ],
    ids=[
        "rejected_unknown_reason",
        "rejected_no_reason",
        "trip_with_reason",
        "no_trip_with_reason",
    ],
)
def test_contradictory_verdict_reason_pairs_refuse(verdict: EvaluationVerdict) -> None:
    machine = ZoneTripState("protected-zone", "fixture.overcurrent.v1")
    machine.startup(None)
    machine.confirm_safety_path()
    with pytest.raises(VerdictError):
        machine.observe(verdict)
    assert machine.arm().refusal == "no_credible_reading"


def test_unknown_effect_vocabulary_refuses() -> None:
    machine = ZoneTripState("protected-zone", "fixture.overcurrent.v1")
    machine.startup("tripped")
    with pytest.raises(VerdictError):
        machine.effect_report("confirmed")
    assert machine.effect == "unknown"


def test_duplicate_attempt_ids_refuse_even_when_both_unresolved() -> None:
    """Isolates the duplicate rule from the resolution invariant: two
    unresolved entries sharing an attempt id violate nothing else, so only
    the duplicate check can refuse them. The vendored reject vector pairs
    its duplicate with a resolved mark and so refuses for two reasons at
    once; the specs corpus sharpening is tracked follow-up work."""
    intent = {
        "zone_id": "protected-zone",
        "profile_id": "fixture.overcurrent.v1",
        "attempt_id": "a-1",
        "binding_seq": 1,
        "outcome": "open_protected_circuit",
        "created_at_ms": 1756684800000,
        "resolved": False,
    }
    machine = ZoneTripState("protected-zone", "fixture.overcurrent.v1")
    with pytest.raises(DurableStateError):
        machine.startup(None, [{"intent": intent}, {"intent": dict(intent)}])


def test_no_driver_result_before_the_pending_transition() -> None:
    """The evidence sequence is trip -> command_pending -> driver result. A
    result recorded with nothing pending is a claim about a call nothing
    made, in every non-pending posture."""
    machine = ZoneTripState("protected-zone", "fixture.overcurrent.v1")
    machine.startup(None)
    with pytest.raises(CommandSequenceError):
        machine.record_driver_result(accepted=True)
    machine.confirm_safety_path()
    machine.observe(EvaluationVerdict("no_trip"))
    machine.arm()
    with pytest.raises(CommandSequenceError):
        machine.record_driver_result(accepted=True)
    transition = machine.observe(EvaluationVerdict("trip"))
    assert transition.outcome == "open_protected_circuit"
    assert machine.command_status == "command_pending"
    with pytest.raises(CommandSequenceError):
        machine.record_driver_result(accepted=True)
    machine.begin_driver_attempt()
    machine.record_driver_result(accepted=True)
    assert machine.command_status == "command_issued"
    with pytest.raises(CommandSequenceError):
        machine.record_driver_result(accepted=True)


def _tripped_pending() -> ZoneTripState:
    machine = ZoneTripState("protected-zone", "fixture.overcurrent.v1")
    machine.startup(None)
    machine.observe(EvaluationVerdict("trip"))
    assert machine.command_status == "command_pending"
    return machine


def test_retry_never_doubles_a_command_in_flight() -> None:
    """The demonstrated race: a retry tick arriving while the first command
    is still awaiting its driver result must be skipped, and no second call
    can be authorised until the lease is consumed or released."""
    machine = _tripped_pending()
    machine.begin_driver_attempt()
    assert machine.outcome_retry().retry == "skipped"
    with pytest.raises(CommandSequenceError):
        machine.begin_driver_attempt()
    machine.record_driver_result(accepted=False)
    assert machine.outcome_retry().retry == "attempted"
    machine.begin_driver_attempt()
    machine.record_driver_result(accepted=True)
    assert machine.outcome_retry().retry == "skipped"


def test_timeout_releases_the_lease_for_backoff() -> None:
    machine = _tripped_pending()
    machine.begin_driver_attempt()
    machine.release_driver_attempt()
    assert machine.command_status == "command_pending"
    assert machine.outcome_retry().retry == "attempted"
    machine.begin_driver_attempt()
    machine.release_driver_attempt()
    with pytest.raises(CommandSequenceError):
        machine.release_driver_attempt()


def test_crash_drops_the_lease_but_not_the_pending_posture() -> None:
    """The lease is non-durable: after a restart the in-memory attempt is
    gone while the durable pending posture survives, so the reading-free
    retry may safely command again."""
    machine = _tripped_pending()
    machine.begin_driver_attempt()
    intent = {
        "zone_id": "protected-zone",
        "profile_id": "fixture.overcurrent.v1",
        "attempt_id": "a-1",
        "binding_seq": 1,
        "outcome": "open_protected_circuit",
        "created_at_ms": 1756684800000,
        "resolved": False,
    }
    machine.startup(None, [{"intent": intent}])
    assert machine.state == "tripped"
    assert machine.command_status == "command_pending"
    assert machine.outcome_retry().retry == "attempted"


@pytest.mark.parametrize(
    "record",
    [{}, {"command_status": None}, {"command_status": ""}, {"command_status": "none"}],
    ids=["absent", "null", "empty", "none_literal"],
)
def test_journal_record_without_a_real_status_refuses(record: dict) -> None:
    """Legacy treatment belongs to the pre-journal durable source alone: a
    journal record missing its command status is corruption, and loading it
    as retryable legacy would launder a malformed current row into history."""
    machine = ZoneTripState("protected-zone", "fixture.overcurrent.v1")
    with pytest.raises(DurableStateError):
        machine.startup("tripped", [{"record": record}])
