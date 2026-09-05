# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Activation held to the vendored safety-profile corpus, case by case."""

import json
from pathlib import Path

import pytest

from ori.safety.activation import (
    ActivationResult,
    ZoneFacts,
    activate,
)
from ori.security.commissioning.profiles import (
    load_profile_set,
    load_shipped_profile_set,
)

CORPUS = json.loads(
    (
        Path(__file__).parent.parent / "vectors/safety_profile/activation.json"
    ).read_text()
)
FIXTURE_SET = load_profile_set(CORPUS["fixtures"])
HARDENED = {"staging": True, "production": True, "development": False}


def _zone(raw: dict) -> ZoneFacts:
    sensor = raw["sensor"]
    return ZoneFacts(
        zone_id=raw["zone_id"],
        sensor_id=sensor["sensor_id"],
        quantity=sensor["quantity"],
        unit=sensor["unit"],
        direction=sensor["direction"],
        range_min=sensor["range_min"],
        range_max=sensor["range_max"],
        rated_capacity_parameter=raw["rated_capacity"]["parameter"],
        rated_capacity_value=raw["rated_capacity"]["value"],
        proof_method=raw["proof_method"],
    )


def _run(case: dict) -> ActivationResult:
    profile_set = (
        FIXTURE_SET if case["profile_set"] == "fixtures" else load_shipped_profile_set()
    )
    return activate(profile_set, [_zone(z) for z in case["zones"]])


@pytest.mark.parametrize("case", CORPUS["cases"], ids=lambda c: c["name"])
def test_activation_case(case: dict) -> None:
    result = _run(case)
    expect = case["expect"]
    profile_set = (
        FIXTURE_SET if case["profile_set"] == "fixtures" else load_shipped_profile_set()
    )
    sensor_by_zone = {z["zone_id"]: z["sensor"]["sensor_id"] for z in case["zones"]}
    outcome_by_profile = {p.id: p.outcome for p in profile_set.profiles}

    # The complete activated record: this tuple is what will eventually
    # authorise a physical outcome, so every field is held to its source.
    assert {
        (a.zone_id, a.profile_id, a.trip_point, a.sensor_id, a.outcome)
        for a in result.activated
    } == {
        (
            e["zone_id"],
            e["profile"],
            e["trip_point"],
            sensor_by_zone[e["zone_id"]],
            outcome_by_profile[e["profile"]],
        )
        for e in expect["activated"]
    }
    assert {(r.zone_id, r.profile_id, r.reason) for r in result.refused} == {
        (e["zone_id"], e["profile"], e["reason"]) for e in expect["refused"]
    }
    assert {(p.zone_id, p.profile_id) for p in result.pending} == {
        (e["zone_id"], e["profile"]) for e in expect["pending_ratification"]
    }
    assert sorted(result.uncovered_zones) == sorted(expect["uncovered_zones"])
    assert (
        result.startup_verdict(hardened=HARDENED[case["posture"]]) == expect["startup"]
    )


def test_skills_are_not_an_input() -> None:
    """activate() has no parameter through which a skill could reach it; the
    corpus cases that vary installed_skills therefore run identically."""
    varied = [c for c in CORPUS["cases"] if c["installed_skills"]]
    assert varied, "the corpus carries a case with a skill installed"
    for case in varied:
        twin = dict(case, installed_skills=[])
        assert _run(case) == _run(twin)


def test_shipped_set_activates_nothing_today() -> None:
    """Every shipped profile is a candidate; a fully commissioned zone gets
    pending_ratification, never activation, until ratification flips a status."""
    shipped = load_shipped_profile_set()
    assert all(p.status == "candidate" for p in shipped.profiles)


def test_pending_ratification_precedes_every_site_fact() -> None:
    """The contract decides pending_ratification before examining any site
    fact. A candidate profile over a zone that would fail every later check
    yields only pending — a refusal here would tell the site it did
    something wrong, and it did not."""
    candidate = load_profile_set(
        [
            {
                "v": 1,
                "id": "fixture.candidate.v1",
                "status": "candidate",
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
    hostile_zone = ZoneFacts(
        zone_id="hostile",
        sensor_id="load-current-hostile",
        quantity="current",
        unit="volt",
        direction="positive_is_generation",
        range_min=0.0,
        range_max=1.0,
        rated_capacity_parameter="some_other_parameter",
        rated_capacity_value=500.0,
        proof_method="undemonstrated",
    )
    result = activate(candidate, [hostile_zone])
    assert [(p.zone_id, p.profile_id) for p in result.pending] == [
        ("hostile", "fixture.candidate.v1")
    ]
    assert result.refused == ()
    assert result.activated == ()
    assert result.startup_verdict(hardened=True) == "start"


def test_zone_facts_from_accepted_zone() -> None:
    """The production join, exercised with a real AcceptedZone."""
    from ori.security.commissioning.binding import AcceptedZone

    zone = AcceptedZone(
        zone_id="main-distribution",
        sensor_id="load-current-main",
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
            "de_energised_terminal_state": "open",
        },
        proof_method="actuate_and_observe",
        proof_performed_at_ms=1756684800000,
        control_proof_method="commanded_and_observed",
        control_proof_performed_at_ms=1756684900000,
    )
    facts = ZoneFacts.from_accepted_zone(zone)
    assert facts == ZoneFacts(
        zone_id="main-distribution",
        sensor_id="load-current-main",
        quantity="current",
        unit="ampere",
        direction="positive_is_load_draw",
        range_min=0.0,
        range_max=30.0,
        rated_capacity_parameter="rated_capacity_amps",
        rated_capacity_value=10.0,
        proof_method="actuate_and_observe",
    )


def test_an_activated_pair_records_the_profiles_own_status(monkeypatch) -> None:
    """The carry, not the re-check.

    `_protection_claim` re-reads `profile_status` where it makes the claim,
    and that re-check has its own test. This is the other half: the recorded
    value has to track the profile. A constant here would satisfy the
    re-check while saying nothing about any profile, so the two are separate
    facts and each needs its own test.

    `_check_pair` is bypassed rather than a ratified profile constructed,
    because every shipped profile is a candidate and the point is precisely
    that activation must not be trusted to have filtered them.
    """
    from ori.safety import activation as activation_module

    monkeypatch.setattr(activation_module, "_check_pair", lambda profile, zone: None)
    candidate = load_profile_set(
        [
            {
                "v": 1,
                "id": "fixture.candidate.v1",
                "status": "candidate",
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
    zone = ZoneFacts(
        zone_id="z",
        sensor_id="s",
        quantity="current",
        unit="ampere",
        direction="positive_is_load_draw",
        range_min=0.0,
        range_max=100.0,
        rated_capacity_parameter="rated_capacity_amps",
        rated_capacity_value=10.0,
        proof_method="undemonstrated",
    )

    result = activate(candidate, [zone])

    assert len(result.activated) == 1
    assert result.activated[0].profile_status == "candidate"
