# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The control leg, re-signed so the consistency stage is the one that decides.

A mutated document fails at `signature` long before `proof_consistency`, so a
suite that mutates without re-signing proves the signature check works and
nothing about the leg's own rules. Every case here is signed after mutation.
"""

from __future__ import annotations

import copy
from typing import Any, Callable

import pytest

from ori.security.commissioning.binding import (
    BindingRefusedError,
    VerifierContext,
    ZoneState,
    actuator_identity,
    verify_binding_envelope,
)
from tests.commissioning.signing import (
    local_gpio_binding,
    public_key_b64,
    sign_envelope,
)

SEED = "7" * 64
DEVICE = "bench-01"
SENSOR = "load-current"


def _context() -> VerifierContext:
    import base64

    return VerifierContext(
        device_id=DEVICE,
        commissioning_anchor_current=base64.b64decode(public_key_b64(SEED)),
        commissioning_anchor_previous=None,
        provisioning_anchor=None,
        accepted_binding_seq=0,
        accepted_binding_hash=None,
        declared_sensor_ids=frozenset({SENSOR}),
        declared_actuators=(actuator_identity("local_gpio", {"gpio_pin": 26}),),
        deployment_posture="development",
        profile_multiplier=None,
    )


def _proven(**overrides: Any) -> dict[str, Any]:
    overrides.setdefault("proof_method", "actuate_and_observe")
    overrides.setdefault("control_proof_method", "commanded_and_observed")
    overrides.setdefault("active_high", False)
    return local_gpio_binding(
        device_id=DEVICE,
        sensor_id=SENSOR,
        gpio_pin=26,
        **overrides,
    )


def _verdict(mutate: Callable[[dict[str, Any]], None], **overrides: Any):
    binding = _proven(**overrides)
    mutate(binding)
    return verify_binding_envelope(sign_envelope(binding, SEED), _context())


def _leg(binding: dict[str, Any]) -> dict[str, Any]:
    return binding["zones"][0]["proof"]["control_path"]


def test_a_re_signed_proven_binding_is_in_force() -> None:
    """The baseline every case below mutates, so a refusal is the mutation's."""
    accepted = _verdict(lambda b: None)
    assert accepted.in_force_eligible
    zone = accepted.zones[0]
    assert zone.control_proof_method == "commanded_and_observed"
    assert zone.control_proof_performed_at_ms == 1800000600000


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(
            lambda b: _leg(b)["observations"][0].__setitem__("gpio_level", "low"),
            id="level_contradicts_the_polarity",
        ),
        pytest.param(
            lambda b: _leg(b)["observations"][0].__setitem__("coil_state", "energised"),
            id="coil_contradicts_the_mapping",
        ),
        pytest.param(
            lambda b: _leg(b)["observations"][0].__setitem__(
                "terminal_state_observed", "closed"
            ),
            id="terminal_contradicts_the_outcome",
        ),
        pytest.param(
            lambda b: _leg(b)["observations"][0].__setitem__(
                "load_present_before", False
            ),
            id="load_flags_contradict_the_outcome",
        ),
        pytest.param(
            lambda b: _leg(b)["observations"][0].__setitem__("sensor_after", 6.39),
            id="sensor_change_inside_the_noise_floor",
        ),
        pytest.param(
            lambda b: _leg(b).__setitem__("observations", _leg(b)["observations"][:1]),
            id="only_one_outcome_commanded",
        ),
        pytest.param(
            lambda b: _leg(b).__setitem__(
                "observations", [copy.deepcopy(_leg(b)["observations"][0])] * 2
            ),
            id="both_observations_the_same_outcome",
        ),
    ],
)
def test_a_control_leg_that_contradicts_its_mapping_is_refused(
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    with pytest.raises(BindingRefusedError) as excinfo:
        _verdict(mutate)
    assert (excinfo.value.stage, excinfo.value.reason) == (
        "proof_consistency",
        "proof_contradiction",
    )


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(
            lambda b: _leg(b)["observations"][0].pop("gpio_level"),
            id="level_missing",
        ),
        pytest.param(
            lambda b: _leg(b)["observations"][1].pop("gpio_level"),
            id="level_missing_on_the_second",
        ),
        pytest.param(
            lambda b: _leg(b).__setitem__("operator", "ade"), id="unknown_key"
        ),
        pytest.param(
            lambda b: _leg(b).__setitem__("method", "actuate_and_observe"),
            id="circuit_method_in_the_control_slot",
        ),
        pytest.param(
            lambda b: _leg(b).__setitem__("reason", "why"),
            id="reason_on_a_commanded_leg",
        ),
        pytest.param(
            lambda b: b["zones"][0]["proof"].__setitem__("control_path", None),
            id="leg_is_null",
        ),
        pytest.param(
            lambda b: b["zones"][0]["proof"].__setitem__("control_path", {}),
            id="leg_is_empty",
        ),
    ],
)
def test_a_malformed_control_leg_is_refused_at_the_grammar(
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    with pytest.raises(BindingRefusedError) as excinfo:
        _verdict(mutate)
    assert (excinfo.value.stage, excinfo.value.reason) == ("parses", "malformed")


def test_an_undemonstrated_control_leg_carrying_observations_is_refused() -> None:
    """A leg that says it proved nothing must not also carry a proof."""
    observations = copy.deepcopy(_proven()["zones"][0]["proof"]["control_path"])

    def mutate(b: dict[str, Any]) -> None:
        b["zones"][0]["proof"]["control_path"]["observations"] = observations[
            "observations"
        ]

    with pytest.raises(BindingRefusedError) as excinfo:
        _verdict(mutate, control_proof_method="undemonstrated")
    assert (excinfo.value.stage, excinfo.value.reason) == ("parses", "malformed")


@pytest.mark.parametrize(
    "control_proof_method, expected",
    [(None, None), ("undemonstrated", "undemonstrated")],
)
def test_an_unproven_control_leg_is_accepted_and_not_in_force(
    control_proof_method: str | None, expected: str | None
) -> None:
    """Absence denies; it never grants, and it is not a refusal either."""
    accepted = _verdict(lambda b: None, control_proof_method=control_proof_method)
    zone = accepted.zones[0]
    assert zone.control_proof_method == expected
    assert not zone.in_force_eligible
    assert not accepted.in_force_eligible


def test_a_control_leg_over_an_undemonstrated_circuit_leg_is_not_in_force() -> None:
    """Each leg answers a different question, so one never stands in for the other."""
    accepted = _verdict(lambda b: None, proof_method="undemonstrated")
    zone = accepted.zones[0]
    assert zone.proof_method == "undemonstrated"
    assert zone.control_proof_method == "commanded_and_observed"
    assert not zone.in_force_eligible


# ── The gates that hold on their own ─────────────────────────────────────────
#
# Routing keeps an unproven document out of `in_force`, so every later gate is
# unreachable through the loader and no end-to-end test can isolate one. Each
# is therefore driven directly with an ineligible binding placed where it
# cannot arrive, because a check that holds only because an earlier check held
# is not a boundary.


def _ineligible_state(**overrides: Any):
    from ori.security.commissioning.anchors import CommissioningAnchors
    from ori.security.commissioning.loader import (
        CommissioningState,
        DeclaredInventory,
    )

    binding = _proven(**overrides)
    accepted = verify_binding_envelope(sign_envelope(binding, SEED), _context())
    assert not accepted.in_force_eligible
    state = CommissioningState(
        anchors=CommissioningAnchors(current=None, previous=None),
        inventory=DeclaredInventory(
            sensor_ids=frozenset({SENSOR}),
            actuators=(actuator_identity("local_gpio", {"gpio_pin": 26}),),
        ),
    )
    state.in_force = accepted
    return state


@pytest.mark.parametrize(
    "overrides",
    [
        {"control_proof_method": None},
        {"control_proof_method": "undemonstrated"},
        {"proof_method": "undemonstrated"},
    ],
    ids=["absent", "undemonstrated", "circuit_leg_undemonstrated"],
)
def test_the_seam_refuses_an_ineligible_zone_placed_in_force(
    overrides: dict[str, Any],
) -> None:
    state = _ineligible_state(**overrides)
    assert state.zone_for_local_gpio(26) is None
    assert not state.actuation_licensed
    (zone,) = state.health()["zones"]
    assert zone["availability"] == "unavailable"


# ── The revision rule, leg by leg ────────────────────────────────────────────
#
# Vendored coverage arrives with the contract change that defines it; these
# drive the rule directly meanwhile.


def _retained(binding: dict[str, Any]) -> dict[str, ZoneState]:
    zone = binding["zones"][0]
    leg = zone["proof"].get("control_path")
    return {
        zone["zone_id"]: ZoneState(
            identity=dict(zone["actuator"]["identity"]),
            mapping=dict(zone["actuator"]["commissioned_mapping"]),
            calibration_ref=zone["sensor"]["calibration_ref"],
            proof_at_ms=zone["proof"]["performed_at_ms"],
            control_proof_at_ms=(
                leg["performed_at_ms"] if isinstance(leg, dict) else None
            ),
        )
    }


def _polarity_revision(control_at_ms: int, *, active_high: bool = True):
    """A revision that inverts the driver stage, carrying a fresh circuit leg."""
    first = _proven()
    revision = _proven(active_high=active_high, binding_seq=2)
    zone = revision["zones"][0]
    zone["proof"]["performed_at_ms"] = 1800000900000
    zone["proof"]["control_path"]["performed_at_ms"] = control_at_ms
    revision["supersedes"] = "sha256:" + "0" * 64
    return first, revision


def _verify_revision(first: dict[str, Any], revision: dict[str, Any]):
    import base64
    import hashlib

    from ori.security.commissioning.binding import canonical_bytes

    revision["supersedes"] = (
        "sha256:" + hashlib.sha256(canonical_bytes(_signed_body(first))).hexdigest()
    )
    ctx = VerifierContext(
        device_id=DEVICE,
        commissioning_anchor_current=base64.b64decode(public_key_b64(SEED)),
        commissioning_anchor_previous=None,
        provisioning_anchor=None,
        accepted_binding_seq=1,
        accepted_binding_hash=revision["supersedes"],
        declared_sensor_ids=frozenset({SENSOR}),
        declared_actuators=(actuator_identity("local_gpio", {"gpio_pin": 26}),),
        deployment_posture="development",
        profile_multiplier=None,
        accepted_zone_state=_retained(_signed_body(first)),
    )
    return verify_binding_envelope(sign_envelope(revision, SEED), ctx)


def _signed_body(binding: dict[str, Any]) -> dict[str, Any]:
    return sign_envelope(binding, SEED)["binding"]


def test_a_polarity_revision_refreshing_both_legs_reaches_in_force() -> None:
    first, revision = _polarity_revision(1800001200000)
    accepted = _verify_revision(first, revision)
    assert accepted.binding_seq == 2
    assert accepted.in_force_eligible
    assert accepted.zones[0].identity["active_high"] is True


@pytest.mark.parametrize("control_at_ms", [1800000600000, 1800000300000])
def test_a_polarity_revision_reusing_its_control_proof_is_refused(
    control_at_ms: int,
) -> None:
    """The proof was taken at the opposite polarity, so it asserts the inverse."""
    first, revision = _polarity_revision(control_at_ms)
    with pytest.raises(BindingRefusedError) as excinfo:
        _verify_revision(first, revision)
    assert (excinfo.value.stage, excinfo.value.reason) == (
        "proof_consistency",
        "stale_proof",
    )


def test_the_circuit_leg_is_fresh_in_that_case() -> None:
    """Otherwise the refusal would prove the circuit rule and not the control one."""
    first, revision = _polarity_revision(1800000600000)
    retained = _retained(_signed_body(first))["bench"]
    assert revision["zones"][0]["proof"]["performed_at_ms"] > retained.proof_at_ms


def test_a_revision_claiming_no_control_leg_is_provisional_not_stale() -> None:
    """A leg it does not claim is not a leg it reused."""
    first, revision = _polarity_revision(1800001200000)
    revision["zones"][0]["proof"].pop("control_path")
    accepted = _verify_revision(first, revision)
    assert not accepted.in_force_eligible


def test_a_revision_after_a_document_with_no_control_leg_is_fresh_by_construction() -> (
    None
):
    """There is nothing to inherit, so any control proof stands."""
    first = _proven(control_proof_method=None)
    _, revision = _polarity_revision(1800000300000)
    accepted = _verify_revision(first, revision)
    assert accepted.in_force_eligible
