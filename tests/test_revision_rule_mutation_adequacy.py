# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The binding corpus must refuse every wrong reading of the revision rule.

A corpus that the runtime passes proves the runtime agrees with it, not that it
would catch another consumer getting the rule wrong. This holds the corpus to a
table of plausible misreadings of commissioned-safety-binding/v1's revision
rule — each one a way a consumer could look retained zones up, decide what
changed, or judge a leg fresh — and fails if the corpus lets any of them
through.

It guards only the misreadings in ori-specs' revision-misreadings-v1.json. A
new way of getting the rule wrong is caught only once it is added to that
table, so a change to the rule's text adds its misreadings in the same change.
"""

from __future__ import annotations

import json
import random
import types
from pathlib import Path
from typing import Any

import pytest

from ori.security.commissioning import binding
from ori.security.commissioning.binding import BindingRefusedError
from tests.golden.verify_commissioned_binding_vectors import run

VECTORS = json.loads(
    (
        Path(__file__).parent
        / "vectors"
        / "commissioned_safety_binding"
        / "binding-vectors-v1.json"
    ).read_text()
)


def _switches(raw: dict) -> dict:
    """A rule from the vendored table, with its collections made comparable."""
    rule = dict(raw)
    rule["exempt"] = tuple(tuple(pair) for pair in raw["exempt"])
    rule["exempt_sets"] = tuple(
        (leg, frozenset(fields)) for leg, fields in raw["exempt_sets"]
    )
    rule["exempt_at_least"] = tuple(tuple(pair) for pair in raw["exempt_at_least"])
    rule["exempt_postures"] = tuple(tuple(pair) for pair in raw["exempt_postures"])
    rule["exempt_kind_change"] = tuple(raw["exempt_kind_change"])
    return rule


# The rule and its misreadings are published beside the corpus by ori-specs and
# vendored under the same pin, so the contract's checker and this harness hold
# the corpus to one table.
TABLE = json.loads(
    (
        Path(__file__).parent
        / "vectors"
        / "commissioned_safety_binding"
        / "revision-misreadings-v1.json"
    ).read_text()
)
REFERENCE: dict[str, Any] = _switches(TABLE["reference"])
MUTANTS: dict[str, dict[str, Any]] = TABLE["misreadings"]
CHANGE_EVENTS = {name: frozenset(f) for name, f in TABLE["change_events"].items()}


def _same_actuator(retained: dict, identity: dict, rule: dict) -> bool:
    if "gpio_pin" in retained and "gpio_pin" in identity:
        if rule["gpio_match"] == "whole":
            return retained == identity
        return bool(retained["gpio_pin"] == identity["gpio_pin"])
    if rule["firmware_match"] == "board":
        return retained.get("firmware_device_id") == identity.get("firmware_device_id")
    if rule["firmware_match"] == "channel":
        return retained.get("channel") == identity.get("channel")
    return retained == identity


def _same_sensor(was: Any, sensor: dict, rule: dict) -> bool:
    if rule["sensor_match"] == "whole":
        return bool(was.sensor == sensor)
    if rule["sensor_match"].startswith("id_and:"):
        field = rule["sensor_match"].removeprefix("id_and:")
        return bool(
            was.sensor.get("sensor_id") == sensor["sensor_id"]
            and was.sensor.get(field) == sensor.get(field)
        )
    return bool(was.sensor.get("sensor_id") == sensor["sensor_id"])


def _ways(zone_id: str, was: Any, zone: dict, rule: dict) -> set:
    ways = set()
    if rule["match_name"] and zone_id == zone["zone_id"]:
        ways.add("name")
    if rule["match_actuator"] and _same_actuator(
        was.identity, zone["actuator"]["identity"], rule
    ):
        ways.add("actuator")
    if rule["match_sensor"] and _same_sensor(was, zone["sensor"], rule):
        ways.add("sensor")
    return ways


def _identity_differs(was: dict, now: dict, rule: dict) -> bool:
    if rule["identity_compare"] == "ignore_board":
        was = {k: v for k, v in was.items() if k != "firmware_device_id"}
        now = {k: v for k, v in now.items() if k != "firmware_device_id"}
    if rule["identity_compare"] == "ignore_channel":
        was = {k: v for k, v in was.items() if k != "channel"}
        now = {k: v for k, v in now.items() if k != "channel"}
    return was != now


def _changes(zone_id: str, was: Any, zone: dict, rule: dict) -> set:
    changed = set()
    if rule["change_identity"] and _identity_differs(
        was.identity, zone["actuator"]["identity"], rule
    ):
        changed.add("identity")
    if (
        rule["change_mapping"]
        and was.mapping != zone["actuator"]["commissioned_mapping"]
    ):
        changed.add("mapping")
    sensor = zone["sensor"]
    if rule["change_sensor"] == "sensor_id":
        differs = was.sensor.get("sensor_id") != sensor["sensor_id"]
    elif rule["change_sensor"] == "id_and_calibration":
        differs = was.sensor.get("sensor_id") != sensor["sensor_id"] or was.sensor.get(
            "calibration_ref"
        ) != sensor.get("calibration_ref")
    elif rule["change_sensor"].startswith("ignore:"):
        field = rule["change_sensor"].removeprefix("ignore:")
        skip = {"range_min", "range_max"} if field == "range" else {field}
        differs = {k: v for k, v in was.sensor.items() if k not in skip} != {
            k: v for k, v in sensor.items() if k not in skip
        }
    else:
        differs = was.sensor != sensor
    if differs:
        changed.add("sensor")
    if rule["proof_change_is_change"]:
        leg = zone["proof"].get("control_path")
        if zone["proof"]["performed_at_ms"] != was.proof_at_ms or (
            isinstance(leg, dict)
            and leg.get("performed_at_ms") != was.control_proof_at_ms
        ):
            changed.add("proof")
    if rule["rename_is_change"] and zone_id != zone["zone_id"]:
        changed.add("name")
    return changed


def _field_changes(zone: dict, was: Any) -> set:
    """The individual fields a revision changed against one retained zone."""
    fields = set()
    now = zone["actuator"]["identity"]
    for key in set(was.identity) | set(now):
        if was.identity.get(key) != now.get(key):
            fields.add(key)
    if was.mapping != zone["actuator"]["commissioned_mapping"]:
        fields.add("mapping")
    for key in set(was.sensor) | set(zone["sensor"]):
        if was.sensor.get(key) != zone["sensor"].get(key):
            fields.add(key)
    return fields


def _exempt(leg: str, zone: dict, was: Any, rule: dict, posture: str) -> bool:
    fields = _field_changes(zone, was)
    if len(fields) == 1 and (leg, next(iter(fields))) in rule["exempt"]:
        return True
    if (leg, frozenset(fields)) in rule["exempt_sets"]:
        return True
    if any(leg == at and len(fields) >= k for at, k in rule["exempt_at_least"]):
        return True
    if (leg, posture) in rule["exempt_postures"]:
        return True
    if leg == "circuit":
        was_gpio = "gpio_pin" in was.identity
        now_gpio = "gpio_pin" in zone["actuator"]["identity"]
        if was_gpio and not now_gpio and "firmware" in rule["exempt_kind_change"]:
            return True
        if now_gpio and not was_gpio and "GPIO" in rule["exempt_kind_change"]:
            return True
    if (
        leg == "control"
        and rule["exempt_control_behind_pre_energisation"]
        and zone["proof"]["method"] == "pre_energisation"
    ):
        return True
    return False


def _stale(
    zone: dict,
    was: Any,
    changed: set,
    single: bool,
    rule: dict,
    posture: str = "production",
) -> bool:
    proof = zone["proof"]
    leg = proof.get("control_path")
    if rule["claimed_methods"] == "actuate_and_observe":
        unclaimed = proof["method"] != "actuate_and_observe"
    else:
        unclaimed = proof["method"] == "undemonstrated"
    control_fresh = (
        isinstance(leg, dict)
        and leg["method"] == "commanded_and_observed"
        and was.control_proof_at_ms is not None
        and leg["performed_at_ms"] > was.control_proof_at_ms
    )
    check_circuit = not (rule["circuit_unclaimed_exempt"] and unclaimed)
    if (
        rule["circuit_skip_if_control_unclaimed"]
        and isinstance(leg, dict)
        and leg["method"] == "undemonstrated"
    ):
        check_circuit = False
    if _exempt("circuit", zone, was, rule, posture):
        check_circuit = False
    circuit_retained = was.proof_at_ms
    if (
        rule["circuit_retained_time"] == "earlier"
        and was.control_proof_at_ms is not None
    ):
        circuit_retained = min(was.proof_at_ms, was.control_proof_at_ms)
    if rule["single_retained_time"] and was.control_proof_at_ms is not None:
        circuit_retained = max(was.proof_at_ms, was.control_proof_at_ms)
    if rule["circuit_skip_if_control_fresh"] and control_fresh:
        check_circuit = False
    if rule["circuit_only_single_match"] and not single:
        check_circuit = False
    if check_circuit:
        at = proof["performed_at_ms"]
        if (
            (at < circuit_retained)
            if rule["circuit_strict"]
            else (at <= circuit_retained)
        ):
            return True
    if not isinstance(leg, dict):
        return bool(
            rule["control_absent_stale"]
            and not unclaimed
            and was.control_proof_at_ms is not None
        )
    if rule["control_only_single_match"] and not single:
        return False
    if _exempt("control", zone, was, rule, posture):
        return False
    if rule["control_requires_claim"] and leg["method"] != "commanded_and_observed":
        return False
    if rule["control_skip_if_circuit_unclaimed"] and unclaimed:
        return False
    if rule["control_on"] == "identity" and "identity" not in changed:
        return False
    if rule["control_on"] == "identity_or_mapping" and not changed & {
        "identity",
        "mapping",
    }:
        return False
    retained = was.control_proof_at_ms
    if (
        rule["single_retained_time"] or rule["control_retained_time"] == "later"
    ) and retained is not None:
        retained = max(was.proof_at_ms, retained)
    if retained is None:
        if rule["control_missing"] == "stale":
            return True
        if rule["control_missing"] == "circuit_time":
            retained = was.proof_at_ms
        else:
            return False
    at = leg["performed_at_ms"]
    return (at < retained) if rule["control_strict"] else (at <= retained)


def _rule(rule: dict):
    def st_proof_consistency(b: dict[str, Any], ctx: Any) -> None:
        for zone in b["zones"]:
            proof = zone["proof"]
            if proof["method"] != "undemonstrated":
                binding._check_observations(zone, proof["observations"])
            leg = proof.get("control_path")
            if isinstance(leg, dict) and leg["method"] != "undemonstrated":
                binding._check_observations(zone, leg["observations"])
        consumed: set = set()
        for zone in b["zones"]:
            held = [
                (zone_id, was, ways)
                for zone_id, was in ctx.accepted_zone_state.items()
                if (ways := _ways(zone_id, was, zone, rule))
                and not (rule["one_to_one"] and zone_id in consumed)
            ]
            if rule["one_to_one"]:
                consumed |= {zone_id for zone_id, _was, _ways_found in held}
            if rule["fresh_against_every_match_once_changed"] and any(
                _changes(zone_id, was, zone, rule) for zone_id, was, _ in held
            ):
                for _zone_id, was, _ in held:
                    if _stale(
                        zone,
                        was,
                        {"identity"},
                        len(held) == 1,
                        rule,
                        ctx.deployment_posture,
                    ):
                        raise BindingRefusedError("proof_consistency", "stale_proof")
                continue
            if rule["visit"] == "first":
                held = held[:1]
            elif rule["visit"] == "last":
                held = held[-1:]
            elif rule["visit"] == "latest_proof" and held:
                held = [max(held, key=lambda h: h[1].proof_at_ms)]
            elif rule["visit"] == "sensor_first":
                sensor = [h for h in held if "sensor" in h[2]]
                held = sensor[:1] or held[:1]
            elif rule["visit"] == "name_if_no_actuator":
                if any("actuator" in h[2] for h in held):
                    held = [h for h in held if h[2] != {"name"}]
            for zone_id, was, _ways_found in held:
                changed = _changes(zone_id, was, zone, rule)
                if not changed:
                    if rule["visit"] == "break_on_unchanged":
                        break
                    continue
                if _stale(
                    zone, was, changed, len(held) == 1, rule, ctx.deployment_posture
                ):
                    raise BindingRefusedError("proof_consistency", "stale_proof")
                if rule["visit"] == "stop_after_pass":
                    break

    return st_proof_consistency


def _survives(rule: dict, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Cases the rule gets wrong; empty when the whole corpus agrees with it."""
    monkeypatch.setattr(binding, "st_proof_consistency", _rule(rule))
    wrong = []
    for case in VECTORS["cases"]:
        try:
            run(case["binding"], case["verifier_context"], case["signature_b64"])
        except BindingRefusedError:
            wrong.append(case["name"])
    for case in VECTORS["reject_cases"]:
        try:
            run(case["binding"], case["verifier_context"], case["signature_b64"])
            wrong.append(case["name"])
        except BindingRefusedError as refusal:
            if (refusal.stage, refusal.reason) != (case["stage"], case["reason"]):
                wrong.append(case["name"])
    return wrong


def test_the_table_measures_something() -> None:
    """An emptied table parametrises no misreading, which pytest would skip."""
    assert MUTANTS
    assert all(set(change) <= set(TABLE["reference"]) for change in MUTANTS.values())


def test_the_reference_rule_agrees_with_the_whole_corpus(monkeypatch) -> None:
    """The harness's reading is the runtime's, or a surviving mutant proves nothing."""
    assert _survives(REFERENCE, monkeypatch) == []


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_the_corpus_refuses_every_misreading_of_the_rule(name, monkeypatch) -> None:
    rule = _switches({**TABLE["reference"], **MUTANTS[name]})
    assert _survives(rule, monkeypatch), (
        f"no vector refuses the misreading {name!r}: a consumer that read the "
        "revision rule this way would pass every case. Add a vector it gets "
        "wrong. This guard covers only the misreadings enumerated in MUTANTS; "
        "exemptions keyed on a set of fields grow exponentially, so only the "
        f"sets in CHANGE_EVENTS ({', '.join(CHANGE_EVENTS)}) are enumerated."
    )


def _random_case(rng: random.Random) -> tuple[dict, Any]:
    """A revision and a retained state, varied over what the rule reads.

    GPIO and firmware identities, every proof method, and several sensor fields,
    so the reference cannot drift from the runtime where the corpus is silent.
    """
    pins, sensors = [19, 21, 26], ["s-a", "s-b", "s-c"]

    def identity(index: int) -> dict:
        if rng.random() < 0.25:
            return {
                "firmware_device_id": rng.choice(["fw-1", "fw-2"]),
                "channel": rng.choice(["r0", "r1"]),
            }
        return {"gpio_pin": pins[index], "active_high": rng.random() < 0.5}

    def sensor(sensor_id: str) -> dict:
        return {
            "sensor_id": sensor_id,
            "noise_floor": rng.choice([0.05, 0.07]),
            "range_min": rng.choice([0.0, 1.0]),
            "unit": rng.choice(["ampere", "amp"]),
            "calibration_ref": rng.choice(["c1", "c2"]),
        }

    def mapping() -> dict:
        return {"open_protected_circuit": rng.choice(["energised", "de_energised"])}

    rows = {}
    for index in range(rng.randint(1, 3)):
        rows[f"z{index}"] = binding.ZoneState(
            identity=identity(index),
            mapping=mapping(),
            sensor=sensor(sensors[index]),
            proof_at_ms=rng.choice([0, 300, 600]),
            control_proof_at_ms=rng.choice([None, 0, 300, 600]),
        )
    zones = []
    for index in range(rng.randint(1, 2)):
        proof: dict[str, Any] = {
            "method": rng.choice(
                ["actuate_and_observe", "pre_energisation", "undemonstrated"]
            ),
            "performed_at_ms": rng.choice([0, 300, 600, 900]),
            "observations": [],
        }
        if rng.random() < 0.7:
            proof["control_path"] = {
                "method": rng.choice(["commanded_and_observed", "undemonstrated"]),
                "performed_at_ms": rng.choice([0, 300, 600, 900]),
                "observations": [],
            }
        zones.append(
            {
                "zone_id": rng.choice(["z0", "z1", "z2", f"new{index}"]),
                "actuator": {
                    "identity": identity(rng.randrange(3)),
                    "commissioned_mapping": mapping(),
                },
                "sensor": sensor(rng.choice(sensors)),
                "proof": proof,
            }
        )
    return {"zones": zones}, types.SimpleNamespace(
        accepted_zone_state=rows,
        deployment_posture=rng.choice(["production", "staging", "development"]),
    )


def test_the_reference_is_the_runtime_rule_beyond_the_corpus(monkeypatch) -> None:
    """Seeded random revisions: the reference and the runtime refuse the same ones.

    Agreement on the corpus alone would let the reference drift from the runtime
    wherever the corpus is silent, and the misreadings would then be measured
    against the wrong rule. Observation checks are stubbed on both sides: this
    compares the revision rule, not the proof's internal consistency.
    """
    monkeypatch.setattr(binding, "_check_observations", lambda *_a: None)
    reference = _rule(REFERENCE)
    rng = random.Random(20260923)
    for _ in range(20_000):
        b, ctx = _random_case(rng)
        verdicts = []
        for rule in (binding.st_proof_consistency, reference):
            try:
                rule(b, ctx)
                verdicts.append("accepted")
            except BindingRefusedError as refusal:
                verdicts.append(refusal.reason)
        assert verdicts[0] == verdicts[1], (b, ctx.accepted_zone_state)
