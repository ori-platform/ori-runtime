# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The binding loader: file beside the config in, binding in force out, retained."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from ori.security.commissioning.anchors import CommissioningAnchors
from ori.security.commissioning.binding import actuator_identity
from ori.security.commissioning.loader import (
    BINDING_RELATIVE_PATH,
    DeclaredInventory,
    load_commissioning_state,
)
from ori.security.commissioning.profiles import load_shipped_profile_set
from ori.state.store import StateStore

CORPUS = json.loads(
    (
        Path(__file__).parent.parent
        / "vectors"
        / "commissioned_safety_binding"
        / "binding-vectors-v1.json"
    ).read_text()
)
ACCEPT = next(
    c for c in CORPUS["cases"] if c["name"] == "two_zone_site_correctly_bound"
)
CTX = ACCEPT["verifier_context"]


def _anchors() -> CommissioningAnchors:
    return CommissioningAnchors(
        current=bytes.fromhex(CTX["commissioning_anchor_current_hex"]),
        previous=bytes.fromhex(CTX["commissioning_anchor_previous_hex"]),
    )


def _inventory() -> DeclaredInventory:
    declared = CTX["declared_inventory"]
    return DeclaredInventory(
        sensor_ids=frozenset(declared["sensor_ids"]),
        actuators=tuple(
            actuator_identity(a["kind"], a["identity"]) for a in declared["actuators"]
        ),
    )


def _envelope() -> dict[str, Any]:
    return {
        "binding": copy.deepcopy(ACCEPT["binding"]),
        "signature": "ed25519:" + ACCEPT["signature_b64"],
    }


def _write(data_path: Path, envelope: dict[str, Any]) -> Path:
    target = data_path / BINDING_RELATIVE_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(envelope))
    return target


async def _load(data_path: Path, store: StateStore, **overrides: Any):
    kwargs: dict[str, Any] = dict(
        data_path=data_path,
        device_id=CTX["device_id"],
        anchors=_anchors(),
        provisioning_anchor=bytes.fromhex(CTX["provisioning_anchor_hex"]),
        inventory=_inventory(),
        posture="production",
        profiles=load_shipped_profile_set(),
        store=store,
    )
    kwargs.update(overrides)
    return await load_commissioning_state(**kwargs)


@pytest.fixture
async def store(tmp_path: Path):
    s = StateStore(db_path=str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


async def test_a_valid_binding_is_accepted_retained_and_licenses_actuation(
    tmp_path: Path, store: StateStore
) -> None:
    _write(tmp_path, _envelope())
    state = await _load(tmp_path, store)
    assert state.in_force is not None
    assert state.in_force.binding_seq == 1
    assert state.in_force.canonical_hash == ACCEPT["canonical_sha256"]
    assert state.last_verdict is not None
    assert (state.last_verdict.stage, state.last_verdict.reason) == (
        "accepted",
        "accepted",
    )
    assert state.actuation_licensed
    zone = state.zone_for_local_gpio(26)
    assert zone is not None and zone.identity["active_high"] is False
    assert zone.mapping["open_protected_circuit"] == "de_energised"
    retained = await store.get_commissioned_binding_in_force()
    assert (
        retained is not None
        and retained["canonical_hash"] == ACCEPT["canonical_sha256"]
    )
    health = state.health()
    assert health["binding_seq"] == 1 and health["actuation_licensed"] is True
    assert {z["zone_id"] for z in health["zones"]} == {
        z["zone_id"] for z in ACCEPT["binding"]["zones"]
    }


async def test_a_restart_reloads_the_binding_in_force_from_the_store(
    tmp_path: Path, store: StateStore
) -> None:
    path = _write(tmp_path, _envelope())
    await _load(tmp_path, store)
    path.unlink()
    state = await _load(tmp_path, store)
    assert state.in_force is not None and state.in_force.binding_seq == 1
    assert state.last_verdict is None
    assert state.actuation_licensed
    assert state.problems == []


async def test_the_file_already_in_force_is_not_re_decided(
    tmp_path: Path, store: StateStore
) -> None:
    _write(tmp_path, _envelope())
    await _load(tmp_path, store)
    state = await _load(tmp_path, store)
    assert state.last_verdict is not None and state.last_verdict.reason == "accepted"
    assert state.last_verdict.binding_seq == 1
    history = await store.commissioned_binding_history()
    assert [h["binding_seq"] for h in history] == [1]


async def test_a_refused_document_leaves_the_binding_in_force_unchanged(
    tmp_path: Path, store: StateStore
) -> None:
    _write(tmp_path, _envelope())
    await _load(tmp_path, store)
    tampered = _envelope()
    tampered["binding"]["binding_seq"] = 2
    tampered["binding"]["supersedes"] = ACCEPT["canonical_sha256"]
    tampered["binding"]["zones"][0]["actuator"]["identity"]["active_high"] = True
    _write(tmp_path, tampered)
    state = await _load(tmp_path, store)
    assert state.in_force is not None and state.in_force.binding_seq == 1
    assert state.last_verdict is not None
    assert (state.last_verdict.stage, state.last_verdict.reason) == (
        "signature",
        "bad_signature",
    )
    assert state.last_verdict.binding_seq == 2
    assert state.actuation_licensed


async def test_a_different_body_under_the_retained_signature_is_verified_not_shortcut(
    tmp_path: Path, store: StateStore
) -> None:
    """The in-force shortcut compares signed bytes, never the signature alone."""
    _write(tmp_path, _envelope())
    await _load(tmp_path, store)
    other = _envelope()
    other["binding"]["reason"] = "re-signed elsewhere"
    _write(tmp_path, other)
    state = await _load(tmp_path, store)
    assert state.last_verdict is not None
    assert (state.last_verdict.stage, state.last_verdict.reason) == (
        "signature",
        "bad_signature",
    )
    assert state.in_force is not None and state.in_force.binding_seq == 1


async def test_no_binding_with_declared_actuators_is_unlicensed_and_reported(
    tmp_path: Path, store: StateStore
) -> None:
    state = await _load(tmp_path, store)
    assert state.in_force is None
    assert not state.actuation_licensed
    assert "binding_missing" in state.problems
    assert state.health()["binding_seq"] == 0
    assert state.health()["last_verdict"] is None


async def test_no_binding_and_no_actuators_licenses_nothing_and_needs_nothing(
    tmp_path: Path, store: StateStore
) -> None:
    state = await _load(
        tmp_path,
        store,
        inventory=DeclaredInventory(sensor_ids=frozenset({"x"}), actuators=()),
    )
    assert state.actuation_licensed
    assert state.problems == []


async def test_an_unreadable_file_is_a_parse_refusal_not_a_crash(
    tmp_path: Path, store: StateStore
) -> None:
    target = tmp_path / BINDING_RELATIVE_PATH
    target.parent.mkdir(parents=True)
    target.write_text("{not json")
    state = await _load(tmp_path, store)
    assert state.last_verdict is not None
    assert (state.last_verdict.stage, state.last_verdict.reason) == (
        "parses",
        "malformed",
    )
    assert state.in_force is None


async def test_a_retained_binding_for_another_device_is_not_in_force(
    tmp_path: Path, store: StateStore
) -> None:
    _write(tmp_path, _envelope())
    await _load(tmp_path, store)
    state = await _load(tmp_path, store, device_id="some-other-device")
    assert state.in_force is None
    assert "retained_binding_for_another_device" in state.problems


async def test_undemonstrated_zones_are_refused_under_hardened_posture_only(
    tmp_path: Path, store: StateStore
) -> None:
    case = next(
        c
        for c in CORPUS["cases"]
        if c["name"] == "undemonstrated_zone_accepted_in_development"
    )
    ctx = case["verifier_context"]
    envelope = {
        "binding": case["binding"],
        "signature": "ed25519:" + case["signature_b64"],
    }
    _write(tmp_path, envelope)
    common: dict[str, Any] = dict(
        device_id=ctx["device_id"],
        anchors=CommissioningAnchors(
            current=bytes.fromhex(ctx["commissioning_anchor_current_hex"]),
            previous=(
                bytes.fromhex(ctx["commissioning_anchor_previous_hex"])
                if ctx.get("commissioning_anchor_previous_hex")
                else None
            ),
        ),
        provisioning_anchor=bytes.fromhex(ctx["provisioning_anchor_hex"]),
        inventory=DeclaredInventory(
            sensor_ids=frozenset(ctx["declared_inventory"]["sensor_ids"]),
            actuators=tuple(
                actuator_identity(a["kind"], a["identity"])
                for a in ctx["declared_inventory"]["actuators"]
            ),
        ),
    )
    hardened = await _load(tmp_path, store, posture="production", **common)
    assert hardened.in_force is None
    assert hardened.last_verdict is not None
    assert hardened.last_verdict.reason == "undemonstrated_binding"
    development = await _load(tmp_path, store, posture="development", **common)
    assert development.in_force is not None


def _write_text(data_path: Path, text: str) -> Path:
    target = data_path / BINDING_RELATIVE_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    return target


@pytest.mark.parametrize(
    "duplicate",
    [
        ('"binding_seq": 1', '"binding_seq": 5, "binding_seq": 1'),
        ('"v": 1', '"v": 1, "v": 1'),
        ('"gpio_pin": 26', '"gpio_pin": 27, "gpio_pin": 26'),
        ('"signature": "ed25519:', '"signature": "x", "signature": "ed25519:'),
    ],
    ids=["different_values", "equal_values", "nested", "envelope"],
)
async def test_a_duplicate_key_is_refused_before_anything_is_read(
    tmp_path: Path, store: StateStore, duplicate: tuple[str, str]
) -> None:
    """A last-wins decoder would verify the signature over the surviving value.

    The file with `"binding_seq": 5, "binding_seq": 1` decodes to the accepted
    document and verifies against its signature; a first-wins parser on a
    device reads 5 from the same bytes. So the wire form is refused during
    parsing, whichever value survives and even when both are equal.
    """
    _write(tmp_path, _envelope())
    accepted = await _load(tmp_path, store)
    assert accepted.in_force is not None
    text = json.dumps(_envelope(), indent=1)
    old, new = duplicate
    assert old in text
    _write_text(tmp_path, text.replace(old, new, 1))
    state = await _load(tmp_path, store)
    assert state.last_verdict is not None
    assert (state.last_verdict.stage, state.last_verdict.reason) == (
        "parses",
        "malformed",
    )
    assert state.in_force is not None
    assert state.in_force.canonical_hash == accepted.in_force.canonical_hash


async def test_a_file_nested_past_the_recursion_limit_is_a_parse_refusal(
    tmp_path: Path, store: StateStore
) -> None:
    """json.loads raises RecursionError here, and that is not a ValueError."""
    _write(tmp_path, _envelope())
    accepted = await _load(tmp_path, store)
    _write_text(tmp_path, "[" * 200_000)
    state = await _load(tmp_path, store)
    assert state.last_verdict is not None
    assert (state.last_verdict.stage, state.last_verdict.reason) == (
        "parses",
        "malformed",
    )
    assert state.in_force is not None and accepted.in_force is not None
    assert state.in_force.canonical_hash == accepted.in_force.canonical_hash


async def test_a_verifier_error_leaves_the_binding_in_force_and_is_reported(
    tmp_path: Path, store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A verifier defect degrades one document, never the runtime.

    The contract's verdict for input that breaks the verifier is malformed and
    the binding in force is unchanged; the problem marker keeps it visible that
    no grammar check decided this.
    """
    _write(tmp_path, _envelope())
    accepted = await _load(tmp_path, store)
    revised = _envelope()
    revised["binding"]["binding_seq"] = 2
    _write(tmp_path, revised)

    def _broken(*_: Any, **__: Any) -> Any:
        raise RuntimeError("verifier defect")

    monkeypatch.setattr(
        "ori.security.commissioning.loader.verify_binding_envelope", _broken
    )
    state = await _load(tmp_path, store)
    assert state.last_verdict is not None
    assert (state.last_verdict.stage, state.last_verdict.reason) == (
        "parses",
        "malformed",
    )
    assert state.last_verdict.binding_seq == 2
    assert "binding_verifier_error" in state.problems
    assert state.in_force is not None and accepted.in_force is not None
    assert state.in_force.canonical_hash == accepted.in_force.canonical_hash
