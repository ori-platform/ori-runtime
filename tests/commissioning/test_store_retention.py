# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Accepted bindings are retained whole; a new one retires, never deletes, the last."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from ori.state.store import StateStore


@pytest.fixture
async def store(tmp_path: Path):
    s = StateStore(db_path=str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


PROVEN_ZONE = {
    "kind": "local_gpio",
    "proof_method": "actuate_and_observe",
    "control_proof_method": "commanded_and_observed",
}


async def _retain(
    store: StateStore,
    seq: int,
    supersedes: str | None,
    zones_json: str = json.dumps([PROVEN_ZONE]),
) -> None:
    await store.retain_commissioned_binding(
        binding_seq=seq,
        canonical_hash=f"sha256:{seq:064x}",
        device_id="bench",
        inventory_generation=1,
        signer_id="commissioning-bench",
        supersedes=supersedes,
        canonical_json='{"binding_seq": %d}' % seq,
        signature="ed25519:sig",
        zones_json=zones_json,
        accepted_at_ms=1_000 + seq,
    )


async def test_nothing_is_in_force_until_a_binding_is_retained(
    store: StateStore,
) -> None:
    assert await store.get_commissioned_binding_in_force() is None
    assert await store.commissioned_binding_history() == []


async def test_the_latest_accepted_binding_is_in_force_and_the_prior_is_retired(
    store: StateStore,
) -> None:
    await _retain(store, 1, None)
    first = await store.get_commissioned_binding_in_force()
    assert first is not None and first["binding_seq"] == 1
    await _retain(store, 2, first["canonical_hash"])
    current = await store.get_commissioned_binding_in_force()
    assert current is not None and current["binding_seq"] == 2
    assert current["supersedes"] == first["canonical_hash"]
    history = await store.commissioned_binding_history()
    assert [(h["binding_seq"], h["retired_at_ms"]) for h in history] == [
        (1, 1_002),
        (2, None),
    ]


async def test_a_sequence_or_hash_already_retained_is_refused(
    store: StateStore,
) -> None:
    await _retain(store, 1, None)
    with pytest.raises(sqlite3.IntegrityError):
        await _retain(store, 1, None)
    current = await store.get_commissioned_binding_in_force()
    assert current is not None and current["binding_seq"] == 1


@pytest.mark.parametrize(
    "zones",
    [
        [],
        [{**PROVEN_ZONE, "control_proof_method": None}],
        [{k: v for k, v in PROVEN_ZONE.items() if k != "control_proof_method"}],
        [{**PROVEN_ZONE, "control_proof_method": "undemonstrated"}],
        [{**PROVEN_ZONE, "proof_method": "undemonstrated"}],
        [{**PROVEN_ZONE, "kind": "firmware_channel"}],
        [PROVEN_ZONE, {**PROVEN_ZONE, "control_proof_method": None}],
    ],
    ids=[
        "no_zones",
        "null_control_leg",
        "absent_control_leg",
        "undemonstrated_control_leg",
        "undemonstrated_circuit_leg",
        "firmware_channel",
        "one_zone_short",
    ],
)
async def test_the_in_force_table_refuses_a_provisional_document(
    store: StateStore, zones: list[dict]
) -> None:
    """The table that licenses driving a coil cannot hold an unproven document."""
    with pytest.raises(ValueError):
        await _retain(store, 1, None, zones_json=json.dumps(zones))
    assert await store.get_commissioned_binding_in_force() is None


async def test_a_provisional_binding_is_retained_apart_and_never_in_force(
    store: StateStore,
) -> None:
    await store.retain_provisional_binding(
        binding_seq=4,
        canonical_hash="sha256:" + "a" * 64,
        device_id="bench",
        inventory_generation=1,
        signer_id="commissioning-bench",
        supersedes=None,
        canonical_json='{"binding_seq": 4}',
        signature="ed25519:sig",
        zones_json=json.dumps([{**PROVEN_ZONE, "control_proof_method": None}]),
        verified_at_ms=9_000,
    )
    assert await store.get_commissioned_binding_in_force() is None
    assert await store.commissioned_binding_history() == []
    held = await store.get_provisional_binding()
    assert held is not None and held["binding_seq"] == 4

    await store.retain_provisional_binding(
        binding_seq=5,
        canonical_hash="sha256:" + "b" * 64,
        device_id="bench",
        inventory_generation=1,
        signer_id="commissioning-bench",
        supersedes=None,
        canonical_json='{"binding_seq": 5}',
        signature="ed25519:sig",
        zones_json=json.dumps([{**PROVEN_ZONE, "control_proof_method": None}]),
        verified_at_ms=9_001,
    )
    held = await store.get_provisional_binding()
    assert held is not None and held["binding_seq"] == 5

    await store.clear_provisional_binding()
    assert await store.get_provisional_binding() is None
