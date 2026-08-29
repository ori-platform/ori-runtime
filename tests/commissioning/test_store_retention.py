# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Accepted bindings are retained whole; a new one retires, never deletes, the last."""

from __future__ import annotations

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


async def _retain(store: StateStore, seq: int, supersedes: str | None) -> None:
    await store.retain_commissioned_binding(
        binding_seq=seq,
        canonical_hash=f"sha256:{seq:064x}",
        device_id="bench",
        inventory_generation=1,
        signer_id="commissioning-bench",
        supersedes=supersedes,
        canonical_json='{"binding_seq": %d}' % seq,
        signature="ed25519:sig",
        zones_json="[]",
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
