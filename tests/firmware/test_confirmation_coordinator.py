# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The runtime-owned cross-store confirmation coordinator: push to the evidence store,
read back the active anchor_epoch_id, and resolve the outbox obligation
(ori-runtime#250)."""

from __future__ import annotations

import json

import pytest

from ori.security.firmware.confirmation import FirmwareConfirmationCoordinator
from ori.security.firmware.telemetry import anchor_epoch_id
from ori.state.store import StateStore

DEVICE = "ori-edge-coord-01"
KEY = "ERERERERERERERERERERERERERERERERERERERERERE="
CAP = "sha256:" + "cc" * 32


def epoch() -> str:
    return anchor_epoch_id(
        device_id=DEVICE, public_key_b64=KEY, posture="development", capability_hash=CAP
    )


class _FakeChain:
    """A stand-in evidence-chain handle: register-and-promote makes an epoch active;
    active_anchor_epoch_id reads it back. `unavailable` simulates an outage;
    `force_epoch` simulates a disagreement."""

    def __init__(self) -> None:
        self.active: dict[str, str] = {}
        self.unavailable = False
        self.force_epoch: str | None = None
        self.register_calls: list[tuple] = []

    def register_layer1_device(
        self,
        device_id,
        public_key,
        alg,
        posture,
        capability_hash,
        hardware_profile,
        provisioned_at_ms,
        approved,
        actor,
        reason,
    ) -> None:
        if self.unavailable:
            raise RuntimeError("evidence store unreachable")
        self.register_calls.append((device_id, actor, reason))
        if approved:
            # The evidence store derives the same epoch from the same inputs.
            self.active[device_id] = self.force_epoch or anchor_epoch_id(
                device_id=device_id,
                public_key_b64=_hex_to_b64(public_key),
                posture=posture,
                capability_hash=capability_hash,
            )

    def active_anchor_epoch_id(self, device_id):
        if self.unavailable:
            raise RuntimeError("evidence store unreachable")
        return self.active.get(device_id)


def _hex_to_b64(hex_str: str) -> str:
    import base64

    return base64.b64encode(bytes.fromhex(hex_str)).decode()


@pytest.fixture
async def wired(tmp_path):
    store = StateStore(db_path=str(tmp_path / "s.db"))
    await store.open()
    chain = _FakeChain()
    coord = FirmwareConfirmationCoordinator(store=store, chain=chain)
    try:
        yield store, chain, coord
    finally:
        await store.close()


async def _approve(store):
    await store.upsert_firmware_device_anchor(
        device_id=DEVICE,
        public_key_b64=KEY,
        posture="development",
        capability_hash=CAP,
        manifest_json=json.dumps({"c": CAP}),
        channel_map_json="{}",
    )
    await store.approve_firmware_device(DEVICE, actor="uid=1:alice", reason="bring-up")


async def test_exact_epoch_match_confirms(wired):
    store, chain, coord = wired
    await _approve(store)
    assert await coord.confirm(DEVICE) == "confirmed"
    assert await store.get_firmware_confirmation_status(DEVICE, epoch()) == "confirmed"
    # The push carried the promotion's real attribution.
    assert chain.register_calls[0][1:] == ("uid=1:alice", "bring-up")


async def test_evidence_store_unavailable_stays_pending(wired):
    store, chain, coord = wired
    await _approve(store)
    chain.unavailable = True
    assert await coord.confirm(DEVICE) == "confirmation_pending"
    assert (
        await store.get_firmware_confirmation_status(DEVICE, epoch())
        == "confirmation_pending"
    )
    # The attempt was recorded so the stuck grant is visibly worked.
    pending = await store.list_pending_firmware_confirmations()
    assert pending[0]["attempt_count"] == 1


async def test_no_active_epoch_on_far_side_stays_pending(wired):
    store, chain, coord = wired
    await _approve(store)
    # Push succeeds but readback reports nothing active (simulate an evidence store
    # that did not activate). Must NOT be read as agreement.

    def _register_without_activating(*args, **kwargs):
        chain.register_calls.append((args[0], args[8], args[9]))

    chain.register_layer1_device = _register_without_activating  # type: ignore
    assert await coord.confirm(DEVICE) == "confirmation_pending"


async def test_different_active_epoch_quarantines(wired):
    store, chain, coord = wired
    await _approve(store)
    chain.force_epoch = (
        "sha256:" + "ff" * 32
    )  # the evidence store ends up on a different epoch
    assert await coord.confirm(DEVICE) == "quarantined"
    assert (
        await store.get_firmware_confirmation_status(DEVICE, epoch()) == "quarantined"
    )


async def test_already_confirmed_is_fail_stable(wired):
    store, chain, coord = wired
    await _approve(store)
    assert await coord.confirm(DEVICE) == "confirmed"
    # A second call with the evidence store DOWN must keep it confirmed, not re-open it.
    chain.unavailable = True
    assert await coord.confirm(DEVICE) == "confirmed"
    assert await store.get_firmware_confirmation_status(DEVICE, epoch()) == "confirmed"


async def test_quarantined_is_not_re_resolved_by_retry(wired):
    store, chain, coord = wired
    await _approve(store)
    chain.force_epoch = "sha256:" + "ff" * 32
    assert await coord.confirm(DEVICE) == "quarantined"
    # Even if the evidence store later agrees, a retry must not auto-clear the quarantine.
    chain.force_epoch = None
    chain.active[DEVICE] = epoch()
    assert await coord.confirm(DEVICE) == "quarantined"


async def test_revoked_identity_has_nothing_to_confirm(wired):
    store, chain, coord = wired
    await _approve(store)
    await store.revoke_firmware_device(DEVICE, actor="op", reason="c")
    assert await coord.confirm(DEVICE) == "confirmation_pending"
    assert chain.register_calls == []


async def test_preexisting_conflicting_epoch_quarantines_without_pushing(wired):
    # The evidence store already holds a DIFFERENT active epoch before the
    # coordinator runs. Reading first catches the disagreement and
    # quarantines it; a blind push-first would have been rejected and
    # misread as a transient outage.
    store, chain, coord = wired
    await _approve(store)
    chain.active[DEVICE] = "sha256:" + "ff" * 32  # a conflicting epoch already held

    assert await coord.confirm(DEVICE) == "quarantined"
    assert (
        await store.get_firmware_confirmation_status(DEVICE, epoch()) == "quarantined"
    )
    # Crucially, no push was attempted against the conflicting state.
    assert chain.register_calls == []


async def test_preexisting_matching_epoch_confirms_without_pushing(wired):
    # If the evidence store already holds the SAME active epoch (e.g. a
    # prior lazy repair registered it), the coordinator confirms from the
    # readback alone -- no redundant push.
    store, chain, coord = wired
    await _approve(store)
    chain.active[DEVICE] = epoch()

    assert await coord.confirm(DEVICE) == "confirmed"
    assert chain.register_calls == []
