# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import inspect
from unittest.mock import patch

import pytest

import ori.reasoning.elevator as elevator_module
from ori.reasoning.capability_posture import CapabilityPosture, CapabilityPostureTracker


@pytest.mark.asyncio
async def test_refresh_populates_all_required_fields():
    tracker = CapabilityPostureTracker(
        probe_interval_seconds=30,
        gateway_heartbeat_ttl_seconds=30,
        internet_probe_host="example.com",
        internet_probe_port=80,
        internet_probe_timeout_ms=500,
    )

    with patch(
        "ori.reasoning.capability_posture.probe_internet_available",
        return_value=True,
    ):
        posture = await tracker.refresh(
            sms_available=True,
            whatsapp_available=False,
            local_slm_loaded=True,
            relay_connected=True,
        )

    assert posture.sms_available is True
    assert posture.whatsapp_available is False
    assert posture.gateway_reachable is False
    assert posture.local_slm_loaded is True
    assert posture.relay_connected is True
    assert posture.internet_available is True
    assert posture.checked_at_ms > 0
    assert posture.expires_at_ms > posture.checked_at_ms


@pytest.mark.asyncio
async def test_gateway_reachability_uses_recent_heartbeat(monkeypatch):
    tracker = CapabilityPostureTracker(
        probe_interval_seconds=30,
        gateway_heartbeat_ttl_seconds=30,
    )
    monkeypatch.setattr("ori.reasoning.capability_posture.monotonic_ms", lambda: 10_000)
    tracker.record_gateway_heartbeat(timestamp_ms=10_000)

    monkeypatch.setattr("ori.reasoning.capability_posture.now_ms", lambda: 35_000)
    monkeypatch.setattr("ori.reasoning.capability_posture.monotonic_ms", lambda: 35_000)
    with patch(
        "ori.reasoning.capability_posture.probe_internet_available",
        return_value=True,
    ):
        posture = await tracker.refresh(
            sms_available=False,
            whatsapp_available=False,
            local_slm_loaded=False,
            relay_connected=False,
        )
    assert posture.gateway_reachable is True

    monkeypatch.setattr("ori.reasoning.capability_posture.now_ms", lambda: 41_001)
    monkeypatch.setattr("ori.reasoning.capability_posture.monotonic_ms", lambda: 41_001)
    with patch(
        "ori.reasoning.capability_posture.probe_internet_available",
        return_value=True,
    ):
        posture = await tracker.refresh(
            sms_available=False,
            whatsapp_available=False,
            local_slm_loaded=False,
            relay_connected=False,
        )
    assert posture.gateway_reachable is False


def _clocks(monkeypatch, wall: list[int], mono: list[int]) -> None:
    monkeypatch.setattr("ori.reasoning.capability_posture.now_ms", lambda: wall[0])
    monkeypatch.setattr(
        "ori.reasoning.capability_posture.monotonic_ms", lambda: mono[0]
    )


def test_a_wall_clock_stepped_back_does_not_hold_a_silent_gateway_reachable(
    monkeypatch,
):
    """Age is judged on the monotonic clock: the TTL bounds a silent gateway."""
    wall, mono = [1_000_000], [50_000]
    _clocks(monkeypatch, wall, mono)
    tracker = CapabilityPostureTracker(gateway_heartbeat_ttl_seconds=30)
    tracker.record_gateway_heartbeat()

    wall[0] = 100_000  # stepped back 900 s
    mono[0] += 31_000
    assert tracker._is_gateway_reachable() is False


def test_a_heartbeat_after_the_wall_clock_steps_back_renews_reachability(
    monkeypatch,
):
    wall, mono = [1_000_000], [50_000]
    _clocks(monkeypatch, wall, mono)
    tracker = CapabilityPostureTracker(gateway_heartbeat_ttl_seconds=30)
    tracker.record_gateway_heartbeat()

    wall[0] = 100_000
    mono[0] += 40_000
    assert tracker._is_gateway_reachable() is False
    tracker.record_gateway_heartbeat()
    assert tracker._is_gateway_reachable() is True
    # The displayed receipt is the latest, though the wall clock went back.
    assert tracker._last_gateway_heartbeat_ms == 100_000


def test_a_snapshot_checked_after_now_is_stale() -> None:
    """A wall clock stepped back must not keep an old snapshot fresh."""
    snapshot = CapabilityPosture(
        sms_available=False,
        whatsapp_available=False,
        gateway_reachable=True,
        local_slm_loaded=False,
        relay_connected=False,
        internet_available=True,
        checked_at_ms=1_000_000,
        expires_at_ms=1_030_000,
    )
    assert snapshot.is_stale(1_010_000) is False
    assert snapshot.is_stale(100_000) is True
    assert snapshot.is_stale(1_030_001) is True


@pytest.mark.asyncio
async def test_internet_availability_updates_on_change():
    tracker = CapabilityPostureTracker(probe_interval_seconds=30)

    with patch(
        "ori.reasoning.capability_posture.probe_internet_available",
        side_effect=[True, False],
    ):
        first = await tracker.refresh(
            sms_available=False,
            whatsapp_available=False,
            local_slm_loaded=False,
            relay_connected=False,
        )
        second = await tracker.refresh(
            sms_available=False,
            whatsapp_available=False,
            local_slm_loaded=False,
            relay_connected=False,
        )

    assert first.internet_available is True
    assert second.internet_available is False


def test_elevator_has_no_hardcoded_public_ip():
    source = inspect.getsource(elevator_module)
    assert "8.8.8.8" not in source
