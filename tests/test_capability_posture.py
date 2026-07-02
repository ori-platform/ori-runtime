# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import inspect
from unittest.mock import patch

import pytest

import ori.reasoning.elevator as elevator_module
from ori.reasoning.capability_posture import CapabilityPostureTracker


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
    tracker.record_gateway_heartbeat(timestamp_ms=10_000)

    monkeypatch.setattr("ori.reasoning.capability_posture.now_ms", lambda: 35_000)
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
