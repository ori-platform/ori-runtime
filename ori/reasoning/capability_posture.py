# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Capability posture snapshot and probe utilities.

This module provides a structured runtime capability snapshot used by the
Intelligence Elevator and policy-refresh workflows.
"""

import asyncio
import socket
from dataclasses import dataclass

from ori.utils.time_utils import monotonic_ms, now_ms

#: runtime-config/v2: the gateway heartbeat TTL's floor and default, three times
#: the longest heartbeat interval gateway-config/v2 admits (30 s).
GATEWAY_HEARTBEAT_TTL_MIN_SECONDS = 90


def probe_internet_available(host: str, port: int, timeout_ms: int) -> bool:
    """Best-effort TCP reachability probe for internet availability."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(max(timeout_ms, 1) / 1000.0)
            sock.connect((host, port))
        return True
    except OSError:
        return False


@dataclass(frozen=True)
class CapabilityPosture:
    """Structured capability snapshot for runtime decisioning."""

    sms_available: bool
    whatsapp_available: bool
    gateway_reachable: bool
    local_slm_loaded: bool
    relay_connected: bool
    internet_available: bool
    checked_at_ms: int
    expires_at_ms: int
    gateway_last_heartbeat_ms: int | None = None

    def is_stale(self, now_ms_value: int | None = None) -> bool:
        """Past its expiry, or checked after now: a wall clock stepped back
        would otherwise keep an old snapshot fresh until it caught up."""
        now = now_ms() if now_ms_value is None else now_ms_value
        return now > self.expires_at_ms or now < self.checked_at_ms


class CapabilityPostureTracker:
    """Build and cache capability posture snapshots."""

    def __init__(
        self,
        *,
        probe_interval_seconds: int = 30,
        gateway_heartbeat_ttl_seconds: int = GATEWAY_HEARTBEAT_TTL_MIN_SECONDS,
        internet_probe_host: str = "one.one.one.one",
        internet_probe_port: int = 53,
        internet_probe_timeout_ms: int = 1000,
    ) -> None:
        self._probe_interval_ms = int(probe_interval_seconds * 1000)
        self._gateway_ttl_ms = int(gateway_heartbeat_ttl_seconds * 1000)
        self._internet_probe_host = internet_probe_host
        self._internet_probe_port = internet_probe_port
        self._internet_probe_timeout_ms = internet_probe_timeout_ms
        # Wall-clock receipt, for display only; age is judged on the monotonic
        # receipt, so a wall clock stepped back cannot hold a gateway reachable.
        self._last_gateway_heartbeat_ms: int | None = None
        self._last_gateway_receipt_mono_ms: int | None = None
        self._last_posture = CapabilityPosture(
            sms_available=False,
            whatsapp_available=False,
            gateway_reachable=False,
            local_slm_loaded=False,
            relay_connected=False,
            internet_available=False,
            checked_at_ms=0,
            expires_at_ms=0,
            gateway_last_heartbeat_ms=None,
        )

    def get_snapshot(self) -> CapabilityPosture:
        """Return the most recently computed posture snapshot."""
        return self._last_posture

    def record_gateway_heartbeat(self, timestamp_ms: int | None = None) -> None:
        """Mark a gateway health heartbeat as received now.

        *timestamp_ms* is the wall-clock receipt, kept for display; every
        heartbeat renews reachability, whatever the wall clock reads.
        """
        self._last_gateway_heartbeat_ms = (
            now_ms() if timestamp_ms is None else int(timestamp_ms)
        )
        self._last_gateway_receipt_mono_ms = monotonic_ms()

    async def refresh(
        self,
        *,
        sms_available: bool,
        whatsapp_available: bool,
        local_slm_loaded: bool,
        relay_connected: bool,
    ) -> CapabilityPosture:
        """Probe live signals and produce a fresh posture snapshot."""
        internet_available = await asyncio.to_thread(
            probe_internet_available,
            self._internet_probe_host,
            self._internet_probe_port,
            self._internet_probe_timeout_ms,
        )

        checked_at_ms = now_ms()
        gateway_reachable = self._is_gateway_reachable()

        posture = CapabilityPosture(
            sms_available=bool(sms_available),
            whatsapp_available=bool(whatsapp_available),
            gateway_reachable=gateway_reachable,
            local_slm_loaded=bool(local_slm_loaded),
            relay_connected=bool(relay_connected),
            internet_available=internet_available,
            checked_at_ms=checked_at_ms,
            expires_at_ms=checked_at_ms + self._probe_interval_ms,
            gateway_last_heartbeat_ms=self._last_gateway_heartbeat_ms,
        )
        self._last_posture = posture
        return posture

    def _is_gateway_reachable(self) -> bool:
        last = self._last_gateway_receipt_mono_ms
        if last is None:
            return False
        return (monotonic_ms() - last) <= self._gateway_ttl_ms
