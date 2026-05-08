# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import json
import os
import socket
from types import SimpleNamespace

import pytest

from ori.runtime import OriRuntime
from ori.runtime_health_socket import RuntimeHealthSocketServer
from ori.time_utils import now_ms


def _short_socket_path(suffix: str) -> str:
    return f"/tmp/ori-{suffix}-{os.getpid()}.sock"


def _require_unix_socket_bindable() -> None:
    probe_path = _short_socket_path("probe")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.bind(probe_path)
    except PermissionError as exc:
        pytest.skip(f"Unix socket bind not permitted in this environment: {exc}")
    finally:
        sock.close()
        if os.path.exists(probe_path):
            os.remove(probe_path)


async def _read_json_line(path: str, request: bytes) -> dict:
    reader, writer = await asyncio.open_unix_connection(path=path)
    writer.write(request)
    await writer.drain()
    raw = await reader.readline()
    writer.close()
    await writer.wait_closed()
    return json.loads(raw.decode("utf-8"))


@pytest.mark.asyncio
async def test_health_socket_serves_snapshot_and_rejects_unsupported_request():
    _require_unix_socket_bindable()
    socket_path = _short_socket_path("health")
    server = RuntimeHealthSocketServer(
        socket_path=socket_path,
        mode=0o660,
        snapshot_provider=lambda: {"device_id": "dev-01", "uptime_s": 12.3},
    )
    bound = await server.start()
    try:
        ok_resp = await _read_json_line(bound, b"GET_HEALTH\n")
        assert ok_resp["ok"] is True
        assert ok_resp["schema_version"] == 1
        assert ok_resp["health"]["device_id"] == "dev-01"

        bad_resp = await _read_json_line(bound, b"PING\n")
        assert bad_resp["ok"] is False
        assert bad_resp["error"]["code"] == "unsupported_request"
    finally:
        await server.close()

    assert not os.path.exists(socket_path)


@pytest.mark.asyncio
async def test_health_socket_removes_stale_socket_before_bind():
    _require_unix_socket_bindable()
    socket_path = _short_socket_path("stale")
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(socket_path)
    stale.close()
    assert os.path.exists(socket_path)

    server = RuntimeHealthSocketServer(
        socket_path=socket_path,
        mode=0o660,
        snapshot_provider=lambda: {"ok": True},
    )
    try:
        await server.start()
    finally:
        await server.close()

    assert not os.path.exists(socket_path)


@pytest.mark.asyncio
async def test_health_socket_refuses_non_socket_existing_path(tmp_path):
    _require_unix_socket_bindable()
    socket_path = tmp_path / "not-a-socket"
    socket_path.write_text("not a socket", encoding="utf-8")

    server = RuntimeHealthSocketServer(
        socket_path=str(socket_path),
        mode=0o660,
        snapshot_provider=lambda: {"ok": True},
    )
    with pytest.raises(RuntimeError, match="is not a socket"):
        await server.start()


def test_runtime_health_snapshot_shape():
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._device_id = "dev-01"
    runtime._runtime_started_at_ms = now_ms() - 5_000
    runtime._health_socket_path = "/tmp/ori-health.sock"
    runtime._device_policy_enabled = True
    runtime._configured_sensors = [
        SimpleNamespace(
            id="sensor-1",
            type="ads1115_voltage",
            protocol="i2c",
            poll_interval_ms=1000,
        )
    ]
    runtime._connected_sensor_ids = {"sensor-1"}
    runtime._sensor_last_seen_ms = {"sensor-1": now_ms() - 200}
    runtime._last_alert_timestamps_by_channel = {"sms": now_ms() - 100}
    runtime._last_alert_timestamps_by_trigger = {"battery_cycle_stress": now_ms() - 50}

    class _Dispatcher:
        def get_policy_state_snapshot(self):
            return {
                "available": True,
                "policy_version": 3,
                "tier": "cloud",
                "relay_b_enabled": True,
                "relay_c_enabled": True,
                "cloud_llm_enabled": True,
                "valid_until": 999_999_999,
                "issued_at": 123_456_789,
                "is_expired": False,
            }

    runtime._dispatcher = _Dispatcher()
    snapshot = runtime._build_health_snapshot()

    assert snapshot["device_id"] == "dev-01"
    assert snapshot["uptime_s"] >= 5.0
    assert snapshot["health_socket_path"] == "/tmp/ori-health.sock"
    assert "capability_posture" in snapshot
    assert isinstance(snapshot["sensors"], list)
    assert snapshot["sensors"][0]["id"] == "sensor-1"
    assert snapshot["last_alert_timestamps"]["by_channel"]["sms"] > 0
    assert snapshot["device_policy"]["enabled"] is True
    assert snapshot["device_policy"]["policy_version"] == 3
