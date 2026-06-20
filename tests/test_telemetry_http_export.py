# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import hashlib
import hmac
import json
from types import SimpleNamespace

import pytest

from ori.config import TelemetryExportConfig
from ori.network.events import OriEvent, SensorReading
from ori.telemetry import http_export
from ori.telemetry.http_export import HttpTelemetryExporter


def _event(value: float = 1250.0) -> OriEvent:
    return OriEvent.from_reading(
        SensorReading(
            sensor_id="phone-main-power",
            sensor_type="usb_power",
            value=value,
            unit="watt",
            timestamp=1_000,
            quality=0.99,
            metadata={"source": "usb_serial", "site": {"name": b"ikeja"}},
            raw=b"\x01\x02",
        ),
        device_id="phone-01",
    )


def _config(**overrides) -> TelemetryExportConfig:
    values = {
        "enabled": True,
        "endpoint": "https://api.example.test/runtime/telemetry",
        "api_key_env": "ORI_ENERGY_DEVICE_API_KEY",
        "flush_interval_s": 30.0,
        "batch_size": 2,
        "timeout_ms": 3000,
        "max_queue_size": 3,
    }
    values.update(overrides)
    return TelemetryExportConfig(**values)


class _FakeResponse:
    def raise_for_status(self) -> None:
        return None


class _FakeAsyncClient:
    requests: list[dict] = []
    fail: bool = False

    def __init__(self, timeout):
        self.timeout = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def post(self, endpoint, *, content, headers):
        self.requests.append(
            {
                "endpoint": endpoint,
                "content": content,
                "headers": headers,
                "timeout": self.timeout,
            }
        )
        if self.fail:
            raise RuntimeError("network down")
        return _FakeResponse()


@pytest.mark.asyncio
async def test_handle_event_queues_sensor_reading_without_raw_bytes():
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config())

    await exporter.handle_event(_event())

    queued = exporter._drain_batch()
    assert len(queued) == 1
    assert queued[0]["event_type"] == "sensor.reading"
    assert queued[0]["reading"]["sensor_type"] == "usb_power"
    assert "raw" not in queued[0]["reading"]
    assert queued[0]["reading"]["metadata"]["site"]["name"] == "b'ikeja'"


@pytest.mark.asyncio
async def test_handle_event_drops_when_queue_is_full():
    exporter = HttpTelemetryExporter(
        device_id="phone-01",
        config=_config(batch_size=1, max_queue_size=1),
    )

    await exporter.handle_event(_event(1.0))
    await exporter.handle_event(_event(2.0))

    assert exporter.dropped_events == 1
    assert len(exporter._drain_batch()) == 1


@pytest.mark.asyncio
async def test_flush_once_posts_hmac_signed_batch(monkeypatch):
    monkeypatch.setenv("ORI_ENERGY_DEVICE_API_KEY", "device-secret")
    _FakeAsyncClient.requests = []
    _FakeAsyncClient.fail = False
    monkeypatch.setattr(
        http_export,
        "_httpx",
        SimpleNamespace(AsyncClient=_FakeAsyncClient),
    )
    monkeypatch.setattr(http_export, "_HTTPX_AVAILABLE", True)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config())
    await exporter.handle_event(_event())

    sent = await exporter.flush_once()

    assert sent == 1
    request = _FakeAsyncClient.requests[0]
    assert request["endpoint"] == "https://api.example.test/runtime/telemetry"
    assert request["timeout"] == 3.0
    headers = request["headers"]
    assert headers["Authorization"] == "Bearer device-secret"
    assert headers["X-Ori-Device-Id"] == "phone-01"
    body = request["content"]
    payload = json.loads(body)
    assert payload["schema_version"] == "runtime.telemetry.v1"
    assert payload["device_id"] == "phone-01"
    signed = headers["X-Ori-Timestamp-Ms"].encode("utf-8") + b"." + body
    expected = hmac.new(
        b"device-secret",
        signed,
        hashlib.sha256,
    ).hexdigest()
    assert headers["X-Ori-Signature"] == f"v1={expected}"


@pytest.mark.asyncio
async def test_flush_once_requeues_when_post_fails(monkeypatch):
    monkeypatch.setenv("ORI_ENERGY_DEVICE_API_KEY", "device-secret")
    _FakeAsyncClient.requests = []
    _FakeAsyncClient.fail = True
    monkeypatch.setattr(
        http_export,
        "_httpx",
        SimpleNamespace(AsyncClient=_FakeAsyncClient),
    )
    monkeypatch.setattr(http_export, "_HTTPX_AVAILABLE", True)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config())
    await exporter.handle_event(_event())

    sent = await exporter.flush_once()

    assert sent == 0
    assert len(exporter._drain_batch()) == 1


@pytest.mark.asyncio
async def test_flush_once_requeues_when_api_key_missing(monkeypatch):
    monkeypatch.delenv("ORI_ENERGY_DEVICE_API_KEY", raising=False)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config())
    await exporter.handle_event(_event())

    sent = await exporter.flush_once()

    assert sent == 0
    assert len(exporter._drain_batch()) == 1


@pytest.mark.asyncio
async def test_serve_until_noops_when_httpx_missing(monkeypatch):
    monkeypatch.setattr(http_export, "_httpx", None)
    monkeypatch.setattr(http_export, "_HTTPX_AVAILABLE", False)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config())
    shutdown = asyncio.Event()

    await exporter.serve_until(shutdown)

    assert exporter.dropped_events == 0
