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
from ori.telemetry.canonical import (
    TelemetryCanonicalizationError,
    canonical_telemetry_bytes,
    telemetry_hmac_sha256,
)
from ori.telemetry.http_export import HttpTelemetryExporter

GOLDEN_BODY = (
    '{"device_id":"phone-gateway-ikeja-01","events":[{"context":{"location":"Ìkẹjà"},'
    '"device_id":"phone-gateway-ikeja-01","event_id":"00000000-0000-4000-8000-000000000001",'
    '"event_type":"sensor.reading","fingerprint":"","reading":{"metadata":{"label":"Mains – east"},'
    '"quality":1.0,"sensor_id":"phone-main-power","sensor_type":"usb_power",'
    '"timestamp":1719000000000,"unit":"watt","value":1240.5},"sensor_id":"phone-main-power",'
    '"source":"usb_serial","timestamp":1719000000000}],"schema_version":"runtime.telemetry.v1",'
    '"sent_at_ms":1719000000000,"sequence":1}'
).encode("utf-8")


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


def test_runtime_telemetry_golden_body_and_hmac() -> None:
    payload = json.loads(GOLDEN_BODY)

    assert canonical_telemetry_bytes(payload) == GOLDEN_BODY
    assert hashlib.sha256(GOLDEN_BODY).hexdigest() == (
        "51e7a268d28c96f7ba516593b7d4ca160848ff641888ce1b3b513f2bbf2370ea"
    )
    assert (
        telemetry_hmac_sha256(
            "test-runtime-telemetry-key", 1_719_000_000_123, GOLDEN_BODY
        )
        == "5ed66b6fc38a5d68e8c0c16bf18ade62968549432fb52baeb8b56625927dba79"
    )
    assert "Ìkẹjà".encode("utf-8") in GOLDEN_BODY
    assert b"\\u" not in GOLDEN_BODY


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), 1e-5])
def test_runtime_telemetry_rejects_noncanonical_numbers(value: float) -> None:
    with pytest.raises(TelemetryCanonicalizationError):
        canonical_telemetry_bytes({"value": value})


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
async def test_flush_once_requeues_when_api_key_missing(monkeypatch, caplog):
    monkeypatch.delenv("ORI_ENERGY_DEVICE_API_KEY", raising=False)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config())
    await exporter.handle_event(_event())

    sent = await exporter.flush_once()

    assert sent == 0
    assert len(exporter._drain_batch()) == 1
    assert "ORI_ENERGY_DEVICE_API_KEY" not in caplog.text
    assert "configured API key environment variable is not set" in caplog.text


@pytest.mark.asyncio
async def test_serve_until_noops_when_httpx_missing(monkeypatch):
    monkeypatch.setattr(http_export, "_httpx", None)
    monkeypatch.setattr(http_export, "_HTTPX_AVAILABLE", False)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config())
    shutdown = asyncio.Event()

    await exporter.serve_until(shutdown)

    assert exporter.dropped_events == 0
