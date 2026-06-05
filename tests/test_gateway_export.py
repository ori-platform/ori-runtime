# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import json
from unittest.mock import patch

import pytest

import ori.gateway_export as gateway_export
from ori.gateway_export import (
    GatewayExportResponder,
    MqttGatewayExportServer,
    _parse_broker_url,
)
from ori.network.events import ActionResult, OriEvent, SensorReading
from ori.reasoning.elevator import ReasoningResult
from ori.state.store import StateStore


@pytest.fixture
async def store(tmp_path):
    state = StateStore(str(tmp_path / "gateway-export.db"))
    await state.open()
    try:
        yield state
    finally:
        await state.close()


def _responder(store, *, device_id="dev-01"):
    return GatewayExportResponder(
        device_id=device_id,
        state_store=store,
        health_snapshot_provider=lambda: {
            "device_id": device_id,
            "uptime_s": 12.5,
            "sensors": [],
        },
    )


def _request(export_type: str, **overrides):
    payload = {
        "request_id": "req-001",
        "export_type": export_type,
        "device_id": "dev-01",
        "limit": 100,
        "params": {},
    }
    payload.update(overrides)
    return payload


def _reading(sensor_id="main-current", value=1.0, timestamp=1_000):
    return SensorReading(
        sensor_id=sensor_id,
        sensor_type="current_clamp",
        value=value,
        unit="ampere",
        timestamp=timestamp,
        quality=0.99,
        metadata={},
    )


async def test_health_export_returns_snapshot(store):
    response = await _responder(store).handle_request(_request("health"))

    assert response.error is None
    assert response.complete is True
    assert response.items == [{"device_id": "dev-01", "uptime_s": 12.5, "sensors": []}]


async def test_rejects_mismatched_device_id(store):
    response = await _responder(store).handle_request(
        _request("health", device_id="other-device")
    )

    assert response.error == "device_id does not match this runtime"
    assert response.items == []
    assert response.request_id == "req-001"


async def test_sensor_history_export_buckets_rows_and_paginates(store):
    for ts, value in ((1_000, 2.0), (2_000, 4.0), (3_700_000, 8.0)):
        await store.append_history(
            OriEvent.from_reading(_reading(value=value, timestamp=ts), "dev-01")
        )

    response = await _responder(store).handle_request(
        _request(
            "sensor_history",
            since_ms=0,
            until_ms=4_000_000,
            limit=1,
            params={"sensor_id": "main-current", "bucket_ms": 3_600_000},
        )
    )

    assert response.error is None
    assert response.complete is False
    assert response.next_page_token == "1"
    assert len(response.items) == 1
    assert response.items[0]["sensor_id"] == "main-current"
    assert response.items[0]["sample_count"] == 2
    assert response.items[0]["avg_value"] == pytest.approx(3.0)

    next_response = await _responder(store).handle_request(
        _request(
            "sensor_history",
            since_ms=0,
            until_ms=4_000_000,
            limit=1,
            page_token=response.next_page_token,
            params={"sensor_id": "main-current", "bucket_ms": 3_600_000},
        )
    )
    assert next_response.complete is True
    assert next_response.items[0]["avg_value"] == pytest.approx(8.0)


async def test_sensor_history_requires_bounds_and_sensor_id(store):
    response = await _responder(store).handle_request(
        _request("sensor_history", params={"sensor_id": "main-current"})
    )

    assert response.error == "since_ms and until_ms are required for sensor_history"
    assert response.request_id == "req-001"


async def test_malformed_json_payload_returns_error_response(store):
    response = await _responder(store).handle_payload(b"{not-json")

    assert response.request_id == "invalid"
    assert response.export_type == "unknown"
    assert response.error == "request payload must be JSON"
    assert response.items == []


async def test_pagination_keeps_next_token_at_source_limit_boundary(store):
    responder = _responder(store)
    rows = [{"idx": idx} for idx in range(1000)]

    response = responder._paged_response(
        "req-001",
        "action_log",
        rows,
        limit=100,
        offset=900,
    )

    assert len(response.items) == 100
    assert response.complete is False
    assert response.next_page_token == "1000"


def test_mqtt_server_fails_lazily_when_paho_missing(store, monkeypatch):
    monkeypatch.setattr(gateway_export, "_PAHO_AVAILABLE", False)
    monkeypatch.setattr(gateway_export, "mqtt", None)

    with pytest.raises(RuntimeError, match="paho-mqtt is not installed"):
        MqttGatewayExportServer(
            broker_url="mqtt://localhost",
            responder=_responder(store),
        )


async def test_action_log_export_uses_runtime_store_boundary(store):
    await store.log_action_for_event(
        ActionResult(
            action_name="alert_whatsapp",
            tier="A",
            executed=True,
            approved=None,
            action_taken="alert_whatsapp",
            timestamp=2_000,
        ),
        trigger_name="voltage_warning",
        device_id="dev-01",
        sensor_id="voltage-main",
        sensor_type="voltage",
    )

    response = await _responder(store).handle_request(
        _request("action_log", since_ms=1_000, until_ms=3_000)
    )

    assert response.error is None
    assert response.items[0]["action_name"] == "alert_whatsapp"
    assert response.items[0]["device_id"] == "dev-01"
    assert response.items[0]["trigger_name"] == "voltage_warning"


async def test_reasoning_log_export_uses_runtime_store_boundary(store):
    result = ReasoningResult(
        text="Grid voltage pattern is unstable.",
        tier="gateway",
        model="llama.cpp",
        tokens_used=64,
        latency_ms=250,
        confidence=0.0,
        action_tier="B",
        prompt="Explain the post-action source switch.",
        reasoning_status="complete",
        correlation_id="corr-tier-b-1",
    )
    with patch("ori.state.store.now_ms", return_value=2_000):
        await store.log_reasoning(
            result=result,
            trigger_name="grid_instability",
            device_id="dev-01",
        )

    response = await _responder(store).handle_request(
        _request(
            "reasoning_log",
            since_ms=1_000,
            until_ms=3_000,
            params={
                "tier_used": "gateway",
                "action_tier": "B",
                "reasoning_status": "complete",
                "correlation_id": "corr-tier-b-1",
            },
        )
    )

    assert response.error is None
    assert response.items[0]["trigger_name"] == "grid_instability"
    assert response.items[0]["tier_used"] == "gateway"
    assert response.items[0]["reasoning_status"] == "complete"
    assert response.items[0]["correlation_id"] == "corr-tier-b-1"
    assert response.items[0]["timestamp"] == 2_000


async def test_tier_c_decision_log_export_uses_runtime_store_boundary(store):
    await store.log_tier_c_decision(
        device_id="dev-01",
        site_type="pharmacy",
        location="Lagos",
        timezone="Africa/Lagos",
        sensor_id="load-current",
        sensor_type="current_clamp",
        reading_value=18.5,
        reading_unit="ampere",
        reading_timestamp=1000,
        history_window=[{"timestamp": 900, "value": 10.0}],
        skill_name="energy-anomaly-detector",
        trigger_name="overcurrent",
        proposed_action="open_safety_circuit",
        confidence=0.91,
        reasoning_tier="local_slm",
        reasoning_model="qwen.gguf",
        prompt_context_summary="load is high",
        operator_decision="approved",
        operator_response="YES-AB12CD34",
        decision_latency_ms=2500,
        approval_timeout_seconds=300,
        safe_default_action="log_to_dashboard",
        safe_default_used=False,
        action_taken="open_safety_circuit",
        action_executed=True,
        final_action_result={"executed": True},
        later_outcome=None,
        proposal_id="AB12CD34",
        created_at=5_000,
    )

    response = await _responder(store).handle_request(
        _request("tier_c_decision_log", since_ms=4_000, until_ms=6_000)
    )

    assert response.error is None
    assert response.items[0]["proposal_id"] == "AB12CD34"
    assert response.items[0]["history_window"] == [{"timestamp": 900, "value": 10.0}]
    assert response.items[0]["site_type"] == "pharmacy"


def test_parse_broker_url_accepts_mqtt_urls():
    parsed = _parse_broker_url("mqtt://operator:secret@broker.local:1884")

    assert parsed == {
        "host": "broker.local",
        "port": 1884,
        "username": "operator",
        "password": "secret",
    }


async def test_mqtt_server_publishes_response_on_request_topic(store):
    published = []

    class _FakeClient:
        def publish(self, topic, payload, qos=0):
            published.append((topic, json.loads(payload.decode("utf-8")), qos))

    server = MqttGatewayExportServer(
        broker_url="mqtt://localhost",
        responder=_responder(store),
        client_factory=lambda **_: _FakeClient(),
    )

    await server._publish_response(
        _FakeClient(),
        json.dumps(_request("health")).encode("utf-8"),
    )

    assert published == [
        (
            "ori/dev-01/export/response/req-001",
            {
                "request_id": "req-001",
                "export_type": "health",
                "device_id": "dev-01",
                "items": [{"device_id": "dev-01", "uptime_s": 12.5, "sensors": []}],
                "next_page_token": "",
                "complete": True,
                "error": None,
            },
            1,
        )
    ]


async def test_mqtt_server_subscribes_to_device_request_topic(store):
    class _FakeClient:
        def __init__(self):
            self.on_connect = None
            self.on_message = None
            self.subscribed = []
            self.connected = None
            self.loop_started = False
            self.loop_stopped = False
            self.disconnected = False

        def username_pw_set(self, username, password):
            pass

        def connect(self, host, port, keepalive):
            self.connected = (host, port, keepalive)
            self.on_connect(self, None, None, 0)

        def loop_start(self):
            self.loop_started = True

        def subscribe(self, topic):
            self.subscribed.append(topic)

        def loop_stop(self):
            self.loop_stopped = True

        def disconnect(self):
            self.disconnected = True

    fake = _FakeClient()
    shutdown = asyncio.Event()
    server = MqttGatewayExportServer(
        broker_url="mqtt://localhost:1884",
        responder=_responder(store),
        client_factory=lambda **_: fake,
    )

    async def _stop():
        await asyncio.sleep(0)
        shutdown.set()

    await asyncio.gather(server.serve_until(shutdown), _stop())

    assert fake.connected == ("localhost", 1884, 60)
    assert fake.subscribed == ["ori/dev-01/export/request"]
    assert fake.loop_started is True
    assert fake.loop_stopped is True
    assert fake.disconnected is True
