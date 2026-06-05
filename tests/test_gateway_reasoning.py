# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

import ori.gateway.reasoning as gateway_reasoning
from ori.gateway.reasoning import GatewayReasoningError, MqttGatewayReasoner
from ori.network.events import OriEvent, SensorReading


def _reading(value: float = 14.2) -> SensorReading:
    return SensorReading(
        sensor_id="main-current",
        sensor_type="current_clamp",
        value=value,
        unit="ampere",
        timestamp=123_456,
        quality=0.99,
        metadata={},
    )


def _event(value: float = 14.2) -> OriEvent:
    return OriEvent.from_reading(_reading(value), "site-a")


def _rule(action_tier: str = "C"):
    return SimpleNamespace(
        rule_name="generator_overrun",
        action_tier=action_tier,
        action="open_safety_circuit",
    )


class _Message:
    def __init__(self, payload: dict):
        self.payload = json.dumps(payload).encode("utf-8")


class _FakeClient:
    def __init__(self, response_builder=None):
        self.response_builder = response_builder
        self.on_connect = None
        self.on_message = None
        self.connected = None
        self.subscribed = []
        self.published = []
        self.loop_started = False
        self.loop_stopped = False
        self.disconnected = False

    def username_pw_set(self, username, password):
        self.credentials = (username, password)

    def connect(self, host, port, keepalive):
        self.connected = (host, port, keepalive)

    def loop_start(self):
        self.loop_started = True
        self.on_connect(self, None, None, 0)

    def subscribe(self, topic):
        self.subscribed.append(topic)

    def publish(self, topic, payload, qos=0, retain=False):
        decoded = json.loads(payload.decode("utf-8"))
        self.published.append((topic, decoded, qos, retain))
        if self.response_builder is not None:
            self.on_message(self, None, _Message(self.response_builder(decoded)))

    def loop_stop(self):
        self.loop_stopped = True

    def disconnect(self):
        self.disconnected = True


@pytest.fixture(autouse=True)
def _force_paho_available(monkeypatch):
    monkeypatch.setattr(gateway_reasoning, "_PAHO_AVAILABLE", True)
    monkeypatch.setattr(gateway_reasoning, "mqtt", object())


async def test_mqtt_gateway_reasoner_publishes_contract_payload():
    fake = _FakeClient(
        response_builder=lambda req: {
            "request_id": req["request_id"],
            "text": "Gateway analysis completed.",
            "model": "llama-gateway",
            "tokens_used": 42,
            "latency_ms": 120,
            "confidence": 0.82,
            "action_tier": "C",
            "proposed_action": "open_safety_circuit",
        }
    )
    store = AsyncMock()
    store.get_history.return_value = [_reading(8.1), _reading(9.2)]
    reasoner = MqttGatewayReasoner(
        broker_url="mqtt://operator:secret@broker.local:1884",
        device_id="site-a",
        timeout_ms=1000,
        client_factory=lambda **_: fake,
        request_id_factory=lambda: "req-1",
    )

    result = await reasoner.reason(
        "Explain generator overrun.",
        event=_event(),
        rule_result=_rule(),
        state_store=store,
    )

    assert result.text == "Gateway analysis completed."
    assert result.tier == "gateway"
    assert result.model == "llama-gateway"
    assert result.action_tier == "C"
    assert result.proposed_action == "open_safety_circuit"
    assert fake.connected == ("broker.local", 1884, 60)
    assert fake.subscribed == ["ori/site-a/reasoning/response"]
    assert fake.loop_stopped is True
    assert fake.disconnected is True
    topic, payload, qos, retain = fake.published[0]
    assert topic == "ori/site-a/reasoning/request"
    assert qos == 1
    assert retain is False
    assert payload == {
        "request_id": "req-1",
        "device_id": "site-a",
        "sensor_type": "current_clamp",
        "trigger_name": "generator_overrun",
        "prompt": "Explain generator overrun.",
        "context": {
            "value": 14.2,
            "unit": "ampere",
            "timestamp": 123_456,
            "history": [
                {"value": 8.1, "timestamp": 123_456},
                {"value": 9.2, "timestamp": 123_456},
            ],
        },
        "action_tier_hint": "C",
        "timeout_ms": 1000,
    }


async def test_mqtt_gateway_reasoner_raises_on_gateway_error():
    fake = _FakeClient(
        response_builder=lambda req: {
            "request_id": req["request_id"],
            "text": "",
            "model": "gateway",
            "tokens_used": 0,
            "latency_ms": 0,
            "confidence": 0,
            "action_tier": "A",
            "proposed_action": None,
            "error": "provider timeout",
        }
    )
    reasoner = MqttGatewayReasoner(
        broker_url="mqtt://broker.local",
        device_id="site-a",
        timeout_ms=1000,
        client_factory=lambda **_: fake,
        request_id_factory=lambda: "req-err",
    )

    with pytest.raises(GatewayReasoningError, match="provider timeout"):
        await reasoner.reason("Prompt", event=_event(), rule_result=_rule("A"))


async def test_mqtt_gateway_reasoner_rejects_invalid_response_action_tier():
    fake = _FakeClient(
        response_builder=lambda req: {
            "request_id": req["request_id"],
            "text": "Gateway response with invalid tier.",
            "model": "gateway",
            "tokens_used": 10,
            "latency_ms": 50,
            "confidence": 0.5,
            "action_tier": "Z",
            "proposed_action": None,
        }
    )
    reasoner = MqttGatewayReasoner(
        broker_url="mqtt://broker.local",
        device_id="site-a",
        timeout_ms=1000,
        client_factory=lambda **_: fake,
        request_id_factory=lambda: "req-bad-tier",
    )

    with pytest.raises(GatewayReasoningError, match="action_tier is invalid"):
        await reasoner.reason("Prompt", event=_event(), rule_result=_rule("A"))


async def test_mqtt_gateway_reasoner_times_out_and_closes_client():
    fake = _FakeClient(response_builder=None)
    reasoner = MqttGatewayReasoner(
        broker_url="mqtt://broker.local",
        device_id="site-a",
        timeout_ms=10,
        client_factory=lambda **_: fake,
        request_id_factory=lambda: "req-timeout",
    )

    with pytest.raises(GatewayReasoningError, match="response timeout"):
        await reasoner.reason("Prompt", event=_event(), rule_result=_rule("A"))

    assert fake.loop_stopped is True
    assert fake.disconnected is True


async def test_mqtt_gateway_reasoner_rejects_invalid_request_id():
    fake = _FakeClient(response_builder=None)
    reasoner = MqttGatewayReasoner(
        broker_url="mqtt://broker.local",
        device_id="site-a",
        timeout_ms=1000,
        client_factory=lambda **_: fake,
        request_id_factory=lambda: "bad/request",
    )

    with pytest.raises(ValueError, match="request_id"):
        await reasoner.reason("Prompt", event=_event(), rule_result=_rule("A"))

    assert fake.published == []


def test_mqtt_gateway_reasoner_fails_lazily_when_paho_missing(monkeypatch):
    monkeypatch.setattr(gateway_reasoning, "_PAHO_AVAILABLE", False)
    monkeypatch.setattr(gateway_reasoning, "mqtt", None)

    with pytest.raises(RuntimeError, match="paho-mqtt is not installed"):
        MqttGatewayReasoner(
            broker_url="mqtt://broker.local",
            device_id="site-a",
            client_factory=lambda **_: _FakeClient(),
        )
