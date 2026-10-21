# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

import ori.gateway.reasoning as gateway_reasoning
from ori.gateway.reasoning import GatewayReasoningError, MqttGatewayReasoner
from ori.network.events import OriEvent, SensorReading
from ori.security.gateway_messages import (
    GatewayMessageAuthConfig,
    GatewayMessageAuthenticator,
)
from tests.gateway_auth_helpers import cache_for


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
        self.on_subscribe = None
        self.connected = None
        self.subscribed = []
        self.published = []
        self.loop_started = False
        self.loop_stopped = False
        self.disconnected = False
        self.tls_context = None

    def username_pw_set(self, username, password):
        self.credentials = (username, password)

    def tls_set_context(self, context):
        self.tls_context = context

    def connect(self, host, port, keepalive):
        self.connected = (host, port, keepalive)

    def loop_start(self):
        self.loop_started = True
        assert self.on_connect is not None
        self.on_connect(self, None, None, 0)

    def subscribe(self, topic, qos=0):
        self.subscribed.append(topic)
        if self.on_subscribe is not None:
            self.on_subscribe(self, None, 1, [qos], None)
        return (0, 1)

    def publish(self, topic, payload, qos=0, retain=False):
        decoded = json.loads(payload.decode("utf-8"))
        self.published.append((topic, decoded, qos, retain))
        if self.response_builder is not None:
            assert self.on_message is not None
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
            "device_id": req["device_id"],
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
            "producer_time": "unknown",
            "history": [
                {"value": 8.1, "timestamp": 123_456, "producer_time": "unknown"},
                {"value": 9.2, "timestamp": 123_456, "producer_time": "unknown"},
            ],
        },
        "action_tier_hint": "C",
        "timeout_ms": 1000,
    }


async def test_mqtt_gateway_reasoner_applies_tls_for_mqtts_url():
    fake = _FakeClient(
        response_builder=lambda req: {
            "request_id": req["request_id"],
            "device_id": req["device_id"],
            "text": "Gateway TLS analysis completed.",
            "model": "llama-gateway",
            "tokens_used": 10,
            "latency_ms": 50,
            "confidence": 0.5,
            "action_tier": "A",
            "proposed_action": None,
        }
    )
    reasoner = MqttGatewayReasoner(
        broker_url="mqtts://broker.local",
        device_id="site-a",
        timeout_ms=1000,
        client_factory=lambda **_: fake,
        request_id_factory=lambda: "req-tls",
    )

    await reasoner.reason("Prompt", event=_event(), rule_result=_rule("A"))

    assert fake.connected == ("broker.local", 8883, 60)
    assert fake.tls_context is not None


async def test_mqtt_gateway_reasoner_raises_on_gateway_error():
    fake = _FakeClient(
        response_builder=lambda req: {
            "request_id": req["request_id"],
            "device_id": req["device_id"],
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
            "device_id": req["device_id"],
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


async def test_mqtt_gateway_reasoner_signs_request_and_verifies_response():
    request_auth = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(shared_secret="gateway-secret"),
        replay_cache=cache_for(
            GatewayMessageAuthConfig(shared_secret="gateway-secret")
        ),
    )
    response_auth = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(shared_secret="gateway-secret"),
        replay_cache=cache_for(
            GatewayMessageAuthConfig(shared_secret="gateway-secret")
        ),
    )

    def _response(req):
        verified_req = response_auth.verify(
            req,
            message_type="reasoning_request",
            expected_device_id="site-a",
            expected_request_id="req-auth",
        )
        assert verified_req["prompt"] == "Prompt"
        return response_auth.sign(
            {
                "request_id": req["request_id"],
                "device_id": req["device_id"],
                "text": "Authenticated gateway analysis.",
                "model": "llama-gateway",
                "tokens_used": 12,
                "latency_ms": 20,
                "confidence": 0.7,
                "action_tier": "A",
                "proposed_action": None,
            },
            message_type="reasoning_response",
        )

    fake = _FakeClient(response_builder=_response)
    reasoner = MqttGatewayReasoner(
        broker_url="mqtt://broker.local",
        device_id="site-a",
        timeout_ms=1000,
        client_factory=lambda **_: fake,
        request_id_factory=lambda: "req-auth",
        message_auth=request_auth,
    )

    result = await reasoner.reason("Prompt", event=_event(), rule_result=_rule("A"))

    assert result.text == "Authenticated gateway analysis."
    assert "auth" in fake.published[0][1]


def _response(req: dict, text: str) -> dict:
    return {
        "request_id": req["request_id"],
        "device_id": req["device_id"],
        "text": text,
        "model": "gateway",
        "tokens_used": 1,
        "latency_ms": 1,
        "confidence": 0.1,
        "action_tier": "A",
        "proposed_action": None,
    }


class _ManyAnswersClient(_FakeClient):
    """Delivers every answer *answers* builds for the request, in order."""

    def __init__(self, answers):
        super().__init__(response_builder=None)
        self._answers = answers

    def publish(self, topic, payload, qos=0, retain=False):
        decoded = json.loads(payload.decode("utf-8"))
        self.published.append((topic, decoded, qos, retain))
        assert self.on_message is not None
        for answer in self._answers(decoded):
            self.on_message(self, None, _Message(answer))


def _signed_by(secret: str, answer: dict) -> dict:
    return GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(shared_secret=secret),
        replay_cache=cache_for(GatewayMessageAuthConfig(shared_secret=secret)),
    ).sign(answer, message_type="reasoning_response")


def _authenticated_reasoner(client, *, timeout_ms: int = 1000):
    return MqttGatewayReasoner(
        broker_url="mqtt://broker.local",
        device_id="site-a",
        timeout_ms=timeout_ms,
        client_factory=lambda **_: client,
        request_id_factory=lambda: "req-1",
        message_auth=GatewayMessageAuthenticator(
            GatewayMessageAuthConfig(shared_secret="gateway-secret"),
            replay_cache=cache_for(
                GatewayMessageAuthConfig(shared_secret="gateway-secret")
            ),
        ),
    )


async def test_an_unverified_response_ends_nothing_and_the_authentic_one_lands():
    """gateway-api/v2 Reasoning Auth Envelope: verification precedes every side
    effect, so a forged answer neither fails the request nor takes its place."""

    def answers(req: dict) -> list[dict]:
        tampered = _signed_by("gateway-secret", _response(req, "authentic"))
        tampered["text"] = "tampered"
        other_request = _signed_by(
            "gateway-secret", {**_response(req, "elsewhere"), "request_id": "req-2"}
        )
        return [
            _response(req, "unsigned"),
            _signed_by("another-secret", _response(req, "forged")),
            tampered,
            other_request,
            _signed_by("gateway-secret", _response(req, "authentic")),
        ]

    result = await _authenticated_reasoner(_ManyAnswersClient(answers)).reason(
        "Prompt", event=_event(), rule_result=_rule("A")
    )
    assert result.text == "authentic"


async def test_a_replayed_response_is_no_answer():
    captured: list[dict] = []

    def answers(req: dict) -> list[dict]:
        if not captured:
            captured.append(_signed_by("gateway-secret", _response(req, "first")))
            return captured
        return [captured[0], _signed_by("gateway-secret", _response(req, "second"))]

    client = _ManyAnswersClient(answers)
    reasoner = _authenticated_reasoner(client)
    first = await reasoner.reason("Prompt", event=_event(), rule_result=_rule("A"))
    second = await reasoner.reason("Prompt", event=_event(), rule_result=_rule("A"))
    assert (first.text, second.text) == ("first", "second")


async def test_only_unverified_responses_leave_the_request_to_time_out():
    client = _ManyAnswersClient(lambda req: [_response(req, "unsigned")])
    with pytest.raises(GatewayReasoningError, match="response timeout"):
        await _authenticated_reasoner(client, timeout_ms=50).reason(
            "Prompt", event=_event(), rule_result=_rule("A")
        )


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


@pytest.mark.parametrize(
    "field, value",
    [
        ("tokens_used", "many"),
        ("latency_ms", [1]),
        ("confidence", "sure"),
        ("confidence", True),
        ("tokens_used", 3.9),
        ("tokens_used", "12"),
        ("tokens_used", -7),
        ("tokens_used", True),
        ("latency_ms", 1e300),
        ("text", {"a": 1}),
        ("model", 7),
        ("proposed_action", 3),
        ("error", {"a": 1}),
        *[
            (field, value)
            for field in ("error", "model")
            for value in (False, 0, 0.0, [], {}, None)
        ],
        ("confidence", 10**400),
        ("confidence", -(10**400)),
    ],
)
async def test_a_response_field_with_no_value_is_the_gateways_error(field, value):
    """Refused at parse as GatewayReasoningError, never left to a caller's fallback."""
    response = {
        "text": "Gateway response.",
        "model": "gateway",
        "tokens_used": 10,
        "latency_ms": 50,
        "confidence": 0.5,
        "action_tier": "A",
        "proposed_action": None,
    }
    response[field] = value
    fake = _FakeClient(
        response_builder=lambda req: {
            "request_id": req["request_id"],
            "device_id": req["device_id"],
            **response,
        }
    )
    reasoner = MqttGatewayReasoner(
        broker_url="mqtt://broker.local",
        device_id="site-a",
        timeout_ms=1000,
        client_factory=lambda **_: fake,
        request_id_factory=lambda: "req-bad-field",
    )

    with pytest.raises(
        GatewayReasoningError, match="malformed|not finite|invalid|not text"
    ):
        await reasoner.reason("Prompt", event=_event(), rule_result=_rule("A"))


@pytest.mark.parametrize(
    "field, literal",
    [
        ("tokens_used", "NaN"),
        ("tokens_used", "Infinity"),
        ("latency_ms", "-Infinity"),
        ("confidence", "NaN"),
    ],
)
async def test_a_non_finite_literal_is_not_an_answer(field, literal):
    """gateway-api/v2 Payload Member Rule: `NaN` and `Infinity` are not JSON,
    so the response is refused before any member is read and the request
    waits, ending in its own timeout."""
    reasoner = _literal_reasoner(field, literal)
    with pytest.raises(GatewayReasoningError, match="response timeout"):
        await reasoner.reason("Prompt", event=_event(), rule_result=_rule("A"))


@pytest.mark.parametrize(
    "field, literal, error",
    [
        ("confidence", "1e400", "confidence is not finite"),
        ("confidence", "-1e400", "confidence is not finite"),
        ("confidence", "9" * 5000, "confidence is not finite"),
        ("tokens_used", "1e400", "field is malformed"),
        ("latency_ms", "9" * 5000, "field is malformed"),
    ],
)
async def test_an_admitted_value_out_of_range_is_the_gateways_error(
    field, literal, error
):
    """`1e400` is JSON, so the rule admits it; it and an integer too long to
    convert read as infinite, and the response's own checks refuse them."""
    reasoner = _literal_reasoner(field, literal)
    with pytest.raises(GatewayReasoningError, match=error):
        await reasoner.reason("Prompt", event=_event(), rule_result=_rule("A"))


def _literal_reasoner(field: str, literal: str) -> MqttGatewayReasoner:
    """A reasoner whose gateway answers with *field* written as *literal*."""

    class _RawClient(_FakeClient):
        def publish(self, topic, payload, qos=0, retain=False):
            decoded = json.loads(payload.decode("utf-8"))
            self.published.append((topic, decoded, qos, retain))
            body = json.dumps(
                {
                    "request_id": decoded["request_id"],
                    "device_id": decoded["device_id"],
                    "text": "Gateway response.",
                    "model": "gateway",
                    "tokens_used": 10,
                    "latency_ms": 50,
                    "confidence": 0.5,
                    "action_tier": "A",
                    "proposed_action": None,
                    field: "__LITERAL__",
                }
            ).replace('"__LITERAL__"', literal)
            message = _Message({})
            message.payload = body.encode()
            assert self.on_message is not None
            self.on_message(self, None, message)

    return MqttGatewayReasoner(
        broker_url="mqtt://broker.local",
        device_id="site-a",
        timeout_ms=50,
        client_factory=lambda **_: _RawClient(),
        request_id_factory=lambda: "req-literal",
    )


@pytest.mark.parametrize("device_id", ["other-device", [], None])
async def test_an_unauthenticated_response_naming_another_device_is_refused(device_id):
    """The body, the topic and the request name one device, per gateway-api/v2."""
    response = {
        "request_id": "req-device",
        "text": "Gateway response.",
        "model": "gateway",
        "tokens_used": 10,
        "latency_ms": 50,
        "confidence": 0.5,
        "action_tier": "A",
        "proposed_action": None,
    }
    if device_id is not None:
        response["device_id"] = device_id
    fake = _FakeClient(response_builder=lambda req: response)
    reasoner = MqttGatewayReasoner(
        broker_url="mqtt://broker.local",
        device_id="site-a",
        timeout_ms=1000,
        client_factory=lambda **_: fake,
        request_id_factory=lambda: "req-device",
    )

    with pytest.raises(GatewayReasoningError, match="another device"):
        await reasoner.reason("Prompt", event=_event(), rule_result=_rule("A"))


@pytest.mark.parametrize(
    "change, model",
    [
        ({"error": ""}, "gateway-model"),
        ({"model": ""}, "gateway"),
        ({"model": None, "drop": "model"}, "gateway"),
        ({"confidence": 10**300}, "gateway-model"),
    ],
)
async def test_a_conforming_response_field_is_accepted(change, model):
    """An empty error, and an empty or omitted model, are within the contract."""
    response = {
        "text": "Gateway response.",
        "model": "gateway-model",
        "tokens_used": 10,
        "latency_ms": 50,
        "confidence": 0.5,
        "action_tier": "A",
        "proposed_action": None,
    }
    change = dict(change)
    dropped = change.pop("drop", None)
    response.update(change)
    if dropped is not None:
        del response[dropped]
    fake = _FakeClient(
        response_builder=lambda req: {
            "request_id": req["request_id"],
            "device_id": req["device_id"],
            **response,
        }
    )
    reasoner = MqttGatewayReasoner(
        broker_url="mqtt://broker.local",
        device_id="site-a",
        timeout_ms=1000,
        client_factory=lambda **_: fake,
        request_id_factory=lambda: "req-good-field",
    )

    result = await reasoner.reason("Prompt", event=_event(), rule_result=_rule("A"))

    assert result.model == model


async def test_a_flood_of_unverified_responses_is_logged_twice_per_kind_not_per_message(
    caplog,
):
    """A request can wait up to a day; one line per dropped answer would let
    any broker client write the log at the ingress rate for that whole time."""
    client = _ManyAnswersClient(
        lambda req: (
            [_response(req, "unsigned")] * 15
            + [_signed_by("gateway-secret", _response(req, "authentic"))]
        )
    )
    with caplog.at_level("WARNING", logger="ori.gateway.reasoning"):
        result = await _authenticated_reasoner(client).reason(
            "Prompt", event=_event(), rule_result=_rule("A")
        )
    assert result.text == "authentic"
    dropped = [r.getMessage() for r in caplog.records if "dropped" in r.getMessage()]
    assert len(dropped) == 2
    assert "dropped 15 unverified responses" in dropped[1]


async def test_one_dropped_response_is_one_line(caplog):
    client = _ManyAnswersClient(
        lambda req: [
            _response(req, "unsigned"),
            _signed_by("gateway-secret", _response(req, "authentic")),
        ]
    )
    with caplog.at_level("WARNING", logger="ori.gateway.reasoning"):
        await _authenticated_reasoner(client).reason(
            "Prompt", event=_event(), rule_result=_rule("A")
        )
    assert [r.getMessage() for r in caplog.records if "dropped" in r.getMessage()] == [
        "[gateway-reasoning] dropped an unverified response for req-1: missing_auth"
    ]


async def test_a_flood_of_replays_is_summed_too(caplog):
    captured: list[dict] = []

    def answers(req: dict) -> list[dict]:
        if not captured:
            captured.append(_signed_by("gateway-secret", _response(req, "first")))
            return list(captured)
        return [captured[0]] * 4 + [
            _signed_by("gateway-secret", _response(req, "second"))
        ]

    reasoner = _authenticated_reasoner(_ManyAnswersClient(answers))
    await reasoner.reason("Prompt", event=_event(), rule_result=_rule("A"))
    with caplog.at_level("WARNING", logger="ori.gateway.reasoning"):
        result = await reasoner.reason("Prompt", event=_event(), rule_result=_rule("A"))
    assert result.text == "second"
    dropped = [r.getMessage() for r in caplog.records if "dropped" in r.getMessage()]
    assert len(dropped) == 2 and "dropped 4 replayed responses" in dropped[1]


async def test_a_response_after_the_answer_is_not_read(caplog):
    client = _ManyAnswersClient(
        lambda req: (
            [_signed_by("gateway-secret", _response(req, "authentic"))]
            + [_response(req, "unsigned")] * 5
        )
    )
    with caplog.at_level("WARNING", logger="ori.gateway.reasoning"):
        result = await _authenticated_reasoner(client).reason(
            "Prompt", event=_event(), rule_result=_rule("A")
        )
    assert result.text == "authentic"
    assert not [r for r in caplog.records if "dropped" in r.getMessage()]


class _RawAnswersClient(_FakeClient):
    """Delivers each payload *answers* builds, bytes as they are."""

    def __init__(self, answers):
        super().__init__(response_builder=None)
        self._answers = answers

    def publish(self, topic, payload, qos=0, retain=False):
        decoded = json.loads(payload.decode("utf-8"))
        self.published.append((topic, decoded, qos, retain))
        assert self.on_message is not None
        for answer in self._answers(decoded):
            message = _Message({})
            message.payload = (
                answer if isinstance(answer, bytes) else (json.dumps(answer).encode())
            )
            self.on_message(self, None, message)


async def test_a_flood_of_malformed_responses_is_counted_not_logged_each(caplog):
    """Malformed and non-object responses are refused under the Payload Member
    Rule and counted in the family's ingress record, never one line each;
    after the answer, none is even decoded."""
    flood = [b"not json"] * 4 + [b"[1]"] * 4
    client = _RawAnswersClient(
        lambda req: (
            flood + [_signed_by("gateway-secret", _response(req, "authentic"))] + flood
        )
    )
    reasoner = _authenticated_reasoner(client)
    with caplog.at_level("WARNING"):
        result = await reasoner.reason("Prompt", event=_event(), rule_result=_rule("A"))
    assert result.text == "authentic"
    assert not [r for r in caplog.records if r.name == "ori.gateway.reasoning"]
    # At most one line a second per reason, two reasons here.
    ingress = [r for r in caplog.records if r.name == "ori.gateway.payload_bounds"]
    assert len(ingress) <= 2
    refusals = reasoner._ingress.refusals()
    assert refusals.get("malformed_json") == 4
    assert refusals.get("not_an_object") == 4


@pytest.mark.parametrize(
    ("grant", "sent", "match"),
    [
        ([0x80], 0, "broker refused subscription"),
        ([0x87], 0, "broker refused subscription"),
        ([], 0, "broker refused subscription"),
        ([0], 4, "could not send subscribe"),
    ],
)
async def test_a_refused_response_subscription_fails_at_once_and_publishes_nothing(
    grant, sent, match
):
    """No request goes out on a response topic the broker will not deliver."""
    fake = _FakeClient(response_builder=lambda req: {})

    def subscribe(topic, qos=0):
        fake.subscribed.append(topic)
        if sent == 0 and fake.on_subscribe is not None:
            fake.on_subscribe(fake, None, 1, grant, None)
        return (sent, 1)

    fake.subscribe = subscribe
    reasoner = MqttGatewayReasoner(
        broker_url="mqtt://broker.local",
        device_id="site-a",
        timeout_ms=30_000,
        client_factory=lambda **_: fake,
        request_id_factory=lambda: "req-refused",
    )

    with pytest.raises(GatewayReasoningError, match=match) as exc:
        await asyncio.wait_for(
            reasoner.reason("Prompt", event=_event(), rule_result=_rule("A")), 5
        )

    assert reasoner.response_topic in str(exc.value)
    assert fake.published == []
    assert fake.loop_stopped and fake.disconnected
