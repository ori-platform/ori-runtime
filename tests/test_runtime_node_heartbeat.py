# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import json
from types import SimpleNamespace

import pytest

import ori.gateway.node_heartbeat as node_heartbeat_module
from ori.gateway.node_heartbeat import (
    RUNTIME_HEARTBEAT_MESSAGE_TYPE,
    RUNTIME_HEARTBEAT_TOPIC_TEMPLATE,
    MqttRuntimeNodeHeartbeatPublisher,
)
from ori.security.gateway_messages import (
    GatewayMessageAuthConfig,
    GatewayMessageAuthenticator,
    GatewayReplayCache,
)
from tests.gateway_auth_helpers import cache_for
from tests.waiting import settle, wait_until


class _FakeClient:
    def __init__(self) -> None:
        self.connected: tuple[str, int, int] | None = None
        self.loop_started = False
        self.loop_stopped = False
        self.disconnected = False
        self.username: tuple[str, str] | None = None
        self.tls_context = None
        self.published: list[tuple[str, bytes, int, bool]] = []

    def username_pw_set(self, username, password):
        self.username = (username, password)

    def tls_set_context(self, context):
        self.tls_context = context

    def connect(self, host, port, keepalive):
        self.connected = (host, port, keepalive)

    def loop_start(self):
        self.loop_started = True

    def loop_stop(self):
        self.loop_stopped = True

    def disconnect(self):
        self.disconnected = True

    def publish(self, topic, payload, qos=0, retain=False):
        self.published.append((topic, payload, qos, retain))
        return SimpleNamespace(rc=0)


def _verifier_cache() -> GatewayReplayCache:
    # Started at clock 0, so a heartbeat signed before it was built still passes.
    return GatewayReplayCache(max_skew_ms=300_000, start_ms=0)


def _auth() -> GatewayMessageAuthenticator:
    return GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(
            shared_secret="site-test-secret",
            max_skew_ms=300_000,
            replay_ttl_ms=300_000,
        ),
        replay_cache=cache_for(
            GatewayMessageAuthConfig(
                shared_secret="site-test-secret",
                max_skew_ms=300_000,
                replay_ttl_ms=300_000,
            )
        ),
    )


def _publisher(
    *,
    device_id: str = "dev-01",
    broker_url: str = "mqtt://localhost",
    snapshot=None,
    authenticator=None,
    client=None,
) -> MqttRuntimeNodeHeartbeatPublisher:
    async def _snapshot():
        return snapshot or {"critical": False, "active_triggers": ["grid_sag"]}

    return MqttRuntimeNodeHeartbeatPublisher(
        broker_url=broker_url,
        device_id=device_id,
        health_snapshot_provider=_snapshot,
        interval_seconds=30,
        authenticator=authenticator,
        client_factory=lambda **_: client or _FakeClient(),
    )


@pytest.mark.asyncio
async def test_runtime_node_heartbeat_publishes_unsigned_retained_false(monkeypatch):
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    client = _FakeClient()
    publisher = _publisher(client=client)

    await publisher._publish_once(client)

    topic, raw_payload, qos, retain = client.published[0]
    payload = json.loads(raw_payload)
    assert topic == RUNTIME_HEARTBEAT_TOPIC_TEMPLATE.format(device_id="dev-01")
    assert qos == 0
    assert retain is False
    assert payload == {
        "active_triggers": ["grid_sag"],
        "device_id": "dev-01",
        "gateway_seen_ms": 0,
        "last_seen_ms": 1_000_000,
        "status": "healthy",
    }


@pytest.mark.asyncio
async def test_runtime_node_heartbeat_signs_payload_when_auth_enabled(monkeypatch):
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    client = _FakeClient()
    authenticator = _auth()
    publisher = _publisher(client=client, authenticator=authenticator)

    await publisher._publish_once(client)

    payload = json.loads(client.published[0][1])
    verified = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(shared_secret="site-test-secret"),
        replay_cache=_verifier_cache(),
    ).verify(
        payload,
        message_type=RUNTIME_HEARTBEAT_MESSAGE_TYPE,
        expected_device_id="dev-01",
    )
    assert verified["device_id"] == "dev-01"
    assert verified["status"] == "healthy"


@pytest.mark.asyncio
async def test_runtime_node_heartbeat_marks_critical_snapshot_degraded(monkeypatch):
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    client = _FakeClient()
    publisher = _publisher(
        client=client,
        snapshot={"status": "critical", "critical": True},
    )

    await publisher._publish_once(client)

    payload = json.loads(client.published[0][1])
    assert payload["status"] == "degraded"


@pytest.mark.asyncio
async def test_runtime_node_heartbeat_serve_until_uses_mqtts_tls(monkeypatch):
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    client = _FakeClient()
    shutdown = asyncio.Event()
    shutdown.set()
    publisher = _publisher(
        broker_url="mqtts://operator:secret@broker.local",
        client=client,
    )

    await publisher.serve_until(shutdown)

    assert client.connected == ("broker.local", 8883, 60)
    assert client.username == ("operator", "secret")
    assert client.tls_context is not None
    assert client.loop_started is True
    assert client.loop_stopped is True
    assert client.disconnected is True
    assert len(client.published) == 1


# ── degradation_reasons (gateway-api/v1) ─────────────────────────────


@pytest.mark.asyncio
async def test_degradation_reasons_omitted_when_nothing_is_degraded(monkeypatch):
    """Absent, never an empty array.

    An empty array is malformed under gateway-api/v1: absent and
    present-empty are different states, and a conforming gateway refuses
    the latter with degradation_reasons_length_invalid.
    """
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    client = _FakeClient()
    publisher = _publisher(
        client=client,
        snapshot={
            "critical": False,
            "active_triggers": [],
            "degradation_reasons": [],
        },
    )

    await publisher._publish_once(client)

    payload = json.loads(client.published[0][1])
    assert "degradation_reasons" not in payload


@pytest.mark.asyncio
async def test_degradation_reasons_omitted_when_empty_even_if_degraded(monkeypatch):
    """Isolates the emptiness guard from the status guard.

    The healthy-status test above cannot prove this on its own: with a
    healthy status the status check also suppresses the field, so a
    regression that emitted `[]` would still pass. A node degraded for some
    unrelated reason, carrying no named reasons, is the case that separates
    them — and it is a real state, since other subsystems can degrade a node
    without naming anything.
    """
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    client = _FakeClient()
    publisher = _publisher(
        client=client,
        snapshot={
            "status": "degraded",
            "critical": False,
            "active_triggers": [],
            "degradation_reasons": [],
        },
    )

    await publisher._publish_once(client)

    payload = json.loads(client.published[0][1])
    assert payload["status"] == "degraded"
    assert "degradation_reasons" not in payload


@pytest.mark.asyncio
async def test_degradation_reasons_emitted_on_a_degraded_heartbeat(monkeypatch):
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    client = _FakeClient()
    publisher = _publisher(
        client=client,
        snapshot={
            "status": "degraded",
            "critical": False,
            "active_triggers": [],
            "degradation_reasons": ["firmware_liveness_degraded"],
        },
    )

    await publisher._publish_once(client)

    payload = json.loads(client.published[0][1])
    assert payload["status"] == "degraded"
    assert payload["degradation_reasons"] == ["firmware_liveness_degraded"]


@pytest.mark.asyncio
async def test_degradation_reasons_are_unique_and_ordered(monkeypatch):
    """Uniqueness and ordering, without teaching production to emit junk.

    Asserting on invented tokens would assert that the publisher emits
    values a conforming gateway is required to reject, encoding the
    opposite of the rollout rule. The vocabulary is extended for the
    duration of the test instead, so the ordering behaviour is exercised
    with tokens the boundary accepts.
    """
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    monkeypatch.setattr(
        node_heartbeat_module,
        "DEGRADATION_REASONS",
        frozenset({"aa_test_only", "zz_test_only"}),
    )
    client = _FakeClient()
    publisher = _publisher(
        client=client,
        snapshot={
            "status": "degraded",
            "critical": False,
            "active_triggers": [],
            "degradation_reasons": ["zz_test_only", "aa_test_only", "zz_test_only"],
        },
    )

    await publisher._publish_once(client)

    reasons = json.loads(client.published[0][1])["degradation_reasons"]
    assert reasons == ["aa_test_only", "zz_test_only"]
    assert reasons == sorted(set(reasons))


@pytest.mark.asyncio
async def test_unratified_tokens_are_never_emitted(monkeypatch):
    """A receiver must refuse an unratified token, so never send one.

    Refusing here costs one reason; emitting costs the whole heartbeat.
    """
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    client = _FakeClient()
    publisher = _publisher(
        client=client,
        snapshot={
            "status": "degraded",
            "critical": False,
            "active_triggers": [],
            "degradation_reasons": ["not_ratified_yet"],
        },
    )

    await publisher._publish_once(client)

    assert "degradation_reasons" not in json.loads(client.published[0][1])


@pytest.mark.asyncio
async def test_ratified_tokens_survive_alongside_unratified_ones(monkeypatch):
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    client = _FakeClient()
    publisher = _publisher(
        client=client,
        snapshot={
            "status": "degraded",
            "critical": False,
            "active_triggers": [],
            "degradation_reasons": ["not_ratified_yet", "firmware_liveness_degraded"],
        },
    )

    await publisher._publish_once(client)

    payload = json.loads(client.published[0][1])
    assert payload["degradation_reasons"] == ["firmware_liveness_degraded"]


@pytest.mark.asyncio
async def test_non_string_reasons_are_refused_not_coerced(monkeypatch):
    """str() over an arbitrary object manufactures a plausible token."""
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    for junk in ({"a": 1}, 42, None, ["nested"]):
        client = _FakeClient()
        publisher = _publisher(
            client=client,
            snapshot={
                "status": "degraded",
                "critical": False,
                "active_triggers": [],
                "degradation_reasons": [junk],
            },
        )
        await publisher._publish_once(client)
        assert "degradation_reasons" not in json.loads(client.published[0][1])


@pytest.mark.asyncio
async def test_over_the_contract_maximum_omits_the_field(monkeypatch):
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    oversized = frozenset(f"tok_{i:02d}" for i in range(17))
    monkeypatch.setattr(node_heartbeat_module, "DEGRADATION_REASONS", oversized)
    client = _FakeClient()
    publisher = _publisher(
        client=client,
        snapshot={
            "status": "degraded",
            "critical": False,
            "active_triggers": [],
            "degradation_reasons": sorted(oversized),
        },
    )

    await publisher._publish_once(client)

    assert "degradation_reasons" not in json.loads(client.published[0][1])


@pytest.mark.asyncio
async def test_degradation_reasons_dropped_rather_than_sent_with_healthy_status(
    monkeypatch, caplog
):
    """Reasons imply degraded. Sending both would be malformed on the wire.

    A caller that names a reason has already contributed critical/degraded
    to the snapshot, so this guards a future caller that forgets — and it
    warns rather than failing silently.
    """
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    client = _FakeClient()
    publisher = _publisher(
        client=client,
        snapshot={
            "critical": False,
            "active_triggers": [],
            "degradation_reasons": ["firmware_liveness_degraded"],
        },
    )

    with caplog.at_level("WARNING"):
        await publisher._publish_once(client)

    payload = json.loads(client.published[0][1])
    assert "degradation_reasons" not in payload
    assert "degradation_reasons" in caplog.text


@pytest.mark.asyncio
async def test_degradation_reasons_are_inside_the_signed_payload(monkeypatch):
    """Signed content, not metadata.

    Tampering after signing must break authentication, which is what makes
    a reordered list a transport failure rather than a semantic one.
    """
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    authenticator = _auth()
    client = _FakeClient()
    publisher = _publisher(
        client=client,
        authenticator=authenticator,
        snapshot={
            "status": "degraded",
            "critical": False,
            "active_triggers": [],
            "degradation_reasons": ["firmware_liveness_degraded"],
        },
    )

    await publisher._publish_once(client)

    payload = json.loads(client.published[0][1])
    assert payload["degradation_reasons"] == ["firmware_liveness_degraded"]
    assert "auth" in payload

    verifier = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(shared_secret="site-test-secret"),
        replay_cache=_verifier_cache(),
    )
    # Unmodified: authenticates.
    verifier.verify(
        payload,
        message_type=RUNTIME_HEARTBEAT_MESSAGE_TYPE,
        expected_device_id="dev-01",
    )
    # Reordered after signing: the canonical bytes changed, so this must
    # fail authentication rather than reach semantic validation.
    tampered = dict(payload)
    tampered["degradation_reasons"] = ["zz_tampered"]
    with pytest.raises(Exception):
        verifier.verify(
            tampered,
            message_type=RUNTIME_HEARTBEAT_MESSAGE_TYPE,
            expected_device_id="dev-01",
        )


def test_degradation_reasons_helper_omits_and_names():
    from ori.runtime import (
        DEGRADATION_REASON_FIRMWARE_LIVENESS,
        _degradation_reasons,
    )

    assert _degradation_reasons(firmware_liveness_degraded=False) == []
    assert _degradation_reasons(firmware_liveness_degraded=True) == [
        DEGRADATION_REASON_FIRMWARE_LIVENESS
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("snapshot", "status"),
    [
        ({"critical": False}, "healthy"),
        ({"status": "degraded", "critical": False}, "degraded"),
        # The gateway accepts healthy and degraded only.
        ({"status": "critical", "critical": True}, "degraded"),
    ],
    ids=["healthy", "degraded", "critical"],
)
async def test_each_local_status_maps_to_its_heartbeat(monkeypatch, snapshot, status):
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    client = _FakeClient()
    await _publisher(client=client, snapshot=snapshot)._publish_once(client)
    assert json.loads(client.published[0][1])["status"] == status


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "snapshot",
    [
        pytest.param(None, id="not-an-object"),
        pytest.param([], id="a-list"),
        pytest.param({}, id="no-critical"),
        pytest.param({"status": "healthy", "critical": False}, id="healthy-spelled"),
        pytest.param({"status": None, "critical": False}, id="null-status"),
        pytest.param({"status": "ok", "critical": False}, id="unknown-status"),
        pytest.param({"status": " degraded", "critical": False}, id="padded-status"),
        pytest.param({"status": 1, "critical": False}, id="numeric-status"),
        pytest.param({"critical": True}, id="critical-without-status"),
        pytest.param({"status": "critical", "critical": False}, id="critical-false"),
        pytest.param(
            {"status": "degraded", "critical": True}, id="critical-on-degraded"
        ),
        pytest.param({"status": "degraded", "critical": 1}, id="critical-not-bool"),
        pytest.param({"critical": "false"}, id="critical-text"),
        # Equal to the booleans under ==, so only the type check refuses them.
        pytest.param({"critical": 0}, id="critical-zero"),
        pytest.param({"status": "critical", "critical": 1}, id="critical-one"),
    ],
)
async def test_a_malformed_snapshot_never_publishes_healthy(
    monkeypatch, caplog, snapshot
):
    """A verdict the runtime cannot read may be hiding a critical one, so
    nothing else is taken from it either."""
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    if isinstance(snapshot, dict):
        snapshot = {
            **snapshot,
            "active_triggers": ["grid_sag"],
            "degradation_reasons": ["firmware_liveness_degraded"],
            "evidence": {"enabled": True, "available": True},
        }

    async def _provider():
        return snapshot

    client = _FakeClient()
    publisher = MqttRuntimeNodeHeartbeatPublisher(
        broker_url="mqtt://localhost",
        device_id="dev-01",
        health_snapshot_provider=_provider,
        interval_seconds=30,
        authenticator=None,
        client_factory=lambda **_: client,
    )
    with caplog.at_level("WARNING"):
        await publisher._publish_once(client)

    assert json.loads(client.published[0][1]) == {
        "active_triggers": [],
        "device_id": "dev-01",
        "gateway_seen_ms": 0,
        "last_seen_ms": 1_000_000,
        "status": "degraded",
    }
    assert "health snapshot is malformed" in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault",
    [
        "provider-raises",
        "unmappable-evidence",
        "overflowing-evidence",
        "trigger-str-raises",
        "get-raises",
        "contains-raises",
        "huge-gap",
        "negative-gap",
        "gap-past-exact-integers",
        "uppercase-chain-head",
        "short-chain-head",
        "lowercase-event-type",
        "long-event-type",
    ],
)
async def test_a_snapshot_that_cannot_be_read_publishes_degraded(monkeypatch, fault):
    """Neither a failing provider nor a value the mapping cannot convert stops
    the heartbeat or publishes healthy."""
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)

    async def _provider():
        if fault == "provider-raises":
            raise RuntimeError("store locked")
        if fault == "trigger-str-raises":
            return {"critical": False, "active_triggers": [_Unprintable()]}
        if fault == "get-raises":
            return _RaisingGet(critical=False)
        if fault == "contains-raises":
            return _RaisingContains(critical=False)
        evidence_text = {
            "uppercase-chain-head": {"chain_head_hash": "AB" * 32},
            "short-chain-head": {"chain_head_hash": "abc"},
            "lowercase-event-type": {"action_event_type": "safety_action"},
            "long-event-type": {"action_event_type": "A" * 65},
        }
        if fault in evidence_text:
            return {
                "critical": False,
                "evidence": {"enabled": True, **evidence_text[fault]},
            }
        if fault in ("negative-gap", "gap-past-exact-integers"):
            gap = -1 if fault == "negative-gap" else 2**53
            return {
                "critical": False,
                "evidence": {"enabled": True, "attestation_gap_count": gap},
            }
        if fault == "huge-gap":
            # Past the int-to-str digit limit as well as the contract's bound.
            return {
                "critical": False,
                "evidence": {"enabled": True, "attestation_gap_count": 10**5000},
            }
        gap = float("inf") if fault == "overflowing-evidence" else "many"
        return {
            "critical": False,
            "evidence": {"enabled": True, "attestation_gap_count": gap},
        }

    client = _FakeClient()
    publisher = MqttRuntimeNodeHeartbeatPublisher(
        broker_url="mqtt://localhost",
        device_id="dev-01",
        health_snapshot_provider=_provider,
        interval_seconds=30,
        authenticator=None,
        client_factory=lambda **_: client,
    )
    await publisher._publish_once(client)
    await publisher._publish_once(client)

    assert len(client.published) == 2
    assert json.loads(client.published[1][1]) == {
        "active_triggers": [],
        "device_id": "dev-01",
        "gateway_seen_ms": 0,
        "last_seen_ms": 1_000_000,
        "status": "degraded",
    }


class _Unprintable:
    def __str__(self) -> str:
        raise LookupError("no name")


@pytest.mark.asyncio
async def test_a_failing_publish_does_not_end_the_heartbeat(monkeypatch):
    """Signing, encoding or the broker call failing on one tick leaves the
    next tick to run."""
    calls = 0

    class _FlakyClient(_FakeClient):
        def publish(self, topic, payload, qos=0, retain=False):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("broker went away")
            return super().publish(topic, payload, qos=qos, retain=retain)

    client = _FlakyClient()
    publisher = _publisher(client=client)
    publisher._interval_seconds = 0.01
    shutdown = asyncio.Event()
    serving = asyncio.create_task(publisher.serve_until(shutdown))
    await wait_until(
        lambda: len(client.published) >= 2 or serving.done(),
        what="two heartbeats published after a failed one, or the publisher ending",
    )
    shutdown.set()
    await settle([serving], what="the publisher stopping on shutdown")
    assert len(client.published) >= 2, "the heartbeat stopped after one failure"
    assert calls >= 3


class _RaisingGet(dict):
    def get(self, *_args, **_kwargs):
        raise KeyError("get")


class _RaisingContains(dict):
    def __contains__(self, _key) -> bool:
        raise KeyError("contains")


@pytest.mark.asyncio
async def test_cancelling_the_publisher_ends_it(monkeypatch):
    """A tick swallows failures, never a cancellation."""
    entered = asyncio.Event()

    async def _slow_provider():
        entered.set()
        await asyncio.sleep(60)
        return {"critical": False}

    client = _FakeClient()
    publisher = MqttRuntimeNodeHeartbeatPublisher(
        broker_url="mqtt://localhost",
        device_id="dev-01",
        health_snapshot_provider=_slow_provider,
        interval_seconds=30,
        authenticator=None,
        client_factory=lambda **_: client,
    )
    serving = asyncio.create_task(publisher.serve_until(asyncio.Event()))
    await asyncio.wait_for(entered.wait(), timeout=5.0)
    serving.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(serving, timeout=5.0)


@pytest.mark.asyncio
async def test_a_heartbeat_that_cannot_be_signed_is_not_claimed_as_published(
    monkeypatch, caplog
):
    """When even the degraded heartbeat cannot be signed, nothing is sent and
    the log says so rather than claiming a publication."""
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)

    class _BrokenSigner:
        def sign(self, payload, *, message_type):
            raise RuntimeError("signing key unavailable")

    client = _FakeClient()
    publisher = _publisher(client=client, authenticator=_BrokenSigner())
    with caplog.at_level("WARNING"):
        await publisher._tick(client)

    assert client.published == []
    assert "publishing degraded" not in caplog.text
    assert "no heartbeat was sent this tick" in caplog.text


@pytest.mark.asyncio
async def test_the_largest_exact_gap_count_is_published(monkeypatch):
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    client = _FakeClient()
    snapshot = {
        "critical": False,
        "evidence": {"enabled": True, "attestation_gap_count": 2**53 - 1},
    }
    await _publisher(client=client, snapshot=snapshot)._tick(client)
    payload = json.loads(client.published[0][1])
    assert payload["status"] == "healthy"
    assert payload["evidence"]["attestation_gap_count"] == 2**53 - 1


@pytest.mark.asyncio
async def test_the_longest_admitted_event_type_is_published(monkeypatch):
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    client = _FakeClient()
    snapshot = {
        "critical": False,
        "evidence": {"enabled": True, "action_event_type": "A" * 64},
    }
    await _publisher(client=client, snapshot=snapshot)._tick(client)
    payload = json.loads(client.published[0][1])
    assert payload["status"] == "healthy"
    assert payload["evidence"]["action_event_type"] == "A" * 64


@pytest.mark.asyncio
async def test_a_mapped_heartbeat_that_cannot_be_encoded_publishes_degraded(
    monkeypatch, caplog
):
    """Encoding, not mapping, fails: the degraded heartbeat goes out instead."""
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)

    class _EvidenceRefusingSigner:
        def sign(self, payload, *, message_type):
            if "evidence" in payload:
                raise RuntimeError("cannot sign evidence")
            return payload

    client = _FakeClient()
    snapshot = {"critical": False, "evidence": {"enabled": True}}
    publisher = _publisher(
        client=client, snapshot=snapshot, authenticator=_EvidenceRefusingSigner()
    )
    with caplog.at_level("WARNING"):
        await publisher._tick(client)
    assert json.loads(client.published[0][1])["status"] == "degraded"
    assert "heartbeat could not be encoded" in caplog.text


@pytest.mark.asyncio
async def test_a_publish_the_client_refuses_is_reported_as_not_sent(
    monkeypatch, caplog
):
    """paho answers a disconnected publish with rc=4 rather than raising."""

    class _Disconnected(_FakeClient):
        def publish(self, topic, payload, qos=0, retain=False):
            return SimpleNamespace(rc=4)

    client = _Disconnected()
    with caplog.at_level("WARNING"):
        await _publisher(client=client)._tick(client)
    assert "no heartbeat was sent this tick" in caplog.text
    assert "rc=4" in caplog.text


_WRONG_TYPES = {
    "gap-negative-fraction": {
        "evidence": {"enabled": True, "attestation_gap_count": -0.5}
    },
    "gap-fraction": {"evidence": {"enabled": True, "attestation_gap_count": 1.9}},
    "gap-bool": {"evidence": {"enabled": True, "attestation_gap_count": True}},
    "gap-string": {"evidence": {"enabled": True, "attestation_gap_count": "5"}},
    "gap-object": {"evidence": {"enabled": True, "attestation_gap_count": {}}},
    "available-string": {"evidence": {"enabled": True, "available": "false"}},
    "available-int": {"evidence": {"enabled": True, "available": 1}},
    "enabled-string": {"evidence": {"enabled": "false"}},
    "enabled-int": {"evidence": {"enabled": 1}},
    "chain-head-zero": {"evidence": {"enabled": True, "chain_head_hash": 0}},
    "chain-head-false": {"evidence": {"enabled": True, "chain_head_hash": False}},
    "event-type-zero": {"evidence": {"enabled": True, "action_event_type": 0}},
    "triggers-not-a-list": {"active_triggers": "grid_sag"},
    "trigger-not-a-string": {"active_triggers": [1]},
}


@pytest.mark.asyncio
@pytest.mark.parametrize("case", sorted(_WRONG_TYPES))
async def test_a_value_of_the_wrong_type_never_publishes_healthy(monkeypatch, case):
    """A type is checked before any conversion: nothing is rounded, parsed
    or read as truthy into a value the contract admits."""
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    client = _FakeClient()
    snapshot = {"critical": False, **_WRONG_TYPES[case]}
    await _publisher(client=client, snapshot=snapshot)._tick(client)
    assert json.loads(client.published[0][1]) == {
        "active_triggers": [],
        "device_id": "dev-01",
        "gateway_seen_ms": 0,
        "last_seen_ms": 1_000_000,
        "status": "degraded",
    }


@pytest.mark.asyncio
async def test_absent_and_null_evidence_values_publish_as_empty(monkeypatch):
    """The values the runtime emits while evidence is unavailable still map."""
    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
    client = _FakeClient()
    snapshot = {
        "critical": False,
        "evidence": {"enabled": True, "chain_head_hash": None, "available": False},
    }
    await _publisher(client=client, snapshot=snapshot)._tick(client)
    payload = json.loads(client.published[0][1])
    assert payload["status"] == "healthy"
    assert payload["evidence"] == {
        "chain_head_hash": "",
        "attestation_gap_count": 0,
        "available": False,
        "action_event_type": "",
    }


@pytest.mark.asyncio
async def test_a_refusing_signing_clock_sends_nothing_and_logs_no_traceback(
    tmp_path, caplog
):
    from ori.security.signing_clock import SigningClock

    # A store that cannot open: the clock refuses every signing time.
    refusing = SigningClock(str(tmp_path / "missing" / "state.db"))
    authenticator = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(shared_secret="site-test-secret", max_skew_ms=300_000),
        replay_cache=_verifier_cache(),
        signing_clock=refusing,
    )
    client = _FakeClient()
    publisher = _publisher(client=client, authenticator=authenticator)
    with caplog.at_level("WARNING"):
        await publisher._tick(client)
    refusing.stop()
    assert client.published == []
    assert not any(record.exc_info for record in caplog.records)
