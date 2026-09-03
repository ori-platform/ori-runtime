# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Tests for ori/runtime.py — Step 20.

All external dependencies (HAL adapters, WhatsApp, SMS, relay, LocalLLM)
are mocked.  No real hardware, credentials, or network calls are made.
"""

import asyncio
import base64
import contextlib
import json
import logging
import os
import textwrap
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from ori.config import (
    Config,
    ConfigValidationError,
    GatewayConfig,
    TelemetryExportConfig,
)
from ori.network.deduplicator import EventDeduplicator
from ori.network.event_bus import EventBus
from ori.network.events import OriEvent, SensorReading
from ori.policy.device_policy import DevicePolicy
from ori.policy.remote_fetch import FetchedRemotePolicy, RemotePolicyFetchError
from ori.reasoning.action_dispatcher import ActionDispatcher
from ori.reasoning.elevator import SkillContext
from ori.runtime import (
    OriRuntime,
    _build_gateway_message_auth,
    _build_gateway_message_encryptor,
    _build_gateway_reasoner,
    _build_local_llm,
    _build_remote_command_verifier,
    _build_runtime_node_heartbeat_publisher,
    _coap_command_from_context,
    _count_active_triggers,
    _maybe_autoload_dotenv,
    _message_from_context,
    _process_target_from_context,
    _resolve_dispatcher_approval_timeout,
    _resolve_local_model_file,
    _resolve_setup_notification_channels,
    _setup_success_message,
    _validate_required_runtime_capabilities,
    _warn_sms_webhook_security_posture,
    requires_production_posture,
)
from ori.security.gateway_messages import (
    GatewayMessageAuthConfig,
    GatewayMessageAuthenticator,
)
from ori.security.remote_commands.throttle import RemoteCommandThrottleDecision
from ori.skills.signing import canonical_signed_payload
from ori.state.store import StateStore
from tests.commissioning.signing import commission_relay

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except Exception:  # pragma: no cover - environment without cryptography support
    Ed25519PrivateKey = None
    Encoding = None
    PublicFormat = None


def _capability_config(
    *,
    profile: str = "production",
    deployment_type: str = "pi",
    enforce: bool = False,
    relay: dict[str, Any] | None = None,
    coap: dict[str, Any] | None = None,
    sensors: list[Any] | None = None,
    default_tier: str = "rule",
    local_model: str = "",
    model_path: str = "",
    status_signaling: dict[str, Any] | None = None,
) -> Any:
    return SimpleNamespace(
        device=SimpleNamespace(
            deployment_profile=profile,
            deployment_type=deployment_type,
        ),
        security={"enforce_production_posture": enforce},
        actions=SimpleNamespace(relay=relay or {}, coap=coap or {}),
        sensors=sensors or [],
        reasoning=SimpleNamespace(
            default_tier=default_tier,
            local_model=local_model,
            model_path=model_path,
        ),
        hal=SimpleNamespace(status_signaling=status_signaling or {}),
    )


# ── Fixtures ──────────────────────────────────────────────────────────────────


def test_build_gateway_message_auth_uses_configured_env_secret(monkeypatch):
    monkeypatch.setenv("GATEWAY_SHARED_SECRET", "site-local-secret")
    config = SimpleNamespace(
        gateway=GatewayConfig(
            enabled=True,
            broker_url="mqtt://broker.local",
            auth={
                "enabled": True,
                "shared_secret_env": "GATEWAY_SHARED_SECRET",
                "max_clock_skew_ms": 300_000,
                "replay_ttl_ms": 300_000,
            },
        )
    )

    auth = _build_gateway_message_auth(config)

    assert auth is not None


def test_remote_command_secret_env_names_are_not_logged(monkeypatch, caplog):
    monkeypatch.delenv("ORI_REMOTE_COMMAND_HMAC_SECRET", raising=False)
    config = SimpleNamespace(
        device=SimpleNamespace(id="device-01"),
        security={
            "remote_commands": {
                "enabled": True,
                "hmac_secret_env": "ORI_REMOTE_COMMAND_HMAC_SECRET",
                "previous_hmac_secret_env": "ORI_REMOTE_COMMAND_PREVIOUS_SECRET",
            }
        },
    )

    with caplog.at_level(logging.WARNING):
        verifier = _build_remote_command_verifier(config)

    assert verifier is not None
    assert "ORI_REMOTE_COMMAND_HMAC_SECRET" not in caplog.text
    assert "ORI_REMOTE_COMMAND_PREVIOUS_SECRET" not in caplog.text
    assert "configured HMAC secret environment variable is not set" in caplog.text


def test_resolve_setup_notification_channels_deduplicates_primary():
    assert _resolve_setup_notification_channels(
        ["primary", "sms", "whatsapp", "primary"],
        "sms",
    ) == ["sms", "whatsapp"]


def test_setup_success_message_is_bounded_and_notification_only():
    config = SimpleNamespace(
        device=SimpleNamespace(
            id="phone-01",
            location="Temidayo Site",
            deployment_type="phone",
        ),
        actions=SimpleNamespace(relay={"enabled": True, "gpio_pin": 26}),
    )

    message = _setup_success_message(
        config=config,
        connected_sensor_count=1,
        active_trigger_count=3,
    )

    assert message == (
        "Ori is online at Temidayo Site: 1 sensor connected and 3 rules active. "
        "Ori will notify you when it detects a configured risk. "
        "No safety cutoff is commissioned, so Ori can warn but cannot intervene."
    )
    assert len(message) <= 320
    assert "protecting" not in message
    assert "skills loaded" not in message
    assert "intervention armed" not in message
    assert "automatic protection" not in message
    assert "relay" not in message


@pytest.mark.parametrize("location", ["", "   ", "\n\t"])
def test_setup_success_message_falls_back_for_empty_location(location):
    config = SimpleNamespace(device=SimpleNamespace(location=location))

    message = _setup_success_message(
        config=config,
        connected_sensor_count=0,
        active_trigger_count=0,
    )

    assert message.startswith("Ori is online at site: 0 sensors connected")
    assert message.endswith(
        "No safety cutoff is commissioned, so Ori can warn but cannot intervene."
    )


def test_setup_success_message_truncates_only_normalized_location():
    config = SimpleNamespace(
        device=SimpleNamespace(location="  Abuja\n" + "very-long-site " * 100)
    )

    message = _setup_success_message(
        config=config,
        connected_sensor_count=12,
        active_trigger_count=34,
    )

    assert len(message) == 320
    assert "\n" not in message
    assert ": 12 sensors connected and 34 rules active." in message
    assert message.endswith(
        "No safety cutoff is commissioned, so Ori can warn but cannot intervene."
    )


def test_count_active_triggers_counts_each_rule_once():
    sensors = [
        SimpleNamespace(id="temperature-1", type="temperature"),
        SimpleNamespace(id="humidity-1", type="humidity"),
        SimpleNamespace(id="current-1", type="current"),
    ]
    skills = [
        SimpleNamespace(
            sensors_required=[
                {"type": "temperature"},
                {"type": "temperature"},
                {"type": "humidity"},
            ],
            triggers=[SimpleNamespace(name="hot"), SimpleNamespace(name="humid")],
        ),
        SimpleNamespace(
            sensors_required=[{"type": "humidity"}],
            triggers=[SimpleNamespace(name="condensation")],
        ),
    ]

    count = _count_active_triggers(
        configured_sensors=sensors,
        connected_sensor_ids={"temperature-1", "humidity-1"},
        loaded_skills=skills,
    )

    assert count == 3


def test_count_active_triggers_excludes_unconnected_unrelated_and_wildcard_skills():
    sensors = [
        SimpleNamespace(id="temperature-1", type="temperature"),
        SimpleNamespace(id="current-1", type="current"),
    ]
    skills = [
        SimpleNamespace(
            sensors_required=[{"type": "temperature"}],
            triggers=[SimpleNamespace(name="hot")],
        ),
        SimpleNamespace(
            sensors_required=[{"type": "voltage"}],
            triggers=[SimpleNamespace(name="sag")],
        ),
        SimpleNamespace(
            sensors_required=[],
            triggers=[SimpleNamespace(name="wildcard")],
        ),
    ]

    count = _count_active_triggers(
        configured_sensors=sensors,
        connected_sensor_ids={"current-1"},
        loaded_skills=skills,
    )

    assert count == 0


def test_count_active_triggers_uses_exact_event_bus_sensor_type():
    count = _count_active_triggers(
        configured_sensors=[SimpleNamespace(id="temperature-1", type=" temperature ")],
        connected_sensor_ids={"temperature-1"},
        loaded_skills=[
            SimpleNamespace(
                sensors_required=[{"type": "temperature"}],
                triggers=[SimpleNamespace(name="hot")],
            )
        ],
    )

    assert count == 0


@pytest.mark.asyncio
async def test_setup_success_notification_sends_enabled_channels():
    class FakeAlertSender:
        def __init__(self):
            self.calls = []

        async def send(self, *, message, to_number, preferred_channel=None):
            raise AssertionError("setup notifications must use exact-channel send")

        async def send_exact(self, *, message, to_number, channel):
            self.calls.append(
                {
                    "message": message,
                    "to_number": to_number,
                    "channel": channel,
                }
            )
            return True

    runtime = OriRuntime()
    runtime._operator_contact = "+2348000000000"
    runtime._connected_sensor_ids = {"phone-main-power"}
    runtime._loaded_skills = [
        SimpleNamespace(
            name="energy-anomaly-detector",
            sensors_required=[{"type": "usb_power"}],
            triggers=[SimpleNamespace(name="high_draw")],
        )
    ]
    runtime._last_alert_timestamps_by_channel = {}
    runtime._last_alert_timestamps_by_trigger = {}
    runtime._runtime_started_at_ms = 1_700_000_000_000
    sender = FakeAlertSender()
    config = SimpleNamespace(
        device=SimpleNamespace(
            id="phone-01",
            location="Temidayo Site",
            deployment_type="phone",
        ),
        sensors=[SimpleNamespace(id="phone-main-power", type="usb_power")],
        actions=SimpleNamespace(
            setup_notifications={"enabled": True, "channels": ["sms", "whatsapp"]},
            primary_alert_channel="sms",
            sms={"enabled": True},
            whatsapp={"enabled": True},
        ),
    )

    await runtime._send_setup_success_notifications(config, sender)

    assert [call["channel"] for call in sender.calls] == ["sms", "whatsapp"]
    assert all(call["to_number"] == "+2348000000000" for call in sender.calls)
    assert all(
        "1 sensor connected and 1 rule active" in call["message"]
        for call in sender.calls
    )
    assert all("cannot intervene" in call["message"] for call in sender.calls)
    assert runtime._last_alert_timestamps_by_trigger["runtime_setup_complete"] > 0


@pytest.mark.asyncio
async def test_setup_success_notification_queues_failed_delivery():
    class FailingAlertSender:
        async def send(self, *, message, to_number, preferred_channel=None):
            raise AssertionError("setup notifications must use exact-channel send")

        async def send_exact(self, *, message, to_number, channel):
            return False

    runtime = OriRuntime()
    runtime._operator_contact = "+2348000000000"
    runtime._connected_sensor_ids = {"temperature-1"}
    runtime._loaded_skills = [
        SimpleNamespace(
            sensors_required=[{"type": "temperature"}],
            triggers=[SimpleNamespace(name="overheat")],
        )
    ]
    runtime._last_alert_timestamps_by_channel = {}
    runtime._last_alert_timestamps_by_trigger = {}
    runtime._runtime_started_at_ms = 1_700_000_000_000
    runtime._state_store = SimpleNamespace(
        enqueue_alert=AsyncMock(return_value=True),
        get_skill_state=AsyncMock(return_value=None),
        set_skill_state=AsyncMock(return_value=None),
    )
    config = SimpleNamespace(
        device=SimpleNamespace(location="Abuja"),
        sensors=[SimpleNamespace(id="temperature-1", type="temperature")],
        actions=SimpleNamespace(
            setup_notifications={"enabled": True, "channels": ["sms"]},
            primary_alert_channel="sms",
            sms={"enabled": True},
            whatsapp={"enabled": False},
        ),
    )

    await runtime._send_setup_success_notifications(config, FailingAlertSender())

    runtime._state_store.enqueue_alert.assert_awaited_once()
    queued = runtime._state_store.enqueue_alert.await_args.kwargs
    assert queued["channel"] == "sms"
    assert queued["action_tier"] == "A"
    assert queued["trigger_name"] == "runtime_setup_complete"
    assert "1 sensor connected and 1 rule active" in queued["message"]
    assert "cannot intervene" in queued["message"]


@pytest.mark.asyncio
async def test_start_telemetry_export_subscribes_wildcard_handler(monkeypatch):
    served = asyncio.Event()

    class FakeExporter:
        def __init__(self, *, device_id, config):
            self.device_id = device_id
            self.config = config

        async def handle_event(self, event):
            return None

        async def serve_until(self, shutdown_event):
            served.set()
            await shutdown_event.wait()

    monkeypatch.setattr("ori.runtime.HttpTelemetryExporter", FakeExporter)
    runtime = OriRuntime()
    event_bus = EventBus()
    config = SimpleNamespace(
        device=SimpleNamespace(id="phone-01"),
        telemetry_export=TelemetryExportConfig(
            enabled=True,
            endpoint="https://api.example.test/runtime/telemetry",
            api_key_env="ORI_ENERGY_DEVICE_API_KEY",
        ),
    )

    task = runtime._start_telemetry_export_if_enabled(config, event_bus)

    try:
        assert task is not None
        assert event_bus.subscriber_count("*") == 1
    finally:
        runtime._shutdown_event.set()
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


def _sms_webhook_posture_config(
    *,
    host: str,
    signature_mode: str = "token_only",
    allowed_source_cidrs: list[str] | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        actions=SimpleNamespace(
            sms={
                "incoming_webhook": {
                    "enabled": True,
                    "host": host,
                    "allowed_source_cidrs": allowed_source_cidrs or [],
                    "signature": {"mode": signature_mode},
                }
            }
        )
    )


def test_sms_webhook_security_posture_warns_for_public_token_only(caplog):
    config = _sms_webhook_posture_config(host="0.0.0.0")

    with caplog.at_level(logging.WARNING):
        _warn_sms_webhook_security_posture(config)

    assert "signature.mode=token_only" in caplog.text
    assert "allowed_source_cidrs is empty" in caplog.text


def test_sms_webhook_security_posture_accepts_loopback_token_only(caplog):
    config = _sms_webhook_posture_config(host="127.0.0.1")

    with caplog.at_level(logging.WARNING):
        _warn_sms_webhook_security_posture(config)

    assert "SMS_WEBHOOK" not in caplog.text


def test_sms_webhook_security_posture_accepts_public_signed_allowlisted(caplog):
    config = _sms_webhook_posture_config(
        host="192.0.2.10",
        signature_mode="token_and_hmac",
        allowed_source_cidrs=["203.0.113.0/24"],
    )

    with caplog.at_level(logging.WARNING):
        _warn_sms_webhook_security_posture(config)

    assert "SMS_WEBHOOK" not in caplog.text


def test_build_gateway_message_auth_accepts_previous_env_secret(monkeypatch):
    monkeypatch.setenv("GATEWAY_SHARED_SECRET", "current-secret")
    monkeypatch.setenv("GATEWAY_PREVIOUS_SHARED_SECRET", "previous-secret")
    config = SimpleNamespace(
        gateway=GatewayConfig(
            enabled=True,
            broker_url="mqtt://broker.local",
            auth={
                "enabled": True,
                "shared_secret_env": "GATEWAY_SHARED_SECRET",
                "previous_shared_secret_env": "GATEWAY_PREVIOUS_SHARED_SECRET",
                "max_clock_skew_ms": 300_000,
                "replay_ttl_ms": 300_000,
            },
        )
    )
    previous_auth = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(shared_secret="previous-secret")
    )
    payload = {
        "request_id": "req-1",
        "device_id": "dev-01",
        "export_type": "health",
    }
    signed = previous_auth.sign(
        payload,
        message_type="export_response",
        signed_at_ms=1_000,
    )

    auth = _build_gateway_message_auth(config)

    assert auth is not None
    assert (
        auth.verify(
            signed,
            message_type="export_response",
            expected_device_id="dev-01",
            expected_request_id="req-1",
            now_ms_value=1_000,
        )
        == payload
    )


def test_build_gateway_message_auth_rejects_missing_env_secret(monkeypatch):
    monkeypatch.delenv("GATEWAY_SHARED_SECRET", raising=False)
    config = SimpleNamespace(
        gateway=GatewayConfig(
            enabled=True,
            broker_url="mqtt://broker.local",
            auth={
                "enabled": True,
                "shared_secret_env": "GATEWAY_SHARED_SECRET",
                "max_clock_skew_ms": 300_000,
                "replay_ttl_ms": 300_000,
            },
        )
    )

    with pytest.raises(ValueError) as excinfo:
        _build_gateway_message_auth(config)
    assert "GATEWAY_SHARED_SECRET" not in str(excinfo.value)
    assert "configured shared-secret environment variable is empty" in str(
        excinfo.value
    )


def test_build_gateway_message_auth_redacts_previous_env_secret(monkeypatch, caplog):
    monkeypatch.setenv("GATEWAY_SHARED_SECRET", "current-secret")
    monkeypatch.delenv("GATEWAY_PREVIOUS_SHARED_SECRET", raising=False)
    config = SimpleNamespace(
        gateway=GatewayConfig(
            enabled=True,
            broker_url="mqtt://broker.local",
            auth={
                "enabled": True,
                "shared_secret_env": "GATEWAY_SHARED_SECRET",
                "previous_shared_secret_env": "GATEWAY_PREVIOUS_SHARED_SECRET",
                "max_clock_skew_ms": 300_000,
                "replay_ttl_ms": 300_000,
            },
        )
    )

    with caplog.at_level(logging.WARNING):
        auth = _build_gateway_message_auth(config)

    assert auth is not None
    assert "GATEWAY_PREVIOUS_SHARED_SECRET" not in caplog.text
    assert "previous shared-secret environment variable is configured but empty" in (
        caplog.text
    )


def test_build_remote_command_verifier_passes_previous_env_secret(monkeypatch):
    monkeypatch.setenv("ORI_REMOTE_COMMAND_HMAC_SECRET", "current-secret")
    monkeypatch.setenv("ORI_REMOTE_COMMAND_PREVIOUS_HMAC_SECRET", "previous-secret")
    config = SimpleNamespace(
        device=SimpleNamespace(id="dev-01"),
        security={
            "remote_commands": {
                "enabled": True,
                "hmac_secret_env": "ORI_REMOTE_COMMAND_HMAC_SECRET",
                "previous_hmac_secret_env": "ORI_REMOTE_COMMAND_PREVIOUS_HMAC_SECRET",
                "max_skew_seconds": 300,
                "allowed_senders": {"sms": ["+2348012345678"]},
                "allow_unlisted_senders": False,
            }
        },
    )

    verifier = _build_remote_command_verifier(config)

    assert verifier is not None


def test_build_gateway_message_encryptor_uses_gateway_secret(monkeypatch):
    monkeypatch.setenv("GATEWAY_SHARED_SECRET", "site-local-secret")
    config = SimpleNamespace(
        gateway=GatewayConfig(
            enabled=True,
            broker_url="mqtt://broker.local",
            auth={
                "enabled": True,
                "shared_secret_env": "GATEWAY_SHARED_SECRET",
            },
            encryption={"enabled": True},
        )
    )

    encryptor = _build_gateway_message_encryptor(config)

    assert encryptor is not None


def test_build_gateway_message_encryptor_rejects_missing_env_secret(monkeypatch):
    monkeypatch.delenv("GATEWAY_SHARED_SECRET", raising=False)
    config = SimpleNamespace(
        gateway=GatewayConfig(
            enabled=True,
            broker_url="mqtt://broker.local",
            auth={
                "enabled": True,
                "shared_secret_env": "GATEWAY_SHARED_SECRET",
            },
            encryption={"enabled": True},
        )
    )

    with pytest.raises(ValueError) as excinfo:
        _build_gateway_message_encryptor(config)
    assert "GATEWAY_SHARED_SECRET" not in str(excinfo.value)
    assert "configured shared-secret environment variable is empty" in str(
        excinfo.value
    )


def test_build_gateway_message_encryptor_requires_auth_enabled():
    config = SimpleNamespace(
        gateway=GatewayConfig(
            enabled=True,
            broker_url="mqtt://broker.local",
            auth={"enabled": False},
            encryption={"enabled": True},
        )
    )

    with pytest.raises(ValueError, match="gateway auth"):
        _build_gateway_message_encryptor(config)


async def _stop_and_join(runtime, start_task: asyncio.Task) -> None:
    """Shut a started runtime down and join its task.

    The cancellation is expected, so `CancelledError` is suppressed; awaiting
    the task is what joins it, and is the point rather than its value.
    """
    await runtime.stop()
    start_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await start_task


@pytest.mark.asyncio
async def test_a_failed_sensor_connect_does_not_take_the_runtime_down(
    minimal_config, monkeypatch
):
    """A sensor that cannot connect is skipped; the runtime keeps running.

    This is the boundary a hardened refusal was briefly placed at, and the
    reason it was withdrawn. Aborting startup on any unconnectable sensor lets
    an unrelated network-backed sensor take the whole runtime down, and with it
    every protection the device does have — Tier D included. A safety runtime
    that will not start is not failing closed; it has removed the agent.

    The sensor is still not silently fine: it is absent from the connected set
    and reported disconnected on the health surface.
    """
    from ori.hal.base import AdapterConnectionError
    from ori.hal.psutil_adapter import PsutilAdapter

    attempts: list[str] = []

    async def _refuse(self, config):
        attempts.append(config.get("sensor_id", "?"))
        raise AdapterConnectionError("simulated: device does not answer")

    monkeypatch.setattr(PsutilAdapter, "connect", _refuse)

    runtime = OriRuntime(config_path=str(minimal_config))
    start_task = asyncio.create_task(runtime.start())
    try:
        # Wait for the sensor loop, not merely for the event bus: the bus is
        # built well before any adapter is connected, so breaking on it would
        # assert against a runtime that had not reached the boundary yet.
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline and not attempts:
            if start_task.done():
                break
            await asyncio.sleep(0.05)

        # The runtime came up rather than aborting.
        assert not start_task.done(), (
            "startup aborted on an unconnectable sensor: "
            f"{start_task.exception() if start_task.done() else ''}"
        )
        assert runtime._event_bus is not None
        # And the sensor is absent, not quietly counted as present.
        assert "cpu-sensor" not in runtime._connected_sensor_ids
        # Without this the test passes whether or not the refusal ever fired:
        # any exception from connect() produces the same skip.
        assert attempts, "connect() was never attempted, so nothing was proven"
    finally:
        await _stop_and_join(runtime, start_task)


@pytest.mark.asyncio
async def test_a_failed_sensor_connect_is_non_fatal_under_hardened_posture_too(
    minimal_config, monkeypatch
):
    """The same boundary, with `enforce_production_posture` on.

    The development case alone does not guard the regression it exists for:
    reinstating a hardened-only refusal leaves it green, because development
    never refuses. This is the posture where the withdrawn behaviour would
    fire, so it is the one that has to hold.

    Aborting here would let any unconnectable sensor — a network-backed one on
    a slow broker, say — take down a runtime that is protecting something else
    entirely. A safety runtime that will not start has removed the agent, which
    is not the same as failing closed.
    """
    import base64

    import yaml
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from ori.hal.base import AdapterConnectionError
    from ori.hal.psutil_adapter import PsutilAdapter
    from ori.security.config_signatures import (
        CONFIG_SIGNATURE_SCHEMA,
        canonical_config_signature_payload,
    )

    # A genuinely hardened config, not a stubbed posture: production posture
    # demands signed skills, signed config and an encrypted state path, and
    # none of those relate to the sensor boundary under test. Satisfying them
    # is what makes `requires_production_posture` true at the sensor loop,
    # which is the only reason this test differs from its development twin.
    private_key = Ed25519PrivateKey.generate()
    public_key_b64 = base64.b64encode(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")

    raw = yaml.safe_load(minimal_config.read_text(encoding="utf-8"))
    assert "security" not in raw, "fixture now sets security; merge rather than assign"
    raw["security"] = {
        "enforce_production_posture": True,
        "skills": {"require_signed": True},
        "config_signature": {"require_signed": True},
    }
    # Local reasoning is a host capability the hardened gate also checks, and it
    # is nothing to do with this boundary; turn it off rather than ship a model.
    raw.setdefault("reasoning", {})["default_tier"] = "rule"
    raw["state"] = {
        "encryption": {
            "mode": "filesystem_required",
            "encrypted_path_prefixes": [str(minimal_config.parent)],
        }
    }
    raw["config_signature"] = {
        "schema": CONFIG_SIGNATURE_SCHEMA,
        "signer_id": "product-provisioning-test",
        "signed_at_ms": 1_800_000_000_000,
        "signature": "ed25519:",
    }
    signature = private_key.sign(canonical_config_signature_payload(raw))
    raw["config_signature"]["signature"] = "ed25519:" + base64.b64encode(
        signature
    ).decode("ascii")

    hardened = minimal_config.parent / "ori-hardened.yaml"
    hardened.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    # The anchor is delivered out of band, as the signing contract requires.
    monkeypatch.setenv("ORI_CONFIG_TRUST_ANCHOR_PUBLIC_KEY_B64", public_key_b64)

    attempts: list[str] = []

    async def _refuse(self, config):
        attempts.append(config.get("sensor_id", "?"))
        raise AdapterConnectionError("simulated: device does not answer")

    monkeypatch.setattr(PsutilAdapter, "connect", _refuse)

    runtime = OriRuntime(config_path=str(hardened))
    start_task = asyncio.create_task(runtime.start())
    try:
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline and not attempts:
            if start_task.done():
                break
            await asyncio.sleep(0.05)

        assert attempts, "connect() was never attempted, so nothing was proven"
        # Without this the test would pass on a config that silently stayed in
        # development, which is the posture it exists to exclude.
        assert runtime._config is not None
        assert requires_production_posture(
            device=runtime._config.device,
            security=runtime._config.security,
        ), "the hardened posture did not take; this test proves nothing"
        assert not start_task.done(), (
            "hardened startup aborted on an unconnectable sensor: "
            f"{start_task.exception() if start_task.done() else ''}"
        )
        assert runtime._event_bus is not None
        assert "cpu-sensor" not in runtime._connected_sensor_ids
    finally:
        await _stop_and_join(runtime, start_task)


@pytest.fixture
def minimal_config(tmp_path: Path) -> Path:
    """Write a minimal valid ori.yaml that uses only the psutil adapter."""
    skill_dir = tmp_path / "skills" / "test-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "skill.yaml").write_text(
        textwrap.dedent("""\
            name: test-skill
            version: 0.1.0
            author: test
            sensors_required:
              - type: cpu_percent
            triggers:
              - name: high_cpu
                condition: "value > 90"
                action_tier: A
                cooldown_seconds: 0
                escalate_to: local_slm
            actions:
              available:
                - name: alert_whatsapp
                  tier: A
              defaults:
                high_cpu: [alert_whatsapp]
        """),
        encoding="utf-8",
    )

    cfg = tmp_path / "ori.yaml"
    cfg.write_text(
        textwrap.dedent(f"""\
            device:
              id: test-device-01
              name: Test Device
              location: Test Lab

            sensors:
              - id: cpu-sensor
                type: cpu_percent
                protocol: psutil
                poll_interval_ms: 100

            skills:
              - name: test-skill
                version: "0.1.0"
                config: {{}}

            reasoning:
              default_tier: local
              local_model: ""
              model_path: ""

            gateway:
              enabled: false
              broker_url: ""

            actions:
              primary_alert_channel: sms
              whatsapp:
                enabled: false
              sms:
                enabled: false
              relay:
                enabled: false

            skills_dir: {str(tmp_path / "skills")}
            database:
              path: {str(tmp_path / "ori_state.db")}
        """),
        encoding="utf-8",
    )
    return cfg


def _patch_external(monkeypatch):
    """Patch all external I/O so tests run without hardware or credentials."""
    monkeypatch.setattr(
        "ori.actions.whatsapp.TwilioProvider.send", AsyncMock(return_value=True)
    )
    monkeypatch.setattr("ori.actions.sms.SMSAction.send", AsyncMock(return_value=True))


def _treat_scratch_skills_as_packaged(monkeypatch):
    """Let skills written to a scratch directory load as first-party.

    Skills are trusted because they ship inside the package; anything else
    must carry a verified signature. Tests that exercise runtime wiring write
    their skills to ``tmp_path``, so they say explicitly that the scratch
    directory stands in for the packaged one rather than relying on unsigned
    content loading by default.
    """
    monkeypatch.setattr(
        "ori.skills.loader.SkillLoader._is_core_bundled_skill",
        lambda self, skill_dir: True,
    )


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestRequiredRuntimeCapabilities:
    def test_development_keeps_optional_degradation(self, monkeypatch, tmp_path):
        config = _capability_config(
            profile="development",
            relay={"gpio_pin": 26},
            coap={"enabled": True},
            sensors=[SimpleNamespace(protocol="coap")],
            default_tier="local",
        )
        monkeypatch.setattr("ori.runtime.gpio_backend_importable", lambda: False)
        monkeypatch.setattr("ori.runtime.coap_backend_available", lambda: False)
        monkeypatch.setattr("ori.runtime.local_llm_backend_available", lambda: False)

        _validate_required_runtime_capabilities(config, str(tmp_path / "ori.yaml"))

    @pytest.mark.parametrize("profile", ["staging", "production"])
    def test_hardened_gpio_relay_requires_gpiozero(
        self, profile, monkeypatch, tmp_path
    ):
        config = _capability_config(
            profile=profile,
            relay={"enabled": False, "gpio_pin": 26},
        )
        monkeypatch.setattr("ori.runtime.gpio_backend_importable", lambda: False)

        with pytest.raises(ConfigValidationError, match="gpiozero.*relay control"):
            _validate_required_runtime_capabilities(config, str(tmp_path / "ori.yaml"))

    def test_hardened_status_signaling_requires_gpiozero(self, monkeypatch, tmp_path):
        config = _capability_config(status_signaling={"enabled": True})
        monkeypatch.setattr("ori.runtime.gpio_backend_importable", lambda: False)

        with pytest.raises(ConfigValidationError, match="gpiozero.*status signaling"):
            _validate_required_runtime_capabilities(config, str(tmp_path / "ori.yaml"))

    @pytest.mark.parametrize("profile", ["staging", "production"])
    def test_hardened_gpio_refuses_an_unarbitrated_backend(
        self, profile, monkeypatch, tmp_path
    ):
        """gpiozero present and pins moving is not the same as pins owned.

        The fallback drives /dev/gpiomem directly and claims no line, so the
        kernel refuses no second writer. Measured on a Pi 4: a claimed line
        reports `consumer="lg"` and an unclaimed one still reads as an input
        while it is being held high.

        The import check cannot see the difference -- it passes either way --
        which is what made this reachable.
        """
        config = _capability_config(
            profile=profile,
            relay={"enabled": True, "gpio_pin": 26},
        )
        monkeypatch.setattr("ori.runtime.gpio_backend_importable", lambda: True)
        monkeypatch.setattr("ori.runtime.gpio_backend_arbitrated", lambda: False)
        monkeypatch.setattr(
            "ori.runtime.resolved_pin_factory_name", lambda: "NativeFactory"
        )

        with pytest.raises(ConfigValidationError, match="NativeFactory"):
            _validate_required_runtime_capabilities(config, str(tmp_path / "ori.yaml"))

    def test_hardened_gpio_accepts_an_arbitrated_backend(self, monkeypatch, tmp_path):
        config = _capability_config(
            profile="production",
            relay={"enabled": True, "gpio_pin": 26},
        )
        monkeypatch.setattr("ori.runtime.gpio_backend_importable", lambda: True)
        monkeypatch.setattr("ori.runtime.gpio_backend_arbitrated", lambda: True)

        _validate_required_runtime_capabilities(config, str(tmp_path / "ori.yaml"))

    def test_a_missing_dependency_is_reported_as_such_not_as_a_bad_factory(
        self, monkeypatch, tmp_path
    ):
        """The two failures need different fixes, so they must read differently.

        One means install a package; the other means the package is installed
        and the platform cannot back it.
        """
        config = _capability_config(
            profile="production",
            relay={"enabled": True, "gpio_pin": 26},
        )
        monkeypatch.setattr("ori.runtime.gpio_backend_importable", lambda: False)
        monkeypatch.setattr("ori.runtime.gpio_backend_arbitrated", lambda: False)

        with pytest.raises(ConfigValidationError, match="gpiozero is unavailable"):
            _validate_required_runtime_capabilities(config, str(tmp_path / "ori.yaml"))

    def test_hardened_unwired_relay_without_gpio_pin_needs_no_gpiozero(
        self, monkeypatch, tmp_path
    ):
        config = _capability_config(relay={"enabled": False})
        monkeypatch.setattr("ori.runtime.gpio_backend_importable", lambda: False)

        _validate_required_runtime_capabilities(config, str(tmp_path / "ori.yaml"))

    @pytest.mark.parametrize(
        "coap,sensors",
        [
            ({"enabled": True}, []),
            ({"enabled": False}, [SimpleNamespace(protocol="coap")]),
        ],
    )
    def test_hardened_coap_requires_aiocoap(self, coap, sensors, monkeypatch, tmp_path):
        config = _capability_config(coap=coap, sensors=sensors)
        monkeypatch.setattr("ori.runtime.coap_backend_available", lambda: False)

        with pytest.raises(ConfigValidationError, match="aiocoap.*CoAP"):
            _validate_required_runtime_capabilities(config, str(tmp_path / "ori.yaml"))

    def test_hardened_local_reasoning_requires_backend(self, monkeypatch, tmp_path):
        model = tmp_path / "model.gguf"
        model.write_bytes(b"model")
        config = _capability_config(
            default_tier="local",
            local_model=str(model),
        )
        monkeypatch.setattr("ori.runtime.local_llm_backend_available", lambda: False)

        with pytest.raises(ConfigValidationError, match="llama-cpp-python"):
            _validate_required_runtime_capabilities(config, str(tmp_path / "ori.yaml"))

    def test_hardened_local_reasoning_requires_model(self, monkeypatch, tmp_path):
        config = _capability_config(default_tier="local")
        monkeypatch.setattr("ori.runtime.local_llm_backend_available", lambda: True)

        with pytest.raises(ConfigValidationError, match="GGUF model"):
            _validate_required_runtime_capabilities(config, str(tmp_path / "ori.yaml"))

    @pytest.mark.parametrize(
        ("local_model", "model_path"),
        [
            ("", ""),
            ("leftover-template-model", ""),
            ("", "/leftover/template/models"),
            ("leftover-template-model", "/leftover/template/models"),
        ],
    )
    def test_hardened_rule_only_does_not_require_llama(
        self, local_model, model_path, monkeypatch, tmp_path
    ):
        config = _capability_config(
            default_tier="rule",
            local_model=local_model,
            model_path=model_path,
        )
        monkeypatch.setattr("ori.runtime.local_llm_backend_available", lambda: False)

        _validate_required_runtime_capabilities(config, str(tmp_path / "ori.yaml"))

    def test_explicit_enforcement_hardens_development(self, monkeypatch, tmp_path):
        config = _capability_config(
            profile="development",
            enforce=True,
            coap={"enabled": True},
        )
        monkeypatch.setattr("ori.runtime.coap_backend_available", lambda: False)

        with pytest.raises(ConfigValidationError, match="aiocoap"):
            _validate_required_runtime_capabilities(config, str(tmp_path / "ori.yaml"))

    async def test_startup_refuses_before_state_store_open(self, monkeypatch):
        config = _capability_config(coap={"enabled": True})
        runtime = OriRuntime(config_path="/unused/ori.yaml")
        opened = AsyncMock(side_effect=AssertionError("state store must not open"))
        monkeypatch.setattr("ori.runtime.Config.load", lambda _path: config)
        monkeypatch.setattr("ori.runtime.coap_backend_available", lambda: False)
        monkeypatch.setattr("ori.runtime.StateStore.open", opened)

        with pytest.raises(ConfigValidationError, match="aiocoap"):
            await runtime.start()

        opened.assert_not_awaited()

    async def test_hardened_relay_initialization_failure_aborts_startup(
        self, minimal_config, monkeypatch
    ):
        _patch_external(monkeypatch)
        config = Config.load(str(minimal_config))
        config.device.deployment_profile = "production"
        config.reasoning.default_tier = "rule"
        config.reasoning.local_model = ""
        config.reasoning.model_path = ""
        config.actions.relay = {"enabled": True, "gpio_pin": 26}
        config.raw["database"] = {"path": str(Path(minimal_config).parent / "state.db")}
        # A hardened relay must be commissioned before it is driven, so the
        # binding is in place and the refusal under test is the backend's.
        commission_relay(
            minimal_config,
            monkeypatch,
            device_id="test-device-01",
            sensor_id="cpu-sensor",
            proof_method="actuate_and_observe",
        )
        monkeypatch.setattr("ori.runtime.Config.load", lambda _path: config)
        monkeypatch.setattr("ori.runtime.gpio_backend_importable", lambda: True)
        # The posture check now also asks which factory resolved, so reaching
        # relay initialisation means claiming an arbitrated backend as well.
        monkeypatch.setattr("ori.runtime.gpio_backend_arbitrated", lambda: True)
        connect = AsyncMock(side_effect=RuntimeError("GPIO chip unavailable"))
        monkeypatch.setattr("ori.runtime.RelayAction.connect", connect)
        runtime = OriRuntime(config_path=str(minimal_config))

        try:
            with pytest.raises(
                ConfigValidationError,
                match="requires configured GPIO relay control to initialise",
            ):
                await runtime.start()
        finally:
            await runtime.stop()

        connect.assert_awaited_once_with(
            gpio_pin=26, active_high=False, tolerate_missing_backend=False
        )


class TestLocalSLMWiring:
    def test_resolve_local_model_from_directory_and_basename(self, tmp_path: Path):
        model_dir = tmp_path / "models"
        model_dir.mkdir()
        model_file = model_dir / "qwen2.5-0.5b-instruct-q4_k_m.gguf"
        model_file.write_bytes(b"fake")

        cfg_path = tmp_path / "ori.yaml"
        cfg_path.write_text("device: {}\n", encoding="utf-8")

        resolved = _resolve_local_model_file(
            local_model="qwen2.5-0.5b-instruct-q4_k_m",
            model_path=str(model_dir),
            config_path=str(cfg_path),
        )
        assert resolved == str(model_file.resolve())

    def test_resolve_local_model_from_absolute_file(self, tmp_path: Path):
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(b"fake")

        cfg_path = tmp_path / "ori.yaml"
        cfg_path.write_text("device: {}\n", encoding="utf-8")

        resolved = _resolve_local_model_file(
            local_model=str(model_file),
            model_path="",
            config_path=str(cfg_path),
        )
        assert resolved == str(model_file.resolve())

    def test_build_local_llm_returns_none_when_model_missing(self, tmp_path: Path):
        cfg_path = tmp_path / "ori.yaml"
        cfg_path.write_text("device: {}\n", encoding="utf-8")
        reasoning_cfg = SimpleNamespace(
            local_model="missing-model",
            model_path=str(tmp_path / "models"),
            local_context_window=2048,
        )

        llm = _build_local_llm(reasoning_cfg, str(cfg_path))
        assert llm is None

    def test_build_local_llm_constructs_with_resolved_model(
        self, tmp_path, monkeypatch
    ):
        model_dir = tmp_path / "models"
        model_dir.mkdir()
        model_file = model_dir / "qwen2.5-0.5b-instruct-q4_k_m.gguf"
        model_file.write_bytes(b"fake")

        cfg_path = tmp_path / "ori.yaml"
        cfg_path.write_text("device: {}\n", encoding="utf-8")
        reasoning_cfg = SimpleNamespace(
            local_model="qwen2.5-0.5b-instruct-q4_k_m",
            model_path=str(model_dir),
            local_context_window=4096,
        )

        calls = {}

        class _FakeLocalLLM:
            def __init__(self, model_path: str, context_window: int = 2048) -> None:
                calls["model_path"] = model_path
                calls["context_window"] = context_window

            @property
            def is_available(self) -> bool:
                return True

        monkeypatch.setattr("ori.runtime.LocalLLM", _FakeLocalLLM)

        llm = _build_local_llm(reasoning_cfg, str(cfg_path))
        assert isinstance(llm, _FakeLocalLLM)
        assert calls["model_path"] == str(model_file.resolve())
        assert calls["context_window"] == 4096

    async def test_runtime_passes_built_local_llm_to_elevator(
        self, minimal_config, monkeypatch
    ):
        _patch_external(monkeypatch)
        sentinel = object()
        captured = {}

        from ori.reasoning.elevator import IntelligenceElevator as _RealElevator

        monkeypatch.setattr(
            "ori.runtime._build_local_llm", lambda *_, **_kwargs: sentinel
        )

        def _elevator_factory(
            local_llm=None, gateway_reasoner=None, config=None, **_kw
        ):
            captured["local_llm"] = local_llm
            captured["gateway_reasoner"] = gateway_reasoner
            return _RealElevator(local_llm=local_llm, config=config)

        monkeypatch.setattr("ori.runtime.IntelligenceElevator", _elevator_factory)

        runtime = OriRuntime(config_path=str(minimal_config))

        async def _stop():
            await asyncio.sleep(0.1)
            await runtime.stop()

        await asyncio.gather(runtime.start(), _stop())
        assert captured["local_llm"] is sentinel
        assert captured["gateway_reasoner"] is None

    def test_build_gateway_reasoner_returns_none_when_gateway_disabled(self):
        cfg = SimpleNamespace(
            gateway=SimpleNamespace(enabled=False, broker_url="", reasoning={}),
            device=SimpleNamespace(id="test-device-01"),
        )

        assert _build_gateway_reasoner(cfg) is None

    def test_build_gateway_reasoner_constructs_when_enabled(self, monkeypatch):
        captured = {}

        class _FakeGatewayReasoner:
            def __init__(
                self,
                *,
                broker_url,
                device_id,
                timeout_ms,
                tls_config=None,
                message_auth=None,
            ):
                captured["broker_url"] = broker_url
                captured["device_id"] = device_id
                captured["timeout_ms"] = timeout_ms
                captured["tls_config"] = tls_config
                captured["message_auth"] = message_auth

        monkeypatch.setattr("ori.runtime.MqttGatewayReasoner", _FakeGatewayReasoner)
        cfg = SimpleNamespace(
            gateway=SimpleNamespace(
                enabled=True,
                broker_url="mqtt://broker.local:1884",
                reasoning={"enabled": True, "timeout_ms": 2500},
                tls={},
            ),
            device=SimpleNamespace(id="test-device-01"),
        )

        reasoner = _build_gateway_reasoner(cfg)

        assert isinstance(reasoner, _FakeGatewayReasoner)
        assert captured == {
            "broker_url": "mqtt://broker.local:1884",
            "device_id": "test-device-01",
            "timeout_ms": 2500,
            "tls_config": {},
            "message_auth": None,
        }

    def test_build_runtime_node_heartbeat_returns_none_when_gateway_disabled(self):
        cfg = SimpleNamespace(
            gateway=SimpleNamespace(
                enabled=False,
                broker_url="",
                node_heartbeat={"enabled": True, "interval_seconds": 30},
            ),
            device=SimpleNamespace(id="test-device-01"),
        )

        assert _build_runtime_node_heartbeat_publisher(cfg, lambda: {}) is None

    def test_build_runtime_node_heartbeat_returns_none_when_disabled(self):
        cfg = SimpleNamespace(
            gateway=SimpleNamespace(
                enabled=True,
                broker_url="mqtt://broker.local",
                node_heartbeat={"enabled": False, "interval_seconds": 30},
            ),
            device=SimpleNamespace(id="test-device-01"),
        )

        assert _build_runtime_node_heartbeat_publisher(cfg, lambda: {}) is None

    def test_build_runtime_node_heartbeat_constructs_when_enabled(self, monkeypatch):
        captured = {}

        class _FakePublisher:
            def __init__(
                self,
                *,
                broker_url,
                device_id,
                health_snapshot_provider,
                interval_seconds,
                tls_config=None,
                authenticator=None,
            ):
                captured["broker_url"] = broker_url
                captured["device_id"] = device_id
                captured["health_snapshot_provider"] = health_snapshot_provider
                captured["interval_seconds"] = interval_seconds
                captured["tls_config"] = tls_config
                captured["authenticator"] = authenticator

        monkeypatch.setattr(
            "ori.runtime.MqttRuntimeNodeHeartbeatPublisher", _FakePublisher
        )

        def provider():
            return {"status": "healthy"}

        cfg = SimpleNamespace(
            gateway=SimpleNamespace(
                enabled=True,
                broker_url="mqtt://broker.local:1884",
                node_heartbeat={"enabled": True, "interval_seconds": 15},
                auth={"enabled": False},
                tls={},
            ),
            device=SimpleNamespace(id="test-device-01"),
        )

        publisher = _build_runtime_node_heartbeat_publisher(cfg, provider)

        assert isinstance(publisher, _FakePublisher)
        assert captured == {
            "broker_url": "mqtt://broker.local:1884",
            "device_id": "test-device-01",
            "health_snapshot_provider": provider,
            "interval_seconds": 15.0,
            "tls_config": {},
            "authenticator": None,
        }


class TestDotenvAutoload:
    def test_disabled_does_not_load_dotenv(self, tmp_path: Path, monkeypatch):
        cfg = tmp_path / "ori.yaml"
        cfg.write_text("device: {}\n", encoding="utf-8")
        env_path = tmp_path / ".env"
        env_path.write_text("ORI_AUTOLOAD_SMOKE=from_dotenv\n", encoding="utf-8")

        monkeypatch.delenv("ORI_AUTOLOAD_DOTENV", raising=False)
        monkeypatch.delenv("ORI_AUTOLOAD_SMOKE", raising=False)

        _maybe_autoload_dotenv(str(cfg))
        assert os.environ.get("ORI_AUTOLOAD_SMOKE") is None

    def test_enabled_loads_config_dir_dotenv(self, tmp_path: Path, monkeypatch):
        cfg = tmp_path / "ori.yaml"
        cfg.write_text("device: {}\n", encoding="utf-8")
        env_path = tmp_path / ".env"
        env_path.write_text("ORI_AUTOLOAD_SMOKE=from_dotenv\n", encoding="utf-8")

        monkeypatch.setenv("ORI_AUTOLOAD_DOTENV", "true")
        monkeypatch.delenv("ORI_AUTOLOAD_SMOKE", raising=False)

        _maybe_autoload_dotenv(str(cfg))
        assert os.environ.get("ORI_AUTOLOAD_SMOKE") == "from_dotenv"

    def test_enabled_does_not_override_existing_env(self, tmp_path: Path, monkeypatch):
        cfg = tmp_path / "ori.yaml"
        cfg.write_text("device: {}\n", encoding="utf-8")
        env_path = tmp_path / ".env"
        env_path.write_text("ORI_AUTOLOAD_SMOKE=from_dotenv\n", encoding="utf-8")

        monkeypatch.setenv("ORI_AUTOLOAD_DOTENV", "true")
        monkeypatch.setenv("ORI_AUTOLOAD_SMOKE", "already_set")

        _maybe_autoload_dotenv(str(cfg))
        assert os.environ.get("ORI_AUTOLOAD_SMOKE") == "already_set"


class TestAdapterProtocol:
    async def test_unknown_protocol_raises_config_error(
        self, tmp_path: Path, monkeypatch
    ):
        """A sensor with an unknown protocol must raise ConfigValidationError
        immediately at startup — never silently substitute a wrong adapter."""
        from ori.config import ConfigValidationError

        skill_dir = tmp_path / "skills" / "s"
        skill_dir.mkdir(parents=True)
        (skill_dir / "skill.yaml").write_text(
            "name: s\nversion: 0.1.0\nauthor: t\ntriggers: []\nactions: {}\n",
            encoding="utf-8",
        )
        cfg = tmp_path / "ori.yaml"
        cfg.write_text(
            textwrap.dedent(f"""\
                device:
                  id: dev-01
                  name: Dev
                  location: Lab
                sensors:
                  - id: inv-current
                    type: current
                    protocol: unknown_proto
                    poll_interval_ms: 1000
                skills: []
                reasoning:
                  default_tier: local
                  local_model: ""
                  model_path: ""
                gateway:
                  enabled: false
                  broker_url: ""
                actions:
                  primary_alert_channel: sms
                  whatsapp:
                    enabled: false
                  sms:
                    enabled: false
                  relay:
                    enabled: false
                skills_dir: {str(tmp_path / "skills")}
            """),
            encoding="utf-8",
        )

        runtime = OriRuntime(config_path=str(cfg))

        async def _stop():
            await asyncio.sleep(0.5)
            await runtime.stop()

        with pytest.raises(ConfigValidationError, match="unknown_proto"):
            await asyncio.gather(runtime.start(), _stop())


class TestLifecycle:
    async def test_runtime_starts_and_stops_cleanly(self, minimal_config, monkeypatch):
        """OriRuntime starts, stop() fires after 0.1 s, no error, all tasks cancelled."""
        _patch_external(monkeypatch)

        runtime = OriRuntime(config_path=str(minimal_config))

        async def _auto_stop():
            await asyncio.sleep(0.1)
            await runtime.stop()

        await asyncio.gather(runtime.start(), _auto_stop())
        # If we reach here, start() returned cleanly after stop()

    async def test_stop_is_idempotent(self, minimal_config, monkeypatch):
        """Calling stop() twice must not raise."""
        _patch_external(monkeypatch)
        runtime = OriRuntime(config_path=str(minimal_config))

        async def _double_stop():
            await asyncio.sleep(0.05)
            await runtime.stop()
            await runtime.stop()  # second call — must be a no-op

        await asyncio.gather(runtime.start(), _double_stop())

    def test_resolve_dispatcher_approval_timeout_uses_max_declared(self):
        skills_cfg = [
            SimpleNamespace(config={"approval_timeout_seconds": 90}),
            SimpleNamespace(config={"approval_timeout_seconds": 600}),
            SimpleNamespace(config={}),
        ]
        resolved = _resolve_dispatcher_approval_timeout(skills_cfg, 300)
        assert resolved == 600

    def test_resolve_dispatcher_approval_timeout_ignores_invalid_values(self):
        skills_cfg = [
            SimpleNamespace(config={"approval_timeout_seconds": "invalid"}),
            SimpleNamespace(config={"approval_timeout_seconds": -1}),
        ]
        resolved = _resolve_dispatcher_approval_timeout(skills_cfg, 300)
        assert resolved == 300

    async def test_start_does_not_duplicate_rotating_file_handler(
        self, minimal_config, monkeypatch
    ):
        """Restarting in-process should keep a single RotatingFileHandler per file."""
        from logging.handlers import RotatingFileHandler

        _patch_external(monkeypatch)
        cfg_path = Path(minimal_config)
        custom_log = cfg_path.parent / "runtime-test.log"
        cfg_path.write_text(
            cfg_path.read_text(encoding="utf-8")
            + textwrap.dedent(
                f"""
                logging:
                  file: "{custom_log}"
                  level: INFO
                """
            ),
            encoding="utf-8",
        )

        runtime1 = OriRuntime(config_path=str(cfg_path))
        runtime2 = OriRuntime(config_path=str(cfg_path))

        async def _run_once(runtime: OriRuntime):
            async def _stop():
                await asyncio.sleep(0.1)
                await runtime.stop()

            await asyncio.gather(runtime.start(), _stop())

        await _run_once(runtime1)
        await _run_once(runtime2)

        root = logging.getLogger()
        target = str(custom_log.resolve())
        matches = [
            h
            for h in root.handlers
            if isinstance(h, RotatingFileHandler)
            and Path(getattr(h, "baseFilename", "")).resolve().as_posix()
            == Path(target).as_posix()
        ]
        assert len(matches) == 1

        # Keep global logger state clean for subsequent tests.
        for h in matches:
            root.removeHandler(h)
            h.close()

    async def test_phone_deployment_skips_relay_init(
        self, tmp_path: Path, monkeypatch, caplog
    ):
        _patch_external(monkeypatch)
        cfg = tmp_path / "ori.yaml"
        cfg.write_text(
            textwrap.dedent("""\
                device:
                  id: phone-dev-01
                  name: Phone Gateway
                  location: Lagos
                  deployment_type: phone
                sensors:
                  - id: cpu-sensor
                    type: cpu_percent
                    protocol: psutil
                    poll_interval_ms: 200
                skills: []
                reasoning:
                  default_tier: local
                  local_model: ""
                  model_path: ""
                gateway:
                  enabled: false
                  broker_url: ""
                actions:
                  primary_alert_channel: sms
                  whatsapp:
                    enabled: false
                  sms:
                    enabled: false
                  relay:
                    enabled: true
                    gpio_pin: 26
            """),
            encoding="utf-8",
        )
        runtime = OriRuntime(config_path=str(cfg))
        mocked_connect = AsyncMock(
            side_effect=AssertionError("relay should not connect")
        )
        monkeypatch.setattr("ori.actions.relay.RelayAction.connect", mocked_connect)

        async def _stop():
            await asyncio.sleep(0.2)
            await runtime.stop()

        with caplog.at_level(logging.WARNING):
            await asyncio.gather(runtime.start(), _stop())

        assert mocked_connect.await_count == 0
        assert any(
            "deployment_type=phone with relay configured" in r.message
            for r in caplog.records
        )

    async def test_runtime_registers_close_gas_valve_as_relay_backed_tier_d_action(
        self, minimal_config, monkeypatch
    ):
        _patch_external(monkeypatch)
        cfg_path = Path(minimal_config)
        config_text = cfg_path.read_text(encoding="utf-8")
        relay_disabled = "  relay:\n    enabled: false\n"
        assert relay_disabled in config_text
        cfg_path.write_text(
            config_text.replace(
                relay_disabled,
                "  relay:\n    enabled: true\n    gpio_pin: 26\n",
            )
            + f"database:\n  path: {cfg_path.parent / 'ori_state.db'}\n",
            encoding="utf-8",
        )
        # Commissioned so that isolating the load energises the coil: the test
        # then observes the outcome reaching the relay as `trigger`.
        commission_relay(
            cfg_path,
            monkeypatch,
            device_id="test-device-01",
            sensor_id="cpu-sensor",
            open_outcome="energised",
            terminal_state="closed",
        )
        connect = AsyncMock(return_value=None)
        trigger = AsyncMock(return_value=True)
        monkeypatch.setattr("ori.actions.relay.RelayAction.connect", connect)
        monkeypatch.setattr("ori.actions.relay.RelayAction.trigger", trigger)

        runtime = OriRuntime(config_path=str(cfg_path))

        async def _stop():
            # Wait for the executor this test drives rather than for a fixed
            # interval. Startup retains the commissioned binding through the
            # state store, so a stop that lands first closes the store out from
            # under it and the failure surfaces as an assertion deep inside
            # `retain_commissioned_binding`, nowhere near this test.
            deadline = asyncio.get_running_loop().time() + 15.0
            while (
                runtime._dispatcher is None
                or "close_gas_valve" not in runtime._dispatcher._executors
            ):
                if asyncio.get_running_loop().time() > deadline:
                    raise AssertionError(
                        "the relay executors were not registered in time"
                    )
                await asyncio.sleep(0.02)
            await runtime.stop()

        await asyncio.gather(runtime.start(), _stop())

        assert runtime._dispatcher is not None
        close_gas_valve = runtime._dispatcher._executors["close_gas_valve"]
        trip_relay = runtime._dispatcher._executors["trip_relay"]
        assert close_gas_valve is trip_relay

        await close_gas_valve("close_gas_valve", SimpleNamespace())

        connect.assert_awaited_once_with(
            gpio_pin=26, active_high=False, tolerate_missing_backend=True
        )
        trigger.assert_awaited_once_with(duration_seconds=None)


class TestStartupLogs:
    async def test_startup_logs_skill_tiers(self, minimal_config, monkeypatch, caplog):
        """After start(), caplog must contain '[skill]' with trigger + tier."""
        _patch_external(monkeypatch)
        _treat_scratch_skills_as_packaged(monkeypatch)
        runtime = OriRuntime(config_path=str(minimal_config))

        async def _stop():
            await asyncio.sleep(0.1)
            await runtime.stop()

        with caplog.at_level(logging.INFO):
            await asyncio.gather(runtime.start(), _stop())

        skill_lines = [r.message for r in caplog.records if "[skill]" in r.message]
        assert any("test-skill" in line for line in skill_lines), (
            f"Expected '[skill] test-skill' in log. Got: {skill_lines}"
        )
        trigger_lines = [r.message for r in caplog.records if "high_cpu" in r.message]
        assert any("Tier A" in line for line in trigger_lines), (
            f"Expected 'Tier A' in trigger log. Got: {trigger_lines}"
        )

    async def test_runtime_logs_event_loop_ready(
        self, minimal_config, monkeypatch, caplog
    ):
        """Log must contain '[runtime] event loop ready' after startup."""
        _patch_external(monkeypatch)
        runtime = OriRuntime(config_path=str(minimal_config))

        async def _stop():
            await asyncio.sleep(0.1)
            await runtime.stop()

        with caplog.at_level(logging.INFO):
            await asyncio.gather(runtime.start(), _stop())

        messages = [r.message for r in caplog.records]
        assert any("event loop ready" in m for m in messages), (
            f"'event loop ready' not found in log. Messages: {messages}"
        )


class TestSkillReload:
    async def test_repeated_reloads_do_not_exhaust_the_subscription_budget(
        self, minimal_config: Path, monkeypatch
    ):
        """Drive the real reload path far past the former exhaustion point.

        The subscription budget counts active handlers. When the counter only
        rose, a runtime replacing the same handlers exhausted it after
        ``budget / cost`` reloads and then failed to register replacements —
        after the previous graph had already been removed. That is the worst
        possible moment to fail, because a partial graph can be missing Tier D
        coverage while the runtime still looks healthy.

        The skill here costs 64 handlers per reload (8 triggers × 8 sensor
        types), so the monotonic counter failed on cycle 16 of the 1,024
        budget. This runs 60 cycles and checks, every cycle, that the handler
        count is stable, that the loader's accounting matches the live bus,
        that the Tier D trigger is still registered, and that no partial graph
        appears.
        """
        _patch_external(monkeypatch)
        _treat_scratch_skills_as_packaged(monkeypatch)

        sensor_types = ["cpu_percent" if i == 0 else f"sensor_{i}" for i in range(8)]
        sensors_block = "".join(f"  - type: {t}\n" for t in sensor_types)
        # One Tier D trigger, so safety coverage is observable across reloads.
        triggers_block = (
            '  - name: dangerous\n    condition: "value > 999"\n'
            "    action_tier: D\n    bypass_llm: true\n    cooldown_seconds: 0\n"
        )
        triggers_block += "".join(
            f'  - name: t{i}\n    condition: "value > {90 + i}"\n'
            "    action_tier: A\n    cooldown_seconds: 0\n"
            for i in range(7)
        )
        defaults_block = "    dangerous: [alert_whatsapp]\n" + "".join(
            f"    t{i}: [alert_whatsapp]\n" for i in range(7)
        )
        skills_root = Path(minimal_config).parent / "skills"
        heavy = skills_root / "test-skill"
        (heavy / "skill.yaml").write_text(
            "name: test-skill\nversion: 0.1.0\nauthor: test\n"
            f"sensors_required:\n{sensors_block}"
            f"triggers:\n{triggers_block}"
            "actions:\n  available:\n    - name: alert_whatsapp\n      tier: A\n"
            f"  defaults:\n{defaults_block}",
            encoding="utf-8",
        )

        runtime = OriRuntime(config_path=str(minimal_config))
        start_task = asyncio.create_task(runtime.start())
        try:
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                if runtime._event_bus is not None and (
                    runtime._event_bus.subscriber_count("cpu_percent") >= 1
                ):
                    break
                await asyncio.sleep(0.05)

            assert runtime._event_bus is not None
            loader = runtime._skill_loader
            expected = len(runtime._skill_subscriptions)
            assert expected == 64, f"expected 8 x 8 handlers, got {expected}"

            def _tier_d_registered() -> bool:
                return any(
                    trigger.action_tier == "D"
                    for skill in runtime._loaded_skills
                    for trigger in skill.triggers
                )

            assert _tier_d_registered(), "Tier D trigger missing before reloads"

            for cycle in range(60):
                assert await runtime.reload_skills() is True, (
                    f"reload failed on cycle {cycle} — the budget leaked"
                )
                live = len(runtime._skill_subscriptions)
                assert live == expected, (
                    f"cycle {cycle}: handler count drifted to {live}"
                )
                assert loader.active_subscriptions == live, (
                    f"cycle {cycle}: loader accounts {loader.active_subscriptions} "
                    f"handlers but {live} are live"
                )
                assert _tier_d_registered(), f"cycle {cycle}: Tier D coverage lost"
                assert runtime._event_bus.subscriber_count("cpu_percent") == 8, (
                    f"cycle {cycle}: partial graph on the bus"
                )
        finally:
            await runtime.stop()
            await asyncio.wait_for(start_task, timeout=10)

    async def test_reload_skills_registers_new_handlers(
        self, minimal_config: Path, monkeypatch
    ):
        _patch_external(monkeypatch)
        _treat_scratch_skills_as_packaged(monkeypatch)
        runtime = OriRuntime(config_path=str(minimal_config))

        start_task = asyncio.create_task(runtime.start())
        try:
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                if runtime._event_bus is not None and (
                    runtime._event_bus.subscriber_count("cpu_percent") >= 1
                ):
                    break
                await asyncio.sleep(0.05)
            assert runtime._event_bus is not None
            assert runtime._event_bus.subscriber_count("cpu_percent") == 1

            skills_root = Path(minimal_config).parent / "skills"
            skill_dir = skills_root / "second-skill"
            skill_dir.mkdir(parents=True, exist_ok=True)
            (skill_dir / "skill.yaml").write_text(
                textwrap.dedent("""\
                    name: second-skill
                    version: 0.1.0
                    author: test
                    sensors_required:
                      - type: cpu_percent
                    triggers:
                      - name: high_cpu_secondary
                        condition: "value > 95"
                        action_tier: A
                        cooldown_seconds: 0
                        escalate_to: local_slm
                    actions:
                      available:
                        - name: alert_whatsapp
                          tier: A
                      defaults:
                        high_cpu_secondary: [alert_whatsapp]
                """),
                encoding="utf-8",
            )

            ok = await runtime.reload_skills()
            assert ok is True
            assert runtime._event_bus.subscriber_count("cpu_percent") == 2
        finally:
            await runtime.stop()
            await start_task

    async def test_reload_skills_keeps_existing_on_empty_result(
        self, minimal_config: Path, monkeypatch
    ):
        _patch_external(monkeypatch)
        _treat_scratch_skills_as_packaged(monkeypatch)
        runtime = OriRuntime(config_path=str(minimal_config))

        start_task = asyncio.create_task(runtime.start())
        try:
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                if runtime._event_bus is not None and (
                    runtime._event_bus.subscriber_count("cpu_percent") >= 1
                ):
                    break
                await asyncio.sleep(0.05)
            assert runtime._event_bus is not None
            before = runtime._event_bus.subscriber_count("cpu_percent")
            assert before == 1

            runtime._skills_dir = str(Path(minimal_config).parent / "missing-skills")
            ok = await runtime.reload_skills()
            assert ok is False
            assert runtime._event_bus.subscriber_count("cpu_percent") == before
        finally:
            await runtime.stop()
            await start_task


class TestShutdown:
    async def test_shutdown_drains_tier_d_tasks(self, minimal_config, monkeypatch):
        """Runtime must await dispatcher-tracked Tier D tasks before shutdown."""
        _patch_external(monkeypatch)
        runtime = OriRuntime(config_path=str(minimal_config))
        completed: list[bool] = []

        async def _tier_d_work():
            await asyncio.sleep(0.2)
            completed.append(True)

        async def _inject_and_stop():
            await asyncio.sleep(0.05)
            tier_d_task = asyncio.create_task(_tier_d_work())

            class _FakeDispatcher:
                def get_inflight_tier_d_tasks(self):
                    return {tier_d_task} if not tier_d_task.done() else set()

            runtime._dispatcher = _FakeDispatcher()
            await runtime.stop()
            # Give the drained task time to finish
            await asyncio.sleep(0.25)

        await asyncio.gather(runtime.start(), _inject_and_stop())
        assert completed == [True], "Tier D task was abandoned before completion"


class TestWatchdog:
    async def test_watchdog_skipped_gracefully_without_device(
        self, minimal_config, monkeypatch, caplog
    ):
        """/dev/watchdog absent → warning logged, runtime continues normally."""
        _patch_external(monkeypatch)
        monkeypatch.setattr("ori.runtime.os.path.exists", lambda p: False)

        runtime = OriRuntime(config_path=str(minimal_config))

        async def _stop():
            await asyncio.sleep(0.1)
            await runtime.stop()

        with caplog.at_level(logging.WARNING):
            await asyncio.gather(runtime.start(), _stop())

        watchdog_warnings = [r.message for r in caplog.records]
        assert watchdog_warnings, "Expected watchdog 'not found' warning in logs"

    async def test_watchdog_writes_magic_v_on_shutdown(
        self, minimal_config, monkeypatch, caplog
    ):
        """/dev/watchdog open/write are called, magic V written on shutdown."""
        import builtins
        from unittest.mock import mock_open

        _patch_external(monkeypatch)
        monkeypatch.setattr("ori.runtime.os.path.exists", lambda p: True)

        m_open = mock_open()
        real_open = builtins.open

        def _smart_open(file, *args, **kwargs):
            if file == "/dev/watchdog":
                return m_open(file, *args, **kwargs)
            return real_open(file, *args, **kwargs)

        monkeypatch.setattr("builtins.open", _smart_open)

        runtime = OriRuntime(config_path=str(minimal_config))

        async def _stop():
            await asyncio.sleep(0.1)
            await runtime.stop()

        with caplog.at_level(logging.INFO):
            await asyncio.gather(runtime.start(), _stop())

        # Assert watchdog device was opened for writing
        m_open.assert_called_with("/dev/watchdog", "wb", buffering=0)

        # Assert magical 'V' was written during shutdown
        handle = m_open()
        writes = [c.args[0] for c in handle.write.call_args_list if c.args]
        assert b"V" in writes, "Expected magic 'V' to be written to watchdog"

        # Check logs for clean shutdown line
        v_log = [r.message for r in caplog.records if "magic V written" in r.message]
        assert v_log, "Expected magic V log message"


class TestSensorPolling:
    async def test_poll_sensor_returns_when_state_store_missing(self, caplog):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._state_store = None
        runtime._shutdown_event = asyncio.Event()

        class _NeverCalledAdapter:
            async def read(self, sensor_id: str) -> SensorReading:
                raise AssertionError("read() should not be called")

        bus = AsyncMock()
        sensor_cfg = SimpleNamespace(id="cpu-sensor", poll_interval_ms=1)
        with caplog.at_level(logging.ERROR):
            await runtime._poll_sensor(_NeverCalledAdapter(), sensor_cfg, bus, "dev-01")
        assert "state_store unavailable for sensor poll task" in caplog.text

    async def test_sensor_read_error_does_not_crash_runtime(
        self, minimal_config, monkeypatch, caplog
    ):
        """AdapterReadError during polling must log a warning, not crash."""
        from ori.hal.base import AdapterReadError

        _patch_external(monkeypatch)

        read_count = 0

        async def _failing_read(*_: Any):
            nonlocal read_count
            read_count += 1
            raise AdapterReadError("sensor timeout")

        monkeypatch.setattr("ori.hal.psutil_adapter.PsutilAdapter.read", _failing_read)

        runtime = OriRuntime(config_path=str(minimal_config))

        async def _stop():
            # Avoid startup timing races: wait until polling has actually
            # happened (or timeout), then stop.
            deadline = time.monotonic() + 2.0
            while read_count < 2 and time.monotonic() < deadline:
                await asyncio.sleep(0.05)
            await runtime.stop()

        with caplog.at_level(logging.WARNING):
            await asyncio.gather(runtime.start(), _stop())

        assert read_count >= 2, "Expected at least 2 poll attempts"
        warning_msgs = [r.message for r in caplog.records if "read failed" in r.message]
        assert warning_msgs, "Expected 'read failed' warning log"

    async def test_a_refused_measurement_reaches_the_outbox_and_survives_restart(
        self, tmp_path
    ):
        """The production path with a real store and the real alert call.

        An earlier version of this test replaced `_send_or_queue_alert` and
        claimed in its own docstring to be exercising it. It proved poll-loop
        classification and nothing about delivery or durability. Here only the
        transport is stubbed: the StateStore is real, the alert path is real,
        and the assertions are about what ended up on disk.
        """
        from ori.hal.base import MeasurementRefusedError
        from ori.runtime import MEASUREMENT_REFUSALS_BEFORE_DEGRADED
        from ori.state.store import StateStore

        store = StateStore(str(tmp_path / "state.db"))
        await store.open()

        runtime = OriRuntime(config_path="ori.yaml")
        runtime._state_store = store
        runtime._shutdown_event = asyncio.Event()
        runtime._operator_contact = "+2340000000000"
        runtime._primary_alert_channel = "sms"
        runtime._measurement_refusals = {}
        runtime._measurement_valid_streak = {}
        runtime._measurement_degraded = set()
        runtime._measurement_unnotified = set()
        runtime._measurement_notify_attempts = {}

        # The transport refuses, so the alert must be durably queued instead.
        sender = AsyncMock()
        sender.send_exact = AsyncMock(return_value=False)
        sender.send = AsyncMock(return_value=False)
        runtime._alert_sender = sender

        attempts = 0

        class _RefusingAdapter:
            async def read(self, sensor_id: str) -> SensorReading:
                nonlocal attempts
                attempts += 1
                if attempts >= MEASUREMENT_REFUSALS_BEFORE_DEGRADED:
                    runtime._shutdown_event.set()
                raise MeasurementRefusedError(
                    f"I2CAdapter: refused a current window on '{sensor_id}': clipped"
                )

        sensor_cfg = SimpleNamespace(id="load-current", poll_interval_ms=1)
        await runtime._poll_sensor(
            _RefusingAdapter(), sensor_cfg, AsyncMock(), "dev-01"
        )

        assert "load-current" in runtime._measurement_degraded

        queued = await store.get_retryable_alerts(limit=10)
        matching = [
            row for row in queued if "load-current" in str(row.get("message", ""))
        ]
        assert matching, f"the warning was not durably queued: {queued}"
        assert matching[0]["action_tier"] == "A"

        # Degraded on disk, and marked as reported because queueing succeeded.
        restored = await store.get_measurement_degradation()
        assert restored == {"load-current": True}

        # A restart restores it, and stays quiet rather than re-alerting.
        successor = OriRuntime(config_path="ori.yaml")
        successor._state_store = store
        state = await store.get_measurement_degradation()
        successor._measurement_degraded = set(state)
        successor._measurement_unnotified = {
            name for name, notified in state.items() if not notified
        }
        assert successor._measurement_degraded == {"load-current"}
        assert successor._measurement_unnotified == set()

        await store.close()

    async def test_a_warning_that_never_reached_anyone_is_still_owed(self, tmp_path):
        """The failure this durability exists to prevent, from the other side.

        With no operator contact the warning cannot be sent or queued. Recording
        that as reported would mean the crash or misconfiguration that stopped
        the alert becomes the reason it is never sent again.
        """
        from ori.hal.base import MeasurementRefusedError
        from ori.runtime import MEASUREMENT_REFUSALS_BEFORE_DEGRADED
        from ori.state.store import StateStore

        store = StateStore(str(tmp_path / "state.db"))
        await store.open()

        runtime = OriRuntime(config_path="ori.yaml")
        runtime._state_store = store
        runtime._shutdown_event = asyncio.Event()
        runtime._operator_contact = ""
        runtime._primary_alert_channel = "sms"
        runtime._alert_sender = AsyncMock()
        runtime._measurement_refusals = {}
        runtime._measurement_valid_streak = {}
        runtime._measurement_degraded = set()
        runtime._measurement_unnotified = set()
        runtime._measurement_notify_attempts = {}

        attempts = 0

        class _RefusingAdapter:
            async def read(self, sensor_id: str) -> SensorReading:
                nonlocal attempts
                attempts += 1
                if attempts >= MEASUREMENT_REFUSALS_BEFORE_DEGRADED:
                    runtime._shutdown_event.set()
                raise MeasurementRefusedError("refused a current window: clipped")

        sensor_cfg = SimpleNamespace(id="load-current", poll_interval_ms=1)
        await runtime._poll_sensor(
            _RefusingAdapter(), sensor_cfg, AsyncMock(), "dev-01"
        )

        assert await store.get_measurement_degradation() == {"load-current": False}
        assert runtime._measurement_unnotified == {"load-current"}
        await store.close()

    async def test_a_store_failure_does_not_stop_polling(self, tmp_path):
        """Persistence runs inside an `except` clause.

        An exception raised there is not caught by the handler that follows it,
        so it would escape `_poll_sensor` and end polling for the sensor — the
        measurement-loss guard taking the sensor down with it.
        """
        from ori.hal.base import MeasurementRefusedError
        from ori.runtime import MEASUREMENT_REFUSALS_BEFORE_DEGRADED

        runtime = OriRuntime(config_path="ori.yaml")
        broken = AsyncMock()
        broken.set_measurement_degraded = AsyncMock(side_effect=OSError("disk gone"))
        runtime._state_store = broken
        runtime._shutdown_event = asyncio.Event()
        runtime._operator_contact = "+2340000000000"
        runtime._primary_alert_channel = "sms"
        runtime._alert_sender = AsyncMock()
        runtime._measurement_refusals = {}
        runtime._measurement_valid_streak = {}
        runtime._measurement_degraded = set()
        runtime._measurement_unnotified = set()
        runtime._measurement_notify_attempts = {}

        attempts = 0

        class _RefusingAdapter:
            async def read(self, sensor_id: str) -> SensorReading:
                nonlocal attempts
                attempts += 1
                if attempts >= MEASUREMENT_REFUSALS_BEFORE_DEGRADED + 2:
                    runtime._shutdown_event.set()
                raise MeasurementRefusedError("refused a current window: clipped")

        sensor_cfg = SimpleNamespace(id="load-current", poll_interval_ms=1)
        # Must return normally rather than propagating the store failure.
        await runtime._poll_sensor(
            _RefusingAdapter(), sensor_cfg, AsyncMock(), "dev-01"
        )
        assert attempts >= MEASUREMENT_REFUSALS_BEFORE_DEGRADED + 2, (
            "polling stopped when persistence failed"
        )
        assert "load-current" in runtime._measurement_degraded

    async def test_recovery_that_cannot_be_persisted_stays_degraded(self):
        """Persist recovery first, then clear memory — not the other way round.

        The other order leaves a sensor healthy in memory and degraded on disk,
        so the next restart resurrects a fault that was already resolved and
        warns about it again.
        """
        from ori.runtime import (
            MEASUREMENT_REFUSALS_BEFORE_DEGRADED,
            MEASUREMENT_WINDOWS_TO_RECOVER,
        )

        runtime = OriRuntime(config_path="ori.yaml")
        store = AsyncMock()
        store.clear_measurement_degraded = AsyncMock(side_effect=OSError("disk gone"))
        runtime._state_store = store
        runtime._operator_contact = "+2340000000000"
        runtime._primary_alert_channel = "sms"
        runtime._alert_sender = AsyncMock()
        runtime._measurement_refusals = {}
        runtime._measurement_valid_streak = {}
        runtime._measurement_degraded = set()
        runtime._measurement_unnotified = set()
        runtime._measurement_notify_attempts = {}

        async def _sent(**_kwargs):
            return True

        runtime._send_or_queue_alert = _sent  # type: ignore[method-assign]

        for _ in range(MEASUREMENT_REFUSALS_BEFORE_DEGRADED):
            await runtime._note_measurement_refusal(
                sensor_id="load-current", detail="clipped"
            )
        assert runtime._measurement_degraded == {"load-current"}

        for _ in range(MEASUREMENT_WINDOWS_TO_RECOVER + 3):
            await runtime._note_measurement_accepted("load-current")

        assert runtime._measurement_degraded == {"load-current"}, (
            "memory diverged from disk when the recovery write failed"
        )

    async def test_a_bus_failure_is_not_treated_as_a_refused_measurement(self):
        """A read that failed is a different condition from one that was refused.

        The sensor did not answer, so there is nothing to say about whether it
        is still measuring. Counting it toward degradation would fire the wrong
        alert for a wiring fault the circuit breaker already handles.
        """
        from ori.hal.base import AdapterReadError

        runtime = OriRuntime(config_path="ori.yaml")
        runtime._state_store = AsyncMock()
        runtime._shutdown_event = asyncio.Event()
        runtime._measurement_refusals = {}
        runtime._measurement_valid_streak = {}
        runtime._measurement_degraded = set()

        attempts = 0

        class _FailingAdapter:
            async def read(self, sensor_id: str) -> SensorReading:
                nonlocal attempts
                attempts += 1
                if attempts >= 5:
                    runtime._shutdown_event.set()
                raise AdapterReadError("I2CAdapter: bus read failed")

        sensor_cfg = SimpleNamespace(id="load-current", poll_interval_ms=1)
        await runtime._poll_sensor(_FailingAdapter(), sensor_cfg, AsyncMock(), "dev-01")

        assert runtime._measurement_degraded == set()
        assert runtime._measurement_refusals == {}

    async def test_poll_sensor_sets_non_empty_fingerprint(self):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._state_store = AsyncMock()
        runtime._shutdown_event = asyncio.Event()

        reading = SensorReading(
            sensor_id="cpu-sensor",
            sensor_type="cpu_percent",
            value=42.4,
            unit="percent",
            timestamp=1_700_000_000_000,
            quality=1.0,
            metadata={"source": "psutil"},
        )

        class _OneShotAdapter:
            async def read(self, sensor_id: str) -> SensorReading:
                runtime._shutdown_event.set()
                return reading

        bus = AsyncMock()
        sensor_cfg = SimpleNamespace(id="cpu-sensor", poll_interval_ms=1)
        await runtime._poll_sensor(_OneShotAdapter(), sensor_cfg, bus, "dev-01")

        event = bus.publish.call_args.args[0]
        assert isinstance(event.fingerprint, str)
        assert event.fingerprint != ""

    async def test_poll_sensor_sets_site_context_from_device_site_type(self):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._state_store = AsyncMock()
        runtime._shutdown_event = asyncio.Event()

        reading = SensorReading(
            sensor_id="cpu-sensor",
            sensor_type="cpu_percent",
            value=42.4,
            unit="percent",
            timestamp=1_700_000_000_000,
            quality=1.0,
            metadata={"source": "psutil"},
        )

        class _OneShotAdapter:
            async def read(self, sensor_id: str) -> SensorReading:
                runtime._shutdown_event.set()
                return reading

        bus = AsyncMock()
        sensor_cfg = SimpleNamespace(
            id="cpu-sensor",
            poll_interval_ms=1,
            calibration={"min_value": 0.0, "max_value": 100.0},
        )
        await runtime._poll_sensor(
            _OneShotAdapter(),
            sensor_cfg,
            bus,
            "dev-01",
            device_timezone="Africa/Lagos",
            device_country_code="NG",
            device_location="Lagos, Nigeria",
            device_site_type="pharmacy",
        )

        event = bus.publish.call_args.args[0]
        assert event.context["device_timezone"] == "Africa/Lagos"
        assert event.context["device_country_code"] == "NG"
        assert event.context["location"] == "Lagos, Nigeria"
        assert event.context["site_type"] == "pharmacy"
        assert event.context["sensor_calibration"] == {
            "min_value": 0.0,
            "max_value": 100.0,
        }

    async def test_poll_sensor_fingerprint_stable_across_timestamp_changes(self):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._state_store = AsyncMock()
        bus = AsyncMock()
        sensor_cfg = SimpleNamespace(id="cpu-sensor", poll_interval_ms=1)

        async def _run_once(reading: SensorReading) -> OriEvent:
            runtime._shutdown_event = asyncio.Event()

            class _OneShotAdapter:
                async def read(self, sensor_id: str) -> SensorReading:
                    runtime._shutdown_event.set()
                    return reading

            await runtime._poll_sensor(_OneShotAdapter(), sensor_cfg, bus, "dev-01")
            return bus.publish.call_args.args[0]

        first = await _run_once(
            SensorReading(
                sensor_id="cpu-sensor",
                sensor_type="cpu_percent",
                value=42.44,  # rounds to 42.4
                unit="percent",
                timestamp=1_700_000_000_000,
                quality=1.0,
                metadata={"source": "psutil"},
            )
        )
        second = await _run_once(
            SensorReading(
                sensor_id="cpu-sensor",
                sensor_type="cpu_percent",
                value=42.44,  # same rounded value, different timestamp
                unit="percent",
                timestamp=1_700_000_060_000,
                quality=1.0,
                metadata={"source": "psutil"},
            )
        )

        assert first.fingerprint == second.fingerprint

    async def test_sensor_staleness_loop_emits_transition_warning_once(self):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._shutdown_event = asyncio.Event()
        runtime._sensor_poll_interval_ms = {"sensor-x": 100}
        runtime._sensor_last_seen_ms = {"sensor-x": int(time.time() * 1000) - 1000}
        runtime._stale_sensor_active = set()
        runtime._primary_alert_channel = "sms"
        runtime._operator_contact = "+2340000000000"
        runtime._send_or_queue_alert = AsyncMock(return_value=True)
        alert_sender = AsyncMock()

        async def _stop():
            await asyncio.sleep(0.05)
            await runtime.stop()

        await asyncio.gather(
            runtime._sensor_staleness_loop(
                alert_sender=alert_sender,
                check_interval_s=0.01,
            ),
            _stop(),
        )

        runtime._send_or_queue_alert.assert_awaited_once()
        kwargs = runtime._send_or_queue_alert.await_args.kwargs
        assert kwargs["trigger_name"] == "sensor_stale_warning"
        assert kwargs["channel"] == "sms"
        assert "sensor-x" in kwargs["message"]

    async def test_deduplicator_suppresses_identical_readings_within_5_seconds(self):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._shutdown_event = asyncio.Event()

        class _Store:
            def __init__(self) -> None:
                self.events: list[OriEvent] = []

            async def append_history(self, event: OriEvent) -> None:
                self.events.append(event)

        class _Bus:
            def __init__(self) -> None:
                self.events: list[OriEvent] = []

            async def publish(self, event: OriEvent) -> None:
                self.events.append(event)

        class _SequenceAdapter:
            def __init__(self, readings: list[SensorReading]) -> None:
                self._readings = readings
                self._idx = 0

            async def read(self, sensor_id: str) -> SensorReading:
                reading = self._readings[self._idx]
                self._idx += 1
                if self._idx >= len(self._readings):
                    runtime._shutdown_event.set()
                return reading

        runtime._state_store = _Store()
        bus = _Bus()
        sensor_cfg = SimpleNamespace(id="cpu-sensor", poll_interval_ms=1)
        readings = [
            SensorReading(
                sensor_id="cpu-sensor",
                sensor_type="cpu_percent",
                value=41.2,
                unit="percent",
                timestamp=1_700_000_000_000,
                quality=1.0,
                metadata={"source": "psutil"},
            ),
            SensorReading(
                sensor_id="cpu-sensor",
                sensor_type="cpu_percent",
                value=41.2,
                unit="percent",
                timestamp=1_700_000_001_000,
                quality=1.0,
                metadata={"source": "psutil"},
            ),
        ]

        with patch("ori.network.deduplicator.now_ms", side_effect=[1_000, 2_000]):
            await runtime._poll_sensor(
                _SequenceAdapter(readings),
                sensor_cfg,
                bus,
                "dev-01",
                EventDeduplicator(),
            )

        assert len(bus.events) == 1
        assert len(runtime._state_store.events) == 2

    async def test_deduplicator_allows_identical_readings_after_6_seconds(self):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._shutdown_event = asyncio.Event()

        class _Store:
            def __init__(self) -> None:
                self.events: list[OriEvent] = []

            async def append_history(self, event: OriEvent) -> None:
                self.events.append(event)

        class _Bus:
            def __init__(self) -> None:
                self.events: list[OriEvent] = []

            async def publish(self, event: OriEvent) -> None:
                self.events.append(event)

        class _SequenceAdapter:
            def __init__(self, readings: list[SensorReading]) -> None:
                self._readings = readings
                self._idx = 0

            async def read(self, sensor_id: str) -> SensorReading:
                reading = self._readings[self._idx]
                self._idx += 1
                if self._idx >= len(self._readings):
                    runtime._shutdown_event.set()
                return reading

        runtime._state_store = _Store()
        bus = _Bus()
        sensor_cfg = SimpleNamespace(id="cpu-sensor", poll_interval_ms=1)
        readings = [
            SensorReading(
                sensor_id="cpu-sensor",
                sensor_type="cpu_percent",
                value=41.2,
                unit="percent",
                timestamp=1_700_000_000_000,
                quality=1.0,
                metadata={"source": "psutil"},
            ),
            SensorReading(
                sensor_id="cpu-sensor",
                sensor_type="cpu_percent",
                value=41.2,
                unit="percent",
                timestamp=1_700_000_006_000,
                quality=1.0,
                metadata={"source": "psutil"},
            ),
        ]

        with patch("ori.network.deduplicator.now_ms", side_effect=[1_000, 7_001]):
            await runtime._poll_sensor(
                _SequenceAdapter(readings),
                sensor_cfg,
                bus,
                "dev-01",
                EventDeduplicator(),
            )

        assert len(bus.events) == 2
        assert len(runtime._state_store.events) == 2

    async def test_non_reading_events_bypass_deduplication(self):
        bus = EventBus()
        seen: list[OriEvent] = []

        async def _handler(event: OriEvent) -> None:
            seen.append(event)

        bus.subscribe("system.alert", _handler)
        deduplicator = EventDeduplicator()

        first = OriEvent(
            event_id="evt-1",
            event_type="system.alert",
            device_id="dev-01",
            sensor_id="",
            timestamp=1_700_000_000_000,
            reading=None,
        )
        second = OriEvent(
            event_id="evt-2",
            event_type="system.alert",
            device_id="dev-01",
            sensor_id="",
            timestamp=1_700_000_000_100,
            reading=None,
        )

        for event in (first, second):
            if event.reading is not None and deduplicator.process(event) is None:
                continue
            await bus.publish(event)

        assert len(seen) == 2

    async def test_deduplication_does_not_block_history_writes(self, tmp_path: Path):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._shutdown_event = asyncio.Event()
        runtime._state_store = StateStore(str(tmp_path / "ori.db"))
        await runtime._state_store.open()

        class _Bus:
            def __init__(self) -> None:
                self.events: list[OriEvent] = []

            async def publish(self, event: OriEvent) -> None:
                self.events.append(event)

        class _SequenceAdapter:
            def __init__(self, readings: list[SensorReading]) -> None:
                self._readings = readings
                self._idx = 0

            async def read(self, sensor_id: str) -> SensorReading:
                reading = self._readings[self._idx]
                self._idx += 1
                if self._idx >= len(self._readings):
                    runtime._shutdown_event.set()
                return reading

        bus = _Bus()
        sensor_cfg = SimpleNamespace(id="cpu-sensor", poll_interval_ms=1)
        readings = [
            SensorReading(
                sensor_id="cpu-sensor",
                sensor_type="cpu_percent",
                value=22.0,
                unit="percent",
                timestamp=1_700_000_000_000,
                quality=1.0,
                metadata={"source": "psutil"},
            ),
            SensorReading(
                sensor_id="cpu-sensor",
                sensor_type="cpu_percent",
                value=22.0,
                unit="percent",
                timestamp=1_700_000_000_100,
                quality=1.0,
                metadata={"source": "psutil"},
            ),
        ]

        try:
            with patch("ori.network.deduplicator.now_ms", side_effect=[1_000, 2_000]):
                await runtime._poll_sensor(
                    _SequenceAdapter(readings),
                    sensor_cfg,
                    bus,
                    "dev-01",
                    EventDeduplicator(),
                )

            history = await runtime._state_store.get_history("cpu-sensor", limit=10)
            assert len(history) == 2
            assert len(bus.events) == 1
        finally:
            await runtime._state_store.close()


class TestCompactionLoop:
    async def test_compaction_loop_runs_deduplicator_cleanup(self):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._shutdown_event = asyncio.Event()

        cleanup_calls = {"count": 0}

        class _Dedup:
            def cleanup(self) -> None:
                cleanup_calls["count"] += 1

        async def _compact(*_args, **_kwargs) -> None:
            runtime._shutdown_event.set()

        runtime._state_store = AsyncMock()
        runtime._state_store.compact_history.side_effect = _compact

        async def _fake_wait_for(awaitable, timeout):  # noqa: ARG001
            if hasattr(awaitable, "close"):
                awaitable.close()
            raise asyncio.TimeoutError

        with patch(
            "ori.runtime.asyncio.wait_for",
            new=AsyncMock(side_effect=_fake_wait_for),
        ):
            await runtime._compaction_loop(_Dedup())

        runtime._state_store.compact_history.assert_awaited_once_with(
            max_backward_skew_ms=3600000
        )
        assert cleanup_calls["count"] == 1


class TestProcessTargetResolution:
    def _ctx(self, *, context: dict | None = None, metadata: dict | None = None):
        reading = SensorReading(
            sensor_id="sleep-blocker",
            sensor_type="sleep_blocking_process",
            value=1.0,
            unit="count",
            timestamp=1_700_000_000_000,
            quality=1.0,
            metadata=metadata or {},
        )
        event = OriEvent.from_reading(reading, "dev-01")
        event.context = context or {}
        return SkillContext(skill=None, event=event, state_store=None)

    def test_prefers_explicit_context_target(self):
        ctx = self._ctx(
            context={"terminate_process": {"pid": 1234, "name": "Zoom"}},
            metadata={"processes": [{"pid": 999, "name": "Other"}]},
        )
        assert _process_target_from_context(ctx) == (1234, "Zoom")

    def test_reads_single_metadata_process(self):
        ctx = self._ctx(metadata={"processes": [{"pid": 2222, "name": "Slack"}]})
        assert _process_target_from_context(ctx) == (2222, "Slack")

    def test_returns_none_on_ambiguous_processes(self):
        ctx = self._ctx(
            metadata={
                "processes": [
                    {"pid": 1, "name": "A"},
                    {"pid": 2, "name": "B"},
                ]
            }
        )
        assert _process_target_from_context(ctx) == (None, "")

    def test_uses_recommended_process_when_present(self):
        ctx = self._ctx(
            metadata={
                "processes": [
                    {"pid": 1, "name": "A"},
                    {"pid": 2, "name": "B"},
                ],
                "recommended_process": {"pid": 2, "name": "B"},
            }
        )
        assert _process_target_from_context(ctx) == (2, "B")


class TestCoapCommandResolution:
    def test_prefers_event_context(self):
        reading = SensorReading(
            sensor_id="s-1",
            sensor_type="temperature",
            value=1.0,
            unit="celsius",
            timestamp=1_700_000_000_000,
            quality=1.0,
        )
        event = OriEvent.from_reading(reading, "dev-01")
        event.context = {
            "coap_command": "open_bypass_valve",
            "coap_payload": '{"state":"open"}',
        }
        ctx = SkillContext(
            skill=SimpleNamespace(config={}),
            event=event,
            state_store=None,
            trigger_name="trigger-a",
        )
        command, payload = _coap_command_from_context(ctx)
        assert command == "open_bypass_valve"
        assert payload == '{"state":"open"}'

    def test_uses_skill_trigger_mapping(self):
        reading = SensorReading(
            sensor_id="s-1",
            sensor_type="temperature",
            value=1.0,
            unit="celsius",
            timestamp=1_700_000_000_000,
            quality=1.0,
        )
        event = OriEvent.from_reading(reading, "dev-01")
        ctx = SkillContext(
            skill=SimpleNamespace(
                config={
                    "coap": {
                        "trigger_commands": {
                            "probable_c2_or_shell_foothold": "isolate_vlan",
                        }
                    }
                }
            ),
            event=event,
            state_store=None,
            trigger_name="probable_c2_or_shell_foothold",
        )
        command, payload = _coap_command_from_context(ctx)
        assert command == "isolate_vlan"
        assert payload is None


class TestMessageComposition:
    def _ctx(self, *, context: dict | None = None):
        reading = SensorReading(
            sensor_id="sensor-1",
            sensor_type="temperature",
            value=27.5,
            unit="celsius",
            timestamp=1_700_000_000_000,
            quality=1.0,
        )
        event = OriEvent.from_reading(reading, "dev-01")
        event.context = context or {}
        return SkillContext(skill=None, event=event, state_store=None)

    def test_sms_uses_operator_message_and_caps_length(self):
        ctx = self._ctx(context={"operator_message": "a" * 220})
        msg = _message_from_context(ctx, "fallback", channel="sms")
        assert len(msg) <= 160
        assert msg.endswith("...")

    def test_whatsapp_prefers_channel_specific_message(self):
        ctx = self._ctx(
            context={
                "operator_message": "generic",
                "channel_messages": {
                    "whatsapp": "WhatsApp enriched message",
                    "sms": "SMS compact message",
                },
            }
        )
        assert (
            _message_from_context(ctx, "fallback", channel="whatsapp")
            == "WhatsApp enriched message"
        )
        assert (
            _message_from_context(ctx, "fallback", channel="sms")
            == "SMS compact message"
        )

    def test_whatsapp_sensor_fallback_is_richer_layout(self):
        ctx = self._ctx()
        msg = _message_from_context(ctx, "fallback", channel="whatsapp")
        assert "\nValue: " in msg


class TestWebhookIngest:
    async def test_ingest_sms_webhook_returns_false_without_sms_action(self):
        runtime = OriRuntime(config_path="ori.yaml")
        ok = await runtime.ingest_sms_webhook({"from": "+234", "text": "YES"})
        assert ok is False

    async def test_ingest_sms_webhook_delegates_to_sms_action(self):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._sms_action = AsyncMock()
        runtime._sms_action.ingest_incoming_webhook.return_value = True
        ok = await runtime.ingest_sms_webhook({"from": "+234", "text": "YES"})
        assert ok is True
        runtime._sms_action.ingest_incoming_webhook.assert_awaited_once()


class TestWebhookServerStartup:
    async def test_runtime_starts_sms_webhook_when_enabled(self, tmp_path, monkeypatch):
        _patch_external(monkeypatch)

        skill_dir = tmp_path / "skills" / "test-skill"
        skill_dir.mkdir(parents=True)
        (skill_dir / "skill.yaml").write_text(
            textwrap.dedent("""\
                name: test-skill
                version: 0.1.0
                author: test
                sensors_required:
                  - type: cpu_percent
                    protocol: psutil
                triggers:
                  - name: high_cpu
                    condition: "value > 90"
                    action_tier: A
                    cooldown_seconds: 0
                    escalate_to: local_slm
                actions:
                  available:
                    - name: alert_whatsapp
                      tier: A
                  defaults:
                    high_cpu: [alert_whatsapp]
            """),
            encoding="utf-8",
        )

        cfg = tmp_path / "ori.yaml"
        cfg.write_text(
            textwrap.dedent(f"""\
                device:
                  id: test-device-01
                  name: Test Device
                  location: Test Lab

                sensors:
                  - id: cpu-sensor
                    type: cpu_percent
                    protocol: psutil
                    poll_interval_ms: 100

                skills:
                  - name: test-skill
                    version: "0.1.0"
                    config: {{}}

                reasoning:
                  default_tier: local
                  local_model: ""
                  model_path: ""

                gateway:
                  enabled: false
                  broker_url: ""

                actions:
                  primary_alert_channel: sms
                  whatsapp:
                    enabled: false
                  sms:
                    enabled: false
                    incoming_webhook:
                      enabled: true
                      host: "127.0.0.1"
                      port: 0
                      path: "/webhooks/sms/africastalking"
                      allowed_source_cidrs:
                        - "127.0.0.1/32"
                      token: "test-token"
                  relay:
                    enabled: false

                skills_dir: {str(tmp_path / "skills")}
            """),
            encoding="utf-8",
        )

        runtime = OriRuntime(config_path=str(cfg))

        class _FakeServer:
            def __init__(self, *args, **kwargs):
                self.args = args
                self.kwargs = kwargs
                self.serve_until = AsyncMock(side_effect=self._serve_until)

            async def _serve_until(self, shutdown_event):
                await shutdown_event.wait()

        fake_instance = _FakeServer()

        with patch("ori.runtime.SMSWebhookServer", return_value=fake_instance) as cls:

            async def _stop():
                await asyncio.sleep(0.1)
                await runtime.stop()

            await asyncio.gather(runtime.start(), _stop())

        cls.assert_called_once()
        assert cls.call_args.kwargs["allowed_source_cidrs"] == ["127.0.0.1/32"]
        fake_instance.serve_until.assert_awaited_once()

    async def test_runtime_webhook_defaults_host_to_localhost(
        self, tmp_path, monkeypatch
    ):
        _patch_external(monkeypatch)

        skill_dir = tmp_path / "skills" / "test-skill"
        skill_dir.mkdir(parents=True)
        (skill_dir / "skill.yaml").write_text(
            textwrap.dedent("""\
                name: test-skill
                version: 0.1.0
                author: test
                sensors_required:
                  - type: cpu_percent
                    protocol: psutil
                triggers:
                  - name: high_cpu
                    condition: "value > 90"
                    action_tier: A
                    cooldown_seconds: 0
                    escalate_to: local_slm
                actions:
                  available:
                    - name: alert_whatsapp
                      tier: A
                  defaults:
                    high_cpu: [alert_whatsapp]
            """),
            encoding="utf-8",
        )

        cfg = tmp_path / "ori.yaml"
        cfg.write_text(
            textwrap.dedent(f"""\
                device:
                  id: test-device-01
                  name: Test Device
                  location: Test Lab

                sensors:
                  - id: cpu-sensor
                    type: cpu_percent
                    protocol: psutil
                    poll_interval_ms: 100

                skills:
                  - name: test-skill
                    version: "0.1.0"
                    config: {{}}

                reasoning:
                  default_tier: local
                  local_model: ""
                  model_path: ""

                gateway:
                  enabled: false
                  broker_url: ""

                actions:
                  primary_alert_channel: sms
                  whatsapp:
                    enabled: false
                  sms:
                    enabled: false
                    incoming_webhook:
                      enabled: true
                      port: 0
                      path: "/webhooks/sms/africastalking"
                      token: "test-token"
                  relay:
                    enabled: false

                skills_dir: {str(tmp_path / "skills")}
            """),
            encoding="utf-8",
        )

        runtime = OriRuntime(config_path=str(cfg))

        class _FakeServer:
            def __init__(self, *args, **kwargs):
                self.args = args
                self.kwargs = kwargs
                self.serve_until = AsyncMock(side_effect=self._serve_until)

            async def _serve_until(self, shutdown_event):
                await shutdown_event.wait()

        fake_instance = _FakeServer()

        with patch("ori.runtime.SMSWebhookServer", return_value=fake_instance) as cls:

            async def _stop():
                await asyncio.sleep(0.1)
                await runtime.stop()

            await asyncio.gather(runtime.start(), _stop())

        cls.assert_called_once()
        assert cls.call_args.kwargs["host"] == "127.0.0.1"

    async def test_runtime_skips_sms_webhook_without_token(self, tmp_path, monkeypatch):
        _patch_external(monkeypatch)

        skill_dir = tmp_path / "skills" / "test-skill"
        skill_dir.mkdir(parents=True)
        (skill_dir / "skill.yaml").write_text(
            textwrap.dedent("""\
                name: test-skill
                version: 0.1.0
                author: test
                sensors_required:
                  - type: cpu_percent
                    protocol: psutil
                triggers:
                  - name: high_cpu
                    condition: "value > 90"
                    action_tier: A
                    cooldown_seconds: 0
                    escalate_to: local_slm
                actions:
                  available:
                    - name: alert_whatsapp
                      tier: A
                  defaults:
                    high_cpu: [alert_whatsapp]
            """),
            encoding="utf-8",
        )

        cfg = tmp_path / "ori.yaml"
        cfg.write_text(
            textwrap.dedent(f"""\
                device:
                  id: test-device-01
                  name: Test Device
                  location: Test Lab
                sensors:
                  - id: cpu-sensor
                    type: cpu_percent
                    protocol: psutil
                    poll_interval_ms: 100
                skills:
                  - name: test-skill
                    version: "0.1.0"
                    config: {{}}
                reasoning:
                  default_tier: local
                  local_model: ""
                  model_path: ""
                gateway:
                  enabled: false
                  broker_url: ""
                actions:
                  primary_alert_channel: sms
                  whatsapp:
                    enabled: false
                  sms:
                    enabled: false
                    incoming_webhook:
                      enabled: true
                      token: ""
                  relay:
                    enabled: false
                skills_dir: {str(tmp_path / "skills")}
            """),
            encoding="utf-8",
        )

        runtime = OriRuntime(config_path=str(cfg))
        with patch("ori.runtime.SMSWebhookServer") as cls:

            async def _stop():
                await asyncio.sleep(0.1)
                await runtime.stop()

            await asyncio.gather(runtime.start(), _stop())

        cls.assert_not_called()


class TestAlertOutbox:
    async def test_send_or_queue_alert_queues_when_send_fails(self, tmp_path):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._state_store = StateStore(str(tmp_path / "outbox-queue.db"))
        await runtime._state_store.open()

        alert_sender = AsyncMock()
        alert_sender.send = AsyncMock(return_value=False)

        try:
            handled = await runtime._send_or_queue_alert(
                channel="sms",
                message="alert message",
                recipient="+2340000000000",
                action_tier="A",
                trigger_name="high_draw",
                original_ts=1234567890,
                alert_sender=alert_sender,
            )
            assert handled is True
            queued = await runtime._state_store.get_retryable_alerts(limit=10)
            assert len(queued) == 1
            assert queued[0]["channel"] == "sms"
            assert queued[0]["status"] == "pending"
        finally:
            await runtime._state_store.close()

    async def test_send_or_queue_alert_respects_device_policy_monthly_cap(
        self, tmp_path
    ):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._state_store = StateStore(str(tmp_path / "alert-cap.db"))
        await runtime._state_store.open()
        dispatcher = ActionDispatcher()
        dispatcher.update_policy(
            DevicePolicy(
                tier="restricted",
                relay_b_enabled=False,
                relay_c_enabled=False,
                cloud_llm_enabled=False,
                valid_until=int(time.time()) + 3600,
                policy_version=3,
                issued_at=int(time.time()),
                signature="test",
                alert_sms_monthly_cap=1,
                alert_whatsapp_monthly_cap=1,
            )
        )
        runtime._dispatcher = dispatcher
        alert_sender = AsyncMock()
        alert_sender.send = AsyncMock(return_value=True)

        try:
            first = await runtime._send_or_queue_alert(
                channel="sms",
                message="first alert",
                recipient="+2340000000000",
                action_tier="A",
                trigger_name="high_draw",
                original_ts=1234567890,
                alert_sender=alert_sender,
            )
            second = await runtime._send_or_queue_alert(
                channel="sms",
                message="second alert",
                recipient="+2340000000000",
                action_tier="A",
                trigger_name="high_draw",
                original_ts=1234567891,
                alert_sender=alert_sender,
            )
            assert first is True
            assert second is False
            alert_sender.send.assert_awaited_once()
        finally:
            await runtime._state_store.close()

    async def test_send_or_queue_alert_never_caps_tier_d(self, tmp_path):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._state_store = StateStore(str(tmp_path / "alert-cap-tier-d.db"))
        await runtime._state_store.open()
        dispatcher = ActionDispatcher()
        dispatcher.update_policy(
            DevicePolicy(
                tier="restricted",
                relay_b_enabled=False,
                relay_c_enabled=False,
                cloud_llm_enabled=False,
                valid_until=int(time.time()) + 3600,
                policy_version=3,
                issued_at=int(time.time()),
                signature="test",
                alert_sms_monthly_cap=0,
                alert_whatsapp_monthly_cap=0,
            )
        )
        runtime._dispatcher = dispatcher
        alert_sender = AsyncMock()
        alert_sender.send = AsyncMock(return_value=True)

        try:
            delivered = await runtime._send_or_queue_alert(
                channel="sms",
                message="tier d alert",
                recipient="+2340000000000",
                action_tier="D",
                trigger_name="dangerous_overcurrent",
                original_ts=1234567890,
                alert_sender=alert_sender,
            )
            assert delivered is True
            alert_sender.send.assert_awaited_once()
        finally:
            await runtime._state_store.close()

    async def test_send_or_queue_alert_ignores_alert_count_persistence_failure(
        self, tmp_path
    ):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._state_store = StateStore(str(tmp_path / "alert-count-failure.db"))
        await runtime._state_store.open()
        dispatcher = ActionDispatcher()
        dispatcher.update_policy(
            DevicePolicy(
                tier="restricted",
                relay_b_enabled=False,
                relay_c_enabled=False,
                cloud_llm_enabled=False,
                valid_until=int(time.time()) + 3600,
                policy_version=3,
                issued_at=int(time.time()),
                signature="test",
                alert_sms_monthly_cap=1,
                alert_whatsapp_monthly_cap=1,
            )
        )
        runtime._dispatcher = dispatcher
        alert_sender = AsyncMock()
        alert_sender.send = AsyncMock(return_value=True)
        runtime._state_store.set_skill_state = AsyncMock(  # type: ignore[method-assign]
            side_effect=RuntimeError("sqlite unavailable")
        )

        try:
            delivered = await runtime._send_or_queue_alert(
                channel="sms",
                message="delivered alert",
                recipient="+2340000000000",
                action_tier="A",
                trigger_name="high_draw",
                original_ts=1234567890,
                alert_sender=alert_sender,
            )
            assert delivered is True
            alert_sender.send.assert_awaited_once()
        finally:
            await runtime._state_store.close()

    async def test_remote_command_incident_emits_tier_a_alert(self, tmp_path):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._state_store = StateStore(str(tmp_path / "remote-lockout.db"))
        await runtime._state_store.open()
        runtime._primary_alert_channel = "sms"
        runtime._operator_contact = "+2340000000000"
        runtime._alert_sender = AsyncMock()
        runtime._send_or_queue_alert = AsyncMock(return_value=True)  # type: ignore[method-assign]
        await runtime._state_store.log_remote_command_security_incident(
            incident_id="incident-1",
            channel="sms",
            from_number="+2348012345678",
            reason="remote_command_rejection_feedback_suppressed",
            rejection_count=6,
            threshold=5,
            window_ms=600_000,
        )
        try:
            decision = RemoteCommandThrottleDecision(
                send_feedback=False,
                incident_logged=True,
                incident_id="incident-1",
                channel="sms",
                from_number="+2348012345678",
                rejection_count=6,
                threshold=5,
                window_ms=600_000,
            )

            await runtime._handle_remote_command_incident(decision)

            runtime._send_or_queue_alert.assert_awaited_once()
            kwargs = runtime._send_or_queue_alert.await_args.kwargs
            assert kwargs["channel"] == "sms"
            assert kwargs["recipient"] == "+2340000000000"
            assert kwargs["action_tier"] == "A"
            assert kwargs["trigger_name"] == "remote_command_abuse"
            assert "repeated rejected remote commands" in kwargs["message"]
            assert "+2348012345678" in kwargs["message"]
            states = list(runtime._remote_command_lockout_states.values())
            assert states[0]["risk_level"] == "elevated"
            assert states[0]["locked_out"] is False
        finally:
            await runtime._state_store.close()

    async def test_load_remote_command_lockout_state_from_persisted_incidents(
        self, tmp_path, monkeypatch
    ):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._state_store = StateStore(str(tmp_path / "remote-lockout-load.db"))
        await runtime._state_store.open()
        now = 1_780_000_000_000
        monkeypatch.setattr("ori.runtime.now_ms", lambda: now)
        try:
            await runtime._state_store.log_remote_command_security_incident(
                incident_id="incident-recent",
                channel="sms",
                from_number="+2348012345678",
                reason="remote_command_rejection_feedback_suppressed",
                rejection_count=6,
                threshold=5,
                window_ms=600_000,
                created_at_ms=now - 1_000,
            )
            await runtime._state_store.log_remote_command_security_incident(
                incident_id="incident-old",
                channel="whatsapp",
                from_number="whatsapp:+2348099999999",
                reason="remote_command_rejection_feedback_suppressed",
                rejection_count=6,
                threshold=5,
                window_ms=600_000,
                created_at_ms=now - 7_200_000,
            )

            await runtime._load_remote_command_lockout_state()

            assert set(runtime._remote_command_lockout_states) == {"sms:+2348012345678"}
            state = runtime._remote_command_lockout_states["sms:+2348012345678"]
            assert state["risk_level"] == "elevated"
            assert state["incident_count"] == 1
            assert state["locked_out"] is False
            snapshot = await runtime._build_health_snapshot()
            senders = snapshot["remote_command_lockout"]["senders"]
            assert len(senders) == 1
            assert senders[0]["from_number"] == "+2348012345678"
            assert senders[0]["stale"] is False
        finally:
            await runtime._state_store.close()

    async def test_health_snapshot_reports_state_store_encryption_posture(
        self, tmp_path
    ):
        encrypted_dir = tmp_path / "encrypted"
        encrypted_dir.mkdir()
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._device_id = "dev-01"
        database_path = encrypted_dir / "ori_state.db"
        runtime._config = SimpleNamespace(
            gateway=SimpleNamespace(
                enabled=False,
                broker_url="",
                broker_posture={},
            ),
            state=SimpleNamespace(
                encryption=SimpleNamespace(
                    mode="filesystem_required",
                    encrypted_path_prefixes=[str(encrypted_dir)],
                    marker_file="",
                )
            ),
            database_path=str(database_path),
        )

        snapshot = await runtime._build_health_snapshot()

        posture = snapshot["state_store_encryption"]
        assert posture == {
            "available": True,
            "mode": "filesystem_required",
            "satisfied": True,
            "marker_configured": False,
            "path_prefix_configured": True,
        }
        assert str(encrypted_dir) not in json.dumps(posture)

    async def test_health_snapshot_reports_gateway_broker_posture(self):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._device_id = "dev-01"
        runtime._config = SimpleNamespace(
            gateway=SimpleNamespace(
                enabled=True,
                broker_url="mqtts://operator:secret@broker.local:8883",
                broker_posture={
                    "deployment_check": "required",
                    "anonymous_access": "disabled",
                    "require_credentials": True,
                    "acl_policy": "per_device_required",
                },
            ),
            state=SimpleNamespace(
                encryption=SimpleNamespace(
                    mode="disabled",
                    encrypted_path_prefixes=[],
                    marker_file="",
                )
            ),
            database_path="ori_state.db",
        )

        snapshot = await runtime._build_health_snapshot()

        posture = snapshot["gateway_broker_posture"]
        assert posture == {
            "available": True,
            "gateway_enabled": True,
            "deployment_check": "required",
            "anonymous_access": "disabled",
            "acl_policy": "per_device_required",
            "require_credentials": True,
            "credentials_configured": True,
            "requires_acl_hardening": False,
        }
        assert "secret" not in json.dumps(posture)

    async def test_load_remote_command_lockout_state_failure_is_non_blocking(self):
        class _FailingIncidentStore:
            async def get_recent_remote_command_incident_senders(
                self, *, since_ms: int, limit: int
            ):
                raise RuntimeError("incident query failed")

        runtime = OriRuntime(config_path="ori.yaml")
        runtime._state_store = _FailingIncidentStore()
        runtime._remote_command_lockout_states["sms:+2348012345678"] = {
            "channel": "sms",
            "from_number": "+2348012345678",
        }

        await runtime._load_remote_command_lockout_state()

        assert runtime._remote_command_lockout_states == {}

    async def test_load_remote_command_lockout_state_uses_configured_bounds(
        self, monkeypatch
    ):
        class _CapturingIncidentStore:
            def __init__(self):
                self.calls: list[dict[str, int]] = []

            async def get_recent_remote_command_incident_senders(
                self, *, since_ms: int, limit: int
            ):
                self.calls.append({"since_ms": since_ms, "limit": limit})
                return []

        now = 1_780_000_000_000
        monkeypatch.setattr("ori.runtime.now_ms", lambda: now)
        store = _CapturingIncidentStore()
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._state_store = store
        runtime._remote_command_lockout_config = {
            "risk_window_ms": 120_000,
            "state_stale_after_ms": 240_000,
            "incident_sender_limit": 7,
            "elevated_incident_threshold": 2,
            "critical_incident_threshold": 4,
            "elevated_rejection_threshold": 8,
            "critical_rejection_threshold": 20,
            "enforcement_enabled": False,
        }

        await runtime._load_remote_command_lockout_state()

        assert store.calls == [{"since_ms": now - 240_000, "limit": 7}]


class TestRemoteDevicePolicy:
    def _signed_policy_payload(self):
        assert Ed25519PrivateKey is not None
        private_key = Ed25519PrivateKey.generate()
        payload = {
            "tier": "cloud",
            "relay_b_enabled": True,
            "relay_c_enabled": False,
            "cloud_llm_enabled": False,
            "valid_until": int(time.time()) + 600,
            "policy_version": 7,
            "issued_at": int(time.time()) - 10,
            "timestamp": int(time.time()),
        }
        signature = private_key.sign(canonical_signed_payload(payload))
        payload["signature"] = "ed25519:" + base64.b64encode(signature).decode("ascii")
        public_key_b64 = base64.b64encode(
            private_key.public_key().public_bytes(
                encoding=Encoding.Raw,
                format=PublicFormat.Raw,
            )
        ).decode("ascii")
        raw_payload = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        return payload, raw_payload, public_key_b64

    @pytest.mark.skipif(
        Ed25519PrivateKey is None,
        reason="cryptography ed25519 is unavailable",
    )
    async def test_applies_verified_remote_policy(self, tmp_path, monkeypatch):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._state_store = StateStore(str(tmp_path / "policy-apply.db"))
        await runtime._state_store.open()
        dispatcher = ActionDispatcher()
        payload, raw_payload, public_key_b64 = self._signed_policy_payload()

        async def _fake_fetch(*_args, **_kwargs):
            return FetchedRemotePolicy(
                policy=DevicePolicy(
                    tier="cloud",
                    relay_b_enabled=True,
                    relay_c_enabled=False,
                    cloud_llm_enabled=False,
                    valid_until=int(time.time()) + 600,
                    policy_version=7,
                    issued_at=int(time.time()) - 10,
                    signature=payload["signature"],
                ),
                raw_payload=raw_payload,
                payload=payload,
            )

        monkeypatch.setattr(
            "ori.runtime.fetch_remote_device_policy_bundle", _fake_fetch
        )

        cfg = SimpleNamespace(
            device=SimpleNamespace(id="dev-01"),
            device_policy={
                "enabled": True,
                "url": "https://example.com/device-policy",
                "auth_token": "token",
                "public_key_b64": public_key_b64,
                "request_timeout_ms": 3000,
                "max_clock_skew_s": 300,
            },
        )

        try:
            await runtime._maybe_refresh_remote_device_policy_once(cfg, dispatcher)
            assert dispatcher.current_policy_version() == 7
            assert dispatcher._policy is not None
            assert dispatcher._policy.relay_c_enabled is False
            cached = await runtime._state_store.get_latest_device_policy_cache()
            assert cached is not None
            assert cached["policy_version"] == 7
            assert cached["raw_payload"] == raw_payload
        finally:
            await runtime._state_store.close()

    async def test_rejection_is_persisted_to_override_log(self, tmp_path, monkeypatch):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._state_store = StateStore(str(tmp_path / "policy-reject.db"))
        await runtime._state_store.open()
        dispatcher = ActionDispatcher()

        async def _fake_fetch(*_args, **_kwargs):
            raise RemotePolicyFetchError(
                "invalid_signature",
                "signature verification failed",
                policy_version=5,
                payload_timestamp=1234567890,
            )

        monkeypatch.setattr(
            "ori.runtime.fetch_remote_device_policy_bundle", _fake_fetch
        )

        cfg = SimpleNamespace(
            device=SimpleNamespace(id="dev-02"),
            device_policy={
                "enabled": True,
                "url": "https://example.com/device-policy",
                "auth_token": "token",
                "public_key_b64": "key",
                "request_timeout_ms": 3000,
                "max_clock_skew_s": 300,
            },
        )

        try:
            await runtime._maybe_refresh_remote_device_policy_once(cfg, dispatcher)
            row = await runtime._state_store._run_read(
                lambda conn: conn.execute(
                    """
                    SELECT override_type, action, reason, device_id
                    FROM override_log
                    ORDER BY id DESC
                    LIMIT 1
                    """
                ).fetchone()
            )
            assert row is not None
            assert row["override_type"] == "policy_rejection"
            assert row["action"] == "refresh_device_policy"
            assert row["device_id"] == "dev-02"
            assert '"code":"invalid_signature"' in row["reason"]
            assert '"policy_version":5' in row["reason"]
        finally:
            await runtime._state_store.close()

    @pytest.mark.skipif(
        Ed25519PrivateKey is None,
        reason="cryptography ed25519 is unavailable",
    )
    async def test_load_cached_policy_applies_when_signature_valid(self, tmp_path):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._state_store = StateStore(str(tmp_path / "policy-cache-valid.db"))
        await runtime._state_store.open()
        dispatcher = ActionDispatcher()
        payload, raw_payload, public_key_b64 = self._signed_policy_payload()

        await runtime._state_store.upsert_device_policy_cache(
            policy_version=int(payload["policy_version"]),
            tier=str(payload["tier"]),
            relay_b_enabled=bool(payload["relay_b_enabled"]),
            relay_c_enabled=bool(payload["relay_c_enabled"]),
            cloud_llm_enabled=bool(payload["cloud_llm_enabled"]),
            valid_until=int(payload["valid_until"]),
            issued_at=int(payload["issued_at"]),
            signature=str(payload["signature"]),
            raw_payload=raw_payload,
        )
        cfg = SimpleNamespace(
            device=SimpleNamespace(id="dev-cache-01"),
            device_policy={"public_key_b64": public_key_b64},
        )

        try:
            await runtime._load_cached_device_policy(cfg, dispatcher)
            assert dispatcher.current_policy_version() == int(payload["policy_version"])
            assert dispatcher._policy is not None
            assert dispatcher._policy.relay_c_enabled is False
        finally:
            await runtime._state_store.close()

    @pytest.mark.skipif(
        Ed25519PrivateKey is None,
        reason="cryptography ed25519 is unavailable",
    )
    async def test_load_cached_policy_rejects_invalid_signature_audits(self, tmp_path):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._state_store = StateStore(str(tmp_path / "policy-cache-bad.db"))
        await runtime._state_store.open()
        dispatcher = ActionDispatcher()
        payload, raw_payload, _public_key_b64 = self._signed_policy_payload()
        _, _, wrong_public_key_b64 = self._signed_policy_payload()

        await runtime._state_store.upsert_device_policy_cache(
            policy_version=int(payload["policy_version"]),
            tier=str(payload["tier"]),
            relay_b_enabled=bool(payload["relay_b_enabled"]),
            relay_c_enabled=bool(payload["relay_c_enabled"]),
            cloud_llm_enabled=bool(payload["cloud_llm_enabled"]),
            valid_until=int(payload["valid_until"]),
            issued_at=int(payload["issued_at"]),
            signature=str(payload["signature"]),
            raw_payload=raw_payload,
        )
        cfg = SimpleNamespace(
            device=SimpleNamespace(id="dev-cache-02"),
            device_policy={"public_key_b64": wrong_public_key_b64},
        )

        try:
            await runtime._load_cached_device_policy(cfg, dispatcher)
            assert dispatcher.current_policy_version() == 0
            row = await runtime._state_store._run_read(
                lambda conn: conn.execute(
                    """
                    SELECT override_type, reason
                    FROM override_log
                    ORDER BY id DESC
                    LIMIT 1
                    """
                ).fetchone()
            )
            assert row is not None
            assert row["override_type"] == "policy_rejection"
            assert '"code":"cache_invalid_payload"' in row["reason"]
        finally:
            await runtime._state_store.close()

    @pytest.mark.skipif(
        Ed25519PrivateKey is None,
        reason="cryptography ed25519 is unavailable",
    )
    async def test_policy_refresh_loop_applies_and_caches_policy(
        self, tmp_path, monkeypatch
    ):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._state_store = StateStore(str(tmp_path / "policy-refresh-loop.db"))
        await runtime._state_store.open()
        dispatcher = ActionDispatcher()
        payload, raw_payload, public_key_b64 = self._signed_policy_payload()
        calls = {"count": 0}

        async def _fake_fetch(*_args, **_kwargs):
            calls["count"] += 1
            runtime._shutdown_event.set()
            return FetchedRemotePolicy(
                policy=DevicePolicy(
                    tier=str(payload["tier"]),
                    relay_b_enabled=bool(payload["relay_b_enabled"]),
                    relay_c_enabled=bool(payload["relay_c_enabled"]),
                    cloud_llm_enabled=bool(payload["cloud_llm_enabled"]),
                    valid_until=int(payload["valid_until"]),
                    policy_version=int(payload["policy_version"]),
                    issued_at=int(payload["issued_at"]),
                    signature=str(payload["signature"]),
                ),
                raw_payload=raw_payload,
                payload=payload,
            )

        monkeypatch.setattr(
            "ori.runtime.fetch_remote_device_policy_bundle",
            _fake_fetch,
        )
        cfg = SimpleNamespace(
            device=SimpleNamespace(id="dev-refresh-01"),
            device_policy={
                "enabled": True,
                "url": "https://example.com/device-policy",
                "auth_token": "token",
                "public_key_b64": public_key_b64,
                "request_timeout_ms": 3000,
                "max_clock_skew_s": 300,
                "refresh_enabled": True,
                "refresh_interval_s": 60,
            },
        )

        try:
            await runtime._device_policy_refresh_loop(
                config=cfg,
                dispatcher=dispatcher,
                refresh_interval_s=0.01,
            )
            assert calls["count"] == 1
            assert dispatcher.current_policy_version() == int(payload["policy_version"])
            cached = await runtime._state_store.get_latest_device_policy_cache()
            assert cached is not None
            assert cached["raw_payload"] == raw_payload
        finally:
            await runtime._state_store.close()

    async def test_policy_refresh_transient_network_audit_dedupes(
        self, tmp_path, monkeypatch
    ):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._state_store = StateStore(str(tmp_path / "policy-refresh-dedupe.db"))
        await runtime._state_store.open()
        dispatcher = ActionDispatcher()

        async def _fake_fetch(*_args, **_kwargs):
            raise RemotePolicyFetchError(
                "network_error",
                "policy endpoint network error: offline",
            )

        monkeypatch.setattr(
            "ori.runtime.fetch_remote_device_policy_bundle",
            _fake_fetch,
        )
        cfg = SimpleNamespace(
            device=SimpleNamespace(id="dev-refresh-02"),
            device_policy={
                "enabled": True,
                "url": "https://example.com/device-policy",
                "auth_token": "token",
                "public_key_b64": "key",
                "request_timeout_ms": 3000,
                "max_clock_skew_s": 300,
                "refresh_enabled": True,
                "refresh_interval_s": 60,
            },
        )

        try:
            await runtime._refresh_remote_device_policy_once(
                config=cfg,
                dispatcher=dispatcher,
                suppress_transient_audit=True,
            )
            await runtime._refresh_remote_device_policy_once(
                config=cfg,
                dispatcher=dispatcher,
                suppress_transient_audit=True,
            )
            row = await runtime._state_store._run_read(
                lambda conn: conn.execute(
                    """
                    SELECT COUNT(*) AS c
                    FROM override_log
                    WHERE override_type='policy_rejection'
                    """
                ).fetchone()
            )
            assert row is not None
            assert int(row["c"]) == 1
        finally:
            await runtime._state_store.close()

    async def test_alert_delivery_loop_delivers_queued_alert(self, tmp_path):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._state_store = StateStore(str(tmp_path / "outbox-deliver.db"))
        await runtime._state_store.open()
        runtime._alert_outbox_retry_interval_s = 0.01

        await runtime._state_store.enqueue_alert(
            alert_id="deliver-1",
            channel="sms",
            recipient="+2340000000000",
            message="msg",
            action_tier="A",
            trigger_name="high_draw",
            original_ts=1234,
        )

        async def _send_and_stop(
            *, message: str, to_number: str, preferred_channel: str | None = None
        ) -> bool:
            runtime._shutdown_event.set()
            return True

        alert_sender = AsyncMock()
        alert_sender.send.side_effect = _send_and_stop

        try:
            await runtime._alert_delivery_loop(alert_sender)
            remaining = await runtime._state_store.get_retryable_alerts(limit=10)
            assert remaining == []
        finally:
            await runtime._state_store.close()

    async def test_alert_delivery_loop_tier_d_never_abandons(self, tmp_path):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._state_store = StateStore(str(tmp_path / "outbox-tierd.db"))
        await runtime._state_store.open()
        runtime._alert_outbox_retry_interval_s = 0.01

        await runtime._state_store.enqueue_alert(
            alert_id="tierd-1",
            channel="sms",
            recipient="+2340000000000",
            message="msg",
            action_tier="D",
            trigger_name="critical",
            original_ts=1234,
        )
        await runtime._state_store.mark_alert_attempt_failed("tierd-1")
        await runtime._state_store.mark_alert_attempt_failed("tierd-1")

        async def _fail_and_stop(
            *, message: str, to_number: str, preferred_channel: str | None = None
        ) -> bool:
            runtime._shutdown_event.set()
            return False

        alert_sender = AsyncMock()
        alert_sender.send.side_effect = _fail_and_stop

        try:
            await runtime._alert_delivery_loop(alert_sender)
            rows = await runtime._state_store.get_retryable_alerts(limit=10)
            assert len(rows) == 1
            assert rows[0]["status"] == "failed"
            assert rows[0]["attempt_count"] == 3
        finally:
            await runtime._state_store.close()

    async def test_alert_delivery_loop_abandons_non_tier_d_at_threshold(self, tmp_path):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._state_store = StateStore(str(tmp_path / "outbox-abandon.db"))
        await runtime._state_store.open()
        runtime._alert_outbox_retry_interval_s = 0.01

        await runtime._state_store.enqueue_alert(
            alert_id="aband-1",
            channel="sms",
            recipient="+2340000000000",
            message="msg",
            action_tier="A",
            trigger_name="high_draw",
            original_ts=1234,
        )
        for _ in range(9):
            await runtime._state_store.mark_alert_attempt_failed("aband-1")

        async def _fail_and_stop(
            *, message: str, to_number: str, preferred_channel: str | None = None
        ) -> bool:
            runtime._shutdown_event.set()
            return False

        alert_sender = AsyncMock()
        alert_sender.send.side_effect = _fail_and_stop

        try:
            await runtime._alert_delivery_loop(alert_sender)
            retryable = await runtime._state_store.get_retryable_alerts(limit=10)
            assert retryable == []

            row = await runtime._state_store._run_read(
                lambda conn: conn.execute(
                    """
                    SELECT status, attempt_count
                    FROM alert_outbox
                    WHERE alert_id = ?
                    """,
                    ("aband-1",),
                ).fetchone()
            )
            assert row["status"] == "abandoned"
            assert row["attempt_count"] == 10
        finally:
            await runtime._state_store.close()


async def _until_started(runtime: OriRuntime, timeout_s: float = 30.0) -> None:
    """Wait for start() to have built the action path and the evidence stack.

    A fixed sleep raced start() on a loaded, coverage-instrumented CI runner.
    """
    deadline = asyncio.get_running_loop().time() + timeout_s
    while runtime._dispatcher is None or runtime._evidence_attestor is None:
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("the runtime did not come up in time")
        await asyncio.sleep(0.05)


class TestEvidencePostureNeverGatesStartup:
    """Tier D is never gated on evidence, not by availability and not by trust.

    A hardened runtime whose release ships no authority-key registry cannot
    establish evidence trust. It must still start, still hold its dispatcher,
    and say so in health — never construct a trust claim it cannot back, and
    never withhold the deterministic safety path because the record is at
    risk.
    """

    @pytest.mark.parametrize("profile", ["production", "development"])
    async def test_a_runtime_without_evidence_trust_still_starts_and_reports_it(
        self, minimal_config, monkeypatch, tmp_path, profile
    ):
        _patch_external(monkeypatch)
        _treat_scratch_skills_as_packaged(monkeypatch)
        monkeypatch.setenv("ORI_EVIDENCE_DEVICE_SECRET", "install-secret-for-test")
        config = Config.load(str(minimal_config))
        config.device.deployment_profile = profile
        config.reasoning.default_tier = "rule"
        config.reasoning.local_model = ""
        config.reasoning.model_path = ""
        config.evidence.enabled = True
        config.evidence.db_path = str(tmp_path / "evidence.db")
        config.evidence.key_path = str(tmp_path / "evidence.key")
        monkeypatch.setattr("ori.runtime.Config.load", lambda _path: config)
        # The release under test ships no authority-key registry.
        monkeypatch.setattr("ori.runtime._load_authority_keys", lambda: {})
        runtime = OriRuntime(config_path=str(minimal_config))
        observed: dict[str, Any] = {}

        async def _observe_then_stop():
            await _until_started(runtime)
            observed["dispatcher"] = runtime._dispatcher
            attestor = runtime._evidence_attestor
            observed["signing_available"] = attestor is not None and attestor.available
            observed["health"] = await runtime._build_health_snapshot()
            await runtime.stop()

        await asyncio.gather(runtime.start(), _observe_then_stop())

        assert observed["dispatcher"] is not None, "the action path did not come up"
        assert observed["signing_available"], (
            "signing is local and must be available even when trust is not"
        )
        health = observed["health"]
        assert health["evidence"]["available"] is True
        assert health["evidence"]["posture_problems"] == ["authority_keys_missing"]
        assert health["status"] == "degraded"
        assert health.get("critical") is not True

    async def test_a_runtime_with_evidence_trust_reports_no_posture_problems(
        self, minimal_config, monkeypatch, tmp_path
    ):
        _patch_external(monkeypatch)
        _treat_scratch_skills_as_packaged(monkeypatch)
        monkeypatch.setenv("ORI_EVIDENCE_DEVICE_SECRET", "install-secret-for-test")
        config = Config.load(str(minimal_config))
        config.device.deployment_profile = "production"
        config.reasoning.default_tier = "rule"
        config.reasoning.local_model = ""
        config.reasoning.model_path = ""
        config.evidence.enabled = True
        config.evidence.db_path = str(tmp_path / "evidence.db")
        config.evidence.key_path = str(tmp_path / "evidence.key")
        monkeypatch.setattr("ori.runtime.Config.load", lambda _path: config)
        monkeypatch.setattr(
            "ori.runtime._load_authority_keys",
            lambda: {("evidence_authority_receipt", "auth-receipt-1"): object()},
        )
        runtime = OriRuntime(config_path=str(minimal_config))
        observed: dict[str, Any] = {}

        async def _observe_then_stop():
            await _until_started(runtime)
            observed["health"] = await runtime._build_health_snapshot()
            await runtime.stop()

        await asyncio.gather(runtime.start(), _observe_then_stop())
        assert observed["health"]["evidence"]["posture_problems"] == []
        assert observed["health"].get("status") != "degraded"
