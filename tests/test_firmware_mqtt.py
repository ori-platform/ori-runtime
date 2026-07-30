# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import json
from types import SimpleNamespace

import pytest

import ori.gateway.firmware_telemetry as firmware_mqtt_module
from ori.network.event_bus import EventBus
from ori.network.events import SensorReading
from ori.security.firmware_liveness import FirmwareLivenessSupervisor


class _FakeVerification:
    """Mirrors the fields of the real ``TelemetryVerification`` that the
    subscriber reads. Carrying only ``accepted`` was enough while the
    supervision hook was skippable; it is not a shape the gate ever
    returns, and a fake that under-describes its subject stops proving
    anything about the caller.
    """

    def __init__(self, accepted: bool = True) -> None:
        self.accepted = accepted
        self.device_id = "ori-fw-7c9f2b3a"
        self.boot_id = 41
        self.capability_hash = "sha256:" + "a" * 64


class _FakeFirmwareGate:
    def __init__(self) -> None:
        self.telemetry_payloads: list[dict] = []
        self.fault_payloads: list[dict] = []

    async def ingest(self, payload: dict):
        self.telemetry_payloads.append(payload)
        return _FakeVerification(), [
            SensorReading(
                sensor_id="ori-fw-7c9f2b3a:ch0",
                sensor_type="current",
                value=8.21,
                unit="ampere",
                timestamp=1_752_537_600_000,
                quality=0.95,
                metadata={
                    "source": "firmware",
                    "attestation": "attested",
                    "firmware_device_id": "ori-fw-7c9f2b3a",
                },
            )
        ]

    async def ingest_fault(self, payload: dict):
        self.fault_payloads.append(payload)
        return _FakeVerification()


class _FakeStore:
    def __init__(self) -> None:
        self.history = []

    async def append_history(self, event):
        self.history.append(event)


class _FakeClient:
    def __init__(self, payloads: list[dict] | None = None) -> None:
        self.payloads = payloads or []
        self.on_connect = None
        self.on_message = None
        self.subscribed: list[tuple[str, int]] = []
        self.connected: tuple | None = None
        self.loop_started = False
        self.loop_stopped = False
        self.disconnected = False

    def username_pw_set(self, username, password):
        pass

    def tls_set_context(self, context):
        pass

    def connect(self, host, port, keepalive):
        self.connected = (host, port, keepalive)
        if self.on_connect is not None:
            self.on_connect(self, None, None, 0)

    def subscribe(self, topic, qos=0):
        self.subscribed.append((topic, qos))

    def loop_start(self):
        self.loop_started = True
        if self.on_message is not None:
            for payload in self.payloads:
                self.on_message(
                    self,
                    None,
                    SimpleNamespace(payload=json.dumps(payload).encode()),
                )

    def loop_stop(self):
        self.loop_stopped = True

    def disconnect(self):
        self.disconnected = True


def _subscriber(*, payloads: list[dict] | None = None, gate=None, store=None, bus=None):
    fake_client = _FakeClient(payloads)
    return (
        firmware_mqtt_module.MqttFirmwareTelemetrySubscriber(
            broker_url="mqtt://localhost",
            telemetry_gate=gate or _FakeFirmwareGate(),
            event_bus=bus or EventBus(),
            state_store=store or _FakeStore(),
            runtime_device_id="runtime-01",
            liveness_supervisor=FirmwareLivenessSupervisor(),
            client_factory=lambda **_: fake_client,
        ),
        fake_client,
    )


async def test_serve_until_subscribes_to_firmware_topic():
    sub, fake = _subscriber()
    shutdown = asyncio.Event()

    async def _stop():
        await asyncio.sleep(0)
        shutdown.set()

    await asyncio.gather(sub.serve_until(shutdown), _stop())

    assert fake.connected == ("localhost", 1883, 60)
    assert fake.subscribed == [(firmware_mqtt_module.FIRMWARE_TELEMETRY_TOPIC, 1)]
    assert fake.loop_started is True
    assert fake.loop_stopped is True
    assert fake.disconnected is True


async def test_signed_telemetry_payload_publishes_accepted_readings_to_event_bus():
    gate = _FakeFirmwareGate()
    store = _FakeStore()
    bus = EventBus()
    delivered = []

    async def _handler(event):
        delivered.append(event)

    bus.subscribe("current", _handler)
    sub, _fake = _subscriber(
        payloads=[{"envelope": {"device_id": "ori-fw-7c9f2b3a"}, "signature": "x"}],
        gate=gate,
        store=store,
        bus=bus,
    )
    shutdown = asyncio.Event()

    async def _stop():
        await asyncio.sleep(0.01)
        shutdown.set()

    await asyncio.gather(sub.serve_until(shutdown), _stop())

    assert len(gate.telemetry_payloads) == 1
    assert len(store.history) == 1
    assert len(delivered) == 1
    event = delivered[0]
    assert event.device_id == "runtime-01"
    assert event.event_type == "sensor.current"
    assert event.source == "firmware"
    assert event.reading.metadata["attestation"] == "attested"


async def test_signed_fault_payload_is_recorded_without_event_bus_publish():
    gate = _FakeFirmwareGate()
    store = _FakeStore()
    bus = EventBus(strict_exceptions=True)
    delivered = []

    async def _handler(event):
        delivered.append(event)

    bus.subscribe("*", _handler)
    sub, _fake = _subscriber(
        payloads=[{"fault": {"device_id": "ori-fw-7c9f2b3a"}, "signature": "x"}],
        gate=gate,
        store=store,
        bus=bus,
    )
    shutdown = asyncio.Event()

    async def _stop():
        await asyncio.sleep(0.01)
        shutdown.set()

    await asyncio.gather(sub.serve_until(shutdown), _stop())

    assert len(gate.fault_payloads) == 1
    assert store.history == []
    assert delivered == []


def test_paho_unavailable_raises():
    with pytest.raises(RuntimeError, match="paho-mqtt is not installed"):
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(firmware_mqtt_module, "_PAHO_AVAILABLE", False)
            firmware_mqtt_module.MqttFirmwareTelemetrySubscriber(
                broker_url="mqtt://localhost",
                telemetry_gate=_FakeFirmwareGate(),
                event_bus=EventBus(),
                state_store=_FakeStore(),
                runtime_device_id="runtime-01",
                liveness_supervisor=FirmwareLivenessSupervisor(),
            )
