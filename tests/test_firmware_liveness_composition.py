# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Runtime composition for firmware liveness.

The supervisor is only useful if the telemetry subscriber and the command
service hold the SAME instance. Two instances leave the service refusing
forever while the subscriber records into a map nobody reads — production
behaviour identical to the feature being absent, with every unit test
still green.

That is not a hypothetical. An earlier revision wired the hook inside the
subscriber and the signer inside the service, and connected neither at the
composition root. Unit tests passed because they called ``note_telemetry``
by hand. These tests go through the real builders instead.
"""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import pytest

from ori.gateway.firmware_commands import (
    FirmwareCommandService,
    MqttFirmwareCommandPublisher,
)
from ori.gateway.firmware_telemetry import MqttFirmwareTelemetrySubscriber
from ori.runtime import (
    _build_firmware_command_service,
    _build_firmware_liveness_stack,
    _build_firmware_telemetry_subscriber,
)
from ori.security.firmware_ingest import FirmwareTelemetryGate
from ori.security.firmware_liveness import (
    FirmwareLivenessError,
    FirmwareLivenessSigner,
    FirmwareLivenessSupervisor,
)
from ori.state.store import StateStore

VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "firmware_layer1_vectors.json").read_text()
)
CASES = {case["name"]: case for case in VECTORS["cases"]}
PUBLIC_KEY_B64 = VECTORS["public_key_b64"]
SEALED_DEVICE = "ori-fw-7c9f2b3a"
SEALED_HASH = "sha256:" + CASES["manifest_full_sealed"]["canonical_sha256_hex"]


def _telemetry_message(case_name: str) -> dict:
    case = CASES[case_name]
    return {
        "envelope": copy.deepcopy(case["input"]),
        "signature": "ed25519:" + case["signature_b64"],
    }


def _manifest_message(case_name: str) -> dict:
    case = CASES[case_name]
    return {
        "manifest": copy.deepcopy(case["input"]),
        "manifest_hash": "sha256:" + case["canonical_sha256_hex"],
        "signature": "ed25519:" + case["signature_b64"],
    }


class _FakeBus:
    """Minimal EventBus surface the subscriber touches."""

    def __init__(self) -> None:
        self.published: list = []

    async def publish(self, event) -> None:
        self.published.append(event)


async def _provision(store) -> None:
    """Register AND approve. Without the approval every message is
    rejected as ``device_not_approved``, which would make the
    tampered-signature test below pass for the wrong reason."""
    gate = FirmwareTelemetryGate(store)
    manifest = CASES["manifest_full_sealed"]["input"]
    await gate.register_device(
        device_id=manifest["device_id"],
        public_key_b64=PUBLIC_KEY_B64,
        posture=manifest["posture"],
        manifest_message=_manifest_message("manifest_full_sealed"),
    )
    assert await gate.approve_device(
        manifest["device_id"], actor="test-operator", reason="composition test"
    )


class _Cfg:
    """Minimal config shape the two builders read.

    Built fresh per instance: the command builder needs
    ``firmware_commands`` enabled and the subscriber tests need it off, and
    shared class-level dicts would let one test's config leak into another.
    """

    class _Gateway:
        def __init__(self, commands: dict) -> None:
            self.enabled = True
            self.broker_url = "mqtt://localhost"
            self.tls: dict = {}
            self.firmware_telemetry = {
                "enabled": True,
                "topic": "ori/fw/+/telemetry",
                "qos": 1,
            }
            self.firmware_commands = commands

    class _Device:
        id = "runtime-01"

    def __init__(self, commands: dict | None = None) -> None:
        self.gateway = _Cfg._Gateway(commands or {})
        self.device = _Cfg._Device()


RUNTIME_KEY_ENV = "ORI_TEST_RUNTIME_COMMAND_SEED"
PROVISIONER_KEY_ENV = "ORI_TEST_PROVISIONER_SEED"


def _command_cfg() -> _Cfg:
    return _Cfg(
        {
            "enabled": True,
            "runtime_command_key_env": RUNTIME_KEY_ENV,
            "provisioner_key_env": PROVISIONER_KEY_ENV,
        }
    )


@pytest.fixture
def command_keys(monkeypatch):
    """Seeds for the command builder, which loads them from the
    environment rather than taking them as arguments."""
    monkeypatch.setenv(
        RUNTIME_KEY_ENV, base64.b64encode(bytes(range(32))).decode("ascii")
    )
    monkeypatch.setenv(
        PROVISIONER_KEY_ENV, base64.b64encode(bytes(range(32, 64))).decode("ascii")
    )


@pytest.fixture
async def store(tmp_path):
    s = StateStore(db_path=str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


def test_builder_passes_the_supervisor_through_to_the_subscriber(store) -> None:
    """Object identity, not merely 'a supervisor exists'."""
    shared = FirmwareLivenessSupervisor()
    subscriber = _build_firmware_telemetry_subscriber(
        _Cfg(), _FakeBus(), store, None, shared
    )
    assert subscriber is not None
    assert subscriber._liveness_supervisor is shared


@pytest.mark.asyncio
async def test_accepted_telemetry_through_the_subscriber_enables_signing(
    store, tmp_path
) -> None:
    """The end-to-end property the composition exists for: telemetry
    arriving on the subscriber makes the service able to sign."""
    shared = FirmwareLivenessSupervisor()
    subscriber = _build_firmware_telemetry_subscriber(
        _Cfg(), _FakeBus(), store, None, shared
    )
    assert subscriber is not None

    await _provision(store)

    # Before any telemetry, nothing is supervised.
    assert shared.supervised_devices() == ()

    await subscriber._ingest_telemetry(_telemetry_message("telemetry_single_reading"))

    supervised = shared.supervised_devices()
    assert [d.device_id for d in supervised] == [SEALED_DEVICE]
    assert supervised[0].capability_hash == SEALED_HASH
    assert supervised[0].boot_id > 0


@pytest.mark.asyncio
async def test_rejected_telemetry_does_not_establish_supervision(store) -> None:
    """An unauthenticated publisher must not be able to keep a device's
    backstop suppressed by asserting supervision no runtime provides."""
    shared = FirmwareLivenessSupervisor()
    subscriber = _build_firmware_telemetry_subscriber(
        _Cfg(), _FakeBus(), store, None, shared
    )
    assert subscriber is not None
    # Provision first: otherwise this passes because the device is
    # unapproved, not because the signature is bad.
    await _provision(store)

    tampered = _telemetry_message("telemetry_single_reading")
    tampered["signature"] = "ed25519:" + "A" * 86 + "=="

    await subscriber._ingest_telemetry(tampered)
    assert shared.supervised_devices() == ()


class _FakeInfo:
    rc = 0

    def wait_for_publish(self, timeout):
        return True


class _FakeClient:
    """Records what reached the wire, so publish/no-publish is asserted on
    the broker call rather than on the absence of an exception."""

    def __init__(self):
        self.published = []

    def username_pw_set(self, *a, **k):
        pass

    def tls_set_context(self, *a, **k):
        pass

    def connect(self, *a, **k):
        pass

    def loop_start(self):
        pass

    def loop_stop(self):
        pass

    def disconnect(self):
        pass

    def publish(self, topic, payload, qos, retain):
        self.published.append((topic, qos, retain))
        return _FakeInfo()


def test_composition_root_gives_both_halves_one_supervisor(store, command_keys) -> None:
    """The composition root itself, not the builders under it.

    Asserting only that each builder passes its argument through left the
    root free to call them with two different supervisors — which is
    exactly the defect that shipped. This is the assertion that fails if
    ``start`` ever composes them apart.
    """
    cfg = _command_cfg()
    supervisor, subscriber, pair = _build_firmware_liveness_stack(
        cfg, _FakeBus(), store, None
    )
    assert subscriber is not None and pair is not None
    _, service = pair

    assert subscriber._liveness_supervisor is supervisor
    assert service.liveness_supervisor is supervisor
    assert subscriber._liveness_supervisor is service.liveness_supervisor


def test_both_builders_receive_the_same_supervisor(store, command_keys) -> None:
    """The composition property, asserted across BOTH builders.

    Asserting it on the telemetry builder alone left the command half
    unproven: because the service used to default to a private supervisor,
    dropping its injection changed nothing any test could see. The
    constructor is now required, but this still pins the wiring.
    """
    shared = FirmwareLivenessSupervisor()
    subscriber = _build_firmware_telemetry_subscriber(
        _Cfg(), _FakeBus(), store, None, shared
    )
    pair = _build_firmware_command_service(_command_cfg(), store, shared)
    assert subscriber is not None and pair is not None
    _, service = pair

    assert subscriber._liveness_supervisor is shared
    assert service.liveness_supervisor is shared
    assert subscriber._liveness_supervisor is service.liveness_supervisor


@pytest.mark.asyncio
async def test_service_signs_only_after_the_shared_supervisor_is_populated(
    store, command_keys, monkeypatch
) -> None:
    """Ties both halves together through the real builders: the service
    refuses, telemetry arrives on the subscriber, the service then signs."""
    fake = _FakeClient()
    # Patched before the builder runs: the builder owns publisher
    # construction, and the point of this test is that nothing between the
    # two builders is hand-assembled.
    monkeypatch.setattr(
        "ori.gateway.firmware_commands._default_client_factory",
        lambda **_: fake,
    )

    shared = FirmwareLivenessSupervisor()
    subscriber = _build_firmware_telemetry_subscriber(
        _Cfg(), _FakeBus(), store, None, shared
    )
    pair = _build_firmware_command_service(_command_cfg(), store, shared)
    assert subscriber is not None and pair is not None
    publisher, service = pair
    await publisher.connect()

    assert subscriber._liveness_supervisor is service.liveness_supervisor

    await _provision(store)

    # Before telemetry: refuses, publishes nothing.
    with pytest.raises(FirmwareLivenessError, match="not supervised"):
        await service.publish_runtime_liveness(
            device_id=SEALED_DEVICE, boot_id=41, capability_hash=SEALED_HASH
        )
    assert fake.published == []

    # Telemetry arrives on the subscriber; the service can now sign.
    await subscriber._ingest_telemetry(_telemetry_message("telemetry_single_reading"))
    device = shared.supervised_devices()[0]
    message = await service.publish_runtime_liveness(
        device_id=device.device_id,
        boot_id=device.boot_id,
        capability_hash=device.capability_hash,
    )
    assert b'"liveness"' in message
    assert fake.published == [(f"ori/fw/{SEALED_DEVICE}/runtime", 1, False)]

    await publisher.close()


# --- The dependency is structural, not merely conventional ---------------
#
# Every constructor on this path used to accept the supervisor as optional
# and quietly build its own on omission. That is the failure these tests
# exist for: a private supervisor is fed by nothing, so the service refuses
# every device forever and the subscriber records into a map nobody reads.
# Production looks like a quiet fleet, and no unit test can tell. Refusing
# at construction is what makes the mistake unrepeatable.


def test_command_service_cannot_be_built_without_a_supervisor(store) -> None:
    publisher = MqttFirmwareCommandPublisher(
        broker_url="mqtt://localhost",
        runtime_device_id="runtime-01",
        client_factory=lambda **_: _FakeClient(),
    )
    with pytest.raises(TypeError, match="liveness_supervisor"):
        FirmwareCommandService(
            store=store,
            publisher=publisher,
            runtime_command_key_bytes=bytes(range(32)),
            provisioner_key_bytes=bytes(range(32, 64)),
        )


def test_telemetry_subscriber_cannot_be_built_without_a_supervisor(store) -> None:
    with pytest.raises(TypeError, match="liveness_supervisor"):
        MqttFirmwareTelemetrySubscriber(
            broker_url="mqtt://localhost",
            telemetry_gate=FirmwareTelemetryGate(store),
            event_bus=_FakeBus(),
            state_store=store,
            runtime_device_id="runtime-01",
        )


def test_telemetry_subscriber_rejects_a_wrongly_typed_supervisor(store) -> None:
    """``Any`` accepted anything and failed at the first accepted reading —
    long after the wiring mistake, and only in production."""
    with pytest.raises(TypeError, match="FirmwareLivenessSupervisor"):
        MqttFirmwareTelemetrySubscriber(
            broker_url="mqtt://localhost",
            telemetry_gate=FirmwareTelemetryGate(store),
            event_bus=_FakeBus(),
            state_store=store,
            runtime_device_id="runtime-01",
            liveness_supervisor=object(),  # type: ignore[arg-type]
        )


def test_signer_cannot_be_built_without_a_supervisor(store) -> None:
    """The third instance of the same defaulting pattern, one layer below
    the two the review named. Left alone it would have re-created the
    private-instance hazard inside any future direct signer caller."""
    with pytest.raises(TypeError, match="supervisor"):
        FirmwareLivenessSigner(store, bytes(range(32)))

    with pytest.raises(FirmwareLivenessError, match="supervisor must be"):
        FirmwareLivenessSigner(
            store,
            bytes(range(32)),
            supervisor=object(),  # type: ignore[arg-type]
        )
