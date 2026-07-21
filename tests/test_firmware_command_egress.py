# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ori.gateway.firmware_commands import (
    FirmwareCommandPublishError,
    FirmwareCommandService,
    MqttFirmwareCommandPublisher,
)
from ori.security.firmware_commands import (
    FirmwareCommandError,
    FirmwareCommandSigner,
    build_provisioning_approval_bytes,
)
from ori.security.firmware_ingest import FirmwareTelemetryGate
from ori.state.store import StateStore

COMMAND_VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "firmware_command_vectors.json").read_text()
)
RUNTIME_SEED = bytes.fromhex(COMMAND_VECTORS["runtime_test_seed_hex"])
PROVISIONER_SEED = bytes([0x22]) * 32
PROVISIONER_PUBLIC = Ed25519PrivateKey.from_private_bytes(PROVISIONER_SEED).public_key()

APPROVAL_VECTORS = json.loads(
    (
        Path(__file__).parent
        / "fixtures"
        / "firmware_provisioning_approval_vectors.json"
    ).read_text()
)

TELEMETRY_VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "firmware_layer1_vectors.json").read_text()
)
MANIFEST_CASES = {
    c["name"]: c for c in TELEMETRY_VECTORS["cases"] if c["kind"] == "manifest"
}


@pytest.fixture
async def store(tmp_path):
    s = StateStore(db_path=str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


def _manifest_message(case_name: str) -> dict:
    case = MANIFEST_CASES[case_name]
    return {
        "manifest": case["input"],
        "manifest_hash": "sha256:" + case["canonical_sha256_hex"],
        "signature": "ed25519:" + case["signature_b64"],
    }


async def _register_device(store: StateStore, *, approve: bool = True) -> str:
    gate = FirmwareTelemetryGate(store)
    manifest = MANIFEST_CASES["manifest_full_sealed"]["input"]
    await gate.register_device(
        device_id=manifest["device_id"],
        public_key_b64=TELEMETRY_VECTORS["public_key_b64"],
        posture=manifest["posture"],
        manifest_message=_manifest_message("manifest_full_sealed"),
    )
    if approve:
        assert await gate.approve_device(
            manifest["device_id"], actor="test-operator", reason="test"
        )
    return manifest["device_id"]


def _runtime_public_b64() -> str:
    signer = FirmwareCommandSigner(store=None, private_key_bytes=RUNTIME_SEED)
    return base64.b64encode(signer.public_key_bytes()).decode("ascii")


def _extract_signed_approval(message: bytes) -> tuple[bytes, bytes]:
    marker = b',"signature":"ed25519:'
    assert message.startswith(b'{"approval":')
    approval = message[len(b'{"approval":') : message.index(marker)]
    signature_b64 = message[message.index(marker) + len(marker) : -len(b'"}')].decode(
        "ascii"
    )
    return approval, base64.b64decode(signature_b64, validate=True)


def test_provisioning_approval_message_uses_fixed_grammar_and_signature() -> None:
    manifest = MANIFEST_CASES["manifest_full_sealed"]["input"]
    message = build_provisioning_approval_bytes(
        capability_hash="sha256:"
        + MANIFEST_CASES["manifest_full_sealed"]["canonical_sha256_hex"],
        device_id=manifest["device_id"],
        posture=manifest["posture"],
        public_key_b64=TELEMETRY_VECTORS["public_key_b64"],
        runtime_public_key_b64=_runtime_public_b64(),
        provisioner_private_key_bytes=PROVISIONER_SEED,
    )

    assert message.startswith(b'{"approval":{"capability_hash":"sha256:')
    assert b'","device_id":"ori-fw-7c9f2b3a","posture":"sealed_flash",' in message
    assert b',"public_key_b64":"' in message
    assert b',"runtime_public_key_b64":"' in message
    assert message.endswith(b'"}')

    approval, signature = _extract_signed_approval(message)
    PROVISIONER_PUBLIC.verify(signature, approval)
    decoded = json.loads(message)
    assert decoded["approval"]["runtime_public_key_b64"] == _runtime_public_b64()


@pytest.mark.parametrize(
    "case", APPROVAL_VECTORS["cases"], ids=lambda case: case["name"]
)
def test_provisioning_approval_reproduces_shared_golden_vectors(case: dict) -> None:
    """Python signer and C verifier agree on the entire retained wire message."""
    assert RUNTIME_SEED.hex() == APPROVAL_VECTORS["runtime_command_test_seed_hex"]
    assert (
        PROVISIONER_PUBLIC.public_bytes_raw().hex()
        == APPROVAL_VECTORS["provisioner_public_key_hex"]
    )
    values = case["input"]
    message = build_provisioning_approval_bytes(
        capability_hash=values["capability_hash"],
        device_id=values["device_id"],
        posture=values["posture"],
        public_key_b64=values["public_key_b64"],
        runtime_public_key_b64=values["runtime_public_key_b64"],
        provisioner_private_key_bytes=PROVISIONER_SEED,
    )
    assert message.hex() == case["message_hex"]


def test_provisioning_approval_rejects_noncanonical_inputs() -> None:
    good = dict(
        capability_hash="sha256:" + "ab" * 32,
        device_id="ori-fw-7c9f2b3a",
        posture="sealed_flash",
        public_key_b64=base64.b64encode(bytes([0x01]) * 32).decode("ascii"),
        runtime_public_key_b64=_runtime_public_b64(),
        provisioner_private_key_bytes=PROVISIONER_SEED,
    )
    build_provisioning_approval_bytes(**good)

    for bad in (
        {"posture": "sealed"},
        {"public_key_b64": base64.b64encode(b"short").decode("ascii")},
        {"runtime_public_key_b64": _runtime_public_b64().rstrip("=")},
        {"provisioner_private_key_bytes": b"short"},
    ):
        with pytest.raises(FirmwareCommandError):
            build_provisioning_approval_bytes(**{**good, **bad})


class _FakePublishInfo:
    rc = 0

    def __init__(self) -> None:
        self.waited: float | None = None

    def wait_for_publish(self, timeout: float) -> bool:
        self.waited = timeout
        return True


class _FakeClient:
    def __init__(self) -> None:
        self.connected: tuple | None = None
        self.loop_started = False
        self.loop_stopped = False
        self.disconnected = False
        self.published: list[dict] = []

    def username_pw_set(self, username, password):
        pass

    def tls_set_context(self, context):
        pass

    def connect(self, host, port, keepalive):
        self.connected = (host, port, keepalive)

    def loop_start(self):
        self.loop_started = True

    def loop_stop(self):
        self.loop_stopped = True

    def disconnect(self):
        self.disconnected = True

    def publish(self, topic, payload, qos, retain):
        info = _FakePublishInfo()
        self.published.append(
            {
                "topic": topic,
                "payload": payload,
                "qos": qos,
                "retain": retain,
                "info": info,
            }
        )
        return info


async def test_mqtt_publisher_uses_retained_provision_and_nonretained_command() -> None:
    fake = _FakeClient()
    publisher = MqttFirmwareCommandPublisher(
        broker_url="mqtt://localhost",
        runtime_device_id="runtime-01",
        client_factory=lambda **_: fake,
    )

    await publisher.connect()
    await publisher.publish_provisioning_approval("ori-fw-7c9f2b3a", b"approval")
    await publisher.publish_command("ori-fw-7c9f2b3a", b"command")
    await publisher.close()

    assert fake.connected == ("localhost", 1883, 60)
    assert fake.published[0] == {
        "topic": "ori/fw/ori-fw-7c9f2b3a/provision",
        "payload": b"approval",
        "qos": 1,
        "retain": True,
        "info": fake.published[0]["info"],
    }
    assert fake.published[1] == {
        "topic": "ori/fw/ori-fw-7c9f2b3a/cmd",
        "payload": b"command",
        "qos": 1,
        "retain": False,
        "info": fake.published[1]["info"],
    }
    assert fake.loop_started is True
    assert fake.loop_stopped is True
    assert fake.disconnected is True


async def test_mqtt_publisher_refuses_bad_topic_or_unconnected_publish() -> None:
    publisher = MqttFirmwareCommandPublisher(
        broker_url="mqtt://localhost",
        runtime_device_id="runtime-01",
        client_factory=lambda **_: _FakeClient(),
    )
    with pytest.raises(FirmwareCommandPublishError, match="not connected"):
        await publisher.publish_command("ori-fw-7c9f2b3a", b"command")

    await publisher.connect()
    with pytest.raises(FirmwareCommandPublishError, match="device_id"):
        await publisher.publish_command("bad/device", b"command")
    await publisher.close()


class _FakePublisher:
    def __init__(self) -> None:
        self.approvals: list[tuple[str, bytes]] = []
        self.commands: list[tuple[str, bytes]] = []

    async def publish_provisioning_approval(
        self, device_id: str, message: bytes
    ) -> None:
        self.approvals.append((device_id, message))

    async def publish_command(self, device_id: str, message: bytes) -> None:
        self.commands.append((device_id, message))


async def test_service_publishes_approval_from_registry_anchor(store) -> None:
    device_id = await _register_device(store)
    fake = _FakePublisher()
    service = FirmwareCommandService(
        store=store,
        publisher=fake,  # type: ignore[arg-type]
        runtime_command_key_bytes=RUNTIME_SEED,
        provisioner_key_bytes=PROVISIONER_SEED,
    )

    message = await service.publish_provisioning_approval(device_id)

    assert fake.approvals == [(device_id, message)]
    approval, signature = _extract_signed_approval(message)
    PROVISIONER_PUBLIC.verify(signature, approval)
    decoded = json.loads(message)
    row = await store.get_firmware_device(device_id)
    assert decoded["approval"] == {
        "capability_hash": row["capability_hash"],
        "device_id": device_id,
        "posture": row["posture"],
        "public_key_b64": row["public_key_b64"],
        "runtime_public_key_b64": _runtime_public_b64(),
        "v": 1,
    }


async def test_service_refuses_approval_for_unapproved_or_revoked_device(store) -> None:
    device_id = await _register_device(store, approve=False)
    service = FirmwareCommandService(
        store=store,
        publisher=_FakePublisher(),  # type: ignore[arg-type]
        runtime_command_key_bytes=RUNTIME_SEED,
        provisioner_key_bytes=PROVISIONER_SEED,
    )

    with pytest.raises(FirmwareCommandError, match="not approved"):
        await service.publish_provisioning_approval(device_id)

    assert await store.approve_firmware_device(
        device_id, actor="test-operator", reason="test"
    )
    assert await store.revoke_firmware_device(
        device_id, actor="test-operator", reason="test"
    )
    with pytest.raises(FirmwareCommandError, match="revoked"):
        await service.publish_provisioning_approval(device_id)


async def test_service_publishes_signed_command_without_retaining(store) -> None:
    device_id = await _register_device(store)
    fake = _FakePublisher()
    service = FirmwareCommandService(
        store=store,
        publisher=fake,  # type: ignore[arg-type]
        runtime_command_key_bytes=RUNTIME_SEED,
        provisioner_key_bytes=PROVISIONER_SEED,
    )

    message = await service.publish_command(
        device_id=device_id,
        action="relay_open",
        channel="relay0",
    )

    assert fake.commands == [(device_id, message)]
    assert b'"cmd_seq":1,' in message
    assert b'"capability_hash":"sha256:' in message
