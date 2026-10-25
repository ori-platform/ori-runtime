# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""runtime-health/v4 `firmware_liveness.undeclared_device_ids` and `mqtt_ingress`.

Driven through the real snapshot builder over a real store, a real command
service and liveness scheduler, and real gateway routes.
"""

from __future__ import annotations

import ast
import asyncio
import json
import textwrap
import time
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from ori.config import Config
from ori.gateway.firmware_liveness_publisher import FirmwareLivenessScheduler
from ori.gateway.heartbeat import MqttGatewayHeartbeatSubscriber
from ori.gateway.payload_bounds import (
    EXPORT_REQUEST,
    GATEWAY_HEALTH,
    IN_FLIGHT_EXCEEDED,
    PAYLOAD_MAXIMA,
    RATE_EXCEEDED,
    REDELIVERY_DUE,
    IngressBound,
    IngressFamilies,
)
from ori.runtime import OriRuntime
from ori.runtime._health_status import STARTUP_DEADLINE_S, past_startup_deadline
from ori.security.firmware.ingest import FirmwareTelemetryGate
from ori.security.payload_members import DUPLICATE_MEMBER
from ori.security.payload_members import REASONS as MEMBER_REASONS
from ori.state.store import StateStore
from tests.firmware.declaring import declaring_message
from tests.firmware.test_signing_domains import (
    DEVICE,
    SEALED,
    _bare_message,
    _provision,
    _service,
)
from tests.package_layout import runtime_source_paths
from tests.waiting import quiesce, wait_until

ZERO = {"payload_too_large": 0, "volume_dropped": 0, "member_refused": 0}


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[StateStore]:
    s = StateStore(db_path=str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


@pytest.fixture
async def runtime(store: StateStore) -> AsyncIterator[OriRuntime]:
    """A runtime whose liveness scheduler runs over the real command service."""
    scheduler = FirmwareLivenessScheduler(_service(store))
    shutdown = asyncio.Event()
    task = asyncio.create_task(scheduler.serve_until(shutdown))
    await wait_until(lambda: scheduler.health()["running"], what="the liveness loop")
    rt = OriRuntime(config_path="ori.yaml")
    rt._device_id = "dev-01"
    rt._firmware_liveness_scheduler = scheduler
    try:
        yield rt
    finally:
        shutdown.set()
        await asyncio.wait_for(task, timeout=30.0)


# --- Devices that do not declare the signing domains -------------------------


async def test_an_undeclared_device_is_named_from_its_acceptance(
    runtime: OriRuntime, store: StateStore
) -> None:
    before = await runtime._build_health_snapshot()
    assert before["firmware_liveness"]["undeclared_device_ids"] == []
    assert "status" not in before

    await _provision(store, _bare_message())
    snapshot = await runtime._build_health_snapshot()
    liveness = snapshot["firmware_liveness"]
    assert liveness["state"] == "available"
    assert liveness["undeclared_device_ids"] == [DEVICE]
    assert snapshot["status"] == "degraded"
    assert snapshot["critical"] is False
    # Adopted gateway first: no gateway accepts the token yet.
    assert snapshot["degradation_reasons"] == []


async def test_a_declaring_device_is_not_named(
    runtime: OriRuntime, store: StateStore
) -> None:
    await _provision(store, declaring_message(SEALED))
    snapshot = await runtime._build_health_snapshot()
    assert snapshot["firmware_liveness"]["undeclared_device_ids"] == []
    assert "status" not in snapshot


async def test_a_device_leaves_the_set_without_a_restart(
    runtime: OriRuntime, store: StateStore
) -> None:
    await _provision(store, _bare_message())
    assert (await runtime._build_health_snapshot())["status"] == "degraded"
    assert await FirmwareTelemetryGate(store).revoke_device(
        DEVICE, actor="op", reason="gone"
    )
    snapshot = await runtime._build_health_snapshot()
    assert snapshot["firmware_liveness"]["undeclared_device_ids"] == []
    assert "status" not in snapshot


async def test_an_undeclared_device_is_never_supervised_or_expiring(
    runtime: OriRuntime, store: StateStore
) -> None:
    await _provision(store, _bare_message())
    scheduler = runtime._firmware_liveness_scheduler
    assert scheduler is not None
    # A device that was supervised before its manifest lost the domains, with
    # its last publication past the expiry window and no tick since.
    scheduler._last_device_success[DEVICE] = scheduler._clock() - 120.0
    liveness = (await runtime._build_health_snapshot())["firmware_liveness"]
    assert liveness["undeclared_device_ids"] == [DEVICE]
    assert liveness["expiring_device_ids"] == []
    assert liveness["supervised_devices"] == 0
    assert liveness["degraded"] is False


async def test_a_loop_not_yet_started_is_starting_and_degraded(
    store: StateStore,
) -> None:
    await _provision(store, _bare_message())
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._device_id = "dev-01"
    runtime._firmware_liveness_scheduler = FirmwareLivenessScheduler(_service(store))
    snapshot = await runtime._build_health_snapshot()
    liveness = snapshot["firmware_liveness"]
    assert liveness["state"] == "starting"
    assert "undeclared_device_ids" not in liveness
    # Never `ok` for a state not yet observed (runtime-health/v4).
    assert snapshot["status"] == "degraded"
    assert snapshot["critical"] is False


async def test_a_loop_not_started_by_the_deadline_is_unavailable(
    store: StateStore,
) -> None:
    await _provision(store, _bare_message())
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._device_id = "dev-01"
    runtime._firmware_liveness_scheduler = FirmwareLivenessScheduler(_service(store))
    runtime._process_started_monotonic = time.monotonic() - STARTUP_DEADLINE_S
    snapshot = await runtime._build_health_snapshot()
    assert snapshot["firmware_liveness"]["state"] == "unavailable"
    assert "undeclared_device_ids" not in snapshot["firmware_liveness"]
    assert snapshot["status"] == "critical"
    assert snapshot["critical"] is True


def test_the_startup_deadline_is_reached_at_its_value() -> None:
    assert not past_startup_deadline(100.0, 100.0 + STARTUP_DEADLINE_S - 0.001)
    assert past_startup_deadline(100.0, 100.0 + STARTUP_DEADLINE_S)


async def test_unlisted_manifests_are_unavailable_and_critical(
    runtime: OriRuntime, store: StateStore
) -> None:
    await _provision(store, _bare_message())

    async def unreadable() -> list[tuple[str, Any]]:
        raise RuntimeError("store unreadable")

    store.list_firmware_device_manifests = unreadable  # type: ignore[method-assign]
    snapshot = await runtime._build_health_snapshot()
    liveness = snapshot["firmware_liveness"]
    assert liveness["state"] == "unavailable"
    assert "undeclared_device_ids" not in liveness
    assert snapshot["status"] == "critical"
    assert snapshot["critical"] is True


async def test_the_health_export_carries_counts_never_device_ids(
    runtime: OriRuntime, store: StateStore
) -> None:
    await _provision(store, _bare_message())
    scheduler = runtime._firmware_liveness_scheduler
    assert scheduler is not None
    scheduler._last_device_success["ori-fw-expiring"] = scheduler._clock() - 120.0
    local = (await runtime._build_health_snapshot())["firmware_liveness"]
    assert local["expiring_device_ids"] == ["ori-fw-expiring"]

    exported = await runtime._exported_health_snapshot()
    liveness = exported["firmware_liveness"]
    assert liveness["undeclared_device_count"] == 1
    assert liveness["expiring_device_count"] == 1
    assert "undeclared_device_ids" not in liveness
    assert "expiring_device_ids" not in liveness
    assert "last_error" not in liveness
    assert "last_error" in local
    raw = json.dumps(exported)
    assert DEVICE not in raw and "ori-fw-expiring" not in raw


# --- mqtt_ingress ------------------------------------------------------------


def _gateway_config(tmp_path: Path, *, enabled: bool) -> Config:
    path = tmp_path / "ori.yaml"
    path.write_text(
        textwrap.dedent(f"""\
            device:
              id: dev-01
              name: Bench
              location: Test Lab
              deployment_profile: development
            sensors:
              - id: cpu
                type: cpu_percent
                protocol: psutil
                poll_interval_ms: 1000
            skills: []
            reasoning:
              default_tier: rule
            gateway:
              enabled: {str(enabled).lower()}
              broker_url: mqtt://localhost
            actions:
              primary_alert_channel: sms
              whatsapp:
                enabled: false
              sms:
                enabled: false
            database:
              path: {tmp_path / "config_state.db"}
            logging:
              file: {tmp_path / "ori.log"}
        """),
        encoding="utf-8",
    )
    return Config.load(str(path))


async def test_no_gateway_is_disabled(tmp_path: Path) -> None:
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._device_id = "dev-01"
    assert (await runtime._build_health_snapshot())["mqtt_ingress"] == {
        "state": "disabled"
    }
    runtime._config = _gateway_config(tmp_path, enabled=False)
    assert runtime._mqtt_ingress_health() == {"state": "disabled"}


async def test_the_export_route_is_reported_once_built_and_exports_counts(
    runtime: OriRuntime, store: StateStore, tmp_path: Path
) -> None:
    """Through the runtime's own builder: the route registers its bound, and
    the health it exports is the projection, not the local snapshot."""
    await _provision(store, _bare_message())
    runtime._config = _gateway_config(tmp_path, enabled=True)
    assert runtime._mqtt_ingress_health() == {"state": "available", "families": {}}

    runtime._state_store = store
    task = runtime._start_gateway_export_responder_if_enabled(runtime._config, None)
    assert task is not None
    task.cancel()
    server = runtime._gateway_export_server
    assert server is not None
    server._loop = asyncio.get_running_loop()

    oversized = b"{" + b" " * PAYLOAD_MAXIMA[EXPORT_REQUEST] + b"}"
    # Refused for size in the callback itself, before anything is scheduled.
    server._on_message(None, None, SimpleNamespace(payload=oversized))
    assert runtime._mqtt_ingress_health()["families"] == {
        EXPORT_REQUEST: {**ZERO, "payload_too_large": 1}
    }

    response = await server._responder.handle_request(
        {"request_id": "r1", "export_type": "health", "device_id": "dev-01"}
    )
    assert response is not None
    (item,) = response.items
    assert item["firmware_liveness"]["undeclared_device_count"] == 1
    assert DEVICE not in json.dumps(item)
    assert item["mqtt_ingress"]["families"][EXPORT_REQUEST]["payload_too_large"] == 1


async def test_a_member_refusal_is_counted_and_a_redelivery_is_not() -> None:
    subscriber = MqttGatewayHeartbeatSubscriber(
        broker_url="mqtt://localhost",
        posture_tracker=SimpleNamespace(record_gateway_heartbeat=lambda _ms: None),  # type: ignore[arg-type]
        device_id="dev-01",
        client_factory=lambda **_: None,
    )
    subscriber._loop = asyncio.get_running_loop()
    families = IngressFamilies()
    families.add(subscriber.ingress)

    subscriber._on_message(None, None, SimpleNamespace(payload=b'{"a":1,"a":2}'))
    await quiesce(what="the work the message scheduled")
    assert subscriber.ingress.refusals()[DUPLICATE_MEMBER] == 1
    subscriber.ingress.refuse(REDELIVERY_DUE)
    assert families.families() == {GATEWAY_HEALTH: {**ZERO, "member_refused": 1}}


@pytest.mark.parametrize("reason", MEMBER_REASONS)
def test_every_member_rule_reason_is_counted_as_member_refused(reason: str) -> None:
    bound = IngressBound(EXPORT_REQUEST)
    families = IngressFamilies()
    families.add(bound)
    bound.refuse(reason)
    assert families.families() == {EXPORT_REQUEST: {**ZERO, "member_refused": 1}}


def test_volume_dropped_sums_the_rate_and_in_flight_drops() -> None:
    bound = IngressBound(EXPORT_REQUEST)
    families = IngressFamilies()
    families.add(bound)
    for _ in range(3):
        bound.admit(b"{}")
    bound._refuse(RATE_EXCEEDED, 2)
    bound.refuse(IN_FLIGHT_EXCEEDED)
    bound.refuse(REDELIVERY_DUE)
    bound.within_size(b"x" * (PAYLOAD_MAXIMA[EXPORT_REQUEST] + 1))
    assert families.families() == {
        EXPORT_REQUEST: {**ZERO, "payload_too_large": 1, "volume_dropped": 2}
    }


def test_one_family_has_one_bound() -> None:
    families = IngressFamilies()
    families.add(IngressBound(EXPORT_REQUEST))
    with pytest.raises(ValueError, match="already has an ingress bound"):
        families.add(IngressBound(EXPORT_REQUEST))


def _ingress_owners() -> set[str]:
    """Every class in ori/gateway that builds an IngressBound."""
    owners: set[str] = set()
    for path in sorted(Path("ori/gateway").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and any(
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Name)
                and call.func.id == "IngressBound"
                for call in ast.walk(node)
            ):
                owners.add(node.name)
    return owners


def test_every_route_with_a_bound_is_registered_where_the_runtime_builds_it() -> None:
    """A route added with an IngressBound and never registered would leave its
    family out of `mqtt_ingress` while its refusals happen."""
    owners = _ingress_owners()
    assert owners == {
        "MqttEvidenceInboundSubscriber",
        "MqttEvidenceOutboundPublisher",
        "MqttGatewayExportServer",
        "MqttGatewayHeartbeatSubscriber",
        "MqttGatewayReasoner",
    }
    registrations = [
        node
        for path in runtime_source_paths()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "add"
        and isinstance(node.func.value, ast.Attribute)
        and node.func.value.attr == "_gateway_ingress"
    ]
    # Each registers the object its own builder returned, and only once.
    assert sorted(ast.unparse(call.args[0]) for call in registrations) == [
        "evidence_inbound_subscriber.ingress",
        "evidence_outbound_publisher.ingress",
        "gateway_reasoner.ingress",
        "hb_subscriber.ingress",
        "server.ingress",
    ]


def _firmware_egress_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> OriRuntime:
    """A runtime configured for firmware command egress, not yet started."""
    import base64
    import secrets
    from unittest.mock import AsyncMock

    from ori.gateway.firmware_commands import MqttFirmwareCommandPublisher
    from ori.security.commissioning.anchors import COMMISSIONING_ANCHOR_ENV
    from tests.test_firmware_command_action_boundary import (
        EPHEMERAL_SEED,
        PROVISIONER_KEY_ENV,
        RUNTIME_KEY_ENV,
        _withhold_hardware,
        _write_runtime,
        public_key_b64,
    )

    cfg = _write_runtime(tmp_path)
    monkeypatch.setenv(COMMISSIONING_ANCHOR_ENV, public_key_b64(EPHEMERAL_SEED))
    for name in (RUNTIME_KEY_ENV, PROVISIONER_KEY_ENV):
        monkeypatch.setenv(name, base64.b64encode(secrets.token_bytes(32)).decode())
    monkeypatch.chdir(tmp_path)
    _withhold_hardware(monkeypatch)
    monkeypatch.setattr(MqttFirmwareCommandPublisher, "close", AsyncMock())
    return OriRuntime(config_path=str(cfg))


async def test_while_command_egress_connects_the_loop_is_starting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Through a real start: health served while the firmware command publisher
    connects reports the loop `starting`, never `disabled`."""
    from ori.gateway.firmware_commands import MqttFirmwareCommandPublisher

    runtime = _firmware_egress_runtime(tmp_path, monkeypatch)
    seen: list[tuple[str, str | None]] = []

    async def connect(_self: Any) -> None:
        snapshot = await runtime._build_health_snapshot()
        seen.append((snapshot["firmware_liveness"]["state"], snapshot.get("status")))

    monkeypatch.setattr(MqttFirmwareCommandPublisher, "connect", connect)
    task = asyncio.ensure_future(runtime.start())
    try:
        await wait_until(lambda: bool(seen), what="the publisher's connect")
    finally:
        await runtime.stop()
        await asyncio.wait_for(task, timeout=30.0)
    assert seen == [("starting", "degraded")]


async def test_a_failed_connect_then_stop_releases_the_scheduler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ori.gateway.firmware_commands import MqttFirmwareCommandPublisher

    runtime = _firmware_egress_runtime(tmp_path, monkeypatch)

    async def refused(_self: Any) -> None:
        raise ConnectionRefusedError("broker down")

    monkeypatch.setattr(MqttFirmwareCommandPublisher, "connect", refused)
    with pytest.raises(ConnectionRefusedError):
        await runtime.start()
    assert runtime._firmware_liveness_scheduler is not None
    await runtime.stop()
    assert runtime._firmware_liveness_scheduler is None
