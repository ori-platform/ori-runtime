# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""A revoked identity's retained provisioning approval converges to none
(firmware-commands/v2, *Provisioning Approval*, and its runtime-side
revocation artifacts), each end state observed through a fresh subscription
to the provisioning topic on a real broker.

An outage is a runtime whose publisher reaches no broker while the broker
keeps its retained approval; a restart is a new service and publisher on the
same store.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest

from ori.gateway.firmware_commands import (
    FirmwareCommandPublishError,
    FirmwareCommandService,
    MqttFirmwareCommandPublisher,
)
from ori.security.firmware.commands import FirmwareCommandError
from ori.security.firmware.ingest import FirmwareTelemetryGate
from ori.security.firmware.liveness import FirmwareLivenessSupervisor
from ori.state.store import StateStore
from ori.utils.time_utils import now_ms
from tests.firmware.test_command_egress import (
    PROVISIONER_SEED,
    RUNTIME_SEED,
    _register_device,
)
from tests.test_dispatch_never_waits_on_delivery import _broker, _free_port
from tests.waiting import wait_until

SENTINEL = b"sentinel"


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[StateStore]:
    s = StateStore(db_path=str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


def _service(store: StateStore, publisher: Any) -> FirmwareCommandService:
    return FirmwareCommandService(
        store=store,
        publisher=publisher,
        runtime_command_key_bytes=RUNTIME_SEED,
        provisioner_key_bytes=PROVISIONER_SEED,
        liveness_supervisor=FirmwareLivenessSupervisor(),
        liveness_table=None,
    )


def _publisher(port: int) -> MqttFirmwareCommandPublisher:
    return MqttFirmwareCommandPublisher(
        broker_url=f"mqtt://127.0.0.1:{port}",
        runtime_device_id="runtime-01",
        publish_timeout_s=2.0,
    )


@contextlib.asynccontextmanager
async def _runtime(
    store: StateStore, port: int
) -> AsyncIterator[FirmwareCommandService]:
    """One runtime's command egress; leaving the block is its stop."""
    publisher = _publisher(port)
    try:
        yield _service(store, publisher)
    finally:
        await publisher.close()


async def _retained(port: int, device_id: str) -> list[bytes]:
    """What a fresh subscription to the provisioning topic receives retained.

    A non-retained sentinel published after the subscription is acknowledged
    arrives after any retained message, so waiting for it bounds the wait.
    """
    import paho.mqtt.client as mqtt

    topic = f"ori/fw/{device_id}/provision"
    received: list[tuple[bytes, bool]] = []
    subscribed: list[int] = []
    client = mqtt.Client(
        callback_api_version=getattr(mqtt, "CallbackAPIVersion").VERSION2,
        client_id="fresh-subscriber",
    )
    client.on_message = lambda _c, _u, message: received.append(
        (bytes(message.payload), bool(message.retain))
    )
    client.on_subscribe = lambda *_args: subscribed.append(1)
    client.connect("127.0.0.1", port)
    client.loop_start()
    try:
        client.subscribe(topic, qos=1)
        await wait_until(lambda: subscribed, what="the subscription to be acknowledged")
        client.publish(topic, SENTINEL, qos=1, retain=False)
        await wait_until(
            lambda: (SENTINEL, False) in received, what="the sentinel to arrive"
        )
    finally:
        client.loop_stop()
        client.disconnect()
    return [payload for payload, retain in received if retain]


async def _promote(store: StateStore, device_id: str) -> None:
    gate = FirmwareTelemetryGate(store)
    assert await gate.approve_device(device_id, actor="operator", reason="promote")
    row = await store.get_firmware_device(device_id)
    assert row is not None
    await store.resolve_firmware_confirmation(
        device_id, row["anchor_epoch_id"], status="confirmed", at_ms=now_ms()
    )


async def _revoke(store: StateStore, device_id: str) -> None:
    assert await FirmwareTelemetryGate(store).revoke_device(
        device_id, actor="operator", reason="revoke"
    )


async def _reinstate(store: StateStore, device_id: str) -> None:
    assert await FirmwareTelemetryGate(store).reinstate_device(
        device_id, actor="operator", reason="reinstate"
    )


async def _start_and_stop(service: FirmwareCommandService) -> None:
    """A runtime's start, whose first pass runs at once, then its stop."""
    passes: list[int] = []
    one_pass = service.clear_withdrawn_provisioning_approvals

    async def counted() -> None:
        try:
            await one_pass()
        finally:
            passes.append(1)

    service.clear_withdrawn_provisioning_approvals = counted  # type: ignore[method-assign]
    stop = asyncio.Event()
    task = asyncio.create_task(service.clear_provisioning_until(stop))
    # Well inside the interval: a first pass that waited for it fails here.
    await wait_until(lambda: passes, what="the pass at start", deadline_s=10.0)
    stop.set()
    await asyncio.wait_for(task, 10)


async def test_a_revocation_leaves_no_retained_approval(
    tmp_path: Path, store: StateStore
) -> None:
    device_id = await _register_device(store)
    with _broker(tmp_path) as port:
        async with _runtime(store, port) as service:
            approval = await service.publish_provisioning_approval(device_id)
            assert await _retained(port, device_id) == [approval]
            await _revoke(store, device_id)
            await service.clear_withdrawn_provisioning_approvals()
        assert await _retained(port, device_id) == []


async def test_a_revocation_while_the_broker_is_unreachable_refuses_to_sign_at_once(
    store: StateStore,
) -> None:
    device_id = await _register_device(store)
    async with _runtime(store, _free_port()) as service:
        await _revoke(store, device_id)
        # Refused by the registry, not by the transport: nothing was signed.
        with pytest.raises(FirmwareCommandError, match="revoked"):
            await service.publish_command(
                device_id=device_id, action="relay_open", channel="relay0"
            )
        with pytest.raises(FirmwareCommandError, match="revoked"):
            await service.publish_provisioning_approval(device_id)
        with pytest.raises(FirmwareCommandPublishError):
            await service.clear_withdrawn_provisioning_approvals()


@pytest.mark.parametrize("broker_at_revocation", ["reachable", "unreachable"])
async def test_a_revocation_then_a_restart_leaves_no_retained_approval(
    tmp_path: Path, store: StateStore, broker_at_revocation: str
) -> None:
    device_id = await _register_device(store)
    with _broker(tmp_path) as port:
        async with _runtime(store, port) as service:
            approval = await service.publish_provisioning_approval(device_id)
        assert await _retained(port, device_id) == [approval]
        # Committed by a tool beside the runtime, or while it was cut off.
        await _revoke(store, device_id)
        if broker_at_revocation == "unreachable":
            async with _runtime(store, _free_port()) as cut_off:
                await _start_and_stop(cut_off)
            assert await _retained(port, device_id) == [approval]
        async with _runtime(store, port) as restarted:
            await _start_and_stop(restarted)
        assert await _retained(port, device_id) == []


class _LandsAfterRevocation:
    """Forwards an approval only once the identity's revocation committed."""

    def __init__(
        self,
        publisher: MqttFirmwareCommandPublisher,
        revoke: Callable[[], Awaitable[None]],
    ) -> None:
        self._publisher = publisher
        self._revoke = revoke

    async def publish_provisioning_approval(
        self, device_id: str, message: bytes
    ) -> None:
        await self._revoke()
        await self._publisher.publish_provisioning_approval(device_id, message)

    async def clear_provisioning_approval(self, device_id: str) -> None:
        await self._publisher.clear_provisioning_approval(device_id)


async def _approval_landed_after_revocation(
    store: StateStore, port: int, device_id: str
) -> FirmwareCommandService:
    publisher = _publisher(port)
    service = _service(
        store, _LandsAfterRevocation(publisher, lambda: _revoke(store, device_id))
    )
    approval = await service.publish_provisioning_approval(device_id)
    assert await _retained(port, device_id) == [approval]
    return service


async def test_an_approval_landing_after_the_revocation_is_not_left_retained(
    tmp_path: Path, store: StateStore
) -> None:
    device_id = await _register_device(store)
    with _broker(tmp_path) as port:
        service = await _approval_landed_after_revocation(store, port, device_id)
        await _start_and_stop(service)
        assert await _retained(port, device_id) == []


async def test_a_reinstatement_without_a_promotion_leaves_no_retained_approval(
    tmp_path: Path, store: StateStore
) -> None:
    device_id = await _register_device(store)
    with _broker(tmp_path) as port:
        service = await _approval_landed_after_revocation(store, port, device_id)
        await _reinstate(store, device_id)
        await _start_and_stop(service)
        assert await _retained(port, device_id) == []


async def test_a_promotion_after_revocation_and_reinstatement_leaves_its_approval(
    tmp_path: Path, store: StateStore
) -> None:
    device_id = await _register_device(store)
    with _broker(tmp_path) as port:
        async with _runtime(store, port) as service:
            await service.publish_provisioning_approval(device_id)
            await _revoke(store, device_id)
            await service.clear_withdrawn_provisioning_approvals()
            await _reinstate(store, device_id)
            await service.clear_withdrawn_provisioning_approvals()
            await _promote(store, device_id)
            promoted = await service.publish_provisioning_approval(device_id)
            await service.clear_withdrawn_provisioning_approvals()
        assert await _retained(port, device_id) == [promoted]


class _Recording:
    def __init__(self) -> None:
        self.sent: list[str] = []

    async def publish_provisioning_approval(
        self, device_id: str, message: bytes
    ) -> None:
        self.sent.append("approval")

    async def clear_provisioning_approval(self, device_id: str) -> None:
        self.sent.append("clear")


async def test_an_approval_is_sent_after_a_clear_that_read_the_authority_it_replaces(
    store: StateStore,
) -> None:
    """A clear that read the identity unpromoted never lands after its approval."""
    device_id = await _register_device(store)
    await _revoke(store, device_id)
    await _reinstate(store, device_id)
    publisher = _Recording()
    service = _service(store, publisher)
    read = asyncio.Event()
    resume = asyncio.Event()
    listed = store.list_firmware_devices_revoked_or_unpromoted

    async def held_list() -> list[str]:
        answer = await listed()
        read.set()
        await resume.wait()
        return answer

    store.list_firmware_devices_revoked_or_unpromoted = held_list  # type: ignore[method-assign]
    clearing = asyncio.create_task(service.clear_withdrawn_provisioning_approvals())
    await read.wait()
    await _promote(store, device_id)
    approving = asyncio.create_task(service.publish_provisioning_approval(device_id))
    await asyncio.sleep(0.05)
    resume.set()
    await asyncio.gather(clearing, approving)
    assert publisher.sent == ["clear", "approval"]


async def test_the_list_names_exactly_the_revoked_and_unpromoted(
    store: StateStore,
) -> None:
    device_id = await _register_device(store, approve=False)
    assert await store.list_firmware_devices_revoked_or_unpromoted() == [device_id]
    await _promote(store, device_id)
    assert await store.list_firmware_devices_revoked_or_unpromoted() == []
    await _revoke(store, device_id)
    assert await store.list_firmware_devices_revoked_or_unpromoted() == [device_id]
    await _reinstate(store, device_id)
    assert await store.list_firmware_devices_revoked_or_unpromoted() == [device_id]
    gate = FirmwareTelemetryGate(store)
    assert await gate.approve_device(device_id, actor="operator", reason="promote")
    # Promoted and awaiting the evidence store: its approval is not yet
    # published, and nothing here clears one.
    assert await store.list_firmware_devices_revoked_or_unpromoted() == []


class _Proxy:
    """A TCP relay to the broker that can be cut and restored, so the
    runtime loses the broker while the broker keeps what it retained."""

    def __init__(self, upstream: int) -> None:
        self.port = _free_port()
        self._upstream = upstream
        self._server: asyncio.Server | None = None
        self._writers: list[asyncio.StreamWriter] = []

    async def open(self) -> None:
        self._server = await asyncio.start_server(self._relay, "127.0.0.1", self.port)

    async def cut(self) -> None:
        assert self._server is not None
        self._server.close()
        # Before the wait: since 3.12 it waits for the relayed connections too.
        for writer in self._writers:
            writer.close()
        self._writers.clear()
        await self._server.wait_closed()

    async def _relay(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        up_reader, up_writer = await asyncio.open_connection(
            "127.0.0.1", self._upstream
        )
        self._writers += [writer, up_writer]

        async def pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
            with contextlib.suppress(OSError):
                while data := await src.read(65536):
                    dst.write(data)
                    await dst.drain()
            dst.close()

        await asyncio.gather(pipe(reader, up_writer), pipe(up_reader, writer))


async def test_the_running_loop_clears_once_the_broker_returns(
    tmp_path: Path, store: StateStore
) -> None:
    """No restart: passes fail while the broker is cut off, and the next pass
    after it returns clears what it retained."""
    device_id = await _register_device(store)
    with _broker(tmp_path) as port:
        proxy = _Proxy(port)
        await proxy.open()
        publisher = _publisher(proxy.port)
        service = _service(store, publisher)
        approval = await service.publish_provisioning_approval(device_id)
        await proxy.cut()
        await _revoke(store, device_id)
        passes: list[bool] = []
        one_pass = service.clear_withdrawn_provisioning_approvals

        async def counted() -> None:
            try:
                await one_pass()
            except Exception:
                passes.append(False)
                raise
            passes.append(True)

        service.clear_withdrawn_provisioning_approvals = counted  # type: ignore[method-assign]
        stop = asyncio.Event()
        loop = asyncio.create_task(
            service.clear_provisioning_until(stop, interval_s=0.2)
        )
        try:
            await wait_until(lambda: passes.count(False) >= 2, what="passes failing")
            assert await _retained(port, device_id) == [approval]
            await proxy.open()
            await wait_until(lambda: True in passes, what="a pass after the return")
            assert await _retained(port, device_id) == []
        finally:
            stop.set()
            await asyncio.wait_for(loop, 10)
            await publisher.close()
            await proxy.cut()


@pytest.mark.parametrize(
    "send",
    [
        lambda p: p.publish_provisioning_approval("ori-fw-7c9f2b3a", b""),
        lambda p: p.publish_command("ori-fw-7c9f2b3a", b""),
        lambda p: p.publish_runtime_liveness("ori-fw-7c9f2b3a", b""),
    ],
    ids=["approval", "command", "liveness"],
)
async def test_an_empty_payload_is_refused_on_every_other_path(send: Any) -> None:
    publisher = _publisher(_free_port())
    with pytest.raises(FirmwareCommandPublishError, match="must be bytes"):
        await send(publisher)


class _FailsFor:
    """Refuses every clear for one identity; records each attempt."""

    def __init__(self, failing: str) -> None:
        self._failing = failing
        self.attempts: list[str] = []

    async def publish_provisioning_approval(
        self, device_id: str, message: bytes
    ) -> None:
        raise AssertionError("no approval is published here")

    async def clear_provisioning_approval(self, device_id: str) -> None:
        self.attempts.append(device_id)
        if device_id == self._failing:
            raise FirmwareCommandPublishError(f"refused for {device_id}")


async def test_an_identity_that_keeps_failing_holds_back_no_other(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each pass tries every identity, and still reports the failure."""

    async def listed() -> list[str]:
        return ["ori-fw-a", "ori-fw-b", "ori-fw-c"]

    monkeypatch.setattr(store, "list_firmware_devices_revoked_or_unpromoted", listed)
    publisher = _FailsFor("ori-fw-a")
    service = _service(store, publisher)
    for _ in range(2):
        with pytest.raises(FirmwareCommandPublishError, match="1 of 3 clears failed"):
            await service.clear_withdrawn_provisioning_approvals()
    assert publisher.attempts == ["ori-fw-a", "ori-fw-b", "ori-fw-c"] * 2
