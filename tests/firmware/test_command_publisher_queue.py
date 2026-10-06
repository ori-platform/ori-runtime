# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A firmware publication that failed is never delivered later.

A QoS 1 client queues what it cannot send and sends it on reconnect. For a
signed command, approval or liveness message that means delivery after the
authority that signed it may have been withdrawn, so the publisher refuses
to hand anything to a disconnected client and discards a client that failed
a publication, queue and all.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import pytest

from ori.gateway.firmware_commands import (
    FirmwareCommandPublishError,
    MqttFirmwareCommandPublisher,
)
from tests.test_dispatch_never_waits_on_delivery import _free_port, _mosquitto

DEVICE = "ori-fw-7c9f2b3a"
FAMILIES = {
    "command": ("publish_command", "cmd"),
    "approval": ("publish_provisioning_approval", "provision"),
    "liveness": ("publish_runtime_liveness", "runtime"),
}


@contextmanager
def _broker_on(root: Path, port: int) -> Iterator[subprocess.Popen[bytes]]:
    binary = _mosquitto()
    if binary is None:
        if os.environ.get("ORI_REQUIRE_MQTT_BROKER") == "1":
            pytest.fail("ORI_REQUIRE_MQTT_BROKER=1 and mosquitto is not installed")
        pytest.skip("mosquitto is not installed")
    config = root / f"mosquitto-{port}.conf"
    config.write_text(
        f"listener {port} 127.0.0.1\nallow_anonymous true\npersistence false\n"
    )
    process = subprocess.Popen(
        [binary, "-c", str(config)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        import socket

        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            with socket.socket() as probe:
                if probe.connect_ex(("127.0.0.1", port)) == 0:
                    break
            time.sleep(0.05)
        yield process
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(5.0)


async def _publish(publisher: MqttFirmwareCommandPublisher, family: str, body: bytes):
    method, _ = FAMILIES[family]
    await getattr(publisher, method)(DEVICE, body)


@pytest.mark.parametrize("family", sorted(FAMILIES))
async def test_a_failed_publication_is_not_delivered_on_reconnect(
    tmp_path: Path, family: str
) -> None:
    import paho.mqtt.client as mqtt

    port = _free_port()
    publisher = MqttFirmwareCommandPublisher(
        broker_url=f"mqtt://127.0.0.1:{port}",
        runtime_device_id="runtime-01",
        publish_timeout_s=2.0,
    )
    with _broker_on(tmp_path, port):
        await publisher.connect()
    # The broker is gone. The runtime is told the publication failed; this is
    # where an operator revokes the device.
    await asyncio.sleep(0.3)
    with pytest.raises(FirmwareCommandPublishError):
        await _publish(publisher, family, b"stale")

    received: list[bytes] = []
    with _broker_on(tmp_path, port):
        device = mqtt.Client(
            callback_api_version=getattr(mqtt, "CallbackAPIVersion").VERSION2,
            client_id="device",
        )
        device.on_message = lambda _c, _u, message: received.append(message.payload)
        device.connect("127.0.0.1", port)
        device.subscribe(f"ori/fw/{DEVICE}/#", qos=1)
        device.loop_start()
        try:
            await asyncio.sleep(0.3)
            await _publish(publisher, family, b"fresh")
            deadline = time.monotonic() + 10.0
            while b"fresh" not in received and time.monotonic() < deadline:
                await asyncio.sleep(0.05)
            # Give anything still queued in a stale client time to arrive.
            await asyncio.sleep(1.5)
        finally:
            device.loop_stop()
            device.disconnect()
            await publisher.close()

    assert received == [b"fresh"]


async def _only_fresh_arrives(
    tmp_path: Path, port: int, publisher: MqttFirmwareCommandPublisher, family: str
) -> list[bytes]:
    """Restart the broker, publish a fresh message, and return what arrived."""
    import paho.mqtt.client as mqtt

    received: list[bytes] = []
    with _broker_on(tmp_path, port):
        device = mqtt.Client(
            callback_api_version=getattr(mqtt, "CallbackAPIVersion").VERSION2,
            client_id="device",
        )
        device.on_message = lambda _c, _u, message: received.append(message.payload)
        device.connect("127.0.0.1", port)
        device.subscribe(f"ori/fw/{DEVICE}/#", qos=1)
        device.loop_start()
        try:
            # Past paho's first reconnect: a stale client left alive would
            # be back on the broker and resending before the fresh message.
            await asyncio.sleep(3.0)
            await _publish(publisher, family, b"fresh")
            deadline = time.monotonic() + 10.0
            while b"fresh" not in received and time.monotonic() < deadline:
                await asyncio.sleep(0.05)
            await asyncio.sleep(0.5)
        finally:
            device.loop_stop()
            device.disconnect()
            await publisher.close()
    return received


@pytest.mark.parametrize("family", sorted(FAMILIES))
async def test_an_unacknowledged_publication_is_not_resent_on_reconnect(
    tmp_path: Path, family: str
) -> None:
    """The broker takes the bytes and never acknowledges; three publish at once."""
    import signal

    port = _free_port()
    publisher = MqttFirmwareCommandPublisher(
        broker_url=f"mqtt://127.0.0.1:{port}",
        runtime_device_id="runtime-01",
        publish_timeout_s=1.0,
    )
    with _broker_on(tmp_path, port) as broker:
        await publisher.connect()
        broker.send_signal(signal.SIGSTOP)
        outcomes = await asyncio.gather(
            *(_publish(publisher, family, b"stale") for _ in range(3)),
            return_exceptions=True,
        )
        assert all(isinstance(o, FirmwareCommandPublishError) for o in outcomes)
        # This is where the device is revoked; the broker dies holding nothing.
        broker.kill()

    assert await _only_fresh_arrives(tmp_path, port, publisher, family) == [b"fresh"]


@pytest.mark.parametrize("family", sorted(FAMILIES))
async def test_a_cancelled_publication_is_not_resent_on_reconnect(
    tmp_path: Path, family: str
) -> None:
    """An outer timeout cancels the publication, as the liveness scheduler does."""
    import signal

    port = _free_port()
    publisher = MqttFirmwareCommandPublisher(
        broker_url=f"mqtt://127.0.0.1:{port}",
        runtime_device_id="runtime-01",
        publish_timeout_s=5.0,
    )
    with _broker_on(tmp_path, port) as broker:
        await publisher.connect()
        broker.send_signal(signal.SIGSTOP)
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(_publish(publisher, family, b"stale"), 0.5)
        broker.kill()

    assert await _only_fresh_arrives(tmp_path, port, publisher, family) == [b"fresh"]


class _Info:
    """As paho's: the wait returns None, and is_published says whether."""

    def __init__(self, rc: int, waited: Any) -> None:
        self.rc = rc
        self._waited = waited

    def wait_for_publish(self, timeout: float) -> None:
        if isinstance(self._waited, BaseException):
            raise self._waited

    def is_published(self) -> bool:
        return bool(self._waited)


class _Client:
    def __init__(self, *, connected: bool, rc: int = 0, waited: Any = True) -> None:
        self.connected = connected
        self.rc = rc
        self.waited = waited
        self.published: list[str] = []
        self.stopped = False

    def username_pw_set(self, *_: Any) -> None:
        pass

    def tls_set_context(self, *_: Any) -> None:
        pass

    def connect(self, *_: Any) -> None:
        pass

    def loop_start(self) -> None:
        pass

    def loop_stop(self) -> None:
        self.stopped = True

    def disconnect(self) -> None:
        self.connected = False

    def is_connected(self) -> bool:
        return self.connected

    def publish(self, topic: str, payload: bytes, qos: int, retain: bool) -> _Info:
        self.published.append(topic)
        return _Info(self.rc, self.waited)


def _publisher(clients: list[_Client]) -> MqttFirmwareCommandPublisher:
    made = iter(clients)
    return MqttFirmwareCommandPublisher(
        broker_url="mqtt://localhost",
        runtime_device_id="runtime-01",
        client_factory=lambda **_: next(made),
        publish_timeout_s=0.05,
    )


async def test_nothing_is_handed_to_a_disconnected_client() -> None:
    lost = _Client(connected=False)
    still_down = _Client(connected=False)
    publisher = _publisher([lost, still_down])
    await publisher.connect()

    with pytest.raises(FirmwareCommandPublishError, match="nothing was queued"):
        await publisher.publish_command(DEVICE, b"command")

    assert lost.published == [] and still_down.published == []
    assert lost.stopped, "a disconnected client is replaced, not left to reconnect"


async def test_a_disconnected_client_is_replaced_without_waiting() -> None:
    lost = _Client(connected=False)
    fresh = _Client(connected=True)
    publisher = _publisher([lost, fresh])
    await publisher.connect()

    await publisher.publish_command(DEVICE, b"command")

    assert lost.published == [] and lost.stopped
    assert fresh.published == [f"ori/fw/{DEVICE}/cmd"]
    await publisher.close()


@pytest.mark.parametrize(
    ("rc", "waited"),
    [
        (4, True),
        (0, False),
        (0, RuntimeError("message publish failed")),
        (0, asyncio.CancelledError()),
    ],
    ids=["rc", "timeout", "raised", "cancelled"],
)
async def test_a_client_that_failed_a_publication_is_discarded(
    rc: int, waited: Any
) -> None:
    failing = _Client(connected=True, rc=rc, waited=waited)
    fresh = _Client(connected=True)
    publisher = _publisher([failing, fresh])
    await publisher.connect()

    expected = (
        asyncio.CancelledError
        if isinstance(waited, asyncio.CancelledError)
        else FirmwareCommandPublishError
    )
    with pytest.raises(expected):
        await publisher.publish_command(DEVICE, b"stale")
    await asyncio.sleep(0.05)  # the network loop is stopped off the event loop
    assert failing.stopped and not failing.connected

    await publisher.publish_command(DEVICE, b"fresh")
    assert failing.published == [f"ori/fw/{DEVICE}/cmd"]
    assert fresh.published == [f"ori/fw/{DEVICE}/cmd"]
    await publisher.close()


async def test_a_publisher_that_cannot_reconnect_refuses() -> None:
    def refuse(**_: Any) -> Any:
        raise ConnectionRefusedError("broker down")

    publisher = MqttFirmwareCommandPublisher(
        broker_url="mqtt://localhost",
        runtime_device_id="runtime-01",
        client_factory=refuse,
    )
    with pytest.raises(FirmwareCommandPublishError, match="not connected"):
        await publisher.publish_command(DEVICE, b"command")


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf"), True])
def test_the_publish_timeout_must_be_finite_and_positive(timeout: Any) -> None:
    with pytest.raises(ValueError, match="finite positive"):
        MqttFirmwareCommandPublisher(
            broker_url="mqtt://localhost",
            runtime_device_id="runtime-01",
            client_factory=lambda **_: _Client(connected=True),
            publish_timeout_s=timeout,
        )


class _Gate:
    """Holds paho's network loop before it writes, or a publish before it queues."""

    def __init__(self) -> None:
        import threading

        self.write = threading.Event()
        self.write.set()
        self.publish = threading.Event()
        self.publish.set()
        self.returned = threading.Event()
        self.returned.set()
        self.reconnect = threading.Event()
        self.reconnect.set()
        self.reconnecting = threading.Event()


def _gated_paho(monkeypatch: pytest.MonkeyPatch, gate: _Gate) -> Any:
    """Swap paho's Client for one the gate can hold; return the original."""
    import paho.mqtt.client as mqtt

    from ori.gateway import firmware_commands

    original = mqtt.Client

    class Gated(original):  # type: ignore[misc, valid-type]
        def loop_write(self) -> Any:
            gate.write.wait(10.0)
            return super().loop_write()

        def reconnect(self) -> Any:
            if not gate.reconnect.is_set():
                gate.reconnecting.set()
                gate.reconnect.wait(10.0)
            return super().reconnect()

        def disconnect(self, *args: Any, **kwargs: Any) -> Any:
            # disconnect wakes the network loop. Let it run first, so a
            # disconnect issued before the socket is shut is observed
            # flushing whatever the client still held.
            if not gate.write.is_set():
                gate.write.set()
                time.sleep(0.3)
            return super().disconnect(*args, **kwargs)

        def publish(self, *args: Any, **kwargs: Any) -> Any:
            gate.publish.wait(10.0)
            info = super().publish(*args, **kwargs)
            gate.returned.wait(10.0)
            return info

    monkeypatch.setattr(firmware_commands.mqtt, "Client", Gated)
    return original


async def _listen(original: Any, port: int, received: list[bytes]) -> Any:
    import paho.mqtt.client as mqtt

    device = original(
        callback_api_version=getattr(mqtt, "CallbackAPIVersion").VERSION2,
        client_id="device",
    )
    device.on_message = lambda _c, _u, message: received.append(message.payload)
    device.connect("127.0.0.1", port)
    device.subscribe(f"ori/fw/{DEVICE}/#", qos=1)
    device.loop_start()
    await asyncio.sleep(0.3)
    return device


@pytest.mark.parametrize("ending", ["timeout", "cancelled"])
@pytest.mark.parametrize("family", sorted(FAMILIES))
async def test_a_live_client_does_not_drain_a_failed_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, family: str, ending: str
) -> None:
    """The broker is up; the publication is held behind the client's loop."""
    gate = _Gate()
    original = _gated_paho(monkeypatch, gate)
    port = _free_port()
    received: list[bytes] = []
    with _broker_on(tmp_path, port):
        device = await _listen(original, port, received)
        publisher = MqttFirmwareCommandPublisher(
            broker_url=f"mqtt://127.0.0.1:{port}",
            runtime_device_id="runtime-01",
            publish_timeout_s=0.5 if ending == "timeout" else 5.0,
        )
        try:
            await publisher.connect()
            gate.write.clear()
            if ending == "timeout":
                with pytest.raises(FirmwareCommandPublishError, match="timed out"):
                    await _publish(publisher, family, b"stale")
            else:
                with pytest.raises(asyncio.TimeoutError):
                    await asyncio.wait_for(_publish(publisher, family, b"stale"), 0.3)
            # This is where the device is revoked; then the loop runs again.
            gate.write.set()
            await asyncio.sleep(1.0)
            assert received == []

            await _publish(publisher, family, b"fresh")
            deadline = time.monotonic() + 5.0
            while not received and time.monotonic() < deadline:
                await asyncio.sleep(0.05)
            await asyncio.sleep(0.3)
        finally:
            gate.write.set()
            device.loop_stop()
            device.disconnect()
            await publisher.close()
    assert received == [b"fresh"]


@pytest.mark.parametrize("position", ["before_queueing", "after_queueing"])
@pytest.mark.parametrize("family", sorted(FAMILIES))
async def test_a_publication_cancelled_inside_publish_is_not_sent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, family: str, position: str
) -> None:
    """The worker is still inside client.publish when the caller is cancelled.

    After queueing, the network loop is held too, so the queued bytes are
    still unwritten when the client is retired.
    """
    gate = _Gate()
    original = _gated_paho(monkeypatch, gate)
    port = _free_port()
    received: list[bytes] = []
    with _broker_on(tmp_path, port):
        device = await _listen(original, port, received)
        publisher = MqttFirmwareCommandPublisher(
            broker_url=f"mqtt://127.0.0.1:{port}",
            runtime_device_id="runtime-01",
            publish_timeout_s=5.0,
        )
        try:
            await publisher.connect()
            if position == "before_queueing":
                gate.publish.clear()
            else:
                gate.write.clear()
                gate.returned.clear()
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(_publish(publisher, family, b"stale"), 0.3)
            # The device is revoked; the worker and the loop then run on.
            gate.publish.set()
            gate.returned.set()
            gate.write.set()
            await asyncio.sleep(1.0)
            assert received == []
        finally:
            gate.publish.set()
            gate.returned.set()
            gate.write.set()
            device.loop_stop()
            device.disconnect()
            await publisher.close()


@pytest.mark.parametrize("ending", ["timeout", "cancelled"])
@pytest.mark.parametrize("family", sorted(FAMILIES))
async def test_a_reconnect_underway_does_not_resend_a_failed_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, family: str, ending: str
) -> None:
    """The connection drops with the publication queued; a reconnect would resend it.

    paho reconnects on its own unless told not to, and a reconnect already
    running has no socket for retirement to shut. The reconnect is held at
    its start, the publication fails, and then the reconnect is released.
    """
    import socket

    gate = _Gate()
    original = _gated_paho(monkeypatch, gate)
    port = _free_port()
    received: list[bytes] = []
    with _broker_on(tmp_path, port):
        device = await _listen(original, port, received)
        publisher = MqttFirmwareCommandPublisher(
            broker_url=f"mqtt://127.0.0.1:{port}",
            runtime_device_id="runtime-01",
            publish_timeout_s=3.0 if ending == "timeout" else 10.0,
        )
        try:
            await publisher.connect()
            client = publisher._client
            assert client is not None
            gate.reconnect.clear()
            gate.write.clear()
            task = asyncio.ensure_future(_publish(publisher, family, b"stale"))
            await asyncio.sleep(0.3)  # queued, not yet written
            client.socket().shutdown(socket.SHUT_RDWR)  # the connection drops
            gate.write.set()  # the loop meets the dead socket
            # A client that reconnects on its own is inside reconnect by now.
            await asyncio.sleep(1.8)
            if ending == "timeout":
                with pytest.raises(FirmwareCommandPublishError):
                    await task
            else:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            # The device is revoked; then the reconnect runs.
            gate.reconnect.set()
            await asyncio.sleep(1.5)
            assert received == []
        finally:
            gate.reconnect.set()
            gate.write.set()
            device.loop_stop()
            device.disconnect()
            await publisher.close()
