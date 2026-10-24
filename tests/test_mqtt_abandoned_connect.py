# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Who owns an MQTT connect attempt's socket, on every path out of it.

Real aiomqtt and paho clients, real executor threads and loopback sockets. The
connect watch hands an abandoned attempt's socket to the event loop, or to the
reaper thread once the loop has accepted that hand-off, and never closes it
where a registration the attempt queued could still run.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import sys
import textwrap
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from ori.hal import mqtt_base
from ori.hal.mqtt_adapter import MqttAdapter
from tests import supervised_process
from tests.test_mqtt_adapter import _config as mqtt_config
from tests.test_mqtt_adapter import _FakeClient
from tests.test_mqtt_family_hostile_payloads import (
    _cap_warnings,
    _closed_by_peer,
    _GatedConnect,
    _wait_sync,
    own_loop,
)
from tests.waiting import DEADLINE_S, HOLD_S, settle, wait_until

__all__ = ["own_loop"]

REPO = Path(__file__).resolve().parents[1]


async def _read_packet(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    head = await reader.readexactly(1)
    length, shift = 0, 0
    while True:
        byte = (await reader.readexactly(1))[0]
        length |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            break
    return head[0] >> 4, await reader.readexactly(length)


async def test_a_watched_connect_that_succeeds_keeps_its_socket() -> None:
    """The watch is installed on every attempt; on success it must not close."""
    topic = mqtt_config()["topic"].encode()
    payload = b'{"reading": {"value": 21.5, "quality": 1.0}}'
    writers: list[asyncio.StreamWriter] = []

    async def broker(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        writers.append(writer)
        kind, _ = await _read_packet(reader)
        assert kind == 1, "expected CONNECT"
        writer.write(b"\x20\x02\x00\x00")
        kind, body = await _read_packet(reader)
        assert kind == 8, "expected SUBSCRIBE"
        writer.write(b"\x90\x03" + body[:2] + b"\x00")
        variable = len(topic).to_bytes(2, "big") + topic + payload
        writer.write(bytes([0x30, len(variable)]) + variable)
        await writer.drain()
        await reader.read()

    server = await asyncio.start_server(broker, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    adapter = MqttAdapter()

    async def value_read() -> bool:
        try:
            return (await adapter.read("s1")).value == 21.5
        except Exception:
            return False

    try:
        await adapter.connect(
            {**mqtt_config(), "broker_host": "127.0.0.1", "port": port}
        )
        await wait_until(value_read, what="the published value to be read")
        for _ in range(20):
            await asyncio.sleep(0)
        assert adapter._link_up and await adapter.health_check()
        sock = adapter._client._client.socket()
        assert sock is not None and sock.fileno() != -1, (
            "the watch closed a live socket"
        )
    finally:
        await adapter.close()
        for writer in writers:
            writer.close()
        server.close()
        await server.wait_closed()


def _abandon_after_the_post(own_loop: Any) -> Any:
    """Connect at start, held in paho; the loop stops; the thread then finishes
    and its post is accepted but never run; only then is the attempt abandoned.
    """
    loop = own_loop.loop
    port = own_loop.listener.getsockname()[1]
    loop.create_task(
        own_loop.adapter.connect(
            {**mqtt_config(), "broker_host": "127.0.0.1", "port": port}
        )
    )
    loop.run_until_complete(
        wait_until(own_loop.gate.entered.is_set, what="the connect to reach paho")
    )
    own_loop.gate.release.set()
    watch = own_loop.watches[-1]
    assert watch.post_accepted.wait(DEADLINE_S), "the loop never took the post"
    assert watch.abandon() == mqtt_base._ConnectWatch.AWAIT_SETTLED
    return watch


def test_an_abandon_after_the_post_is_closed_when_the_loop_closes(
    own_loop: Any,
) -> None:
    own_loop.gate = _GatedConnect(own_loop.paho, fail_first=False)
    with own_loop.patched():
        _abandon_after_the_post(own_loop)
        own_loop.loop.close()
        _wait_sync(
            lambda: own_loop.gate.socket.fileno() == -1, what="the reaper to close it"
        )
    assert own_loop.peer_reads_eof()


def test_an_abandon_after_the_post_is_held_to_the_cap(
    own_loop: Any, caplog: pytest.LogCaptureFixture
) -> None:
    own_loop.gate = _GatedConnect(own_loop.paho, fail_first=False)
    with (
        own_loop.patched(owner_wait_s=0.2),
        caplog.at_level(logging.WARNING, logger="ori.hal.mqtt_base"),
    ):
        _abandon_after_the_post(own_loop)
        _wait_sync(lambda: _cap_warnings(caplog), what="the cap to pass")
        assert own_loop.peer_reads_eof(), "the connection was not ended at the cap"
        assert own_loop.gate.socket.fileno() != -1, "released while the loop is open"
        assert len(_cap_warnings(caplog)) == 1
        own_loop.loop.close()
        _wait_sync(
            lambda: own_loop.gate.socket.fileno() == -1, what="the reaper to close it"
        )


class _StubWatch:
    def __init__(self) -> None:
        self.sock, self.peer = socket.socketpair()
        self._deadline = 0.0

    def _reap(self, now: float) -> bool:
        self.sock.close()
        return False


def test_the_reaper_starts_again_after_going_idle() -> None:
    reaper = mqtt_base._REAPER
    first, second = _StubWatch(), _StubWatch()
    try:
        with patch("ori.hal.mqtt_base.REAPER_POLL_S", 0.01):
            reaper.hand_over(first)  # type: ignore[arg-type]
            _wait_sync(
                lambda: first.sock.fileno() == -1 and reaper._thread is None,
                what="the reaper to close the first and go idle",
            )
            reaper.hand_over(second)  # type: ignore[arg-type]
            _wait_sync(lambda: second.sock.fileno() == -1, what="a second reaper")
    finally:
        for stub in (first, second):
            stub.sock.close()
            stub.peer.close()


async def test_attempts_abandoned_before_they_started_leave_nothing_pending() -> None:
    """Queued behind a saturated executor, an abandoned attempt that never
    starts leaves nothing to wait for. A worker may still take a queued one
    before its cancellation lands; that one is then owned like any other."""
    paho = pytest.importorskip("paho.mqtt.client")
    loop = asyncio.get_running_loop()
    executor = ThreadPoolExecutor(max_workers=2)
    loop.set_default_executor(executor)
    release = threading.Event()
    entered: list[Any] = []
    built: list[socket.socket] = []
    original = paho.Client._create_socket_connection

    def gated(client: Any) -> Any:
        entered.append(client)
        release.wait(HOLD_S)
        sock = original(client)
        built.append(sock)
        return sock

    peers: list[asyncio.StreamWriter] = []
    readers: list[asyncio.StreamReader] = []

    async def hold(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        readers.append(reader)
        peers.append(writer)

    server = await asyncio.start_server(hold, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    adapters = [MqttAdapter() for _ in range(8)]
    try:
        with (
            patch.object(paho.Client, "_create_socket_connection", gated),
            patch("ori.hal.mqtt_base.reconnect_delay", lambda _a: 3600.0),
            patch("ori.hal.mqtt_base.ABANDONED_CONNECT_WAIT_S", HOLD_S),
        ):
            tasks = [
                asyncio.create_task(
                    adapter.connect(
                        {
                            **mqtt_config(topic=f"fixture/{index}"),
                            "broker_host": "127.0.0.1",
                            "port": port,
                        }
                    )
                )
                for index, adapter in enumerate(adapters)
            ]
            await wait_until(lambda: len(entered) >= 2, what="both workers to connect")
            for task in tasks:
                task.cancel()
            release.set()
            # Each cancelled connect awaits only the attempts that started; a
            # queued one it waited on would hold it for the whole bound.
            await settle(tasks, what="the cancelled connects", deadline_s=DEADLINE_S)
            closing = asyncio.gather(*(adapter.close() for adapter in adapters))
            await settle({closing}, what="every close", deadline_s=DEADLINE_S)
        assert len(entered) <= len(adapters)
        assert not any(adapter._abandoned_connects for adapter in adapters)
        assert all(sock.fileno() == -1 for sock in built), "a started socket is open"
        await wait_until(lambda: len(readers) == len(built), what="every connection")
        for reader in readers:
            await wait_until(lambda r=reader: _closed_by_peer(r), what="peer EOF")
    finally:
        release.set()
        await asyncio.gather(*(adapter.close() for adapter in adapters))
        for writer in peers:
            writer.close()
        server.close()
        await server.wait_closed()
        executor.shutdown(wait=True)


_EXIT_SCRIPT = textwrap.dedent(
    """
    import asyncio, socket, threading, time
    from concurrent.futures import ThreadPoolExecutor
    from unittest.mock import patch
    import paho.mqtt.client as paho
    from ori.hal.mqtt_adapter import MqttAdapter

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    original = paho.Client._create_socket_connection
    calls = [0]

    def gated(client):
        calls[0] += 1
        if calls[0] == 1:
            raise ConnectionRefusedError(61, "broker down")
        entered.set()
        release.wait(30)
        try:
            return original(client)
        finally:
            finished.set()

    loop = asyncio.new_event_loop()
    loop.set_default_executor(ThreadPoolExecutor(max_workers=1))
    adapter = MqttAdapter()
    config = {
        "sensor_type": "temperature", "broker_host": "127.0.0.1", "port": port,
        "topic": "fixture",
    }

    async def abandon():
        await adapter.connect(config)
        async with asyncio.timeout(30):
            while not entered.is_set():
                await asyncio.sleep(0.001)
        await adapter.close()

    with (
        patch.object(paho.Client, "_create_socket_connection", gated),
        patch("ori.hal.mqtt_base.reconnect_delay", lambda _a: 0.001),
        patch("ori.hal.mqtt_base.ABANDONED_CONNECT_WAIT_S", 0.01),
    ):
        loop.run_until_complete(abandon())
        release.set()
        finished.wait(30)
    # The loop is stopped and still open, and the attempt abandoned.
    print(time.time(), flush=True)
    """
)


def test_an_abandoned_attempt_does_not_delay_interpreter_exit(tmp_path: Path) -> None:
    script = tmp_path / "abandon_and_exit.py"
    script.write_text(_EXIT_SCRIPT, encoding="utf-8")
    completed = supervised_process.run(
        [sys.executable, "-B", str(script)],
        timeout=120,
        capture_output=True,
        cwd=str(REPO),
        env={"PYTHONPATH": str(REPO), "PATH": "/usr/bin:/bin"},
    )
    exited_at = time.time()
    assert completed.returncode == 0, completed.stderr
    reached_end = float(completed.stdout.decode().strip().splitlines()[-1])
    assert exited_at - reached_end < 10.0, (
        f"exit took {exited_at - reached_end:.1f}s after the script ended"
    )


def _completes_in_a_thread(body: Any) -> bool:
    """Whether *body* returns, run on a daemon thread a deadlock cannot hold."""
    done = threading.Event()

    def run() -> None:
        body()
        done.set()

    threading.Thread(target=run, daemon=True).start()
    return done.wait(DEADLINE_S)


def test_a_hand_over_reentered_from_a_finalizer_does_not_deadlock() -> None:
    """Garbage collection can finalize an abandoned connect, which hands over,
    on a thread already inside the reaper's lock."""
    reaper = mqtt_base._AbandonedSocketReaper()
    stub = _StubWatch()

    def nested() -> None:
        with reaper._lock:
            reaper.hand_over(stub)  # type: ignore[arg-type]

    try:
        with patch("ori.hal.mqtt_base.REAPER_POLL_S", 0.01):
            assert _completes_in_a_thread(nested), "the reaper's lock deadlocked"
            _wait_sync(lambda: stub.sock.fileno() == -1, what="the stub reaped")
    finally:
        stub.sock.close()
        stub.peer.close()


def test_an_abandon_reentered_under_the_watch_lock_does_not_deadlock() -> None:
    loop = asyncio.new_event_loop()
    try:

        async def make() -> Any:
            client = SimpleNamespace(_client_connect=lambda: None)
            return mqtt_base._ConnectWatch.install(client, "test")

        watch = loop.run_until_complete(make())

        def nested() -> None:
            with watch._lock:
                watch.abandon()

        assert _completes_in_a_thread(nested), "the watch's lock deadlocked"
    finally:
        loop.close()


def _close_inside_a_running_loop(coro: Any) -> RuntimeError | None:
    """Close *coro* as a finalizer would while another loop runs in the thread.

    A coroutine that awaits during its close suspends there, and `close()`
    raises `RuntimeError: coroutine ignored GeneratorExit` at once.
    """

    async def close() -> RuntimeError | None:
        try:
            coro.close()
        except RuntimeError as exc:
            # "coroutine ignored GeneratorExit": reported for the assertion.
            return exc
        return None

    return asyncio.run(close())


def test_a_connect_closed_while_paho_connects_awaits_nothing(own_loop: Any) -> None:
    own_loop.gate = _GatedConnect(own_loop.paho, fail_first=False)
    loop = own_loop.loop
    port = own_loop.listener.getsockname()[1]
    with own_loop.patched():
        task = loop.create_task(
            own_loop.adapter.connect(
                {**mqtt_config(), "broker_host": "127.0.0.1", "port": port}
            )
        )
        loop.run_until_complete(
            wait_until(own_loop.gate.entered.is_set, what="the connect to reach paho")
        )
        task._log_destroy_pending = False  # type: ignore[attr-defined]
        assert _close_inside_a_running_loop(task.get_coro()) is None
        own_loop.gate.release.set()
        loop.close()
        _wait_sync(
            lambda: (
                own_loop.gate.socket is not None and own_loop.gate.socket.fileno() == -1
            ),
            what="the abandoned socket to be closed",
        )


async def test_a_connect_closed_while_subscribing_awaits_nothing() -> None:
    subscribing = asyncio.Event()
    clients: list[Any] = []

    class _Hanging(_FakeClient):
        async def subscribe(self, topic: str) -> Any:
            subscribing.set()
            await asyncio.Event().wait()

        async def __aexit__(self, *exc: Any) -> None:
            # A real disconnect suspends; a close must not wait for it.
            await asyncio.sleep(0)
            self.closed = True

    def build(**kwargs: Any) -> Any:
        client = _Hanging(**kwargs)
        clients.append(client)
        return client

    adapter = MqttAdapter()
    with (
        patch("ori.hal.mqtt_base._AIOMQTT_AVAILABLE", True),
        patch("ori.hal.mqtt_base._aiomqtt", SimpleNamespace(Client=build)),
    ):
        coro = adapter.connect(mqtt_config())
        task = asyncio.ensure_future(coro)
        await wait_until(subscribing.is_set, what="the connect to subscribe")
        task._log_destroy_pending = False  # type: ignore[attr-defined]
        # The task cannot be closed under its own running loop, so the
        # coroutine is closed from a thread, as a finalizer elsewhere would.
        failure = await asyncio.to_thread(_close_inside_a_running_loop, coro)
    assert failure is None, failure
    assert adapter._client is None


async def test_a_connect_closed_while_subscribing_leaves_no_stale_writer() -> None:
    """SUBSCRIBE queues its own `add_writer` through `call_soon_threadsafe`.
    A connect coroutine closed before that runs must not free the descriptor
    under it, or the writer lands on whatever socket reuses the number."""
    paho = pytest.importorskip("paho.mqtt.client")
    loop = asyncio.get_running_loop()
    writers: list[asyncio.StreamWriter] = []
    held: list[asyncio.StreamReader] = []

    async def connack_only(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        writers.append(writer)
        held.append(reader)
        kind, _ = await _read_packet(reader)
        assert kind == 1, "expected CONNECT"
        writer.write(b"\x20\x02\x00\x00")
        await writer.drain()

    server = await asyncio.start_server(connack_only, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    adapter = MqttAdapter()
    coro = adapter.connect({**mqtt_config(), "broker_host": "127.0.0.1", "port": port})
    task = asyncio.ensure_future(coro)
    task._log_destroy_pending = False  # type: ignore[attr-defined]
    loop_thread = threading.get_ident()
    original = paho.Client._call_socket_register_write
    pair: list[socket.socket] = []
    late: list[int] = []

    def close_then_reuse() -> None:
        coro.close()
        left, right = socket.socketpair()
        pair.extend([left, right])

    def register_write(client: Any) -> None:
        if threading.get_ident() == loop_thread and not late and client._sock:
            # The SUBSCRIBE write: queue the close ahead of aiomqtt's own
            # `add_writer`, so it runs once the coroutine has suspended.
            late.append(client._sock.fileno())
            loop.call_soon(close_then_reuse)
        original(client)

    try:
        with patch.object(paho.Client, "_call_socket_register_write", register_write):
            await wait_until(
                lambda: pair, what="the connect to be closed mid-subscribe"
            )
            for _ in range(20):
                await asyncio.sleep(0)
        (old_fd,) = late
        new_fds = {sock.fileno() for sock in pair}
        for fd in new_fds:
            assert not loop.remove_writer(fd), "a stale writer took over a reused fd"
            assert not loop.remove_reader(fd), "a stale reader took over a reused fd"
        if old_fd not in new_fds:
            assert not loop.remove_writer(old_fd) and not loop.remove_reader(old_fd)
        await wait_until(lambda: _closed_by_peer(held[0]), what="the broker to see EOF")
    finally:
        await adapter.close()
        for sock in pair:
            sock.close()
        for writer in writers:
            writer.close()
        server.close()
        await server.wait_closed()
