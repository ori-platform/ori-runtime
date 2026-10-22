# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The event loop Tier D runs on never waits on the gateway replay store.

An admission holds the replay cache's lock across its store transaction, on a
worker or paho thread, and that can wait out the store's busy timeout. Every
replay check a receiver on the event loop makes therefore runs off it.
"""

from __future__ import annotations

import ast
import asyncio
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import ori.gateway.reasoning as gateway_reasoning
from ori.gateway.evidence_inbound import (
    EVIDENCE_INBOUND_MESSAGE_TYPE,
    EvidenceInboundRouter,
)
from ori.gateway.evidence_outbound import (
    EVIDENCE_OUTBOUND_ACK_MESSAGE_TYPE,
    EvidenceOutboundAckRouter,
)
from ori.security import gateway_messages
from ori.security.gateway_messages import (
    GatewayMessageAuthConfig,
    GatewayMessageAuthenticator,
    GatewayMessageAuthError,
    ReplayWorkRefusedError,
)
from tests.gateway_auth_helpers import cache_for
from tests.waiting import wait_until

ORI = Path(__file__).resolve().parents[1] / "ori"
DEVICE = "site-a-edge-01"
#: The authenticator's and the replay cache's synchronous entry points: each
#: can wait on the cache's lock.
BLOCKING = {
    "authenticate",
    "verify",
    "verify_broadcast",
    "commit",
    "check",
    "admit",
    "prune",
    "evict_one",
    "floor_ms",
    "refresh",
    "close",
}
RECEIVERS = ("message_auth", "authenticator", "replay_cache")


def _receiver(node: ast.expr) -> str:
    return ast.unparse(node).lower()


def _blocking_calls(source: str, where: str) -> list[str]:
    found: list[str] = []
    for function in ast.walk(ast.parse(source)):
        if not isinstance(function, ast.AsyncFunctionDef):
            continue
        stack: list[ast.AST] = list(function.body)
        while stack:
            node = stack.pop()
            # A nested function or lambda runs where it is called, not here.
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in BLOCKING
                and any(name in _receiver(node.func.value) for name in RECEIVERS)
            ):
                found.append(f"{where}:{node.lineno}")
            stack.extend(ast.iter_child_nodes(node))
    return found


def test_no_coroutine_calls_a_replay_check_on_the_event_loop() -> None:
    found = [
        hit
        for path in sorted(ORI.rglob("*.py"))
        for hit in _blocking_calls(
            path.read_text(encoding="utf-8"), str(path.relative_to(ORI.parent))
        )
    ]
    assert found == [], (
        "a coroutine calls the replay cache's lock-taking methods directly; "
        "use authenticate_async, commit_async or run_off_loop. This scan sees "
        "direct calls on receivers named like the authenticator or the cache; "
        "an alias, a helper or a lock held across one is caught only by the "
        "behavioural tests below."
    )


def test_the_guard_scan_sees_a_direct_call_and_skips_a_nested_one() -> None:
    source = (
        "async def f(self):\n"
        "    self._message_auth.authenticate(p)\n"
        "    self._replay_cache.floor_ms()\n"
        "    def g():\n"
        "        self._message_auth.commit(c)\n"
    )
    assert _blocking_calls(source, "x") == ["x:3", "x:2"]


def _authenticator(tmp_path: Path) -> GatewayMessageAuthenticator:
    config = GatewayMessageAuthConfig(shared_secret="off-the-loop", max_skew_ms=600_000)
    cache = cache_for(config, db_path=str(tmp_path / "state.db"))
    return GatewayMessageAuthenticator(config, replay_cache=cache)


def _record_check_threads(auth: GatewayMessageAuthenticator) -> list[str]:
    cache = auth._replay_cache
    check = cache.check
    threads: list[str] = []

    def recording(key: str, *, signed_at_ms: int) -> str | None:
        threads.append(threading.current_thread().name)
        return check(key, signed_at_ms=signed_at_ms)

    cache.check = recording  # type: ignore[method-assign]
    return threads


async def test_authenticate_async_checks_off_the_loop(tmp_path: Path) -> None:
    auth = _authenticator(tmp_path)
    threads = _record_check_threads(auth)
    envelope = auth.sign(
        {"device_id": DEVICE, "request_id": "r"}, message_type="export_request"
    )
    try:
        await auth.verify_async(
            envelope, message_type="export_request", expected_device_id=DEVICE
        )
    finally:
        auth._replay_cache.close()
    assert threads and all(name.startswith("ori-gateway-replay") for name in threads)


async def test_the_outbound_acknowledgement_route_checks_off_the_loop(
    tmp_path: Path,
) -> None:
    auth = _authenticator(tmp_path)
    threads = _record_check_threads(auth)
    router = EvidenceOutboundAckRouter(
        device_id=DEVICE,
        outbox=None,  # type: ignore[arg-type]
        message_auth=auth,
    )
    envelope = auth.sign(
        {"device_id": DEVICE, "acks": []},
        message_type=EVIDENCE_OUTBOUND_ACK_MESSAGE_TYPE,
    )
    try:
        await router.handle_ack(json.dumps(envelope))
    except Exception:  # noqa: BLE001 - only where the check ran is asserted
        pass
    finally:
        auth._replay_cache.close()
    assert threads and all(name.startswith("ori-gateway-replay") for name in threads)


async def test_the_inbound_evidence_route_checks_off_the_loop(tmp_path: Path) -> None:
    auth = _authenticator(tmp_path)
    threads = _record_check_threads(auth)
    router = EvidenceInboundRouter(device_id=DEVICE, ingest=None, message_auth=auth)
    envelope = auth.sign(
        {"device_id": DEVICE, "artifact_type": "custody", "artifact": {}},
        message_type=EVIDENCE_INBOUND_MESSAGE_TYPE,
    )
    try:
        await router.route(json.dumps(envelope).encode())
    finally:
        auth._replay_cache.close()
    assert threads and all(name.startswith("ori-gateway-replay") for name in threads)


async def test_the_loop_runs_while_another_thread_holds_the_cache(
    tmp_path: Path,
) -> None:
    """An admission on another thread holds the lock: the loop keeps running.

    Load-proof: the order is what is asserted, not a duration. Were the loop
    blocked, the holder's own timeout would release the lock first.
    """
    auth = _authenticator(tmp_path)
    router = EvidenceOutboundAckRouter(
        device_id=DEVICE,
        outbox=None,  # type: ignore[arg-type]
        message_auth=auth,
    )
    envelope = json.dumps(
        auth.sign(
            {"device_id": DEVICE, "acks": []},
            message_type=EVIDENCE_OUTBOUND_ACK_MESSAGE_TYPE,
        )
    )
    held, release = threading.Event(), threading.Event()
    order: list[str] = []

    def hold() -> None:
        with auth._replay_cache._lock:
            held.set()
            release.wait(5)
            order.append("released")

    holder = threading.Thread(target=hold)
    holder.start()
    assert held.wait(5)
    routed = asyncio.ensure_future(router.handle_ack(envelope))
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    order.append("loop ran")
    release.set()
    try:
        await routed
    except Exception:  # noqa: BLE001 - only the order is asserted
        pass
    holder.join(5)
    auth._replay_cache.close()
    assert order == ["loop ran", "released"]


async def test_without_a_store_the_check_stays_on_the_loop() -> None:
    """Memory alone never waits on a store, so no thread is spent on it."""
    config = GatewayMessageAuthConfig(shared_secret="off-the-loop", max_skew_ms=600_000)
    auth = GatewayMessageAuthenticator(config, replay_cache=cache_for(config))
    assert not auth.persists_replay_keys
    threads = _record_check_threads(auth)
    envelope = auth.sign(
        {"device_id": DEVICE, "request_id": "r"}, message_type="export_request"
    )
    await auth.verify_async(
        envelope, message_type="export_request", expected_device_id=DEVICE
    )
    assert threads == [threading.current_thread().name]


async def test_the_replay_thread_is_not_the_default_executor(tmp_path: Path) -> None:
    """Every default-executor worker blocked: replay work still runs."""
    loop = asyncio.get_running_loop()
    pool = ThreadPoolExecutor(max_workers=1)
    loop.set_default_executor(pool)
    blocked, release = threading.Event(), threading.Event()

    def occupy() -> None:
        blocked.set()
        release.wait(5)

    occupied = loop.run_in_executor(None, occupy)
    assert blocked.wait(5)
    auth = _authenticator(tmp_path)
    envelope = auth.sign(
        {"device_id": DEVICE, "request_id": "r"}, message_type="export_request"
    )
    try:
        payload = await asyncio.wait_for(
            auth.verify_async(
                envelope, message_type="export_request", expected_device_id=DEVICE
            ),
            timeout=5,
        )
        assert release.is_set() is False and payload["request_id"] == "r"
    finally:
        release.set()
        _ = await occupied
        auth._replay_cache.close()


async def test_replay_work_past_the_ceiling_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gateway_messages, "_REPLAY_WORK_CEILING", 1)
    auth = _authenticator(tmp_path)
    started, release = threading.Event(), threading.Event()

    def busy() -> bool:
        started.set()
        return release.wait(5)

    held = asyncio.ensure_future(auth.run_off_loop(busy))
    assert await asyncio.to_thread(started.wait, 5)
    envelope = auth.sign(
        {"device_id": DEVICE, "request_id": "r"}, message_type="export_request"
    )
    try:
        with pytest.raises(GatewayMessageAuthError, match="replay_store_busy"):
            await auth.verify_async(
                envelope, message_type="export_request", expected_device_id=DEVICE
            )
    finally:
        release.set()
        _ = await held
        auth._replay_cache.close()


async def test_a_closed_cache_refuses_replay_work_and_cancels_what_waits(
    tmp_path: Path,
) -> None:
    auth = _authenticator(tmp_path)
    cache = auth._replay_cache
    started, release = threading.Event(), threading.Event()
    ran: list[str] = []

    def busy() -> bool:
        started.set()
        return release.wait(5)

    held = asyncio.ensure_future(cache.run_off_loop(busy))
    assert await asyncio.to_thread(started.wait, 5)
    queued = asyncio.ensure_future(cache.run_off_loop(ran.append, "queued"))
    await asyncio.sleep(0)
    cache.close()
    release.set()
    _ = await held
    with pytest.raises(asyncio.CancelledError):
        _ = await queued
    with pytest.raises(ReplayWorkRefusedError):
        await cache.run_off_loop(ran.append, "after")
    assert ran == []


class _Message:
    def __init__(self, payload: dict) -> None:
        self.payload = json.dumps(payload).encode("utf-8")


class _AnsweringClient:
    """Answers from a thread of its own, as paho's network thread does."""

    def __init__(self, answer: Any) -> None:
        self.answer = answer
        self.on_connect = self.on_message = self.on_subscribe = None
        self.thread: threading.Thread | None = None
        self.stopped = self.disconnected = False

    def connect(self, *_args: Any) -> None:
        return None

    def loop_start(self) -> None:
        self.on_connect(self, None, None, 0)  # type: ignore[misc]

    def subscribe(self, _topic: str, qos: int = 0) -> tuple[int, int]:
        if self.on_subscribe is not None:
            self.on_subscribe(self, None, 1, [qos], None)
        return (0, 1)

    def publish(self, _topic: str, payload: bytes, *_args: Any) -> Any:
        request = json.loads(payload.decode("utf-8"))
        message = _Message(self.answer(request))
        self.thread = threading.Thread(
            target=self.on_message,
            args=(self, None, message),  # type: ignore[arg-type]
        )
        self.thread.start()
        return SimpleNamespace(rc=0)

    def loop_stop(self) -> None:
        self.stopped = True

    def disconnect(self) -> None:
        self.disconnected = True


def _reasoning_rig(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Any, GatewayMessageAuthenticator, _AnsweringClient]:

    monkeypatch.setattr(gateway_reasoning, "_PAHO_AVAILABLE", True)
    monkeypatch.setattr(gateway_reasoning, "mqtt", object())
    auth = _authenticator(tmp_path)
    config = GatewayMessageAuthConfig(shared_secret="off-the-loop", max_skew_ms=600_000)
    gateway = GatewayMessageAuthenticator(config, replay_cache=cache_for(config))

    def answer(request: dict) -> dict:
        return gateway.sign(
            {
                "request_id": request["request_id"],
                "device_id": request["device_id"],
                "text": "answer",
                "model": "gateway",
                "tokens_used": 1,
                "latency_ms": 1,
                "confidence": 0.1,
                "action_tier": "A",
                "proposed_action": None,
            },
            message_type="reasoning_response",
        )

    client = _AnsweringClient(answer)
    reasoner = gateway_reasoning.MqttGatewayReasoner(
        broker_url="mqtt://broker.local",
        device_id=DEVICE,
        timeout_ms=200,
        client_factory=lambda **_: client,
        request_id_factory=lambda: "req",
        message_auth=auth,
    )
    return reasoner, auth, client


_RULE = SimpleNamespace(rule_name="r", action_tier="A", action="alert_sms")


async def test_the_loop_runs_while_a_reasoning_answer_is_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The record waits on the store; the round trip waits for it off the loop.

    Load-proof: the loop is shown to run during the record by order alone.
    """
    reasoner, auth, client = _reasoning_rig(tmp_path, monkeypatch)
    cache = auth._replay_cache
    admit = cache.admit
    recording, release = threading.Event(), threading.Event()
    order: list[str] = []

    def slow_admit(*args: Any, **kwargs: Any) -> str | None:
        recording.set()
        if not release.wait(5):
            order.append("record gave up waiting")
        order.append("recorded")
        return admit(*args, **kwargs)

    cache.admit = slow_admit  # type: ignore[method-assign]
    round_trip = asyncio.ensure_future(
        reasoner.reason("Prompt", event=None, rule_result=_RULE)
    )
    try:
        assert await asyncio.to_thread(recording.wait, 5)
        # The round trip's own wait ends while the record is held; the loop
        # still runs.
        await asyncio.sleep(0.3)
        order.append("loop ran")
        release.set()
        try:
            await asyncio.wait_for(round_trip, timeout=30)
        except Exception:  # noqa: BLE001 - the timeout or the answer; order is asserted
            pass
        order.append("round trip ended")
    finally:
        release.set()
        if client.thread is not None:
            client.thread.join(5)
        cache.close()
    assert order == ["loop ran", "recorded", "round trip ended"]


async def test_an_answer_whose_round_trip_ended_records_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """gateway-api/v2 Payload Volume: a response with no pending request adds
    no state, even when it was authenticated while the request was pending."""

    reasoner, auth, client = _reasoning_rig(tmp_path, monkeypatch)
    cache = auth._replay_cache
    check = cache.check
    checking, release = threading.Event(), threading.Event()

    def slow_check(key: str, *, signed_at_ms: int) -> str | None:
        checking.set()
        release.wait(5)
        return check(key, signed_at_ms=signed_at_ms)

    cache.check = slow_check  # type: ignore[method-assign]
    try:
        with pytest.raises(gateway_reasoning.GatewayReasoningError, match="timeout"):
            await reasoner.reason("Prompt", event=None, rule_result=_RULE)
        assert checking.is_set()
    finally:
        release.set()
        if client.thread is not None:
            client.thread.join(5)
    try:
        assert cache._held == {}
        rows = await asyncio.to_thread(
            lambda: (
                __import__("sqlite3")
                .connect(tmp_path / "state.db")
                .execute("SELECT COUNT(*) FROM gateway_replay_cache")
                .fetchone()[0]
            )
        )
        assert rows == 0
    finally:
        cache.close()


async def test_a_below_floor_answer_is_not_logged_as_a_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:

    reasoner, auth, client = _reasoning_rig(tmp_path, monkeypatch)
    cache = auth._replay_cache
    cache._start_floor = 2**52  # every answer is below the floor
    try:
        with (
            caplog.at_level("WARNING"),
            pytest.raises(gateway_reasoning.GatewayReasoningError),
        ):
            await reasoner.reason("Prompt", event=None, rule_result=_RULE)
    finally:
        if client.thread is not None:
            client.thread.join(5)
        cache.close()
    assert "a below-the-replay-floor response" in caplog.text
    assert "a replayed response" not in caplog.text


async def test_replay_work_admitted_past_the_ceiling_in_sequence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Finished work leaves the ceiling: sequential checks are never refused."""
    monkeypatch.setattr(gateway_messages, "_REPLAY_WORK_CEILING", 2)
    auth = _authenticator(tmp_path)
    try:
        for index in range(5):
            envelope = auth.sign(
                {"device_id": DEVICE, "request_id": f"r{index}"},
                message_type="export_request",
            )
            await auth.verify_async(
                envelope, message_type="export_request", expected_device_id=DEVICE
            )
    finally:
        auth._replay_cache.close()


async def test_a_cancelled_round_trip_still_ends_after_the_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cancelled mid-record, the round trip ends only once the record has.

    Load-proof: the order of the two ends is asserted, never a duration. The
    record lingers after release so a round trip that did not wait for it
    would end first.
    """
    import time

    reasoner, auth, client = _reasoning_rig(tmp_path, monkeypatch)
    cache = auth._replay_cache
    admit = cache.admit
    recording, release = threading.Event(), threading.Event()
    order: list[str] = []

    def slow_admit(*args: Any, **kwargs: Any) -> str | None:
        recording.set()
        release.wait(5)
        time.sleep(0.3)
        order.append("recorded")
        return admit(*args, **kwargs)

    cache.admit = slow_admit  # type: ignore[method-assign]
    round_trip = asyncio.ensure_future(
        reasoner.reason("Prompt", event=None, rule_result=_RULE)
    )
    round_trip.add_done_callback(lambda _done: order.append("round trip ended"))
    try:
        assert await asyncio.to_thread(recording.wait, 5)
        round_trip.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(round_trip, timeout=30)
    finally:
        release.set()
        if client.thread is not None:
            client.thread.join(5)
        cache.close()
    assert order == ["recorded", "round trip ended"]
    assert client.stopped and client.disconnected


async def test_closing_the_cache_mid_record_does_not_hang_the_round_trip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Shutdown closes the cache while an answer is being recorded."""
    reasoner, auth, client = _reasoning_rig(tmp_path, monkeypatch)
    cache = auth._replay_cache
    admit = cache.admit
    recording, release = threading.Event(), threading.Event()

    def slow_admit(*args: Any, **kwargs: Any) -> str | None:
        recording.set()
        release.wait(5)
        return admit(*args, **kwargs)

    cache.admit = slow_admit  # type: ignore[method-assign]
    round_trip = asyncio.ensure_future(
        reasoner.reason("Prompt", event=None, rule_result=_RULE)
    )
    try:
        assert await asyncio.to_thread(recording.wait, 5)
        await asyncio.to_thread(cache.close)
        release.set()
        try:
            await asyncio.wait_for(round_trip, timeout=10)
        except GatewayMessageAuthError:
            raise
        except Exception:  # noqa: BLE001 - any end but a hang
            pass
    finally:
        release.set()
        if client.thread is not None:
            client.thread.join(5)
    assert round_trip.done() and client.disconnected


async def test_waiting_for_a_record_occupies_no_shared_thread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With one default-executor worker, other work still runs while the
    round trip waits for an answer's record."""
    loop = asyncio.get_running_loop()
    loop.set_default_executor(ThreadPoolExecutor(max_workers=1))
    reasoner, auth, client = _reasoning_rig(tmp_path, monkeypatch)
    cache = auth._replay_cache
    admit = cache.admit
    recording, release = threading.Event(), threading.Event()

    def slow_admit(*args: Any, **kwargs: Any) -> str | None:
        recording.set()
        release.wait(5)
        return admit(*args, **kwargs)

    cache.admit = slow_admit  # type: ignore[method-assign]
    round_trip = asyncio.ensure_future(
        reasoner.reason("Prompt", event=None, rule_result=_RULE)
    )
    try:
        while not recording.is_set():
            await asyncio.sleep(0.01)
        # Past the round trip's own wait, it is now waiting for the record.
        await asyncio.sleep(0.3)
        assert not round_trip.done()
        assert (
            await asyncio.wait_for(loop.run_in_executor(None, lambda: "ran"), 5)
            == "ran"
        )
    finally:
        release.set()
        try:
            await asyncio.wait_for(round_trip, timeout=30)
        except Exception:  # noqa: BLE001 - the timeout or the answer
            pass
        if client.thread is not None:
            client.thread.join(5)
        cache.close()


async def test_a_cancellation_during_teardown_still_disconnects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reasoner, auth, client = _reasoning_rig(tmp_path, monkeypatch)
    stopping, release = threading.Event(), threading.Event()

    def slow_stop() -> None:
        stopping.set()
        release.wait(5)
        client.stopped = True

    client.loop_stop = slow_stop  # type: ignore[method-assign]
    round_trip = asyncio.ensure_future(
        reasoner.reason("Prompt", event=None, rule_result=_RULE)
    )
    try:
        assert await asyncio.to_thread(stopping.wait, 5)
        round_trip.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(round_trip, timeout=30)
    finally:
        release.set()
        if client.thread is not None:
            client.thread.join(5)
        auth._replay_cache.close()
    assert client.stopped and client.disconnected


def test_loop_shutdown_mid_teardown_still_disconnects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`asyncio.run` returns while `loop_stop` blocks: its shutdown cancels
    every task, and the client is still disconnected."""
    reasoner, auth, client = _reasoning_rig(tmp_path, monkeypatch)
    stopping, release = threading.Event(), threading.Event()

    def slow_stop() -> None:
        stopping.set()
        release.wait(5)
        client.stopped = True

    client.loop_stop = slow_stop  # type: ignore[method-assign]

    async def main() -> None:
        asyncio.ensure_future(reasoner.reason("Prompt", event=None, rule_result=_RULE))
        await asyncio.to_thread(stopping.wait, 5)

    try:
        asyncio.run(main())
        assert stopping.is_set()
    finally:
        release.set()
        for thread in threading.enumerate():
            if thread.name == "ori-gateway-reasoning-teardown":
                thread.join(5)
        if client.thread is not None:
            client.thread.join(5)
        auth._replay_cache.close()
    assert client.stopped and client.disconnected


async def test_teardown_joining_an_authenticating_callback_occupies_no_shared_thread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    loop = asyncio.get_running_loop()
    loop.set_default_executor(ThreadPoolExecutor(max_workers=1))
    reasoner, auth, client = _reasoning_rig(tmp_path, monkeypatch)
    cache = auth._replay_cache
    check = cache.check
    checking, release = threading.Event(), threading.Event()

    def slow_check(key: str, *, signed_at_ms: int) -> str | None:
        checking.set()
        release.wait(15)
        return check(key, signed_at_ms=signed_at_ms)

    def joining_stop() -> None:
        # As paho's loop_stop does: join the network thread.
        if client.thread is not None:
            client.thread.join(20)
        client.stopped = True

    cache.check = slow_check  # type: ignore[method-assign]
    client.loop_stop = joining_stop  # type: ignore[method-assign]
    round_trip = asyncio.ensure_future(
        reasoner.reason("Prompt", event=None, rule_result=_RULE)
    )
    try:
        # Polled on the loop: the one default worker must stay free.
        await wait_until(checking.is_set, what="the answer reaching its replay check")
        await asyncio.sleep(0.3)  # past the round trip's wait: teardown joins
        assert (
            await asyncio.wait_for(loop.run_in_executor(None, lambda: "ran"), 2)
            == "ran"
        )
    finally:
        release.set()
        try:
            await asyncio.wait_for(round_trip, timeout=30)
        except Exception:  # noqa: BLE001 - the timeout; only isolation is asserted
            pass
        cache.close()
    assert client.disconnected
