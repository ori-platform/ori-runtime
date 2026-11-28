# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Every first send holds its outbox row from the retry loop until it settles.

An acceptance that cannot be recorded keeps the row out of this process's
retries, so no alert is sent twice within one process.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import Any

import pytest

from ori.runtime import OriRuntime
from ori.state.store import StateStore
from tests.test_tier_d_failure_notice import (
    _committed,
    _one_retry_pass,
    _runtime,
    _sender,
    _Transport,
)

Send = Callable[[OriRuntime, _Transport], Coroutine[Any, Any, Any]]


async def _ordinary(runtime: OriRuntime, transport: _Transport) -> Any:
    return await runtime._send_or_queue_alert(
        channel="whatsapp",
        message="Overcurrent detected",
        recipient=runtime._operator_contact,
        action_tier="A",
        trigger_name="overcurrent",
        original_ts=1_800_000_000_000,
        received_at_ms=1_800_000_000_000,
        alert_sender=_sender(transport),
        notice_kind="protection_degraded",
    )


async def _safety(runtime: OriRuntime, transport: _Transport) -> Any:
    return await runtime._send_or_queue_safety_alert(
        message="Sensor never connected",
        trigger_name="sensor_absent",
        alert_sender=_sender(transport),
    )


PATHS = pytest.mark.parametrize("send", [_ordinary, _safety], ids=["alert", "safety"])


@pytest.fixture
async def store(tmp_path: Path) -> Any:
    s = StateStore(str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


def _break_recording(store: StateStore, monkeypatch: pytest.MonkeyPatch) -> None:
    async def broken(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("database is locked")

    monkeypatch.setattr(store, "mark_alert_accepted", broken)


@PATHS
async def test_an_acceptance_it_cannot_record_is_not_sent_again(
    store: StateStore, monkeypatch: pytest.MonkeyPatch, send: Send
) -> None:
    runtime, transport = _runtime(store), _Transport(accepted=True)
    _break_recording(store, monkeypatch)
    with pytest.raises(RuntimeError, match="locked"):
        await send(runtime, transport)
    await _one_retry_pass(runtime, transport, passes=5)
    assert len(transport.sent) == 1


@PATHS
async def test_a_repeat_of_an_unrecorded_acceptance_keeps_its_hold(
    store: StateStore, monkeypatch: pytest.MonkeyPatch, send: Send
) -> None:
    runtime, transport = _runtime(store), _Transport(accepted=True)
    _break_recording(store, monkeypatch)
    with pytest.raises(RuntimeError):
        await send(runtime, transport)
    held = dict(runtime._alert_first_attempts)
    assert len(held) == 1
    if send is _ordinary:
        # The same alert again: its row exists, so nothing is sent, and the
        # hold the first send left is not released by this one.
        assert await send(runtime, transport) is True
        assert dict(runtime._alert_first_attempts) == held
    await _one_retry_pass(runtime, transport, passes=3)
    assert len(transport.sent) == 1


@PATHS
async def test_the_retry_loop_leaves_a_row_alone_while_its_first_send_is_held(
    store: StateStore, send: Send
) -> None:
    runtime, transport = _runtime(store), _Transport(accepted=True, held=True)
    sending = asyncio.create_task(send(runtime, transport))
    await asyncio.wait_for(transport.entered.wait(), 5)
    assert _committed(store)
    for _ in range(3):
        assert await runtime._next_retry_batch(10) == []
    transport.release.set()
    assert await asyncio.wait_for(sending, 5) is True
    assert len(transport.sent) == 1
    assert not runtime._alert_first_attempts
    assert await store.get_retryable_alerts(10, mandatory=True) == []


@PATHS
async def test_a_refused_first_send_is_left_to_the_retry_loop(
    store: StateStore, send: Send
) -> None:
    runtime, refusing = _runtime(store), _Transport(accepted=False)
    assert await send(runtime, refusing) is True
    assert not runtime._alert_first_attempts
    accepting = _Transport(accepted=True)
    await _one_retry_pass(runtime, accepting)
    assert len(accepting.sent) == 1


async def test_an_overlapping_send_of_the_same_alert_keeps_the_row_held(
    store: StateStore,
) -> None:
    """The send that finishes first, here one that finds the row already queued,
    does not release the hold the other send still needs."""
    runtime, transport = _runtime(store), _Transport(accepted=True, held=True)
    first = asyncio.create_task(_ordinary(runtime, transport))
    await asyncio.wait_for(transport.entered.wait(), 5)
    assert await _ordinary(runtime, transport) is True  # finds the row queued
    assert await runtime._next_retry_batch(10) == []
    transport.release.set()
    assert await asyncio.wait_for(first, 5) is True
    assert len(transport.sent) == 1
    assert not runtime._alert_first_attempts


def _block_recording(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> asyncio.Event:
    """Recording waits for ever; the returned event is set once it is entered."""
    entered = asyncio.Event()

    async def blocked(*_args: Any, **_kwargs: Any) -> None:
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(store, "mark_alert_accepted", blocked)
    return entered


@PATHS
async def test_a_first_send_cancelled_while_recording_is_not_sent_again(
    store: StateStore, monkeypatch: pytest.MonkeyPatch, send: Send
) -> None:
    runtime, transport = _runtime(store), _Transport(accepted=True)
    entered = _block_recording(store, monkeypatch)
    sending = asyncio.create_task(send(runtime, transport))
    await asyncio.wait_for(entered.wait(), 5)
    sending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await sending
    await _one_retry_pass(runtime, transport, passes=3)
    assert len(transport.sent) == 1


async def test_a_retry_cancelled_while_recording_is_not_sent_again(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A retry loop restarted in the same process leaves the row alone."""
    runtime, transport = _runtime(store), _Transport(accepted=True)
    assert await store.enqueue_alert(
        alert_id="x",
        channel="whatsapp",
        recipient=runtime._operator_contact,
        message="CRITICAL",
        action_tier="A",
        trigger_name="overcurrent",
        original_ts=1,
        notice_kind="protection_degraded",
    )
    entered = _block_recording(store, monkeypatch)
    runtime._alert_outbox_retry_interval_s = 0.01
    loop = asyncio.create_task(runtime._alert_delivery_loop(_sender(transport)))
    await asyncio.wait_for(entered.wait(), 5)
    loop.cancel()
    with pytest.raises(asyncio.CancelledError):
        await loop
    assert len(transport.sent) == 1
    await _one_retry_pass(runtime, transport, passes=3)
    assert len(transport.sent) == 1


@PATHS
async def test_after_a_restart_an_unrecorded_acceptance_is_sent_once_more(
    store: StateStore, monkeypatch: pytest.MonkeyPatch, send: Send
) -> None:
    runtime, transport = _runtime(store), _Transport(accepted=True)
    _break_recording(store, monkeypatch)
    with pytest.raises(RuntimeError):
        await send(runtime, transport)
    monkeypatch.undo()  # the restarted process records normally
    await _one_retry_pass(_runtime(store), transport, passes=3)
    assert len(transport.sent) == 2
    assert await store.get_retryable_alerts(10, mandatory=True) == []
