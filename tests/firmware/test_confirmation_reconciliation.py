# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Outstanding confirmation obligations must resolve without a restart.

`confirm()` was reached from exactly two places: a drain at startup, and the
pre-signing gate on firmware-sourced evidence. That is survivable while
confirmation is a same-process call that either works or does not. Once it
crosses a boundary and arrives asynchronously, a normally approved device with
no firmware traffic waits for a restart, because nothing re-examines the
obligation.

The coordinator is deliberately untouched by this work: an already-confirmed
epoch is left alone, a quarantined one stays terminal, an unreachable store
remains pending rather than optimistic, and attempts are recorded. What was
missing was something to call it again.
"""

from __future__ import annotations

import asyncio

import pytest

from ori.security.firmware.reconciliation import FirmwareConfirmationReconciler


class _Store:
    """Pending obligations, with terminal rows already excluded as the real one does."""

    def __init__(self, pending: list[str] | None = None) -> None:
        self.pending = list(pending or [])
        self.list_calls = 0

    async def list_pending_firmware_confirmations(self, limit: int = 100) -> list[dict]:
        self.list_calls += 1
        return [{"device_id": device_id} for device_id in self.pending]


class _Coordinator:
    def __init__(self, results: dict[str, list[str]] | None = None) -> None:
        self.results = results or {}
        self.calls: list[str] = []
        self.concurrent = 0
        self.peak_concurrent = 0

    async def confirm(self, device_id: str) -> str:
        self.calls.append(device_id)
        self.concurrent += 1
        self.peak_concurrent = max(self.peak_concurrent, self.concurrent)
        try:
            await asyncio.sleep(0)
            outcomes = self.results.get(device_id)
            if not outcomes:
                return "confirmation_pending"
            return outcomes.pop(0) if len(outcomes) > 1 else outcomes[0]
        finally:
            self.concurrent -= 1


def _reconciler(store, coordinator, **kwargs):
    kwargs.setdefault("interval_s", 0.01)
    kwargs.setdefault("max_interval_s", 0.04)
    return FirmwareConfirmationReconciler(
        store=store, coordinator=coordinator, **kwargs
    )


# --- one cycle -------------------------------------------------------------


@pytest.mark.asyncio
async def test_nothing_pending_calls_the_coordinator_not_at_all():
    coordinator = _Coordinator()
    confirmed, seen = await _reconciler(_Store([]), coordinator).reconcile_once()
    assert (confirmed, seen) == (0, 0)
    assert coordinator.calls == []


@pytest.mark.asyncio
async def test_several_obligations_for_one_device_collapse_to_one_call():
    store = _Store()
    store.pending = ["dev-a", "dev-a", "dev-b"]
    coordinator = _Coordinator({"dev-a": ["confirmed"], "dev-b": ["confirmed"]})
    confirmed, seen = await _reconciler(store, coordinator).reconcile_once()
    assert coordinator.calls == ["dev-a", "dev-b"]
    assert (confirmed, seen) == (2, 2)


@pytest.mark.asyncio
async def test_one_failing_device_does_not_stop_the_others():
    class _Raising(_Coordinator):
        async def confirm(self, device_id: str) -> str:
            if device_id == "dev-bad":
                raise RuntimeError("evidence store unreachable")
            return await super().confirm(device_id)

    coordinator = _Raising({"dev-a": ["confirmed"], "dev-b": ["confirmed"]})
    store = _Store(["dev-a", "dev-bad", "dev-b"])
    confirmed, seen = await _reconciler(store, coordinator).reconcile_once()
    assert (confirmed, seen) == (2, 3)


@pytest.mark.asyncio
async def test_concurrency_is_bounded():
    """A large pending set must not monopolise the loop the runtime shares."""
    store = _Store([f"dev-{index}" for index in range(20)])
    coordinator = _Coordinator()
    await _reconciler(store, coordinator, max_concurrent=3).reconcile_once()
    assert coordinator.peak_concurrent <= 3


@pytest.mark.asyncio
async def test_an_unlistable_store_yields_no_calls_rather_than_raising():
    class _Broken(_Store):
        async def list_pending_firmware_confirmations(self, limit: int = 100):
            raise RuntimeError("database is locked")

    coordinator = _Coordinator()
    confirmed, seen = await _reconciler(_Broken(), coordinator).reconcile_once()
    assert (confirmed, seen) == (0, 0)
    assert coordinator.calls == []


# --- the loop --------------------------------------------------------------


async def _run_briefly(reconciler, shutdown, seconds=0.12):
    task = asyncio.create_task(reconciler.serve_until(shutdown))
    await asyncio.sleep(seconds)
    shutdown.set()
    reconciler.nudge()
    await asyncio.wait_for(task, timeout=1)


@pytest.mark.asyncio
async def test_a_confirmation_arriving_later_is_acted_on_without_a_restart():
    """The defect: nothing re-examined the obligation between restarts."""
    store = _Store(["dev-a"])
    coordinator = _Coordinator({"dev-a": ["confirmation_pending", "confirmed"]})
    reconciler = _reconciler(store, coordinator)
    shutdown = asyncio.Event()
    await _run_briefly(reconciler, shutdown)
    assert coordinator.calls.count("dev-a") >= 2


@pytest.mark.asyncio
async def test_an_unavailable_store_backs_off_rather_than_hammering():
    store = _Store(["dev-a"])
    coordinator = _Coordinator()  # never confirms
    reconciler = _reconciler(store, coordinator, interval_s=0.01, max_interval_s=0.02)
    shutdown = asyncio.Event()
    await _run_briefly(reconciler, shutdown, seconds=0.15)
    # Without backoff a 10ms interval over 150ms would attempt roughly 15
    # times; doubling to a 20ms ceiling roughly halves that. The bound is
    # loose on purpose so the test asserts backoff, not scheduler precision.
    assert 1 <= coordinator.calls.count("dev-a") <= 12


@pytest.mark.asyncio
async def test_a_nudge_reconciles_without_waiting_out_the_interval():
    """A restored link is new information; the earned backoff no longer applies."""
    store = _Store(["dev-a"])
    coordinator = _Coordinator()
    reconciler = _reconciler(store, coordinator, interval_s=30.0, max_interval_s=30.0)
    shutdown = asyncio.Event()
    task = asyncio.create_task(reconciler.serve_until(shutdown))
    await asyncio.sleep(0)
    reconciler.nudge()
    for _ in range(50):
        if coordinator.calls:
            break
        await asyncio.sleep(0.01)
    shutdown.set()
    reconciler.nudge()
    await asyncio.wait_for(task, timeout=1)
    assert coordinator.calls == ["dev-a"], "nudge should not wait out a 30s interval"


@pytest.mark.asyncio
async def test_terminal_rows_are_never_retried():
    """Confirmed and quarantined epochs leave the pending set and stay gone.

    The store excludes them; this asserts the worker adds no path back in.
    """
    store = _Store(["dev-a"])
    coordinator = _Coordinator({"dev-a": ["confirmed"]})
    reconciler = _reconciler(store, coordinator)
    await reconciler.reconcile_once()
    store.pending = []  # resolved, so the store stops returning it
    await reconciler.reconcile_once()
    assert coordinator.calls == ["dev-a"]


@pytest.mark.asyncio
async def test_shutdown_ends_the_loop_promptly():
    reconciler = _reconciler(
        _Store([]), _Coordinator(), interval_s=30.0, max_interval_s=30.0
    )
    shutdown = asyncio.Event()
    task = asyncio.create_task(reconciler.serve_until(shutdown))
    await asyncio.sleep(0)
    shutdown.set()
    await asyncio.wait_for(task, timeout=1)


# --- construction ----------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"interval_s": 0},
        {"interval_s": -1},
        {"interval_s": 10, "max_interval_s": 5},
        {"max_concurrent": 0},
    ],
)
def test_invalid_configuration_is_refused(kwargs):
    with pytest.raises(ValueError):
        FirmwareConfirmationReconciler(
            store=_Store(), coordinator=_Coordinator(), **kwargs
        )


# --- the reconnect path, end to end ----------------------------------------
#
# The nudge tests above prove the reconciler responds to being woken. They do
# not prove anything wakes it. The reconnect criterion is satisfied by a chain
# — MQTT connect callback, `call_soon_threadsafe`, late-bound runtime
# callback, reconciler — and every link is somewhere a mistake could hide
# while every unit test stayed green.


class _RecordingLoop:
    def __init__(self) -> None:
        self.scheduled: list = []

    def call_soon_threadsafe(self, callback, *args) -> None:
        self.scheduled.append(callback)


def _subscriber_with_hook(on_connected):
    """A subscriber built without touching MQTT or the network."""
    from ori.gateway.firmware_telemetry import MqttFirmwareTelemetrySubscriber

    subscriber = object.__new__(MqttFirmwareTelemetrySubscriber)
    subscriber._topic = "ori/fw/+/telemetry"
    subscriber._qos = 1
    subscriber._on_connected = on_connected
    subscriber._loop = _RecordingLoop()
    return subscriber


class _Client:
    def __init__(self) -> None:
        self.subscribed: list = []

    def subscribe(self, topic, qos=0) -> None:
        self.subscribed.append((topic, qos))


def test_successful_connect_schedules_the_hook_on_the_loop():
    """`_on_connect` runs on the MQTT client's thread, never the event loop."""
    calls: list[int] = []
    subscriber = _subscriber_with_hook(lambda: calls.append(1))
    client = _Client()

    subscriber._on_connect(client, None, None, 0)

    assert client.subscribed == [("ori/fw/+/telemetry", 1)]
    assert subscriber._loop.scheduled, "hook must be handed to the loop"
    for scheduled in subscriber._loop.scheduled:
        scheduled()
    assert calls == [1]


def test_failed_connect_does_not_schedule_the_hook():
    """A refused connection is not a restored link."""
    calls: list[int] = []
    subscriber = _subscriber_with_hook(lambda: calls.append(1))
    client = _Client()

    subscriber._on_connect(client, None, None, 5)

    assert client.subscribed == []
    assert subscriber._loop.scheduled == []
    assert calls == []


def test_connect_without_a_hook_is_harmless():
    subscriber = _subscriber_with_hook(None)
    client = _Client()
    subscriber._on_connect(client, None, None, 0)
    assert client.subscribed == [("ori/fw/+/telemetry", 1)]
    assert subscriber._loop.scheduled == []


def test_runtime_callback_resolves_the_reconciler_when_it_fires():
    """Late binding is the point: the subscriber outlives the unset attribute.

    The telemetry subscriber is constructed before the evidence attestor
    decides whether a reconciler exists at all. A callback that captured the
    attribute at build time would capture None and never recover.
    """
    from ori.runtime import OriRuntime

    runtime = object.__new__(OriRuntime)
    runtime._firmware_confirmation_reconciler = None

    # Built and invoked while the attribute is still unset: must not raise.
    runtime._nudge_firmware_confirmations()

    reconciler = _reconciler(_Store(["dev-a"]), _Coordinator())
    runtime._firmware_confirmation_reconciler = reconciler
    runtime._nudge_firmware_confirmations()

    assert reconciler._wake.is_set()


def test_liveness_stack_forwards_the_callback_to_the_subscriber():
    """A stack that wires each half correctly and connects neither is the
    mistake this construction site exists to prevent."""
    from ori import runtime as runtime_module

    captured: dict = {}

    def _fake_builder(*args, **kwargs):
        captured["on_connected"] = kwargs.get("on_connected")
        return None

    original = runtime_module._build_firmware_telemetry_subscriber
    runtime_module._build_firmware_telemetry_subscriber = _fake_builder
    try:
        sentinel = object()
        runtime_module._build_firmware_liveness_stack(
            _StubConfig(), None, None, None, sentinel
        )
    finally:
        runtime_module._build_firmware_telemetry_subscriber = original

    assert captured["on_connected"] is sentinel


class _StubGatewayCfg:
    enabled = False
    firmware_telemetry: dict = {}
    firmware_commands: dict = {}


class _StubConfig:
    gateway = _StubGatewayCfg()


# --- the configured interval reaches the worker ----------------------------
#
# Rejecting invalid values proves only that the gate exists. These prove the
# value that survives it is the one the worker actually runs on, and that the
# two ends agree about the ceiling.


def test_config_interval_bound_is_the_backoff_ceiling():
    """One number, not two that can drift apart.

    A base interval above the ceiling would make the first delay exceed the
    maximum the backoff may reach, so the documented ceiling would be false
    for that configuration.
    """
    from ori.security.firmware.reconciliation import DEFAULT_MAX_INTERVAL_S

    accepted = _gateway_firmware_commands(DEFAULT_MAX_INTERVAL_S)
    assert accepted["confirmation_retry_interval_s"] == DEFAULT_MAX_INTERVAL_S

    from ori.config import ConfigValidationError

    with pytest.raises(ConfigValidationError) as excinfo:
        _gateway_firmware_commands(DEFAULT_MAX_INTERVAL_S + 0.5)
    assert "confirmation_retry_interval_s" in str(excinfo.value)


def _gateway_firmware_commands(interval):
    """Parse a minimal config and return the normalised firmware_commands."""
    import tempfile
    from pathlib import Path

    import yaml as _yaml

    from ori.config import Config

    document = {
        "device": {"id": "d", "name": "n", "location": "l"},
        "sensors": [
            {
                "id": "cpu",
                "type": "cpu_percent",
                "protocol": "psutil",
                "poll_interval_ms": 1000,
            }
        ],
        "gateway": {
            "enabled": True,
            "broker_url": "mqtt://127.0.0.1:1883",
            "firmware_commands": {"confirmation_retry_interval_s": interval},
        },
    }
    with tempfile.TemporaryDirectory() as workspace:
        path = Path(workspace) / "ori.yaml"
        path.write_text(_yaml.safe_dump(document))
        return Config.load(str(path)).gateway.firmware_commands


@pytest.mark.parametrize("interval", [1.0, 5.0, 120.0, 900.0])
def test_a_configured_interval_runs_the_worker_at_that_interval(interval):
    """Every value config accepts must construct and be the delay used."""
    from ori.security.firmware.reconciliation import DEFAULT_MAX_INTERVAL_S

    parsed = _gateway_firmware_commands(interval)
    reconciler = FirmwareConfirmationReconciler(
        store=_Store(),
        coordinator=_Coordinator(),
        interval_s=parsed["confirmation_retry_interval_s"],
    )
    assert reconciler._interval_s == interval
    assert reconciler._max_interval_s == DEFAULT_MAX_INTERVAL_S
    assert reconciler._interval_s <= reconciler._max_interval_s


def test_the_default_interval_is_the_one_config_applies():
    """The default lives in one place, so config and worker cannot drift."""
    from ori.security.firmware.reconciliation import DEFAULT_INTERVAL_S

    document_default = _gateway_firmware_commands(DEFAULT_INTERVAL_S)
    assert document_default["confirmation_retry_interval_s"] == DEFAULT_INTERVAL_S
    assert (
        FirmwareConfirmationReconciler(
            store=_Store(), coordinator=_Coordinator()
        )._interval_s
        == DEFAULT_INTERVAL_S
    )
