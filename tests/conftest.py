# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Test-wide guards.

The suite must not be able to move a physical output. On a developer machine
that is true by accident — gpiozero is absent, so every GPIO path falls back to
simulation. On a Pi it was not true at all: `RelayAction.connect` builds a real
`OutputDevice` whenever gpiozero is importable, so running the suite claimed
BCM 26 and toggled it, and a bench with a relay wired would have actuated.

Safety that depends on a dependency being missing is not safety. The guard here
substitutes gpiozero's output classes with recording fakes, so the tests keep
exercising the real code paths and reach no pin.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
from collections.abc import Callable, Generator, Iterator
from pathlib import Path
from typing import Any

import pytest

#: Set to run against real hardware. Deliberately awkward: an operator who wants
#: a bench test opts in for that run, and nothing acquires the ability by
#: default because a dependency happened to be installed.
ALLOW_GPIO_ENV = "ORI_TEST_ALLOW_REAL_GPIO"

#: Every gpiozero name the runtime constructs. `Device` is absent on purpose:
#: `resolved_pin_factory_name` calls `Device.ensure_pin_factory()` to learn
#: which backend would drive a pin, which opens the chip and claims no line.
#: That answer is what the hardened-posture check needs, and faking it would
#: report a capability the host does not have.
_OUTPUT_CLASSES = ("OutputDevice", "DigitalOutputDevice", "LED", "Buzzer", "PWMLED")


class FakeGPIODevice:
    """Stands in for a gpiozero output, recording instead of driving."""

    def __init__(self, pin: int | str, *args: Any, **kwargs: Any) -> None:
        self.pin = pin
        self.active_high = bool(kwargs.get("active_high", True))
        self.value = float(bool(kwargs.get("initial_value", False)))
        self.closed = False
        self.history: list[str] = []

    def on(self) -> None:
        self.value = 1.0
        self.history.append("on")

    def off(self) -> None:
        self.value = 0.0
        self.history.append("off")

    def toggle(self) -> None:
        self.value = 0.0 if self.value else 1.0
        self.history.append("toggle")

    def close(self) -> None:
        self.closed = True
        self.history.append("close")

    def __repr__(self) -> str:
        return f"FakeGPIODevice(pin={self.pin!r}, value={self.value})"


def _real_gpio_allowed() -> bool:
    return os.environ.get(ALLOW_GPIO_ENV, "").strip().lower() in {"1", "true", "yes"}


def pytest_configure(config: pytest.Config) -> None:
    from tests import action_taken_guard
    from tests.package_layout import hold_reexports

    hold_reexports()
    # Before any fixture, so a session fixture's setup writes under it too.
    action_taken_guard.install()


_LATE_PATCHES_DIR = pytest.StashKey[Path]()
_LATE_PATCHES_KEY = "ori_late_patch_findings"
#: Every worker the controller configured, each of which must leave a file.
_LATE_PATCHES_WORKERS = pytest.StashKey[set[str]]()


@pytest.hookimpl(optionalhook=True)
def pytest_configure_node(node: Any) -> None:
    """Give each xdist worker a place to leave what it found after its last
    test: by then it has already sent the controller its exit status."""
    config = node.config
    if _LATE_PATCHES_DIR not in config.stash:
        left = Path(tempfile.mkdtemp(prefix="ori-late-"))
        config.stash[_LATE_PATCHES_DIR] = left
        config.stash[_LATE_PATCHES_WORKERS] = set()
        config.add_cleanup(lambda: shutil.rmtree(left, ignore_errors=True))
    config.stash[_LATE_PATCHES_WORKERS].add(node.workerinput["workerid"])
    node.workerinput[_LATE_PATCHES_KEY] = str(config.stash[_LATE_PATCHES_DIR])


class _LateCheck:
    """The check after the last test, as a plugin registered when the session
    starts: after every plugin pytest registers while it configures, so its
    wrapper is outside theirs."""

    @pytest.hookimpl(wrapper=True, tryfirst=True)
    def pytest_sessionfinish(self, session: pytest.Session) -> Iterator[None]:
        """Fail the run for what changed after the last test's teardown check,
        where no test's report is left to carry it.

        A worker leaves its findings for the controller, which reads them here,
        after every worker has stopped.
        """
        from tests import action_taken_guard
        from tests.package_layout import begin_phase

        result = yield
        config = session.config
        problems = begin_phase("After the last test")
        # A session fixture's finalizer writes after the last test's check.
        problems += [
            f"After the last test: action_log row outside the vocabulary: {row} "
            f"({action_taken_guard.LIMIT})"
            for row in action_taken_guard.drain()
        ]
        workerinput = getattr(config, "workerinput", None)
        if workerinput is not None and _LATE_PATCHES_KEY in workerinput:
            # Written even when clean: a missing file is a worker that stopped
            # before its check finished, never one that found nothing.
            found = Path(workerinput[_LATE_PATCHES_KEY]) / workerinput["workerid"]
            # Renamed into place whole, so a worker stopped while writing
            # leaves no file rather than an empty one that reads as clean.
            partial = found.with_name(f"{found.name}.partial")
            partial.write_text("\n".join(problems), encoding="utf-8")
            os.replace(partial, found)
            return result
        if _LATE_PATCHES_DIR in config.stash:
            left = config.stash[_LATE_PATCHES_DIR]
            for worker in sorted(config.stash[_LATE_PATCHES_WORKERS]):
                found = left / worker
                if not found.exists():
                    problems.append(
                        f"After the last test: worker {worker} stopped before its "
                        "check of the bindings finished, so what it left is unknown."
                    )
                    continue
                problems += found.read_text(encoding="utf-8").splitlines()
        if problems:
            writer = config.get_terminal_writer()
            writer.line()
            writer.sep("=", "checks after the last test", red=True)
            for problem in problems:
                writer.line(problem, red=True)
            # An interrupted or broken run keeps the status that says so.
            if session.exitstatus in (
                pytest.ExitCode.OK,
                pytest.ExitCode.NO_TESTS_COLLECTED,
            ):
                session.exitstatus = pytest.ExitCode.TESTS_FAILED
        return result


def pytest_sessionstart(session: pytest.Session) -> None:
    session.config.pluginmanager.register(_LateCheck(), "ori-late-patch-check")


def pytest_unconfigure(config: pytest.Config) -> None:
    from tests.package_layout import release_reexports

    release_reexports()


_PATCH_PROBLEMS = pytest.StashKey[dict[str, list[str]]]()


def _patch_problems(item: pytest.Item, when: str, problems: list[str]) -> None:
    item.stash.setdefault(_PATCH_PROBLEMS, {}).setdefault(when, []).extend(problems)


_VOCABULARY_PROBLEMS = pytest.StashKey[dict[str, list[str]]]()


def _vocabulary_rows(item: pytest.Item, when: str, phase: str) -> None:
    """Hold the action-log rows outside the vocabulary written since the last
    drain for *item*'s *when* report (`tests/action_taken_guard.py`)."""
    from tests import action_taken_guard

    rows = [
        f"{phase}: action_log row outside the vocabulary: {row} "
        f"({action_taken_guard.LIMIT})"
        for row in action_taken_guard.drain()
    ]
    item.stash.setdefault(_VOCABULARY_PROBLEMS, {}).setdefault(when, []).extend(rows)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_setup(item: pytest.Item) -> Iterator[None]:
    """Check the bindings in ``ori.config`` and ``ori.runtime`` a test starts
    from, and what its fixtures' setup changed.

    A write made while a test module was collected is caught at its first test.
    """
    from tests.package_layout import begin_phase

    _patch_problems(item, "setup", begin_phase("Left before this test started"))
    _vocabulary_rows(item, "setup", "Written outside any test")
    try:
        return (yield)
    finally:
        _patch_problems(item, "setup", begin_phase("In setup"))
        _vocabulary_rows(item, "setup", "In setup")


@pytest.hookimpl(wrapper=True)
def pytest_runtest_call(item: pytest.Item) -> Iterator[None]:
    """Check what the test body changed, however soon it was undone."""
    from tests.package_layout import check_bindings

    try:
        return (yield)
    finally:
        _patch_problems(item, "call", check_bindings())
        _vocabulary_rows(item, "call", "In the test body")


@pytest.hookimpl(wrapper=True)
def pytest_runtest_teardown(item: pytest.Item) -> Iterator[None]:
    """Check what fixture teardown changed, a module- or session-scope
    fixture's included, since the last test of its scope runs its teardown."""
    from tests.package_layout import begin_phase, check_bindings

    # Other plugins' hooks run between the call's check and here.
    _patch_problems(item, "teardown", begin_phase("Before teardown"))
    _vocabulary_rows(item, "teardown", "Before teardown")
    try:
        return (yield)
    finally:
        _patch_problems(item, "teardown", check_bindings())
        _vocabulary_rows(item, "teardown", "In teardown")


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_makereport(
    item: pytest.Item, call: pytest.CallInfo[None]
) -> Generator[None, pytest.TestReport, pytest.TestReport]:
    """Fail the phase whose bindings reach no caller, or only some, or that
    wrote an action-log row outside the vocabulary.

    Set on the finished report, outside every other wrapper, so neither
    ``xfail`` nor a skip can turn the refusal into an expected outcome.
    """
    report: pytest.TestReport = yield
    for key, section in (
        (_PATCH_PROBLEMS, "patch targets"),
        (_VOCABULARY_PROBLEMS, "action_taken vocabulary"),
    ):
        problems = item.stash.get(key, {}).pop(call.when, [])
        if not problems:
            continue
        text = "\n".join(problems)
        if report.failed:
            report.sections.append((section, text))
        else:
            report.outcome = "failed"
            report.longrepr = text
        if hasattr(report, "wasxfail"):
            del report.wasxfail
    return report


@pytest.fixture(autouse=True)
def no_real_gpio(monkeypatch: pytest.MonkeyPatch) -> None:
    """Refuse real GPIO for the whole suite unless a run opts in.

    Autouse rather than a marker each hardware test remembers to apply: the
    failure mode is a test that forgets, and a guard you can forget is the one
    already in place — a module-level skip that fires when gpiozero is *absent*,
    which is exactly backwards.
    """
    if _real_gpio_allowed():
        return
    try:
        import gpiozero  # pyright: ignore[reportMissingImports]
    except ImportError:
        return  # Nothing here can reach a pin.

    for name in _OUTPUT_CLASSES:
        if hasattr(gpiozero, name):
            monkeypatch.setattr(gpiozero, name, FakeGPIODevice)


@pytest.fixture(autouse=True)
def no_child_outlives_its_test() -> Iterator[None]:
    """Fail a test that leaves a running child no Supervised holds.

    Whatever spelling started it: the spawn scan in
    `tests/test_supervised_process.py` reads names, and a name can always be
    spelled another way. The leaked child is killed before the test fails.
    """
    yield
    from tests.supervised_process import leaked_children

    leaked = leaked_children()
    if leaked:
        pytest.fail(
            "the test left running children no Supervised holds (killed): "
            + "; ".join(leaked)
        )


def _mark_startup_complete(runtime: Any) -> "asyncio.Event":
    """An event set when `start()` finishes its last step.

    `start()` ends by awaiting the shutdown event, and
    `_send_setup_success_notifications` is the last step it takes before doing
    so, which makes wrapping that step an exact marker rather than a guess.
    The shutdown event itself is not one: several background loops await it
    too, so a waiter on it says nothing about whether startup is done.

    If that step is ever renamed this fails loudly with `AttributeError`
    rather than silently going back to racing.
    """
    complete = asyncio.Event()
    original = runtime._send_setup_success_notifications

    async def _marked(*args: Any, **kwargs: Any) -> Any:
        try:
            return await original(*args, **kwargs)
        finally:
            complete.set()

    runtime._send_setup_success_notifications = _marked
    return complete


async def run_runtime_until(
    runtime: Any,
    reached: Callable[[], bool],
    *,
    description: str,
    timeout: float = 15.0,
) -> None:
    """Start a runtime, wait for a state and for startup, then stop it.

    The pattern this replaces slept for a fixed interval and then stopped:

    ```python
    async def _stop():
        await asyncio.sleep(0.1)
        await runtime.stop()

    await asyncio.gather(runtime.start(), _stop())
    ```

    The sleep is a guess that startup got far enough. When it has not — a
    loaded runner, a slower interpreter — the stop tears down a half-built
    runtime, and the failure does not surface at the test that caused it: it
    surfaces wherever startup happened to be, as an assertion inside an
    unrelated component. One of these failed in CI as a bare `AssertionError`
    sixty lines into the state store, from a pull request that does not touch
    the file containing the test.

    **Waiting for the asserted state is not enough on its own.** That state
    becomes true partway through startup, and `start()` still has adapter
    connections, background services, the webhook, the health socket and
    reconciliation ahead of it. Stopping there closes resources those later
    steps are still using — the same race, entered by observation instead of
    by a guess. So this waits for the state, and then for startup to finish,
    and only then stops.

    Both waits earn their place. The state wait is what fails with a useful
    message when the thing the test asserts on never happens; the startup wait
    is what makes the teardown safe. Neither substitutes for the other, and
    the assertions still hold afterwards because what they read — log records,
    recorded calls — persists past the moment it first became true.
    """
    complete = _mark_startup_complete(runtime)

    async def _stop_when_safe() -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while not reached():
            if loop.time() > deadline:
                raise AssertionError(
                    f"startup did not reach {description} within {timeout}s"
                )
            await asyncio.sleep(0.02)
        await asyncio.wait_for(complete.wait(), timeout=timeout)
        await runtime.stop()

    await asyncio.gather(runtime.start(), _stop_when_safe())


def logged(caplog: Any, fragment: str) -> bool:
    """Whether a log record containing `fragment` has been emitted yet."""
    return any(fragment in record.message for record in caplog.records)


async def run_runtime_full_startup(runtime: Any, *, timeout: float = 15.0) -> None:
    """Start a runtime, let startup finish completely, then stop it.

    For tests whose subject is the lifecycle itself, or which assert that
    something did *not* happen: there is no partial state to wait for, and an
    absence cannot be waited for at all.
    """
    await run_runtime_until(
        runtime,
        lambda: True,
        description="the end of startup",
        timeout=timeout,
    )


SLOW_STARTUP_PROBE_ENV = "ORI_SLOW_STARTUP_PROBE"

# Opt-in harness for slow startup. A test that waits
# for a state rather than an interval must keep passing when startup is slower
# than the interval it used to guess with, and a run on a fast machine is not
# evidence of that:
#
#     ORI_SLOW_STARTUP_PROBE=1 python3 -m pytest tests/test_runtime.py
#
# It slows an early startup phase and a late one. Slowing only the early phase
# moves every wait later together, so a teardown that fires at a partial state
# still lands before the steps that would notice it; the late delay is what
# puts a stop between the state a test waits for and the startup work that
# follows it.
#
# In-tree and opt-in rather than a recipe in a pull request, so the check can
# be run again by whoever next doubts one of these tests.
if os.environ.get(SLOW_STARTUP_PROBE_ENV) == "1":
    from ori.runtime import OriRuntime as _ProbeRuntime
    from ori.state.store import StateStore as _ProbeStore

    _PROBE_DELAY_S = 0.6
    _probe_original_open = _ProbeStore.open
    _probe_original_health_socket = _ProbeRuntime._start_health_socket_if_enabled

    @pytest.fixture(autouse=True)
    def slow_startup_probe(monkeypatch: pytest.MonkeyPatch) -> None:
        async def _slow_open(self: Any, *args: Any, **kwargs: Any) -> Any:
            result = await _probe_original_open(self, *args, **kwargs)
            await asyncio.sleep(_PROBE_DELAY_S)
            return result

        async def _slow_late(self: Any, *args: Any, **kwargs: Any) -> Any:
            await asyncio.sleep(_PROBE_DELAY_S)
            return await _probe_original_health_socket(self, *args, **kwargs)

        monkeypatch.setattr(_ProbeStore, "open", _slow_open)
        monkeypatch.setattr(
            _ProbeRuntime, "_start_health_socket_if_enabled", _slow_late
        )


STALL_ENV = "ORI_TEST_STALL_MS"

# Opt-in loaded-runner simulation. Every iteration of the event loop first
# blocks the loop thread for this many milliseconds, as a runner whose cores
# are busy, or a coverage tracer, takes the loop away from the test:
#
#     ORI_TEST_STALL_MS=3 python3 -m pytest tests/test_tier_c_approval_sequences.py
#
# Wall-clock time then runs ahead of the work the loop gets through: a timer
# shorter than the stall is already due when the loop next looks, so a test
# that sleeps a fixed window, or bounds a wait and carries on when the bound
# runs out, reaches its assertion before the work it asserts on. Such a test
# fails here deterministically rather than once in a while in CI; one that
# waits for the event it asserts (`tests/waiting.py`) only takes longer.
#
# It slows neither threads nor subprocesses, and it cannot make a latency
# bound meaningful; it widens the gap between a window and the work behind it.
_STALL_MS = float(os.environ.get(STALL_ENV, "") or 0)
if _STALL_MS > 0:
    import asyncio.base_events as _base_events
    import time as _time

    _unstalled_run_once = _base_events.BaseEventLoop._run_once  # type: ignore[attr-defined]

    def _stalled_run_once(self: Any) -> None:
        _time.sleep(_STALL_MS / 1000.0)
        _unstalled_run_once(self)

    _base_events.BaseEventLoop._run_once = _stalled_run_once  # type: ignore[attr-defined]


CLOCK_SCALE_ENV = "ORI_TEST_CLOCK_SCALE"

# The same pressure, faster and more repeatable: the event loop's clock runs
# this many times faster than real time, so every timer, timeout and deadline
# on the loop expires that much sooner while threads, subprocesses and the
# store work at their real speed.
#
#     ORI_TEST_CLOCK_SCALE=1000 python3 -m pytest tests/test_tier_c_approval_sequences.py
#
# A window measured on the loop (`asyncio.sleep`, `wait_for`, `asyncio.wait`,
# `loop.time()`) shrinks by the factor; `tests/waiting.py` measures its own
# deadline on the loop too, which the factor shortens alike, so its waits are
# scaled up by it to stay a bound on a hang. Product timers shrink as well, so
# a test that relies on one not expiring before real work completes fails here
# for that reason, not for the one this hunts: read the message.
_CLOCK_SCALE = float(os.environ.get(CLOCK_SCALE_ENV, "") or 0)
if _CLOCK_SCALE > 0:
    import asyncio.base_events as _clock_events
    import time as _clock_time

    _clock_origin = _clock_time.monotonic()

    def _scaled_time(self: Any) -> float:
        return _clock_origin + (_clock_time.monotonic() - _clock_origin) * _CLOCK_SCALE

    _clock_events.BaseEventLoop.time = _scaled_time  # type: ignore[method-assign]
