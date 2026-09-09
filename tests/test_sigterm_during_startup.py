# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""What a stop signal means depends on how far startup has got.

After startup, it stops the runtime. During startup it cannot: `stop()` closes
the state store, the adapters and every server while startup is still building
and using them, so the two are serialised rather than allowed to interleave.
"""

from __future__ import annotations

import asyncio
import textwrap
from pathlib import Path

import pytest

from ori.runtime import OriRuntime


def _runtime() -> OriRuntime:
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._shutdown_event = asyncio.Event()
    return runtime


@pytest.mark.asyncio
async def test_a_signal_during_startup_does_not_tear_down_immediately() -> None:
    """The request is recorded; nothing is closed while startup still runs."""
    runtime = _runtime()
    stopped: list[str] = []
    runtime.stop = lambda: stopped.append("stop")  # type: ignore[method-assign]

    runtime._request_stop()

    assert runtime._stop_requested_during_startup is True
    assert stopped == []


@pytest.mark.asyncio
async def test_a_signal_after_startup_stops_the_runtime() -> None:
    """Once startup is done the signal means what it plainly means."""
    runtime = _runtime()
    runtime._startup_complete = True
    stopped: list[str] = []

    async def _stop() -> None:
        stopped.append("stop")

    runtime.stop = _stop  # type: ignore[method-assign]

    runtime._request_stop()
    await asyncio.sleep(0)

    assert stopped == ["stop"]


@pytest.mark.asyncio
async def test_a_second_signal_during_startup_tears_down_without_a_checkpoint() -> None:
    """Startup can block where no checkpoint is coming, so asking twice works.

    An adapter connect against hardware that never answers is exactly when an
    operator sends the first signal and exactly when the first signal cannot
    be honoured. The second is taken as an instruction, not a repetition.
    """
    runtime = _runtime()
    stopped: list[str] = []

    async def _stop() -> None:
        stopped.append("stop")

    runtime.stop = _stop  # type: ignore[method-assign]

    runtime._request_stop()
    assert stopped == []

    runtime._request_stop()
    await asyncio.sleep(0)

    assert stopped == ["stop"]


@pytest.mark.asyncio
async def test_a_checkpoint_passes_through_when_nothing_asked_to_stop() -> None:
    runtime = _runtime()
    assert await runtime._stop_if_requested_during_startup() is False


@pytest.mark.asyncio
async def test_a_checkpoint_stops_and_tells_startup_to_abandon() -> None:
    runtime = _runtime()
    stopped: list[str] = []

    async def _stop() -> None:
        stopped.append("stop")

    runtime.stop = _stop  # type: ignore[method-assign]
    runtime._stop_requested_during_startup = True

    assert await runtime._stop_if_requested_during_startup() is True
    assert stopped == ["stop"]


def test_startup_checks_the_request_at_several_points() -> None:
    """One checkpoint would leave the rest of startup racing the teardown.

    Read from the source rather than counted in a comment, so removing one
    fails here. The window each closes is the phase it precedes; a single
    checkpoint would only narrow the race, not order the two operations.
    """
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / "ori" / "runtime.py").read_text()
    start = source.index("async def start(")
    end = source.index("def _request_stop(")
    body = source[start:end]

    assert body.count("await self._stop_if_requested_during_startup()") >= 4


def test_startup_acts_on_the_handoff_rather_than_only_calling_it() -> None:
    """`start()` must stop when the handoff says a request is its to honour.

    Calling the handoff and discarding its answer leaves the runtime parked on
    an event that the deferred request never sets, so a stop asked for during
    startup would hang the process instead of ending it. Read from the source
    because driving `start()` needs a device's worth of configuration.
    """
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / "ori" / "runtime.py").read_text()

    assert (
        "if await self._complete_startup():\n            await self.stop()\n            return"
        in source
    )


def test_the_signal_handler_is_not_wired_straight_to_stop() -> None:
    """The handler routes on startup state; wiring it to `stop()` is the defect.

    `loop.add_signal_handler(SIGTERM, lambda: create_task(self.stop()))` is
    what ran teardown concurrently with startup.
    """
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / "ori" / "runtime.py").read_text()

    assert "loop.add_signal_handler(signal.SIGTERM, self._request_stop)" in source
    assert "loop.add_signal_handler(signal.SIGINT, self._request_stop)" in source
    assert "signal.SIGTERM, lambda: asyncio.create_task(self.stop())" not in source


@pytest.mark.asyncio
async def test_a_request_made_during_startup_is_honoured_at_the_handoff() -> None:
    """A stop asked for during startup is not lost when startup finishes."""
    runtime = _runtime()
    runtime._stop_requested_during_startup = True

    assert await runtime._complete_startup() is True
    assert runtime._startup_complete is True


@pytest.mark.asyncio
async def test_the_handoff_claims_nothing_when_no_stop_was_requested() -> None:
    runtime = _runtime()

    assert await runtime._complete_startup() is False
    assert runtime._startup_complete is True


@pytest.mark.asyncio
async def test_the_handoff_does_not_stop_a_runtime_already_stopping() -> None:
    """A teardown already under way is not started a second time."""
    runtime = _runtime()
    runtime._stop_requested_during_startup = True
    runtime._shutdown_event.set()

    assert await runtime._complete_startup() is False


@pytest.mark.asyncio
async def test_the_handoff_opens_the_handler_before_reading_the_request() -> None:
    """No instant may be owned by neither the checkpoints nor the handler.

    Reading the request before raising the flag would leave a gap: a signal
    arriving in it is deferred by a handler that no later checkpoint will
    reach. This asserts the flag is already up while the request is read, by
    signalling from inside the read.
    """
    runtime = _runtime()
    observed: list[bool] = []

    class _Watching:
        def __bool__(self) -> bool:
            # The handler's view at the moment the request is consulted.
            observed.append(runtime._startup_complete)
            return False

    runtime._stop_requested_during_startup = _Watching()  # type: ignore[assignment]

    await runtime._complete_startup()

    assert observed == [True]


@pytest.mark.asyncio
async def test_stop_survives_a_runtime_that_never_started() -> None:
    """The ordering is the fix, but a partial teardown must still not raise."""
    runtime = OriRuntime(config_path="ori.yaml")

    await runtime.stop()

    assert runtime._shutdown_event.is_set()


# --------------------------------------------------------------------------
# The real thing: a signal delivered during a real start()
# --------------------------------------------------------------------------


@pytest.fixture
def startable_config(tmp_path: Path) -> Path:
    """A minimal valid ori.yaml whose startup runs on any machine."""
    skill_dir = tmp_path / "skills" / "test-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "skill.yaml").write_text(
        textwrap.dedent("""\
            name: test-skill
            version: 0.1.0
            author: test
            sensors_required:
              - type: cpu_percent
            triggers:
              - name: high_cpu
                condition: "value > 90"
                action_tier: A
                cooldown_seconds: 0
                escalate_to: local_slm
            actions:
              available:
                - name: alert_whatsapp
                  tier: A
              defaults:
                high_cpu: [alert_whatsapp]
        """),
        encoding="utf-8",
    )
    cfg = tmp_path / "ori.yaml"
    cfg.write_text(
        textwrap.dedent(f"""\
            device:
              id: test-device-01
              name: Test Device
              location: Test Lab
            sensors:
              - id: cpu-sensor
                type: cpu_percent
                protocol: psutil
                poll_interval_ms: 100
            skills:
              - name: test-skill
                version: "0.1.0"
                config: {{}}
            reasoning:
              default_tier: local
              local_model: ""
              model_path: ""
            gateway:
              enabled: false
              broker_url: ""
            actions:
              primary_alert_channel: sms
              whatsapp:
                enabled: false
              sms:
                enabled: false
              relay:
                enabled: false
            skills_dir: {str(tmp_path / "skills")}
            database:
              path: {str(tmp_path / "ori_state.db")}
            logging:
              level: INFO
              file: {str(tmp_path / "ori.log")}
        """),
        encoding="utf-8",
    )
    return cfg


# Three real startup steps, at increasing depth. Named rather than counted, so
# a rename fails here instead of silently testing one phase three times.
EARLY = "_restore_measurement_state"
MIDDLE = "_start_sms_webhook_if_enabled"
LATE = "_reconcile_pending_attestations"


async def _start_with_signal_at(
    runtime: OriRuntime, monkeypatch: pytest.MonkeyPatch, step: str
) -> list[str]:
    """Run a real `start()`, signalling when `step` runs, and trace the order.

    The trace records every startup step that ran after the signal and the
    moment the state store was closed. A teardown that overlapped startup
    would put the close before a step, which is the failure #530 describes and
    the one a test calling private helpers cannot see.
    """
    trace: list[str] = []

    for name in (EARLY, MIDDLE, LATE):
        original = getattr(OriRuntime, name)

        def _traced(self, *args, _name=name, _original=original, **kwargs):
            trace.append(f"step:{_name}")
            if _name == step:
                self._request_stop()
            return _original(self, *args, **kwargs)

        monkeypatch.setattr(OriRuntime, name, _traced)

    real_stop = OriRuntime.stop

    async def _traced_stop(self):
        trace.append("stop")
        return await real_stop(self)

    monkeypatch.setattr(OriRuntime, "stop", _traced_stop)

    await asyncio.wait_for(runtime.start(), timeout=30.0)
    return trace


@pytest.mark.parametrize("step", [EARLY, MIDDLE, LATE])
@pytest.mark.asyncio
async def test_a_signal_during_a_real_startup_stops_without_overlapping_it(
    startable_config: Path, monkeypatch: pytest.MonkeyPatch, step: str
) -> None:
    """A real `start()`, signalled at three depths, must never tear down early.

    The property is ordering, not merely that nothing raised: `stop()` closes
    the state store and the adapters, and every startup step that runs after
    that is using something already closed. So the teardown must come after
    the last step, at every depth the signal can arrive.
    """
    runtime = OriRuntime(config_path=str(startable_config))

    trace = await _start_with_signal_at(runtime, monkeypatch, step)

    assert "stop" in trace, "the signal did not lead to a teardown"
    assert f"step:{step}" in trace, "the step that signals never ran"
    # Nothing from startup may run once the teardown has begun.
    after_stop = trace[trace.index("stop") + 1 :]
    assert [entry for entry in after_stop if entry.startswith("step:")] == []
    assert runtime._shutdown_event.is_set()


@pytest.mark.asyncio
async def test_a_signal_early_in_a_real_startup_skips_the_later_phases(
    startable_config: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unwinding means abandoning the rest, not finishing it first.

    A signal at the first phase that still ran the webhook, the health socket
    and reconciliation would have deferred the stop rather than honoured it,
    and would leave those resources built purely to be torn down.
    """
    runtime = OriRuntime(config_path=str(startable_config))

    trace = await _start_with_signal_at(runtime, monkeypatch, EARLY)

    # The first checkpoint after the signal is the one before the webhook, so
    # neither the middle nor the late phase may run. Asserting only the late
    # one would pass with that checkpoint deleted, because a later checkpoint
    # would catch the same signal a phase further on.
    assert f"step:{MIDDLE}" not in trace
    assert f"step:{LATE}" not in trace
    assert trace.index("stop") < len(trace)


@pytest.mark.asyncio
async def test_a_real_startup_with_no_signal_reaches_its_last_phase(
    startable_config: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The counterpart: without a signal the checkpoints stop nothing.

    Without this, every assertion above would be satisfied by a runtime whose
    startup never got past its first phase for some unrelated reason.
    """
    runtime = OriRuntime(config_path=str(startable_config))

    async def _stop_once_started() -> None:
        for _ in range(1500):
            if runtime._startup_complete:
                await runtime.stop()
                return
            await asyncio.sleep(0.02)
        raise AssertionError("startup never completed")

    trace: list[str] = []
    for name in (EARLY, MIDDLE, LATE):
        original = getattr(OriRuntime, name)

        def _traced(self, *args, _name=name, _original=original, **kwargs):
            trace.append(f"step:{_name}")
            return _original(self, *args, **kwargs)

        monkeypatch.setattr(OriRuntime, name, _traced)

    await asyncio.wait_for(
        asyncio.gather(runtime.start(), _stop_once_started()), timeout=30.0
    )

    assert [f"step:{EARLY}", f"step:{MIDDLE}", f"step:{LATE}"] == [
        entry for entry in trace if entry.startswith("step:")
    ]
