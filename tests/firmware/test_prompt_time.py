# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""What a skill prompt's {time} says about a reading's time.

A firmware reading is driven from a signed envelope through the real ingest
gate into the prompt the elevator composes. The device reports no
measurement time, so {time} says so and names its arrival at the runtime as
an arrival, adding the liveness bound only where this process signed the nonce.
"""

from __future__ import annotations

import dataclasses
import functools
import re
import textwrap
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from ori.config import Config
from ori.network.events import OriEvent, SensorReading
from ori.reasoning.elevator import IntelligenceElevator
from ori.reasoning.prompt_time import prompt_time
from ori.runtime import OriRuntime
from ori.security.firmware.ingest import FirmwareTelemetryGate
from ori.security.firmware.liveness import (
    FirmwareLivenessSigner,
    FirmwareLivenessSupervisor,
)
from ori.security.firmware.reading_age import (
    LivenessTable,
    ReadingAgeTracker,
    liveness_bound,
)
from ori.skills.hooks_api import HookHistoryAdapter
from ori.skills.os_sandbox import OSSandboxHookRunner
from ori.startup_stages import STARTUP_STAGES, StartupContext
from ori.state.store import StateStore
from tests.firmware.test_reading_age_presentation import DEVICE, SECOND, _envelope
from tests.firmware.test_telemetry import SEALED_HASH, provision_and_approve

RECEIVED_MS = 1_752_537_600_000
RECEIVED = "2025-07-15 00:00:00 UTC"


class _Clock:
    def __init__(self) -> None:
        self.now = 50 * SECOND

    def __call__(self) -> int:
        return self.now


@pytest.fixture
async def store(tmp_path: Path):
    s = StateStore(db_path=str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


def _skill() -> Any:
    return SimpleNamespace(name="s", prompts={"t": "Time: {time}"})


async def _prompt(elevator: IntelligenceElevator, reading: SensorReading) -> str:
    event = OriEvent.from_reading(reading, device_id=DEVICE)
    return await elevator._build_prompt(event, _skill(), None, trigger_name="t")


async def _firmware_prompt(
    store: StateStore, *, nonce_state: str, wired: bool = True
) -> str:
    tracker, reading = await _ingest(store, nonce_state=nonce_state)
    elevator = IntelligenceElevator(
        liveness_bound=functools.partial(liveness_bound, tracker) if wired else None
    )
    return await _prompt(elevator, reading)


async def _ingest(
    store: StateStore, *, nonce_state: str
) -> tuple[ReadingAgeTracker, SensorReading]:
    clock = _Clock()
    table = LivenessTable(per_device_bound=8, total_bound=64)
    tracker = ReadingAgeTracker(table, clock=clock)
    gate = FirmwareTelemetryGate(store, reading_age=tracker)
    await provision_and_approve(gate, "manifest_full_sealed")
    signer = FirmwareLivenessSigner(
        None,
        bytes([0x11]) * 32,
        supervisor=FirmwareLivenessSupervisor(),
        table=table,
        clock=clock,
    )
    message = signer.sign_liveness_v2_bytes(
        device_id=DEVICE, boot_id=41, capability_hash=SEALED_HASH, runtime_seq=1
    )
    nonce = re.search(rb'"nonce":"([0-9a-f]{32})"', message)
    assert nonce is not None
    held = {"signed": nonce.group(1).decode(), "null": None}[nonce_state]

    clock.now += 4 * SECOND  # the device's buffer, the broker, the queue
    verification, readings = await gate.ingest(
        _envelope(nonce=held), received_at_ms=RECEIVED_MS
    )
    assert verification.accepted, verification.error_code
    clock.now += 2 * SECOND  # reasoning, before the prompt is composed
    return tracker, readings[0]


async def test_a_bounded_firmware_reading_names_its_arrival_and_its_bound(
    store,
) -> None:
    prompt = await _firmware_prompt(store, nonce_state="signed")
    match = re.search(
        r"^Time: not reported by device, runtime liveness bound polled no more than "
        r"(\d+) s ago, as of "
        r"(\S+); arrived at the runtime at (.+)$",
        prompt,
        re.MULTILINE,
    )
    assert match, prompt
    assert match.group(1) == "6"
    assert match.group(2).endswith("+00:00")
    assert match.group(3) == RECEIVED


async def test_an_unbounded_firmware_reading_names_only_its_arrival(store) -> None:
    prompt = await _firmware_prompt(store, nonce_state="null")
    assert f"Time: not reported by device; arrived at the runtime at {RECEIVED}\n" in (
        prompt + "\n"
    ), prompt
    assert "polled" not in prompt


async def test_an_elevator_without_the_bound_still_names_the_arrival(store) -> None:
    prompt = await _firmware_prompt(store, nonce_state="signed", wired=False)
    assert f"Time: not reported by device; arrived at the runtime at {RECEIVED}" in (
        prompt
    ), prompt
    assert "polled" not in prompt


def _reading(producer_time: str) -> SensorReading:
    return SensorReading(
        sensor_id="cpu",
        sensor_type="cpu_percent",
        value=99.0,
        unit="percent",
        timestamp=RECEIVED_MS,
        quality=1.0,
        metadata={"source": "psutil"},
        producer_time=producer_time,
    )


async def test_a_reported_time_is_shown_as_the_measurement() -> None:
    prompt = await _prompt(IntelligenceElevator(), _reading("reported"))
    assert f"Time: {RECEIVED}" in prompt, prompt
    assert "received" not in prompt


async def test_a_time_of_unstated_basis_is_not_shown() -> None:
    prompt = await _prompt(IntelligenceElevator(), _reading("unknown"))
    assert "Time: not stated" in prompt, prompt
    assert "2025-07-15" not in prompt


async def test_an_arrival_time_is_named_as_one() -> None:
    prompt = await _prompt(IntelligenceElevator(), _reading("not_reported"))
    assert f"Time: not reported by device; arrived at the runtime at {RECEIVED}" in (
        prompt
    ), prompt


def test_a_bound_that_cannot_be_computed_is_left_out() -> None:
    def broken(_reading: Any) -> None:
        raise RuntimeError("tracker unavailable")

    stated = prompt_time(_reading("not_reported"), broken)
    assert stated == f"not reported by device; arrived at the runtime at {RECEIVED}"


def _runtime_config(tmp_path: Path) -> Path:
    cfg = tmp_path / "ori.yaml"
    cfg.write_text(
        textwrap.dedent(f"""\
            device:
              id: test-device-01
              name: Test Device
              location: Test Lab
            sensors: []
            skills: []
            reasoning:
              default_tier: rule
            gateway:
              enabled: false
              broker_url: ""
            actions:
              primary_alert_channel: sms
              operator_contact: "+2348000000000"
              whatsapp:
                enabled: false
              sms:
                enabled: false
            database:
              path: {tmp_path / "ori_state.db"}
        """),
        encoding="utf-8",
    )
    return cfg


@pytest.mark.parametrize("with_tracker", [True, False], ids=["firmware", "none"])
async def test_the_reasoning_stage_hands_its_elevator_the_dispatchers_tracker(
    store, tmp_path: Path, with_tracker: bool
) -> None:
    names = [stage.name for stage in STARTUP_STAGES]
    assert names.index("dispatcher") < names.index("reasoning")
    tracker, reading = await _ingest(store, nonce_state="signed")
    cfg = _runtime_config(tmp_path)
    runtime = OriRuntime(config_path=str(cfg))
    runtime._firmware_reading_age = tracker if with_tracker else None
    context = StartupContext()
    context.config = Config.load(str(cfg))
    await runtime._stage_reasoning(context)
    bound = context.elevator._liveness_bound
    if with_tracker:
        assert bound is not None and bound(reading) is not None
    else:
        assert bound is None


@pytest.mark.parametrize(
    "metadata",
    [{"source": "mqtt"}, {"seq": "same"}, {"seq": "1"}, {"boot_id": 41.0}],
    ids=["not_firmware", "float_seq", "text_seq", "float_boot_id"],
)
async def test_a_bound_is_lent_only_to_the_firmware_reading_it_was_signed_for(
    store, metadata: dict[str, Any]
) -> None:
    tracker, reading = await _ingest(store, nonce_state="signed")
    assert liveness_bound(tracker, reading) is not None
    if metadata.get("seq") == "same":
        metadata = {"seq": float(reading.metadata["seq"])}
    other = dataclasses.replace(reading, metadata={**reading.metadata, **metadata})
    assert liveness_bound(tracker, other) is None


def _stored(producer_time: str, value: float) -> SensorReading:
    return dataclasses.replace(_reading(producer_time), value=value, sensor_id="s1")


@pytest.mark.parametrize(
    ("producer_time", "last", "row"),
    [
        ("reported", "1752537600000", '{"value":1.0,"measured_at":1752537600000}'),
        (
            "not_reported",
            '{"arrived_at":1752537600000}',
            '{"value":1.0,"arrived_at":1752537600000}',
        ),
        ("unknown", "null", '{"value":1.0}'),
    ],
)
async def test_a_history_placeholder_names_each_time_by_its_basis(
    store, producer_time: str, last: str, row: str
) -> None:
    await store.append_history(
        OriEvent.from_reading(_stored(producer_time, 1.0), device_id=DEVICE)
    )
    skill = SimpleNamespace(
        name="s",
        prompts={
            "t": "Last: {history.last_timestamp('s1')}\n"
            "Rows: {history.fetch_history('s1', 2)}"
        },
    )
    event = OriEvent.from_reading(_stored("reported", 2.0), device_id=DEVICE)
    prompt = await IntelligenceElevator()._build_prompt(
        event, skill, store, trigger_name="t"
    )
    assert f"Last: {last}\n" in prompt, prompt
    assert f"Rows: [{row}]" in prompt, prompt
    assert '"timestamp"' not in prompt


async def test_the_prompt_never_calls_the_value_current() -> None:
    prompt = await _prompt(IntelligenceElevator(), _reading("not_reported"))
    assert "Value: 99.0 percent" in prompt, prompt
    assert "current" not in prompt.lower()


async def test_both_hook_history_surfaces_return_the_same_rows(
    store, tmp_path: Path
) -> None:
    for basis, value in (("reported", 1.0), ("not_reported", 2.0), ("unknown", 3.0)):
        await store.append_history(
            OriEvent.from_reading(_stored(basis, value), device_id=DEVICE)
        )
    in_process = HookHistoryAdapter(store).fetch_history("s1", limit=3)
    runner = OSSandboxHookRunner(
        hooks_path=tmp_path / "hooks.py",
        state_store=store,
        skill_name="probe",
        os_sandbox_config={},
    )
    isolated = runner._handle_rpc_request(
        {
            "method": "history.fetch_history",
            "params": {"sensor_id": "s1", "limit": 3},
        },
        None,
    )["result"]
    assert isolated == in_process
    assert [row["producer_time"] for row in in_process] == [
        "unknown",
        "not_reported",
        "reported",
    ]
