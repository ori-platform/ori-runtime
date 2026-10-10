# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""What the operator is told about a firmware reading's time.

Driven from a signed envelope through the real ingest gate, into the Tier C
approval request the dispatcher composes. The device reports no measurement
time, so "Measured" says so. Only this runtime, having signed the liveness
nonce the reading carries, adds how long ago the device polled, and always
with the wall-clock instant it computed that bound.
"""

from __future__ import annotations

import ast
import base64
import copy
import functools
import re
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ori.network.events import OriEvent
from ori.reasoning.action_dispatcher import ActionDispatcher
from ori.reasoning.elevator import SkillContext
from ori.security.firmware.ingest import FirmwareTelemetryGate
from ori.security.firmware.liveness import (
    FirmwareLivenessSigner,
    FirmwareLivenessSupervisor,
)
from ori.security.firmware.reading_age import (
    LivenessTable,
    ReadingAgeTracker,
    measured_statement,
)
from ori.state.store import StateStore
from tests.firmware.test_telemetry import (
    CASES,
    SEALED_HASH,
    provision_and_approve,
    signed_envelope,
)
from tests.test_action_dispatcher import FakeSkill, _result
from tests.waiting import drained

DEVICE = "ori-fw-7c9f2b3a"
SECOND = 1_000_000_000


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


def _envelope(*, nonce: str | None, version: int = 2) -> dict[str, Any]:
    envelope = copy.deepcopy(CASES["telemetry_single_reading"]["input"])
    if version == 2:
        envelope["v"] = 2
        envelope["liveness_nonce"] = nonce
    return signed_envelope(envelope)


async def _approval_body(
    store: StateStore, *, nonce_state: str, version: int = 2
) -> tuple[str, _Clock]:
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
    held = {"signed": nonce.group(1).decode(), "null": None, "unknown": "ab" * 16}[
        nonce_state
    ]

    clock.now += 4 * SECOND  # the device's buffer, the broker, the queue
    verification, readings = await gate.ingest(
        _envelope(nonce=held, version=version), received_at_ms=1_752_537_600_000
    )
    assert verification.accepted, verification.error_code
    clock.now += 2 * SECOND  # reasoning, before the request is composed

    sender = AsyncMock()
    dispatcher = ActionDispatcher(
        state_store=store,
        alert_sender=sender,
        config={"operator_contact": "+234800000000", "device_timezone": "UTC"},
        measured_time=functools.partial(measured_statement, tracker),
    )
    dispatcher.register_executor("terminate_process", AsyncMock())
    event = OriEvent.from_reading(readings[0], device_id=DEVICE)
    context = SkillContext(
        skill=FakeSkill(), event=event, state_store=None, trigger_name="t"
    )
    with patch.object(
        dispatcher, "_listen_for_response", new=AsyncMock(return_value="NO")
    ):
        await dispatcher.dispatch(
            "terminate_process",
            "C",
            context,
            _result(action_tier="C"),
            approval_timeout_seconds=10,
        )
    await drained(dispatcher)
    return sender.send.await_args.kwargs["alert"].sms_body, clock


async def test_a_bounded_firmware_reading_says_when_it_was_polled_and_as_of_when(
    store,
) -> None:
    body, _clock = await _approval_body(store, nonce_state="signed")
    match = re.search(
        r"^Measured: not reported by device, polled no more than (\d+) s ago, "
        r"as of (\w+ \d\d:\d\d:\d\d)$",
        body,
        re.MULTILINE,
    )
    assert match, body
    # Signed at 50 s, composed at 56 s: six seconds, never the time since receipt.
    assert match.group(1) == "6"
    assert "Detected: " in body


@pytest.mark.parametrize(
    ("nonce_state", "version"),
    [("null", 2), ("unknown", 2), ("signed", 1)],
    ids=["null_nonce", "nonce_this_runtime_never_signed", "v1_envelope"],
)
async def test_an_unbounded_firmware_reading_claims_no_time(
    store, nonce_state: str, version: int
) -> None:
    body, _clock = await _approval_body(store, nonce_state=nonce_state, version=version)
    assert re.search(r"^Measured: not reported by device$", body, re.MULTILINE), body
    assert "polled" not in body


def test_every_approval_message_is_composed_with_its_reading() -> None:
    """Both approval workflows pass the reading, or a firmware reading would show receipt as measurement."""
    source = Path(ActionDispatcher.__module__.replace(".", "/") + ".py")
    tree = ast.parse(Path(__file__).resolve().parents[2].joinpath(source).read_text())
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "_format_approval_message"
    ]
    assert len(calls) >= 2
    for call in calls:
        assert "reading" in {k.arg for k in call.keywords}, (
            f"line {call.lineno}: _format_approval_message without reading=; this "
            "guard sees only calls by that name, not a message composed elsewhere"
        )


def test_a_statement_that_cannot_be_composed_claims_no_time() -> None:
    def broken(_reading: Any, _timezone: str) -> str | None:
        raise RuntimeError("tracker unavailable")

    dispatcher = ActionDispatcher(
        state_store=None, alert_sender=AsyncMock(), measured_time=broken
    )
    body = dispatcher._format_approval_message(
        device_id="dev",
        timestamp_ms=1_752_537_600_000,
        result=_result(action_tier="C"),
        action="open_protected_circuit",
        timeout_seconds=30,
        device_timezone="UTC",
        received_at_ms=1_752_537_600_000,
        reading=object(),
    )
    assert re.search(r"^Measured: unavailable$", body, re.MULTILINE), body


def test_the_runtime_wires_the_statement_into_its_dispatcher() -> None:
    """The dispatcher reads no provenance; the runtime hands it the firmware statement."""
    source = Path(__file__).resolve().parents[2].joinpath("ori/runtime.py").read_text()
    assert "functools.partial(measured_statement, reading_age)" in source


def test_a_reading_that_reports_its_own_time_keeps_it_under_the_firmware_statement() -> (
    None
):
    """The statement replaces Measured only for a firmware reading."""
    from ori.network.events import SensorReading

    tracker = ReadingAgeTracker(LivenessTable(per_device_bound=8, total_bound=64))
    dispatcher = ActionDispatcher(
        state_store=None,
        alert_sender=AsyncMock(),
        measured_time=functools.partial(measured_statement, tracker),
    )
    measured_ms = 1_752_537_600_000
    local = SensorReading(
        sensor_id="cpu",
        sensor_type="cpu_percent",
        value=99.0,
        unit="percent",
        timestamp=measured_ms,
        quality=1.0,
        metadata={"source": "psutil"},
    )
    body = dispatcher._format_approval_message(
        device_id="dev",
        timestamp_ms=measured_ms,
        result=_result(action_tier="C"),
        action="open_protected_circuit",
        timeout_seconds=30,
        device_timezone="UTC",
        received_at_ms=measured_ms + 60_000,
        reading=local,
    )
    expected = ActionDispatcher._format_local_time(measured_ms, "UTC")
    assert f"Measured: {expected}\n" in body, body


async def test_a_rotated_key_reusing_counters_never_lends_its_bound_to_the_old_reading(
    store,
) -> None:
    """A new key epoch restarts (boot_id, seq); each message keeps its own signing start."""
    from ori.security.firmware.telemetry import canonical_json_bytes
    from tests.firmware.test_telemetry import signed_manifest_for_key

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

    def nonce_for(capability_hash: str, boot_id: int) -> str:
        message = signer.sign_liveness_v2_bytes(
            device_id=DEVICE,
            boot_id=boot_id,
            capability_hash=capability_hash,
            runtime_seq=1,
        )
        found = re.search(rb'"nonce":"([0-9a-f]{32})"', message)
        assert found is not None
        return found.group(1).decode()

    old_body = copy.deepcopy(CASES["telemetry_single_reading"]["input"])
    old_body.update(v=2, liveness_nonce=nonce_for(SEALED_HASH, old_body["boot_id"]))
    clock.now += 100 * SECOND
    old_verification, old_readings = await gate.ingest(
        signed_envelope(old_body), received_at_ms=1
    )
    assert old_verification.accepted, old_verification.error_code

    sealed = {
        "posture": "sealed_flash",
        "secure_boot_enabled": True,
        "flash_encryption_enabled": True,
        "key_storage": "efuse_derived",
    }
    new_seed = bytes([0x55]) * 32
    manifest = signed_manifest_for_key(new_seed, device_id=DEVICE, **sealed)
    new_hash = await gate.reprovision_device(
        device_id=DEVICE,
        public_key_b64=manifest["public_key_b64"],
        posture="sealed_flash",
        manifest_message=manifest,
        actor="op",
        reason="key rotation",
    )
    assert await gate.approve_device(DEVICE, actor="op", reason="rotation")

    new_body = copy.deepcopy(old_body)
    new_body.update(
        capability_hash=new_hash,
        liveness_nonce=nonce_for(new_hash, old_body["boot_id"]),
    )
    clock.now += 1 * SECOND
    signature = Ed25519PrivateKey.from_private_bytes(new_seed).sign(
        canonical_json_bytes(new_body)
    )
    new_message = {
        "envelope": new_body,
        "signature": "ed25519:" + base64.b64encode(signature).decode(),
    }
    new_verification, new_readings = await gate.ingest(new_message, received_at_ms=2)
    assert new_verification.accepted, new_verification.error_code
    assert (new_verification.boot_id, new_verification.seq) == (
        old_verification.boot_id,
        old_verification.seq,
    )
    old_epoch = old_readings[0].metadata["key_epoch_id"]
    new_epoch = new_readings[0].metadata["key_epoch_id"]
    assert old_epoch != new_epoch

    old_line = measured_statement(tracker, old_readings[0], "UTC")
    new_line = measured_statement(tracker, new_readings[0], "UTC")
    assert old_line and old_line.startswith(
        "not reported by device, polled no more than 101 s ago"
    )
    assert new_line and new_line.startswith(
        "not reported by device, polled no more than 1 s ago"
    )
    # The lookup alarm snapshots use names the message by its key epoch too.
    boot_seq = (old_verification.boot_id, old_verification.seq)
    old_bound = tracker.message_bound(DEVICE, old_epoch, *boot_seq)
    new_bound = tracker.message_bound(DEVICE, new_epoch, *boot_seq)
    assert old_bound and new_bound and old_bound.age_upper_ms == 101_000
    assert new_bound.age_upper_ms == 1_000
    # A reading that names no key epoch gets no bound at all.
    del old_readings[0].metadata["key_epoch_id"]
    assert (
        measured_statement(tracker, old_readings[0], "UTC") == "not reported by device"
    )


def test_a_pause_between_the_two_clock_reads_lengthens_the_bound() -> None:
    """T is read before the last monotonic sample, so A at T is never understated."""
    mono = [0]
    wall_at_read = 1_752_537_600_000

    def wall() -> int:
        mono[0] += 100 * SECOND  # the host suspends between the two reads
        return wall_at_read

    table = LivenessTable(per_device_bound=8, total_bound=64)
    tracker = ReadingAgeTracker(table, clock=lambda: mono[0], wall_ms=wall)
    signer = FirmwareLivenessSigner(
        None,
        bytes([0x11]) * 32,
        supervisor=FirmwareLivenessSupervisor(),
        table=table,
        clock=lambda: mono[0],
    )
    message = signer.sign_liveness_v2_bytes(
        device_id=DEVICE, boot_id=41, capability_hash=SEALED_HASH, runtime_seq=1
    )
    found = re.search(rb'"nonce":"([0-9a-f]{32})"', message)
    assert found is not None
    mono[0] = 10 * SECOND
    tracker.note_accepted(
        version=2,
        device_id=DEVICE,
        boot_id=41,
        capability_hash=SEALED_HASH,
        seq=1,
        channels=["ch0"],
        liveness_nonce=found.group(1).decode(),
        key_epoch_id="k1",
    )
    from types import SimpleNamespace

    reading = SimpleNamespace(
        metadata={
            "source": "firmware",
            "firmware_device_id": DEVICE,
            "key_epoch_id": "k1",
            "boot_id": 41,
            "seq": 1,
        }
    )
    # Operator message: at T the poll was at least 110 s before, never 10 s.
    line = measured_statement(tracker, reading, "UTC")
    assert line is not None and "polled no more than 110 s ago" in line, line
    # Health: the same rule, and T is the wall reading taken first.
    [device] = tracker.health()
    assert device["liveness_bound"]["age_upper_ms"] == 210_000
    assert device["liveness_bound"]["as_of"].startswith("2025-07-15T00:00:00")
