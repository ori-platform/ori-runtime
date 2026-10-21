# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""firmware-telemetry/v2 Layer 1 evidence families, at the subscriber.

A payload carries exactly one family key beside its signature, decided on the
keys before any inner object is read. Only `envelope` and `fault` are consumed;
the other three are not acted on, so none of them can supervise a device.
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
from types import SimpleNamespace
from typing import Any

import pytest

from ori.gateway.firmware_telemetry import (
    CONSUMED_FAMILIES,
    MqttFirmwareTelemetrySubscriber,
)
from ori.security.firmware.ingest import FirmwareTelemetryGate
from ori.security.firmware.liveness import FirmwareLivenessSupervisor
from ori.security.firmware.telemetry import FAMILY_KEYS, payload_family
from ori.state.store import StateStore
from tests.firmware.test_envelope_vectors_v2 import ACCEPTED, _wire
from tests.firmware.test_liveness_composition import _fakebus
from tests.firmware.test_telemetry import provision_and_approve


def test_the_families_are_the_contracts() -> None:
    # Transcribed from firmware-telemetry/v2.md, not derived from the code.
    assert FAMILY_KEYS == {
        "envelope",
        "fault",
        "maintenance_event",
        "result",
        "command_result",
    }
    assert CONSUMED_FAMILIES == {"envelope", "fault"}


@pytest.mark.parametrize("family", sorted(FAMILY_KEYS))
def test_each_family_alone_is_its_family(family: str) -> None:
    assert payload_family({family: {}, "signature": "ed25519:x"}) == family


@pytest.mark.parametrize(
    "payload",
    [
        {"envelope": {}, "fault": {}, "signature": "s"},
        {"envelope": {}, "command_result": {}, "signature": "s"},
        {"envelope": {}, "extra": 1, "signature": "s"},
        {"Envelope": {}, "signature": "s"},
        {"envelope": {}},
        {"signature": "s"},
        {},
    ],
    ids=[
        "two_families",
        "envelope_and_command_result",
        "extra_key",
        "case_variant",
        "no_signature",
        "no_family",
        "empty",
    ],
)
def test_anything_but_exactly_one_family_is_refused(payload: dict[str, Any]) -> None:
    assert payload_family(payload) is None


class _Route:
    def __init__(self, subscriber: MqttFirmwareTelemetrySubscriber) -> None:
        self.calls: list[str] = []

        def spy(name: str) -> Any:
            async def ingest(_payload: dict[str, Any]) -> None:
                return None

            def record(payload: dict[str, Any]) -> Any:
                self.calls.append(name)
                return ingest(payload)

            return record

        subscriber._ingest_telemetry = spy("envelope")  # type: ignore[method-assign]
        subscriber._ingest_fault = spy("fault")  # type: ignore[method-assign]


def _subscriber() -> MqttFirmwareTelemetrySubscriber:
    return MqttFirmwareTelemetrySubscriber(
        broker_url="mqtt://127.0.0.1:1",
        telemetry_gate=SimpleNamespace(),  # type: ignore[arg-type]
        event_bus=_fakebus(),
        state_store=SimpleNamespace(),  # type: ignore[arg-type]
        runtime_device_id="runtime-01",
        liveness_supervisor=FirmwareLivenessSupervisor(),
        client_factory=lambda **_: None,
    )


async def _deliver(payload: dict[str, Any]) -> list[str]:
    subscriber = _subscriber()
    route = _Route(subscriber)
    subscriber._loop = asyncio.get_running_loop()
    message = SimpleNamespace(payload=json.dumps(payload).encode())
    await asyncio.to_thread(subscriber._on_message, None, None, message)
    return route.calls


@pytest.mark.parametrize("family", sorted(CONSUMED_FAMILIES))
async def test_a_consumed_family_reaches_its_own_ingest(family: str) -> None:
    assert await _deliver({family: {}, "signature": "s"}) == [family]


@pytest.mark.parametrize("family", sorted(FAMILY_KEYS - CONSUMED_FAMILIES))
async def test_an_unadopted_family_reaches_no_ingest(family: str) -> None:
    assert await _deliver({family: {}, "signature": "s"}) == []


@pytest.mark.parametrize(
    "payload",
    [
        {"envelope": {}, "fault": {}, "signature": "s"},
        {"fault": {}, "envelope": {}, "signature": "s"},
        {"envelope": {}, "command_result": {}, "signature": "s"},
        {"envelope": {}, "extra": 1, "signature": "s"},
    ],
)
async def test_a_payload_with_more_than_one_key_is_never_routed_by_its_first(
    payload: dict[str, Any],
) -> None:
    assert await _deliver(payload) == []


async def test_refusals_are_reported_coalesced(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A sender can repeat a refused payload at will; the log line does not."""
    subscriber = _subscriber()
    route = _Route(subscriber)
    subscriber._loop = asyncio.get_running_loop()
    refused = json.dumps({"envelope": {}, "fault": {}, "signature": "s"}).encode()
    with caplog.at_level(logging.WARNING, logger="ori.gateway.firmware_telemetry"):
        for _ in range(5):
            message = SimpleNamespace(payload=refused)
            await asyncio.to_thread(subscriber._on_message, None, None, message)
    assert route.calls == []
    (record,) = [r for r in caplog.records if "Layer 1 family" in r.getMessage()]
    assert record.levelno == logging.WARNING


@pytest.mark.parametrize(
    "extra",
    [{"fault": {}}, {"command_result": {}}, {"junk": 1}],
    ids=["fault", "command_result", "unknown_key"],
)
async def test_the_gate_refuses_a_signed_envelope_beside_another_key(
    tmp_path: Any, extra: dict[str, Any]
) -> None:
    """The gate holds the rule itself; the route is not its only check."""
    store = StateStore(db_path=str(tmp_path / "state.db"))
    await store.open()
    try:
        gate = FirmwareTelemetryGate(store)
        await provision_and_approve(gate, "manifest_full_sealed")
        message = _wire(ACCEPTED[0])
        refused, _ = await gate.ingest(copy.deepcopy(message) | extra)
        assert not refused.accepted
        assert refused.error_code == "invalid_envelope"
        accepted, _ = await gate.ingest(message)
        assert accepted.accepted, "the refusal advanced the freshness mark"
    finally:
        await store.close()
