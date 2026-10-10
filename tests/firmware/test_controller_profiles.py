# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""firmware-telemetry/v2 Controller Profiles, driven by ori-specs' profile corpus.

Documents, refusals and byte strings go through the document loader. Every
interpretation, range, agreement and state case goes through the gate a device
reaches: a genuinely signed manifest registered and promoted, then signed
readings and faults ingested, with the lifecycle driven through the gate's own
promotion, rotation, revocation and reinstatement.
"""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ori.hal.base import MeasurementRefusedError, refuse_unusable_reading
from ori.network.events import SensorReading
from ori.security.firmware.controller_profiles import (
    ControllerAlarmTracker,
    ControllerProfileLibrary,
    ProfileGrammarError,
    agreement,
    load_profile_document,
    measurement_in_range,
    silence_bound_ms,
    suspend_counting_clock,
    validate_profile_document,
)
from ori.security.firmware.ingest import FirmwareTelemetryGate
from ori.security.firmware.telemetry import (
    FirmwareVerificationError,
    canonical_json_bytes,
    key_epoch_id,
)
from ori.state.store import StateStore
from tests.firmware.test_telemetry import signed_manifest_for_key

VECTORS = Path(__file__).parent.parent / "vectors" / "firmware_telemetry"
CORPUS = json.loads(
    (VECTORS / "controller-profile-vectors-v2.json").read_text(encoding="utf-8")
)
DOCUMENTS = {case["name"]: case for case in CORPUS["cases"]}
REJECTS = {case["name"]: case for case in CORPUS["reject_cases"]}
REJECT_BYTES = {case["name"]: case for case in CORPUS["reject_bytes"]}
INTERPRETATIONS = {case["name"]: case for case in CORPUS["interpretations"]}
RANGES = {case["name"]: case for case in CORPUS["ranges"]}
AGREEMENTS = {case["name"]: case for case in CORPUS["agreements"]}
STATES = {case["name"]: case for case in CORPUS["states"]}

DEVICE = "ori-fw-cp000001"
ALARM_CHANNEL = "ch3"
MEASURE_CHANNEL = "ch1"


def _document(name: str) -> Any:
    return load_profile_document(bytes.fromhex(DOCUMENTS[name]["canonical_hex"]))


def _library(*names: str) -> ControllerProfileLibrary:
    return ControllerProfileLibrary(_document(name) for name in set(names))


def _seed(epoch: int) -> bytes:
    return bytes([0x42 + epoch]) * 32


def _public_key(epoch: int) -> str:
    raw = Ed25519PrivateKey.from_private_bytes(_seed(epoch)).public_key()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return base64.b64encode(raw.public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def _signed(family: str, body: dict[str, Any], epoch: int) -> dict[str, Any]:
    key = Ed25519PrivateKey.from_private_bytes(_seed(epoch))
    signature = key.sign(canonical_json_bytes(body))
    return {
        family: body,
        "signature": "ed25519:" + base64.b64encode(signature).decode(),
    }


def _bridged(
    channel: str, sensor_type: str, unit: str, binding: dict[str, Any]
) -> dict[str, Any]:
    return {
        "channel": channel,
        "sensor_type": sensor_type,
        "unit": unit,
        "protocol": "modbus_rtu",
        "source": "foreign_device",
        # Above every reading's quality below, so an alarm word below its
        # floor is exercised on every alarm case.
        "quality_floor": 0.9,
        "controller_profile": binding,
    }


def _binding(document: str, profile_channel: str, **over: Any) -> dict[str, Any]:
    case = DOCUMENTS[document]
    binding = {
        "id": case["document"]["id"],
        "digest": case["digest"],
        "profile_channel": profile_channel,
        "qualification": "unqualified",
        "record": None,
    }
    binding.update(over)
    return binding


def _manifest(epoch: int, channels: list[dict[str, Any]], version: int) -> dict:
    return signed_manifest_for_key(
        _seed(epoch),
        device_id=DEVICE,
        device_mode="bridge_node",
        firmware_version=f"0.1.{version}",
        transports=["mqtt", "rs485"],
        channels=channels,
    )


class Device:
    """One device's signed messages and its anchor lifecycle, through the gate."""

    def __init__(
        self,
        store: StateStore,
        library: ControllerProfileLibrary,
        channels: list[dict[str, Any]],
    ) -> None:
        self.store = store
        self.library = library
        self.channels = channels
        self.now = 0
        self.gate = self._gate()
        self.epoch = 0
        self.version = 0
        self.hashes: dict[int, str] = {}
        self.pending: tuple[str, int, str] | None = None

    def _gate(self) -> FirmwareTelemetryGate:
        return FirmwareTelemetryGate(
            self.store,
            profiles=self.library,
            alarms=ControllerAlarmTracker(clock=lambda: self.now),
        )

    async def provision(self) -> None:
        message = _manifest(0, self.channels, self.version)
        await self.gate.register_device(
            device_id=DEVICE,
            public_key_b64=message["public_key_b64"],
            posture="development",
            manifest_message=message,
        )
        assert await self.gate.approve_device(DEVICE, actor="t", reason="t")
        self.hashes[0] = message["manifest_hash"]

    async def stage_manifest(
        self, channels: list[dict[str, Any]] | None = None
    ) -> None:
        self.version += 1
        message = _manifest(self.epoch, channels or self.channels, self.version)
        await self.gate.register_device(
            device_id=DEVICE,
            public_key_b64=_public_key(self.epoch),
            posture="development",
            manifest_message=message,
        )
        self.pending = ("manifest", self.epoch, message["manifest_hash"])

    async def stage_key(self) -> None:
        epoch = self.epoch + 1
        message = _manifest(epoch, self.channels, self.version)
        await self.gate.reprovision_device(
            device_id=DEVICE,
            public_key_b64=message["public_key_b64"],
            posture="development",
            manifest_message=message,
            actor="t",
            reason="rotation",
        )
        self.pending = ("key", epoch, message["manifest_hash"])

    async def promote(self) -> None:
        if self.pending is None:
            row = await self.store.get_firmware_device(DEVICE)
            assert row is not None
            if row["revoked"] or not row["approved"]:
                assert await self.gate.approve_device(DEVICE, actor="t", reason="t")
                return
            await self.stage_manifest()
        assert self.pending is not None
        _kind, epoch, manifest_hash = self.pending
        assert await self.gate.approve_device(DEVICE, actor="t", reason="t")
        self.epoch = epoch
        self.hashes[epoch] = manifest_hash
        self.pending = None

    async def rotate(self) -> None:
        if self.pending is None or self.pending[0] != "key":
            await self.stage_key()
        await self.promote()

    async def revoke(self) -> None:
        assert await self.gate.revoke_device(DEVICE, actor="t", reason="t")
        self.pending = None

    async def reinstate(self) -> None:
        assert await self.gate.reinstate_device(DEVICE, actor="t", reason="t")

    def restart(self) -> None:
        self.gate = self._gate()

    def envelope(
        self,
        *,
        epoch: int,
        boot_id: int,
        seq: int,
        readings: list[dict[str, Any]],
        capability_hash: str | None = None,
        liveness_nonce: str | None | object = ...,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "v": 1,
            "alg": "ed25519",
            "device_id": DEVICE,
            "boot_id": boot_id,
            "seq": seq,
            "capability_hash": capability_hash or self.hashes[epoch],
            "posture": "development",
            "device_uptime_ms": self.now + 1,
            "emitted_at_ms": None,
            "readings": readings,
        }
        if liveness_nonce is not ...:
            body["v"] = 2
            body["liveness_nonce"] = liveness_nonce
        return _signed("envelope", body, epoch)

    def fault(self, *, epoch: int, boot_id: int, seq: int) -> dict[str, Any]:
        body = {
            "v": 2,
            "alg": "ed25519",
            "device_id": DEVICE,
            "boot_id": boot_id,
            "seq": seq,
            "capability_hash": self.hashes[epoch],
            "posture": "development",
            "device_uptime_ms": self.now + 1,
            "code": "sensor_fault",
            "subject": ALARM_CHANNEL,
            "detail": "modbus_timeout",
        }
        return _signed("fault", body, epoch)

    async def alarm_state(self) -> dict[str, Any]:
        states = {state["channel"]: state for state in await self.gate.alarm_states()}
        return states.get(ALARM_CHANNEL, {"state": "unknown"})


def _reading(channel: str, sensor_type: str, unit: str, value: Any) -> dict:
    return {
        "channel": channel,
        "sensor_type": sensor_type,
        "unit": unit,
        "value": value,
        "quality": 0.5,
    }


def _alarm(value: Any) -> dict[str, Any]:
    return _reading(ALARM_CHANNEL, "controller_alarm_word", "bitmask", value)


@pytest.fixture
async def store(tmp_path: Path):
    s = StateStore(db_path=str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


# --- documents ------------------------------------------------------------


def test_the_corpus_is_the_one_the_contract_pins() -> None:
    manifest = json.loads((VECTORS / "MANIFEST.json").read_text(encoding="utf-8"))
    assert (
        manifest["files"]["controller-profile-vectors-v2.json"]
        == "3504e144432b3c8f05f66850c60d974ed44588f175702a0a2f2162dbaa6ea6d3"
    )
    assert len(DOCUMENTS) == 7 and len(REJECTS) == 97 and len(REJECT_BYTES) == 6
    assert len(STATES) == 42


@pytest.mark.parametrize("name", list(DOCUMENTS))
def test_every_document_is_held_with_its_canonical_bytes_and_digest(name: str) -> None:
    case = DOCUMENTS[name]
    assert canonical_json_bytes(case["document"]).hex() == case["canonical_hex"]
    document = _document(name)
    assert document.digest == case["digest"]
    assert document.canonical.hex() == case["canonical_hex"]


@pytest.mark.parametrize("name", list(REJECTS))
def test_every_refused_document_is_refused_by_the_grammar(name: str) -> None:
    document = REJECTS[name]["document"]
    with pytest.raises(ProfileGrammarError) as grammar:
        validate_profile_document(document)
    assert grammar.value.code == "invalid_profile_document"
    # Refused under its own rule, so a missing check cannot hide behind
    # another that happens to fire.
    assert grammar.value.rule == REJECTS[name]["rule"]
    try:
        held = canonical_json_bytes(document)
    except FirmwareVerificationError:
        return
    with pytest.raises(FirmwareVerificationError) as loaded:
        load_profile_document(held)
    assert loaded.value.code == "invalid_profile_document"


@pytest.mark.parametrize("name", list(REJECT_BYTES))
def test_every_non_canonical_byte_string_is_refused_on_its_bytes(name: str) -> None:
    with pytest.raises(FirmwareVerificationError) as refused:
        load_profile_document(bytes.fromhex(REJECT_BYTES[name]["bytes_hex"]))
    assert refused.value.code == "non_canonical_document"


def test_the_digest_is_over_the_bytes_held(tmp_path: Path) -> None:
    held = bytes.fromhex(DOCUMENTS["rectifier"]["canonical_hex"])
    (tmp_path / "rectifier.json").write_bytes(held)
    (tmp_path / "indented.json").write_bytes(
        json.dumps(json.loads(held), indent=2).encode()
    )
    (tmp_path / "duplicate.json").write_bytes(
        bytes.fromhex(REJECT_BYTES["reject_bytes_duplicate_key"]["bytes_hex"])
    )
    (tmp_path / "notes.txt").write_text("not a profile")
    library = ControllerProfileLibrary.from_directory(tmp_path)
    assert library.held() == [
        {"id": "example-rectifier", "digest": DOCUMENTS["rectifier"]["digest"]}
    ]
    assert sorted(library.refused, key=lambda r: r["file"]) == [
        {"file": "duplicate.json", "reason": "non_canonical_document"},
        {"file": "indented.json", "reason": "non_canonical_document"},
        {"file": "notes.txt", "reason": "not_a_json_file"},
    ]


def _canonical_rectifier_with(**channel_override: Any) -> bytes:
    document = json.loads(json.dumps(DOCUMENTS["rectifier"]["document"]))
    document["channels"][0].update(channel_override)
    return canonical_json_bytes(document)


@pytest.mark.parametrize(
    ("name", "content", "reason"),
    [
        ("deep.json", b"[" * 2000 + b"]" * 2000, "non_canonical_document"),
        (
            "surrogate.json",
            b'{"v":"\\ud800"}',  # a lone surrogate escape
            "non_canonical_document",
        ),
        ("function_list.json", None, "invalid_profile_document"),
        ("function_object.json", None, "invalid_profile_document"),
        ("upper.JSON", b"{}", "not_a_json_file"),
    ],
)
def test_no_hostile_file_stops_the_library_loading(
    tmp_path: Path, name: str, content: bytes | None, reason: str
) -> None:
    """The runtime reads this directory at start, before Tier D is running."""
    if content is None:
        content = _canonical_rectifier_with(function=[] if "list" in name else {})
    (tmp_path / name).write_bytes(content)
    (tmp_path / "rectifier.json").write_bytes(
        bytes.fromhex(DOCUMENTS["rectifier"]["canonical_hex"])
    )
    library = ControllerProfileLibrary.from_directory(tmp_path)
    assert library.refused == [{"file": name, "reason": reason}]
    assert len(library.held()) == 1


def test_a_fifo_or_device_is_refused_without_being_read(tmp_path: Path) -> None:
    import os

    os.mkfifo(tmp_path / "pipe.json")
    (tmp_path / "zero.json").symlink_to("/dev/zero")
    (tmp_path / "big.json").write_bytes(b" " * ((1 << 20) + 1))
    (tmp_path / "dir.json").mkdir()
    library = ControllerProfileLibrary.from_directory(tmp_path)
    assert {r["file"] for r in library.refused} == {
        "pipe.json",
        "zero.json",
        "big.json",
        "dir.json",
    }
    assert all(r["reason"].startswith("unreadable") for r in library.refused)


def test_a_directory_path_that_cannot_be_opened_holds_nothing() -> None:
    library = ControllerProfileLibrary.from_directory("pro\x00files")
    assert library.held() == []
    assert library.refused and library.refused[0]["reason"].startswith("unreadable")


def test_a_missing_directory_holds_nothing_and_says_so(tmp_path: Path) -> None:
    library = ControllerProfileLibrary.from_directory(tmp_path / "absent")
    assert library.held() == []
    assert library.refused and library.refused[0]["reason"].startswith("unreadable")
    assert ControllerProfileLibrary.from_directory(None).refused == []


# --- agreement ------------------------------------------------------------


@pytest.mark.parametrize("name", list(AGREEMENTS))
def test_every_agreement_case(name: str) -> None:
    case = AGREEMENTS[name]
    channel = case["manifest_channel"]
    binding = {
        "id": channel["controller_profile_id"],
        "digest": channel["digest"],
        "profile_channel": channel["profile_channel"],
    }
    reason = agreement(_document(case["document"]), binding, channel)
    assert (reason is None) == (case["expected"] == "use")


@pytest.mark.parametrize("name", list(AGREEMENTS))
async def test_every_agreement_case_through_the_gate(
    store: StateStore, name: str
) -> None:
    case = AGREEMENTS[name]
    channel = case["manifest_channel"]
    binding = {
        "id": channel["controller_profile_id"],
        "digest": channel["digest"],
        "profile_channel": channel["profile_channel"],
        "qualification": "unqualified",
        "record": None,
    }
    sensor_type, unit = channel["sensor_type"], channel["unit"]
    alarm = sensor_type == "controller_alarm_word"
    name_ = ALARM_CHANNEL if alarm else MEASURE_CHANNEL
    device = Device(
        store,
        _library(case["document"]),
        [_bridged(name_, sensor_type, unit, binding)],
    )
    await device.provision()
    reading = _reading(name_, sensor_type, unit, 0 if alarm else 0.0)
    if not alarm:
        reading["quality"] = 1.0
    verification, readings = await device.gate.ingest(
        device.envelope(epoch=0, boot_id=1, seq=1, readings=[reading])
    )
    assert verification.accepted
    if alarm:
        assert readings == []
        state = await device.alarm_state()
        status = state.get("reading", state.get("latest_reading", {})).get(
            "profile_status"
        )
    else:
        (reading,) = readings
        status = reading.metadata["controller_profile_status"]
    assert (status == "usable") == (case["expected"] == "use")


# --- interpretation -------------------------------------------------------


def _expected_alarm_view(expected: dict[str, Any]) -> dict[str, Any]:
    return {
        "asserted": sorted(k for k, v in expected["alarms"].items() if v == "asserted"),
        "not_asserted": sorted(
            k for k, v in expected["alarms"].items() if v == "not_asserted"
        ),
        "unmapped_set_bits": expected["unmapped_set_bits"],
    }


@pytest.mark.parametrize("name", list(INTERPRETATIONS))
async def test_every_interpretation_through_the_gate(
    store: StateStore, name: str
) -> None:
    case = INTERPRETATIONS[name]
    binding = _binding(case["document"], case["profile_channel"])
    device = Device(
        store,
        _library(case["document"], case["pinned_document"]),
        [_bridged(ALARM_CHANNEL, "controller_alarm_word", "bitmask", binding)],
    )
    await device.provision()
    if case["registers"] is not None:
        order = DOCUMENTS[case["document"]]["document"]
        word_order = next(
            c for c in order["channels"] if c["name"] == case["profile_channel"]
        )["word_order"]
        regs = case["registers"]
        if len(regs) == 1:
            combined = regs[0]
        else:
            high, low = regs if word_order == "high_first" else regs[::-1]
            combined = (high << 16) | low
        assert combined == case["value"]
    verification, readings = await device.gate.ingest(
        device.envelope(epoch=0, boot_id=1, seq=1, readings=[_alarm(case["value"])])
    )
    assert verification.accepted and readings == []
    # Another document of the same id pinned now changes nothing about a
    # reading accepted under the earlier one.
    if case["pinned_document"] != case["document"]:
        await device.stage_manifest(
            [
                _bridged(
                    ALARM_CHANNEL,
                    "controller_alarm_word",
                    "bitmask",
                    _binding(case["pinned_document"], case["profile_channel"]),
                )
            ]
        )
    state = await device.alarm_state()
    if not case["expected"]["interpreted"]:
        assert state["state"] == "unknown"
        assert state["reason"] == "value_not_a_word"
        assert state["latest_reading"]["seq"] == 1
        return
    assert state["state"] == "as_of"
    assert {
        "asserted": sorted(alarm["id"] for alarm in state["asserted"]),
        "not_asserted": sorted(state["not_asserted_at_that_poll"]),
        "unmapped_set_bits": state["unmapped_set_bits"],
    } == _expected_alarm_view(case["expected"])
    meanings = {
        alarm["id"]: alarm["meaning"]
        for channel in DOCUMENTS[case["document"]]["document"]["channels"]
        for alarm in channel.get("alarms", [])
    }
    assert all(alarm["meaning"] == meanings[alarm["id"]] for alarm in state["asserted"])


# --- ranges ---------------------------------------------------------------


@pytest.mark.parametrize("name", list(RANGES))
def test_every_range_case(name: str) -> None:
    case = RANGES[name]
    channel = _document(case["document"]).channels[case["profile_channel"]]
    assert measurement_in_range(channel, case["value"]) == (
        case["expected"] == "in_range"
    )


@pytest.mark.parametrize("name", list(RANGES))
async def test_every_range_case_through_the_gate(store: StateStore, name: str) -> None:
    case = RANGES[name]
    profile_channel = _document(case["document"]).channels[case["profile_channel"]]
    sensor_type, unit = profile_channel["sensor_type"], profile_channel["unit"]
    device = Device(
        store,
        _library(case["document"], case["pinned_document"]),
        [
            _bridged(
                MEASURE_CHANNEL,
                sensor_type,
                unit,
                _binding(case["document"], case["profile_channel"]),
            )
        ],
    )
    await device.provision()
    reading = _reading(MEASURE_CHANNEL, sensor_type, unit, case["value"])
    reading["quality"] = 1.0
    verification, readings = await device.gate.ingest(
        device.envelope(epoch=0, boot_id=1, seq=1, readings=[reading])
    )
    assert verification.accepted
    assert len(readings) == (1 if case["expected"] == "in_range" else 0)


# --- state ----------------------------------------------------------------


async def _apply(device: Device, event: dict[str, Any]) -> None:
    kind = event["kind"]
    device.now = event["t"]
    if kind in ("reading", "uninterpretable", "pending_reading", "other"):
        if kind == "other":
            readings: list[dict[str, Any]] = []
        else:
            readings = [_alarm(1.5 if kind == "uninterpretable" else 1)]
        capability_hash = None
        if kind == "pending_reading":
            assert device.pending is not None
            capability_hash = device.pending[2]
        await device.gate.ingest(
            device.envelope(
                epoch=event["epoch"],
                boot_id=event["boot_id"],
                seq=event["seq"],
                readings=readings,
                capability_hash=capability_hash,
            )
        )
    elif kind == "fault":
        await device.gate.ingest_fault(
            device.fault(
                epoch=event["epoch"], boot_id=event["boot_id"], seq=event["seq"]
            )
        )
    elif kind == "restart":
        device.restart()
    else:
        await {
            "stage_manifest": device.stage_manifest,
            "stage_key": device.stage_key,
            "promote": device.promote,
            "rotate": device.rotate,
            "revoke": device.revoke,
            "reinstate": device.reinstate,
        }[kind]()


def _state_document(poll_interval_ms: int) -> tuple[ControllerProfileLibrary, dict]:
    """The rectifier at the case's poll interval: the bound is the profile's."""
    document = dict(DOCUMENTS["rectifier"]["document"])
    document["poll_interval_ms"] = poll_interval_ms
    held = load_profile_document(canonical_json_bytes(document))
    binding = {
        "id": held.id,
        "digest": held.digest,
        "profile_channel": "alarm_word_1",
        "qualification": "unqualified",
        "record": None,
    }
    return ControllerProfileLibrary([held]), binding


@pytest.mark.parametrize("name", list(STATES))
async def test_every_state_case_through_the_gate(store: StateStore, name: str) -> None:
    case = STATES[name]
    library, binding = _state_document(case["poll_interval_ms"])
    device = Device(
        store,
        library,
        [_bridged(ALARM_CHANNEL, "controller_alarm_word", "bitmask", binding)],
    )
    await device.provision()
    for event in case["events"]:
        await _apply(device, event)
    device.now = case["query_ms"]
    state = await device.alarm_state()
    expected = case["expected"]
    if expected["state"] == "unknown":
        assert state["state"] == "unknown"
        return
    assert state["state"] == "as_of", state
    assert state["reading"]["key_epoch_id"] == key_epoch_id(
        device_id=DEVICE, public_key_b64=_public_key(expected["epoch"])
    )
    assert (state["reading"]["boot_id"], state["reading"]["seq"]) == (
        expected["boot_id"],
        expected["seq"],
    )


def test_the_bound_is_three_polls_and_thirty_seconds() -> None:
    assert silence_bound_ms(5000) == 45_000
    assert silence_bound_ms(1_190_000) == 3_600_000


def test_the_receiver_clock_counts_suspend_where_the_runtime_ships() -> None:
    import time

    from ori.utils.platform import runtime_platform

    clock = suspend_counting_clock()
    if runtime_platform().startswith("linux"):
        assert clock is not None
        assert abs(clock() - time.clock_gettime_ns(time.CLOCK_BOOTTIME) // 10**6) < 1000
    elif runtime_platform() == "darwin":
        assert clock is not None


def test_without_a_suspend_counting_clock_no_alarm_state_stands() -> None:
    tracker = ControllerAlarmTracker(clock=None)
    tracker._clock = None
    library, binding = _state_document(5000)
    channel = library.get(binding["digest"]).channels["alarm_word_1"]  # type: ignore[union-attr]
    from ori.security.firmware.controller_profiles import interpret_alarm_word

    tracker.note_reading(
        device_id=DEVICE,
        channel=ALARM_CHANNEL,
        activation=("a", 1),
        key_epoch_id="k",
        boot_id=1,
        seq=1,
        received_at_ms=0,
        value=1,
        poll_interval_ms=5000,
        interpretation=interpret_alarm_word(channel, 1),
        not_interpreted="",
        profile=binding,
        profile_status="usable",
    )
    active = {
        "approved": True,
        "revoked": False,
        "anchor_epoch_id": "a",
        "activation_id": 1,
    }
    assert tracker.state(DEVICE, ALARM_CHANNEL, active)["state"] == "unknown"


# --- what an alarm word may never become ----------------------------------


async def test_an_alarm_word_is_never_a_sensor_reading_and_a_shared_one_is_not_read(
    store: StateStore,
) -> None:
    binding = _binding("rectifier", "alarm_word_1")
    measure = _binding(
        "rectifier",
        "output_current",
        qualification="qualified",
        record="controllers/records/example-rectifier.md",
    )
    measure_binding = {**binding, **{k: measure[k] for k in ("profile_channel",)}}
    device = Device(
        store,
        _library("rectifier"),
        [
            _bridged(MEASURE_CHANNEL, "current", "ampere", measure_binding),
            _bridged(ALARM_CHANNEL, "controller_alarm_word", "bitmask", binding),
        ],
    )
    await device.provision()
    alone, readings = await device.gate.ingest(
        device.envelope(epoch=0, boot_id=1, seq=1, readings=[_alarm(9)])
    )
    assert alone.accepted and readings == []
    assert (await device.alarm_state())["state"] == "as_of"

    current = _reading(MEASURE_CHANNEL, "current", "ampere", 12.3)
    current["quality"] = 1.0
    shared, readings = await device.gate.ingest(
        device.envelope(epoch=0, boot_id=1, seq=2, readings=[current, _alarm(0)])
    )
    assert shared.accepted
    assert [r.sensor_type for r in readings] == ["current"]
    state = await device.alarm_state()
    assert state["state"] == "unknown"
    assert state["reason"] == "shared_envelope"
    assert state["latest_reading"]["seq"] == 2


async def test_a_bridged_reading_carries_the_qualification_it_was_accepted_under(
    store: StateStore,
) -> None:
    qualified = _binding(
        "rectifier",
        "output_current",
        qualification="qualified",
        record="controllers/records/example-rectifier.md",
    )
    device = Device(
        store,
        _library("rectifier"),
        [_bridged(MEASURE_CHANNEL, "current", "ampere", qualified)],
    )
    await device.provision()
    reading = _reading(MEASURE_CHANNEL, "current", "ampere", 12.3)
    reading["quality"] = 1.0
    verification, (accepted,) = await device.gate.ingest(
        device.envelope(epoch=0, boot_id=1, seq=1, readings=[reading])
    )
    assert verification.accepted
    assert accepted.metadata["controller_profile"] == qualified
    assert accepted.metadata["controller_profile_status"] == "usable"


async def test_an_unknown_profile_names_no_alarm(store: StateStore) -> None:
    device = Device(
        store,
        ControllerProfileLibrary(),
        [
            _bridged(
                ALARM_CHANNEL,
                "controller_alarm_word",
                "bitmask",
                _binding("rectifier", "alarm_word_1"),
            )
        ],
    )
    await device.provision()
    await device.gate.ingest(
        device.envelope(epoch=0, boot_id=1, seq=1, readings=[_alarm(9)])
    )
    state = await device.alarm_state()
    assert state["state"] == "unknown"
    assert state["reason"] == "profile_unknown"
    assert state["latest_reading"]["word"] == 9
    assert "asserted" not in state


@pytest.mark.parametrize(
    ("sensor_type", "unit"),
    [
        ("controller_alarm_word", "bitmask"),
        ("controller_alarm_word", "count"),
        ("current", "bitmask"),
    ],
)
def test_no_alarm_word_is_ever_evaluated_as_a_measurement(
    sensor_type: str, unit: str
) -> None:
    reading = SensorReading(
        sensor_id="x:ch3",
        sensor_type=sensor_type,
        value=9.0,
        unit=unit,
        timestamp=1,
        quality=1.0,
    )
    with pytest.raises(MeasurementRefusedError):
        refuse_unusable_reading(reading)


async def test_a_reading_from_before_a_revocation_never_stands_after_repromotion(
    store: StateStore,
) -> None:
    """The reinstated anchor is byte-for-byte the revoked one; only its
    activation differs, so that is what a latest reading is scoped to."""
    library, binding = _state_document(5000)
    device = Device(
        store,
        library,
        [_bridged(ALARM_CHANNEL, "controller_alarm_word", "bitmask", binding)],
    )
    await device.provision()
    await device.gate.ingest(
        device.envelope(epoch=0, boot_id=1, seq=1, readings=[_alarm(1)])
    )
    before = await store.get_firmware_device(DEVICE)
    assert (await device.alarm_state())["state"] == "as_of"
    await device.revoke()
    await device.reinstate()
    await device.promote()
    after = await store.get_firmware_device(DEVICE)
    assert before is not None and after is not None
    assert after["anchor_epoch_id"] == before["anchor_epoch_id"]
    assert after["activation_id"] != before["activation_id"]
    assert (await device.alarm_state())["state"] == "unknown"


@pytest.mark.parametrize(
    ("value", "in_range"),
    [(0.0, True), (0.5, True), (1.0, True), (0.1, False), (0.3, False), (1.5, False)],
)
def test_a_value_between_counts_of_a_coarse_scale_is_not_a_decode(
    value: float, in_range: bool
) -> None:
    """At 0.5 per count only every fifth tenth is a decode; rounding alone
    would find a count for each."""
    document = json.loads(json.dumps(DOCUMENTS["rectifier"]["document"]))
    channel = document["channels"][0]
    channel.update(raw_max=2, scale={"mantissa": 5, "exponent": -1})
    held = load_profile_document(canonical_json_bytes(document))
    assert measurement_in_range(held.channels[channel["name"]], value) is in_range


async def test_the_runtime_holds_its_configured_documents_and_reports_alarms(
    store: StateStore, tmp_path: Path
) -> None:
    """The subscriber the runtime builds holds the configured documents, keeps
    an alarm word off the event bus, and health reports it as of its reading."""
    from types import SimpleNamespace

    from ori.runtime import OriRuntime, _build_firmware_telemetry_subscriber
    from ori.security.firmware.liveness import FirmwareLivenessSupervisor
    from tests.firmware.test_liveness_composition import _cfg, _fakebus

    profiles = tmp_path / "profiles"
    profiles.mkdir()
    (profiles / "rectifier.json").write_bytes(
        bytes.fromhex(DOCUMENTS["rectifier"]["canonical_hex"])
    )
    config = _cfg()
    config.gateway.firmware_telemetry["controller_profiles_dir"] = str(profiles)
    bus = _fakebus()
    subscriber = _build_firmware_telemetry_subscriber(
        config, bus, store, None, FirmwareLivenessSupervisor()
    )
    assert subscriber is not None
    gate = subscriber.telemetry_gate
    assert gate.profiles.held() == [
        {"id": "example-rectifier", "digest": DOCUMENTS["rectifier"]["digest"]}
    ]

    device = Device(
        store,
        gate.profiles,
        [
            _bridged(
                ALARM_CHANNEL,
                "controller_alarm_word",
                "bitmask",
                _binding("rectifier", "alarm_word_1"),
            )
        ],
    )
    device.gate = gate
    await device.provision()
    await subscriber._ingest_telemetry(
        device.envelope(epoch=0, boot_id=1, seq=1, readings=[_alarm(9)])
    )
    assert bus.published == []

    health = await OriRuntime._firmware_controller_profiles_health(
        SimpleNamespace(
            _firmware_profile_library=gate.profiles,
            _firmware_alarm_tracker=gate.alarms,
            _firmware_reading_age=gate.reading_age,
            _state_store=store,
        )  # type: ignore[arg-type]
    )
    assert health["enabled"] is True
    assert health["documents_refused"] == []
    (channel,) = health["alarm_channels"]
    assert channel["device_id"] == DEVICE and channel["channel"] == ALARM_CHANNEL
    assert channel["state"] == "as_of"
    assert channel["reading"]["seq"] == 1
    assert {alarm["id"] for alarm in channel["asserted"]} == {
        "ac_input_fail",
        "over_temperature",
        "fan_stopped",
    }


async def test_a_started_runtime_reports_what_its_subscriber_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The join itself: the tracker `start` builds is the one its subscriber
    feeds and the one health reads."""
    import textwrap

    from ori.gateway.firmware_telemetry import MqttFirmwareTelemetrySubscriber
    from ori.runtime import OriRuntime
    from tests.waiting import settle, wait_until

    profiles = tmp_path / "profiles"
    profiles.mkdir()
    (profiles / "rectifier.json").write_bytes(
        bytes.fromhex(DOCUMENTS["rectifier"]["canonical_hex"])
    )
    cfg = tmp_path / "ori.yaml"
    cfg.write_text(
        textwrap.dedent(f"""\
            device:
              id: runtime-cp-01
              name: Controller profiles
              location: Test Lab
              deployment_profile: development
            sensors:
              - id: cpu
                type: cpu_percent
                protocol: psutil
                poll_interval_ms: 1000
            skills: []
            reasoning:
              default_tier: rule
            gateway:
              enabled: true
              broker_url: mqtt://127.0.0.1:1
              node_heartbeat:
                enabled: false
              reasoning:
                enabled: false
              firmware_telemetry:
                enabled: true
                controller_profiles_dir: profiles
            actions:
              primary_alert_channel: sms
              whatsapp:
                enabled: false
              sms:
                enabled: false
            database:
              path: {tmp_path / "ori_state.db"}
            logging:
              file: {tmp_path / "ori.log"}
        """),
        encoding="utf-8",
    )
    subscribers: list[MqttFirmwareTelemetrySubscriber] = []

    async def _serve(self: MqttFirmwareTelemetrySubscriber, shutdown: Any) -> None:
        subscribers.append(self)
        await shutdown.wait()

    monkeypatch.setattr(MqttFirmwareTelemetrySubscriber, "serve_until", _serve)
    runtime = OriRuntime(config_path=str(cfg))
    task = asyncio.create_task(runtime.start())
    try:
        await wait_until(
            lambda: (runtime._startup_complete and subscribers) or task.done(),
            what="the runtime to start its firmware subscriber",
        )
        assert not task.done(), task.exception() if task.done() else ""
        (subscriber,) = subscribers
        store = runtime._state_store
        assert store is not None
        device = Device(
            store,
            ControllerProfileLibrary(),
            [
                _bridged(
                    ALARM_CHANNEL,
                    "controller_alarm_word",
                    "bitmask",
                    _binding("rectifier", "alarm_word_1"),
                )
            ],
        )
        await device.provision()
        await subscriber._ingest_telemetry(
            device.envelope(epoch=0, boot_id=1, seq=1, readings=[_alarm(9.0)])
        )
        health = (await runtime._build_health_snapshot())[
            "firmware_controller_profiles"
        ]
        assert health["documents_held"] == [
            {"id": "example-rectifier", "digest": DOCUMENTS["rectifier"]["digest"]}
        ]
        (channel,) = health["alarm_channels"]
        assert channel["state"] == "as_of"
        assert channel["reading"]["word"] == 9
        assert type(channel["reading"]["word"]) is int
    finally:
        await runtime.stop()
        task.cancel()
        await settle({task}, what="the runtime task to stop")


async def test_a_fault_racing_a_repromotion_still_holds_the_channel(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fault verified before revoke, reinstate and promote of byte-identical
    anchor bytes, and advanced after them, holds under the new activation."""
    library, binding = _state_document(5000)
    device = Device(
        store,
        library,
        [_bridged(ALARM_CHANNEL, "controller_alarm_word", "bitmask", binding)],
    )
    await device.provision()
    real_advance = store.advance_firmware_freshness
    raced: list[bool] = []

    async def advance(*args: Any, **kwargs: Any) -> bool:
        if not raced:
            raced.append(True)
            await device.revoke()
            await device.reinstate()
            await device.promote()
            during, readings = await device.gate.ingest(
                device.envelope(epoch=0, boot_id=1, seq=2, readings=[_alarm(1)])
            )
            assert during.accepted and readings == []
            assert (await device.alarm_state())["state"] == "as_of"
        return await real_advance(*args, **kwargs)

    monkeypatch.setattr(store, "advance_firmware_freshness", advance)
    fault = await device.gate.ingest_fault(device.fault(epoch=0, boot_id=1, seq=3))
    assert raced and fault.accepted
    state = await device.alarm_state()
    assert state["state"] == "unknown"
    assert state["reason"] == "sensor_fault"


async def test_runtime_health_presents_alarm_snapshots_and_readings_with_an_anchored_bound(
    store: StateStore, tmp_path: Path
) -> None:
    """The sections the runtime serves: a matched alarm reading is a snapshot polled
    no more than A ago, as of T; an unmatched one is unbounded; no A goes without T."""
    import re
    from types import SimpleNamespace

    from ori.runtime import OriRuntime, _build_firmware_telemetry_subscriber
    from ori.security.firmware.liveness import (
        FirmwareLivenessSigner,
        FirmwareLivenessSupervisor,
    )
    from ori.security.firmware.reading_age import LivenessTable, ReadingAgeTracker
    from tests.firmware.test_liveness_composition import _cfg, _fakebus

    profiles = tmp_path / "profiles"
    profiles.mkdir()
    (profiles / "rectifier.json").write_bytes(
        bytes.fromhex(DOCUMENTS["rectifier"]["canonical_hex"])
    )
    config = _cfg()
    config.gateway.firmware_telemetry["controller_profiles_dir"] = str(profiles)
    now = [10_000_000_000]
    table = LivenessTable(per_device_bound=8, total_bound=64)
    tracker = ReadingAgeTracker(table, clock=lambda: now[0])
    subscriber = _build_firmware_telemetry_subscriber(
        config,
        _fakebus(),
        store,
        None,
        FirmwareLivenessSupervisor(),
        reading_age=tracker,
    )
    assert subscriber is not None
    gate = subscriber.telemetry_gate
    device = Device(
        store,
        gate.profiles,
        [
            _bridged(
                ALARM_CHANNEL,
                "controller_alarm_word",
                "bitmask",
                _binding("rectifier", "alarm_word_1"),
            )
        ],
    )
    device.gate = gate
    await device.provision()
    signer = FirmwareLivenessSigner(
        None,
        bytes([0x11]) * 32,
        supervisor=FirmwareLivenessSupervisor(),
        table=table,
        clock=lambda: now[0],
    )
    signed = signer.sign_liveness_v2_bytes(
        device_id=DEVICE, boot_id=1, capability_hash=device.hashes[0], runtime_seq=1
    )
    nonce = re.search(rb'"nonce":"([0-9a-f]{32})"', signed)
    assert nonce is not None
    runtime = SimpleNamespace(
        _firmware_profile_library=gate.profiles,
        _firmware_alarm_tracker=gate.alarms,
        _firmware_reading_age=tracker,
        _state_store=store,
    )

    now[0] += 2_000_000_000
    await subscriber._ingest_telemetry(
        device.envelope(
            epoch=0,
            boot_id=1,
            seq=1,
            readings=[_alarm(9)],
            liveness_nonce=nonce.group(1).decode(),
        )
    )
    now[0] += 1_500_000_000
    profiles_health = await OriRuntime._firmware_controller_profiles_health(runtime)  # type: ignore[arg-type]
    (channel,) = profiles_health["alarm_channels"]
    bound = channel["reading"]["liveness_bound"]
    assert bound["age_upper_ms"] == 3500
    assert re.fullmatch(
        r"snapshot polled no more than 4 s ago, as of \S+", bound["text"]
    ), bound
    assert bound["text"].endswith(bound["as_of"])
    (latest,) = OriRuntime._firmware_reading_age_health(runtime)["devices"]  # type: ignore[arg-type]
    assert latest["latest_reading"]["seq"] == 1
    assert latest["liveness_bound"]["text"].startswith(
        "polled no more than 4 s ago, as of "
    )

    await subscriber._ingest_telemetry(
        device.envelope(
            epoch=0, boot_id=1, seq=2, readings=[_alarm(9)], liveness_nonce=None
        )
    )
    profiles_health = await OriRuntime._firmware_controller_profiles_health(runtime)  # type: ignore[arg-type]
    (channel,) = profiles_health["alarm_channels"]
    assert channel["reading"]["seq"] == 2
    assert channel["reading"]["liveness_bound"] == "unbounded"
    reading_health = OriRuntime._firmware_reading_age_health(runtime)  # type: ignore[arg-type]
    assert reading_health["devices"][0]["liveness_bound"] == "unbounded"
    # Every A that leaves in either section is named with its T.
    for text in re.findall(
        r"no more than [^,]+, as of [^\"]+", str(profiles_health) + str(reading_health)
    ):
        assert ", as of " in text
