# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Controller profiles against bytes the reference firmware produced.

`tests/fixtures/firmware_controller_profile_artifacts.json` is the reference
firmware's own output for a bridged site, vendored at a pinned commit: the
signed manifest, the two profile documents it binds and five signed envelopes,
each with the receiver outcome it states as fields. Every other controller
profile test uses contract corpus or runtime-built bytes; these are the
producer's, so the firmware's serializer and this runtime's gate must agree on
them.

The documents are loaded the way the runtime loads them, from the configured
directory, each file named by its digest as published. The manifest is
registered through `FirmwareTelemetryGate.register_device`, and each envelope
arrives as raw MQTT payload bytes on the subscriber's message callback, from a
thread as the MQTT client delivers it.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ori.gateway.firmware_telemetry import MqttFirmwareTelemetrySubscriber
from ori.runtime import _build_firmware_telemetry_subscriber
from ori.security.firmware.liveness import FirmwareLivenessSupervisor
from ori.security.firmware.telemetry import canonical_json_bytes
from ori.state.store import StateStore
from ori.utils.strict_json import unique_members
from tests.firmware.test_liveness_composition import _cfg, _fakebus
from tests.waiting import wait_until

FIXTURE_PATH = (
    Path(__file__).parent.parent
    / "fixtures"
    / "firmware_controller_profile_artifacts.json"
)
#: The reference firmware commit the fixture was copied from, byte for byte.
SOURCE_COMMIT = "b0093f1dc69be976081990eca2da1e782f6cc88a"
FIXTURE_SHA256 = "f099c88a33cbb7c3beace5dfee26067ab2c8a2775aa63e857d7d52153e67adfa"
ARTIFACTS = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
DEVICE = ARTIFACTS["device_id"]
ENVELOPES = {envelope["name"]: envelope for envelope in ARTIFACTS["envelopes"]}

#: Every field an `expect` may carry, by the outcome it states. A field the
#: producer adds that this test does not assert fails here rather than passing
#: unread.
EXPECT_FIELDS = {
    "use": {
        "channel",
        "envelope",
        "profile_id",
        "qualification",
        "reading",
        "unit",
        "value",
    },
    "producer_defect_not_used": {
        "channel",
        "envelope",
        "profile_id",
        "qualification",
        "reading",
        "unit",
        "value",
    },
    "alarm_snapshot": {
        "asserted_at_that_poll",
        "channel",
        "envelope",
        "not_asserted_at_that_poll",
        "profile_id",
        "qualification",
        "reading",
        "unit",
        "word",
    },
}


def _strict(raw: bytes) -> Any:
    return json.loads(raw, object_pairs_hook=unique_members())


def _manifest_message() -> dict[str, Any]:
    return _strict(bytes.fromhex(ARTIFACTS["manifest"]["message_hex"]))


def _bindings() -> dict[str, dict[str, Any]]:
    manifest = _manifest_message()["manifest"]
    return {ch["channel"]: ch["controller_profile"] for ch in manifest["channels"]}


class Site:
    """The runtime's firmware subscriber, holding the firmware's documents."""

    def __init__(self, store: StateStore, profiles_dir: Path) -> None:
        config = _cfg()
        config.gateway.firmware_telemetry["controller_profiles_dir"] = str(profiles_dir)
        self.bus = _fakebus()
        subscriber = _build_firmware_telemetry_subscriber(
            config, self.bus, store, None, FirmwareLivenessSupervisor()
        )
        assert subscriber is not None
        self.subscriber: MqttFirmwareTelemetrySubscriber = subscriber
        self.gate = subscriber.telemetry_gate
        self.store = store
        self._verifications: list[Any] = []
        # Each scheduled ingest ends here, published or not, with its exception
        # if it raised: completion is the subscriber's, not the gate's.
        self._finished: list[BaseException | None] = []
        ingest = self.gate.ingest
        handle = subscriber._ingest_telemetry

        async def _verdict(payload: dict[str, Any], **kwargs: Any) -> Any:
            outcome = await ingest(payload, **kwargs)
            self._verifications.append(outcome[0])
            return outcome

        async def _handled(payload: dict[str, Any]) -> None:
            try:
                await handle(payload)
            except BaseException as exc:
                self._finished.append(exc)
                raise
            self._finished.append(None)

        self.gate.ingest = _verdict  # type: ignore[method-assign]
        subscriber._ingest_telemetry = _handled  # type: ignore[method-assign]

    async def provision(self) -> str:
        message = _manifest_message()
        capability_hash = await self.gate.register_device(
            device_id=DEVICE,
            public_key_b64=ARTIFACTS["device_public_key_b64"],
            posture=message["manifest"]["posture"],
            manifest_message=message,
        )
        assert await self.gate.approve_device(DEVICE, actor="t", reason="t")
        return capability_hash

    async def deliver(self, payload: bytes) -> Any:
        """Hand the bytes to the subscriber as the MQTT client thread does,
        and return the gate's verdict once the subscriber has finished with it,
        publication included."""
        self.subscriber._loop = asyncio.get_running_loop()
        before = len(self._finished)
        verdicts = len(self._verifications)
        message = SimpleNamespace(payload=payload)
        thread = threading.Thread(
            target=self.subscriber._on_message, args=(None, None, message)
        )
        thread.start()
        await asyncio.to_thread(thread.join)
        await wait_until(
            lambda: len(self._finished) > before,
            what="the subscriber to finish handling the envelope",
        )
        (failure,) = self._finished[before:]
        if failure is not None:
            raise failure
        (verification,) = self._verifications[verdicts:]
        return verification

    async def channel(self, name: str) -> dict[str, Any]:
        """The channel as the runtime registered it from the manifest."""
        row = await self.store.get_firmware_device(DEVICE)
        assert row is not None
        return row["channel_map"][name]

    async def alarm_state(self, channel: str) -> dict[str, Any]:
        states = {s["channel"]: s for s in await self.gate.alarm_states()}
        return states[channel]


@pytest.fixture
async def store(tmp_path: Path):
    s = StateStore(db_path=str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


@pytest.fixture
def profiles_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "profiles"
    directory.mkdir()
    for document in ARTIFACTS["profile_documents"]:
        (directory / document["asset_name"]).write_bytes(
            bytes.fromhex(document["document_hex"])
        )
    return directory


@pytest.fixture
async def site(store: StateStore, profiles_dir: Path) -> Site:
    return Site(store, profiles_dir)


def test_the_fixture_is_the_one_pinned() -> None:
    assert hashlib.sha256(FIXTURE_PATH.read_bytes()).hexdigest() == FIXTURE_SHA256
    for document in ARTIFACTS["profile_documents"]:
        digest = hashlib.sha256(bytes.fromhex(document["document_hex"])).hexdigest()
        assert document["digest"] == "sha256:" + digest
        assert document["asset_name"] == f"controller-profile-{digest}.json"
    assert list(ENVELOPES) == [
        "rectifier_dc_voltage",
        "rectifier_dc_current",
        "panel_output_current",
        "panel_alarm_word",
        "rectifier_dc_voltage_out_of_range",
    ]


def test_the_device_key_is_the_disclosed_test_seed() -> None:
    seed = bytes.fromhex(ARTIFACTS["test_seed_hex"])
    assert seed == b"\x42" * 32
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    raw = public.public_bytes(Encoding.Raw, PublicFormat.Raw)
    assert base64.b64encode(raw).decode() == ARTIFACTS["device_public_key_b64"]


@pytest.mark.parametrize(
    "hex_bytes",
    [ARTIFACTS["manifest"]["message_hex"]]
    + [envelope["message_hex"] for envelope in ARTIFACTS["envelopes"]]
    + [document["document_hex"] for document in ARTIFACTS["profile_documents"]],
    ids=["manifest"]
    + list(ENVELOPES)
    + [document["profile_id"] for document in ARTIFACTS["profile_documents"]],
)
def test_the_runtime_serializes_every_firmware_message_to_the_same_bytes(
    hex_bytes: str,
) -> None:
    raw = bytes.fromhex(hex_bytes)
    assert canonical_json_bytes(_strict(raw)) == raw


@pytest.mark.parametrize("name", list(ENVELOPES))
def test_every_expectation_is_one_this_test_asserts(name: str) -> None:
    expect = ENVELOPES[name]["expect"]
    assert set(expect) == EXPECT_FIELDS[expect["reading"]]
    assert expect["envelope"] == "accept"


async def test_the_runtime_holds_the_documents_the_manifest_binds(site: Site) -> None:
    assert site.gate.profiles.refused == []
    assert sorted(site.gate.profiles.held(), key=lambda d: d["id"]) == sorted(
        (
            {"id": document["profile_id"], "digest": document["digest"]}
            for document in ARTIFACTS["profile_documents"]
        ),
        key=lambda d: d["id"],
    )
    assert {b["digest"] for b in _bindings().values()} == {
        document["digest"] for document in ARTIFACTS["profile_documents"]
    }


async def test_the_manifest_registers_under_the_recorded_capability_hash(
    site: Site,
) -> None:
    assert await site.provision() == ARTIFACTS["manifest"]["capability_hash"]
    row = await site.store.get_firmware_device(DEVICE)
    assert row is not None and row["approved"]
    assert set(row["channel_map"]) == set(_bindings())


async def test_every_envelope_reaches_the_outcome_the_firmware_states(
    site: Site, caplog: pytest.LogCaptureFixture
) -> None:
    await site.provision()
    bindings = _bindings()
    for name, envelope in ENVELOPES.items():
        expect = envelope["expect"]
        binding = bindings[expect["channel"]]
        assert binding["id"] == expect["profile_id"], name
        assert binding["qualification"] == expect["qualification"], name

        published = len(site.bus.published)
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="ori.security.firmware.ingest"):
            verification = await site.deliver(bytes.fromhex(envelope["message_hex"]))
        assert verification.accepted, (name, verification)
        assert verification.device_id == DEVICE
        new = site.bus.published[published:]
        registered = await site.channel(expect["channel"])
        assert registered["unit"] == expect["unit"], name
        assert registered["controller_profile"] == binding, name

        if expect["reading"] == "use":
            (event,) = new
            reading = event.reading
            assert reading.sensor_id == f"{DEVICE}:{expect['channel']}"
            assert reading.value == expect["value"]
            assert reading.unit == expect["unit"]
            assert reading.metadata["controller_profile"] == binding
            assert reading.metadata["controller_profile_status"] == "usable"
        elif expect["reading"] == "alarm_snapshot":
            assert new == [], name
            assert registered["sensor_type"] == "controller_alarm_word"
            state = await site.alarm_state(expect["channel"])
            assert state["state"] == "as_of", state
            assert state["reading"]["seq"] == verification.seq
            assert state["reading"]["word"] == expect["word"]
            assert type(state["reading"]["word"]) is int
            assert state["reading"]["profile"] == binding
            assert [a["id"] for a in state["asserted"]] == expect[
                "asserted_at_that_poll"
            ]
            assert (
                state["not_asserted_at_that_poll"]
                == expect["not_asserted_at_that_poll"]
            )
        else:
            assert expect["reading"] == "producer_defect_not_used"
            assert new == [], name
            (defect,) = [
                r.getMessage()
                for r in caplog.records
                if "firmware producer defect" in r.getMessage()
            ]
            assert f"channel={expect['channel']}" in defect
            assert repr(expect["value"]) in defect
            assert binding["digest"] in defect


async def test_a_flipped_bit_in_a_firmware_envelope_is_refused(site: Site) -> None:
    """The acceptances above are of the firmware's signatures, not of any
    envelope that names the device."""
    await site.provision()
    raw = bytearray(bytes.fromhex(ENVELOPES["rectifier_dc_voltage"]["message_hex"]))
    at = raw.index(b'"value":48.0') + len(b'"value":4')
    raw[at] = ord("9")
    verification = await site.deliver(bytes(raw))
    assert not verification.accepted
    assert verification.error_code == "signature_verification_failed", verification
    assert site.bus.published == []

    genuine = await site.deliver(
        bytes.fromhex(ENVELOPES["rectifier_dc_voltage"]["message_hex"])
    )
    assert genuine.accepted
    assert [e.reading.value for e in site.bus.published] == [48.0]
