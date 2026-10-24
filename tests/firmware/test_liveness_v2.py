# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The runtime half of firmware-commands/v2 Runtime Liveness at v 2.

The signer reproduces the corpus's bytes, never repeats a nonce, replaces one
the live table holds, and reads the signing start before it signs. Each
interval publishes one message at ``v`` 2 and never ``v`` 1, and an interval
whose nonce, signing or publish fails sends nothing in its place
(firmware-commands/v2, Which ``v`` the runtime publishes).
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest

from ori.gateway.firmware_commands import FirmwareCommandService
from ori.security.firmware import reading_age
from ori.security.firmware.liveness import (
    FirmwareLivenessError,
    FirmwareLivenessNonceError,
    FirmwareLivenessSigner,
    FirmwareLivenessSupervisor,
    build_liveness_bytes,
)
from ori.security.firmware.reading_age import LivenessTable, ReadingAgeTracker

VECTOR_PATH = (
    Path(__file__).parent.parent
    / "vectors"
    / "firmware_commands"
    / "liveness-vectors-v2.json"
)
# The digest firmware-commands/v2 Golden vectors pins for this corpus.
SPEC_DECLARED_SHA256 = (
    "456efbd957fc53ebc71087593d8ed96f7312a5a3b8cb3ed419d21944e3d7b98e"
)
VECTORS = json.loads(VECTOR_PATH.read_text())
SEED = bytes.fromhex(VECTORS["runtime_test_seed_hex"])
ACCEPTED = VECTORS["cases"]
DEVICE = "ori-fw-7c9f2b3a"
HASH = "sha256:" + "13751b5335ccedcd4ffcc82bbda28ebfb7558859f36a74e710f1a0b0ab23da8d"

# Refusals whose liveness object the builder can be asked for: each must be
# refused before anything is signed. Every other refusal is decided by device
# state or by bytes the builder cannot express, listed exactly so a new case
# upstream is triaged here rather than silently skipped.
BUILDER_REFUSES = {
    "reject_v2_nonce_uppercase",
    "reject_v2_nonce_non_hex",
    "reject_v2_nonce_31_chars",
    "reject_v2_nonce_33_chars",
    "reject_v2_nonce_empty",
    "reject_v2_nonce_integer",
    "reject_v2_nonce_boolean",
}
DEVICE_ONLY = {
    # Grammar the builder cannot emit: it writes one field set and order per v.
    "reject_v2_missing_nonce",
    "reject_v1_with_nonce",
    "reject_v2_nonce_null",
    "reject_v2_extra_field",
    "reject_v2_nonce_out_of_order",
    "reject_unsupported_version",
    # Decided by the device's own boot, manifest, high-water mark or key.
    "reject_v2_replayed_exact_bytes",
    "reject_v2_regressing_runtime_seq",
    "reject_v2_reissued_runtime_seq_fresh_nonce",
    "reject_v2_same_seq_as_accepted_v1",
    "reject_v1_same_seq_as_accepted_v2",
    "reject_v2_wrong_device",
    "reject_v2_wrong_boot",
    "reject_v2_manifest_mismatch",
    "reject_v2_rogue_key",
}
# Real runtime-key signatures in a form the device refuses: the object alone,
# the command domain, the liveness domain with no NUL. The signer never makes them.
SIGNER_NEVER_PRODUCES = {
    "reject_v2_signed_over_object_alone",
    "reject_v2_signed_in_command_domain",
    "reject_v2_liveness_domain_without_nul",
}


def _signer(**kwargs: Any) -> FirmwareLivenessSigner:
    return FirmwareLivenessSigner(
        kwargs.pop("store", None),
        SEED,
        supervisor=FirmwareLivenessSupervisor(),
        **kwargs,
    )


def _table() -> LivenessTable:
    return LivenessTable(per_device_bound=8, total_bound=64)


def test_the_vendored_corpus_is_the_one_the_contract_pins() -> None:
    assert hashlib.sha256(VECTOR_PATH.read_bytes()).hexdigest() == SPEC_DECLARED_SHA256


@pytest.mark.parametrize("case", ACCEPTED, ids=[c["name"] for c in ACCEPTED])
def test_the_signer_reproduces_every_accepted_case(case: dict[str, Any]) -> None:
    fields = case["input"]
    if fields["v"] == 1:
        liveness = build_liveness_bytes(
            boot_id=fields["boot_id"],
            capability_hash=fields["capability_hash"],
            device_id=fields["device_id"],
            runtime_seq=fields["runtime_seq"],
        )
        assert liveness.hex() == case["liveness_hex"]
        assert _signer().sign_liveness_bytes(liveness).hex() == case["message_hex"]
        return
    table = _table()
    signer = _signer(
        table=table,
        nonce_source=lambda: bytes.fromhex(fields["nonce"]),
        clock=lambda: 5,
    )
    message = signer.sign_liveness_v2_bytes(
        device_id=fields["device_id"],
        boot_id=fields["boot_id"],
        capability_hash=fields["capability_hash"],
        runtime_seq=fields["runtime_seq"],
    )
    assert message.hex() == case["message_hex"]
    assert table.holds(fields["nonce"])


def test_every_refusal_is_triaged_exactly() -> None:
    refusals = {
        c["name"]
        for key in ("reject_cases", "precedence_cases", "transport_reject_cases")
        for c in VECTORS[key]
    }
    transport = {c["name"] for c in VECTORS["transport_reject_cases"]}
    precedence = {c["name"] for c in VECTORS["precedence_cases"]}
    assert refusals == (
        BUILDER_REFUSES | DEVICE_ONLY | SIGNER_NEVER_PRODUCES | transport | precedence
    )
    assert not BUILDER_REFUSES & DEVICE_ONLY
    assert not SIGNER_NEVER_PRODUCES & (BUILDER_REFUSES | DEVICE_ONLY)


@pytest.mark.parametrize("name", sorted(SIGNER_NEVER_PRODUCES))
def test_the_signer_never_signs_a_refused_form(name: str) -> None:
    case = next(c for c in VECTORS["reject_cases"] if c["name"] == name)
    fields = case["input"]
    signer = _signer(
        table=_table(),
        nonce_source=lambda: bytes.fromhex(fields["nonce"]),
        clock=lambda: 5,
    )
    message = signer.sign_liveness_v2_bytes(
        device_id=fields["device_id"],
        boot_id=fields["boot_id"],
        capability_hash=fields["capability_hash"],
        runtime_seq=fields["runtime_seq"],
    )
    assert bytes.fromhex(case["liveness_hex"]) in message
    assert message.hex() != case["message_hex"]
    assert case["signature_b64"].encode() not in message


@pytest.mark.parametrize("name", sorted(BUILDER_REFUSES))
def test_the_builder_refuses_every_nonce_the_grammar_refuses(name: str) -> None:
    case = next(c for c in VECTORS["reject_cases"] if c["name"] == name)
    fields = case["input"]
    with pytest.raises(FirmwareLivenessError, match="nonce"):
        build_liveness_bytes(
            boot_id=fields["boot_id"],
            capability_hash=fields["capability_hash"],
            device_id=fields["device_id"],
            runtime_seq=fields["runtime_seq"],
            nonce=fields["nonce"],
        )


def test_the_published_messages_are_never_retained() -> None:
    assert VECTORS["retain"] is False


def _v2(signer: FirmwareLivenessSigner, runtime_seq: int = 7) -> dict[str, Any]:
    wire = signer.sign_liveness_v2_bytes(
        device_id=DEVICE, boot_id=41, capability_hash=HASH, runtime_seq=runtime_seq
    )
    return json.loads(wire)["liveness"]


def test_two_signings_never_carry_one_nonce_even_under_one_runtime_seq() -> None:
    table = _table()
    signer = _signer(table=table)
    nonces = {_v2(signer, runtime_seq=7)["nonce"] for _ in range(2)}
    nonces |= {_v2(signer, runtime_seq=8)["nonce"] for _ in range(2)}
    assert len(nonces) == 4 and len(table) == 4


def test_a_nonce_the_live_table_holds_is_replaced_before_signing() -> None:
    table = _table()
    draws = iter([b"\x01" * 16, b"\x01" * 16, b"\x02" * 16])
    signer = _signer(table=table, nonce_source=lambda: next(draws), clock=lambda: 1)
    assert _v2(signer)["nonce"] == "01" * 16
    assert _v2(signer)["nonce"] == "02" * 16
    assert len(table) == 2


def test_a_source_that_only_collides_refuses_rather_than_reuses() -> None:
    table = _table()
    signer = _signer(table=table, nonce_source=lambda: b"\x01" * 16, clock=lambda: 1)
    _v2(signer)
    with pytest.raises(FirmwareLivenessNonceError, match="collided"):
        _v2(signer)
    assert len(table) == 1


def test_the_signing_start_is_read_before_signing() -> None:
    order: list[str] = []
    table = _table()

    def clock() -> int:
        order.append("clock")
        return 9

    signer = _signer(table=table, clock=clock)
    real = signer.sign_liveness_bytes

    def sign(liveness: bytes) -> bytes:
        order.append("sign")
        assert len(table) == 1, "the entry is recorded at the signing start"
        return real(liveness)

    signer.sign_liveness_bytes = sign  # type: ignore[method-assign]
    _v2(signer)
    assert order == ["clock", "sign"]


@pytest.mark.parametrize(
    "clock", [lambda: None, lambda: 1 // 0], ids=["none", "raises"]
)
def test_a_signing_start_that_cannot_be_read_records_no_entry(clock: Any) -> None:
    table = _table()
    signer = _signer(table=table, clock=clock)
    assert _v2(signer)["v"] == 2, "the message may still be published"
    assert len(table) == 0


class _Allocator:
    def __init__(self, *, fail_from: int | None = None) -> None:
        self.next = 10
        self.fail_from = fail_from

    async def get_firmware_device(self, device_id: str) -> dict:
        return {
            "device_id": device_id,
            "manifest": {"runtime_key_domains": "firmware-commands/v2"},
        }

    async def allocate_firmware_runtime_seq(
        self, device_id: str, *, capability_hash: str
    ) -> int:
        if self.fail_from is not None and self.next >= self.fail_from:
            raise PermissionError("authority changed")
        value = self.next
        self.next += 1
        return value


def _supervised_signer(store: Any, **kwargs: Any) -> FirmwareLivenessSigner:
    supervisor = FirmwareLivenessSupervisor()
    supervisor.note_telemetry(device_id=DEVICE, boot_id=41, capability_hash=HASH)
    return FirmwareLivenessSigner(store, SEED, supervisor=supervisor, **kwargs)


async def test_an_interval_signs_one_message_at_v2() -> None:
    table = _table()
    signer = _supervised_signer(_Allocator(), table=table)
    message = json.loads(
        await signer.sign_liveness(device_id=DEVICE, boot_id=41, capability_hash=HASH)
    )["liveness"]
    assert (message["v"], message["runtime_seq"]) == (2, 10)
    assert table.holds(message["nonce"]) and len(table) == 1


def _failing(failure: str, table: LivenessTable) -> FirmwareLivenessSigner:
    """A supervised signer whose *failure* step fails for every message."""
    kwargs: dict[str, Any] = {"table": table}
    if failure == "nonce":
        kwargs["nonce_source"] = lambda: b"short"
    if failure == "clock":
        kwargs["clock"] = lambda: 1 // 0
    signer = _supervised_signer(_Allocator(), **kwargs)
    if failure == "signing":
        real = signer.sign_liveness_bytes

        def sign(liveness: bytes) -> bytes:
            # Only the v 2 signature fails, so a fallback signing v 1
            # through the same method would succeed and be seen.
            if b'"nonce"' in liveness:
                raise RuntimeError("hsm unavailable")
            return real(liveness)

        signer.sign_liveness_bytes = sign  # type: ignore[method-assign]
    return signer


@pytest.mark.parametrize(
    ("failure", "raised"),
    [("nonce", FirmwareLivenessNonceError), ("signing", RuntimeError)],
)
async def test_a_failed_interval_signs_nothing_and_leaves_no_entry(
    failure: str, raised: type[Exception]
) -> None:
    """No `v` 1 message in its place, and a failed signing records nothing."""
    table = _table()
    with pytest.raises(raised):
        await _failing(failure, table).sign_liveness(
            device_id=DEVICE, boot_id=41, capability_hash=HASH
        )
    assert len(table) == 0


async def test_a_nonce_failure_is_not_a_supervision_refusal() -> None:
    """The publish loop counts a refusal as the device meant to lapse; a nonce
    the runtime could not draw is a publication it owed and failed."""
    assert not issubclass(FirmwareLivenessNonceError, FirmwareLivenessError)


async def test_an_unreadable_clock_still_signs_at_v2_with_no_entry() -> None:
    table = _table()
    message = json.loads(
        await _failing("clock", table).sign_liveness(
            device_id=DEVICE, boot_id=41, capability_hash=HASH
        )
    )["liveness"]
    assert message["v"] == 2 and len(table) == 0


async def test_an_unsupervised_device_gets_no_message() -> None:
    signer = FirmwareLivenessSigner(
        _Allocator(), SEED, supervisor=FirmwareLivenessSupervisor(), table=_table()
    )
    with pytest.raises(FirmwareLivenessError, match="not supervised"):
        await signer.sign_liveness(device_id=DEVICE, boot_id=41, capability_hash=HASH)


class _Publisher:
    def __init__(self, *, fail: bool = False) -> None:
        self.sent: list[int] = []
        self.fail = fail

    async def publish_runtime_liveness(self, device_id: str, message: bytes) -> None:
        self.sent.append(json.loads(message)["liveness"]["v"])
        if self.fail:
            raise ConnectionError("publish failed")


def _service(
    publisher: _Publisher, table: LivenessTable, *, signer_failure: str = ""
) -> FirmwareCommandService:
    supervisor = FirmwareLivenessSupervisor()
    supervisor.note_telemetry(device_id=DEVICE, boot_id=41, capability_hash=HASH)
    service = FirmwareCommandService(
        store=_Allocator(),
        publisher=publisher,  # type: ignore[arg-type]
        runtime_command_key_bytes=SEED,
        provisioner_key_bytes=bytes(range(32)),
        liveness_supervisor=supervisor,
        liveness_table=table,
    )
    if signer_failure:
        service._liveness = _failing(signer_failure, table)
    return service


async def test_the_service_publishes_one_message_at_v2() -> None:
    publisher = _Publisher()
    table = _table()
    message = await _service(publisher, table).publish_runtime_liveness(
        device_id=DEVICE, boot_id=41, capability_hash=HASH
    )
    assert publisher.sent == [2] and json.loads(message)["liveness"]["v"] == 2
    assert len(table) == 1


async def test_the_service_never_publishes_liveness_at_v1() -> None:
    """Whatever produced the message, the service is the one door, and it
    refuses one not at v 2: as a failure, not a supervision refusal."""
    publisher = _Publisher()
    service = _service(publisher, _table())

    async def v1(**_kwargs: Any) -> bytes:
        return service._liveness.sign_liveness_bytes(
            build_liveness_bytes(
                boot_id=41, capability_hash=HASH, device_id=DEVICE, runtime_seq=1
            )
        )

    service._liveness.sign_liveness = v1  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="not at v 2") as raised:
        await service.publish_runtime_liveness(
            device_id=DEVICE, boot_id=41, capability_hash=HASH
        )
    assert not isinstance(raised.value, FirmwareLivenessError)
    assert publisher.sent == []


@pytest.mark.parametrize(
    ("failure", "raised", "sent", "entries"),
    [
        ("nonce", FirmwareLivenessNonceError, [], 0),
        ("signing", RuntimeError, [], 0),
        ("publish", ConnectionError, [2], 1),
        ("clock", None, [2], 0),
    ],
)
async def test_no_failure_is_ever_answered_with_v1(
    failure: str, raised: type[Exception] | None, sent: list[int], entries: int
) -> None:
    """Each of the four failures: never a `v` 1 substitute. A nonce or signing
    failure sends nothing; a publish failure is raised after its one attempt,
    its entry kept from the signing start; an unreadable clock still publishes,
    with no entry."""
    publisher = _Publisher(fail=failure == "publish")
    table = _table()
    service = _service(
        publisher, table, signer_failure=failure if failure != "publish" else ""
    )
    call = service.publish_runtime_liveness(
        device_id=DEVICE, boot_id=41, capability_hash=HASH
    )
    if raised is None:
        published = await call
        assert json.loads(published)["liveness"]["v"] == 2
    else:
        with pytest.raises(raised):
            _ = await call
    assert publisher.sent == sent and 1 not in publisher.sent
    assert len(table) == entries


@pytest.mark.parametrize(
    ("platform", "expected"),
    [
        ("linux", "CLOCK_BOOTTIME"),
        ("android", "CLOCK_BOOTTIME"),
        ("darwin", "CLOCK_MONOTONIC"),
        ("win32", None),
    ],
)
def test_the_signing_clock_counts_suspended_time(
    monkeypatch: pytest.MonkeyPatch, platform: str, expected: str | None
) -> None:
    """CLOCK_BOOTTIME and macOS CLOCK_MONOTONIC count suspend; nothing else is used."""
    monkeypatch.setattr(reading_age, "runtime_platform", lambda: platform)
    import time

    monkeypatch.setattr(time, "CLOCK_BOOTTIME", 7, raising=False)
    clock_id = reading_age.signing_clock_id()
    assert clock_id == (None if expected is None else getattr(time, expected))
    if expected is None:
        assert reading_age.signing_clock_ns() is None


def test_the_host_clock_reads() -> None:
    assert isinstance(reading_age.signing_clock_ns(), int)


def test_a_v1_envelope_never_takes_a_bound_even_naming_a_held_nonce() -> None:
    table = _table()
    signer = _signer(table=table, clock=lambda: 100)
    nonce = _v2(signer)["nonce"]
    tracker = ReadingAgeTracker(table, clock=lambda: 200)
    common = {
        "device_id": DEVICE,
        "boot_id": 41,
        "capability_hash": HASH,
        "channels": ["ch0"],
        "liveness_nonce": nonce,
        "key_epoch_id": "k1",
    }
    assert tracker.note_accepted(version=1, seq=1, **common) is None
    assert tracker.note_accepted(version=2, seq=2, **common) == 100


def test_health_shows_the_latest_reading_and_a_heartbeat_never_replaces_it() -> None:
    table = _table()
    now = [100]
    signer = _signer(table=table, clock=lambda: now[0])
    nonce = _v2(signer)["nonce"]
    tracker = ReadingAgeTracker(table, clock=lambda: now[0])
    common = {"device_id": DEVICE, "boot_id": 41, "capability_hash": HASH, "version": 2}
    tracker.note_accepted(
        seq=1, channels=["ch0"], liveness_nonce=nonce, key_epoch_id="k1", **common
    )
    tracker.note_accepted(
        seq=2, channels=[], liveness_nonce=None, key_epoch_id="k1", **common
    )
    now[0] = 100 + 2_500_000_000
    [device] = tracker.health()
    assert device["latest_reading"] == {"key_epoch_id": "k1", "boot_id": 41, "seq": 1}
    bound = device["liveness_bound"]
    assert bound["age_upper_ms"] == 2500
    assert bound["text"].startswith("polled no more than 3 s ago, as of ")
    assert bound["text"].endswith(bound["as_of"])
    assert not re.search(r"\b(fresh|current|live|now)\b", json.dumps(tracker.health()))


def test_a_restart_empties_the_table_and_a_stored_reading_has_no_bound() -> None:
    """Each start builds a new tracker: nothing survives it, and nothing is persisted."""
    from ori.runtime._firmware_wiring import (
        firmware_reading_age as _firmware_reading_age,
    )
    from tests.firmware.test_liveness_composition import _command_cfg

    config = _command_cfg()
    first = _firmware_reading_age(config)
    assert first is not None and first.table is not None
    signer = _signer(table=first.table)
    nonce = _v2(signer)["nonce"]
    first.note_accepted(
        version=2,
        device_id=DEVICE,
        boot_id=41,
        capability_hash=HASH,
        seq=1,
        channels=["ch0"],
        liveness_nonce=nonce,
        key_epoch_id="k1",
    )
    assert first.message_bound(DEVICE, "k1", 41, 1) is not None
    second = _firmware_reading_age(config)
    assert second is not None and second.table is not None
    assert len(second.table) == 0
    assert second.message_bound(DEVICE, "k1", 41, 1) is None
    # The per-device bound holds an hour of messages at the default interval.
    assert second.table.per_device_bound >= 3600 / 15


def test_only_a_runtime_that_signs_liveness_keeps_a_table() -> None:
    from ori.runtime._firmware_wiring import (
        firmware_reading_age as _firmware_reading_age,
    )
    from tests.firmware.test_liveness_composition import _cfg, _command_cfg

    telemetry_only = _firmware_reading_age(_cfg())
    assert telemetry_only is not None and telemetry_only.table is None
    signing = _firmware_reading_age(_command_cfg())
    assert signing is not None and signing.table is not None
    no_telemetry = _command_cfg()
    no_telemetry.gateway.firmware_telemetry = {"enabled": False}
    assert _firmware_reading_age(no_telemetry) is None


def test_a_short_interval_cannot_grow_the_table_without_limit() -> None:
    from ori.runtime._firmware_wiring import (
        firmware_reading_age as _firmware_reading_age,
    )
    from tests.firmware.test_liveness_composition import _command_cfg

    config = _command_cfg()
    config.gateway.firmware_commands["liveness_interval_s"] = 1.0
    tracker = _firmware_reading_age(config)
    assert tracker is not None and tracker.table is not None
    assert tracker.table.per_device_bound == 3601
    assert tracker.table.total_bound == reading_age.DEFAULT_TOTAL_BOUND


@pytest.mark.parametrize(
    "overrides",
    [
        {"nonce": "a" * 32 + "\n"},
        {"device_id": DEVICE + "\n"},
        {"capability_hash": HASH + "\n"},
    ],
    ids=["nonce", "device_id", "capability_hash"],
)
def test_a_trailing_newline_never_reaches_the_signed_bytes(
    overrides: dict[str, str],
) -> None:
    fields: dict[str, Any] = {
        "boot_id": 41,
        "capability_hash": HASH,
        "device_id": DEVICE,
        "runtime_seq": 1,
        "nonce": "a" * 32,
        **overrides,
    }
    with pytest.raises(FirmwareLivenessError):
        build_liveness_bytes(**fields)
