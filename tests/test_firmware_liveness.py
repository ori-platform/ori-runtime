# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Runtime liveness signing (firmware-commands/v1).

The interesting property is not that a message can be signed. It is that
this runtime refuses to sign one when it is no longer receiving from the
device — because the device cannot check that, and a signature would
otherwise assert supervision that does not exist.
"""

from __future__ import annotations

import base64
import json

import pytest

from ori.security.firmware_liveness import (
    FirmwareLivenessError,
    FirmwareLivenessSigner,
    FirmwareLivenessSupervisor,
    build_liveness_bytes,
)

DEVICE = "ori-fw-7c9f2b3a"
HASH = "sha256:" + "a" * 64
OTHER_HASH = "sha256:" + "b" * 64
SEED = bytes(range(32))


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeStore:
    """Durable per-device counter, as the real registry row provides."""

    def __init__(self) -> None:
        self.seqs: dict[str, int] = {}

    async def allocate_firmware_runtime_seq(self, device_id: str) -> int:
        if device_id not in self.seqs:
            raise KeyError(device_id)
        self.seqs[device_id] += 1
        return self.seqs[device_id]

    def register(self, device_id: str, start: int = 0) -> None:
        self.seqs[device_id] = start


# ── canonical bytes ───────────────────────────────────────────────────


def test_canonical_bytes_are_byte_exact() -> None:
    assert build_liveness_bytes(
        boot_id=41, capability_hash=HASH, device_id=DEVICE, runtime_seq=9007
    ) == (
        b'{"boot_id":41,"capability_hash":"' + HASH.encode() + b'",'
        b'"device_id":"' + DEVICE.encode() + b'","runtime_seq":9007,"v":1}'
    )


def test_field_order_is_lexicographic() -> None:
    obj = json.loads(
        build_liveness_bytes(
            boot_id=1, capability_hash=HASH, device_id=DEVICE, runtime_seq=1
        )
    )
    assert list(obj) == ["boot_id", "capability_hash", "device_id", "runtime_seq", "v"]


@pytest.mark.parametrize("runtime_seq", [0, -1, 2**53, True, 1.0, "1"])
def test_runtime_seq_zero_and_out_of_range_refused(runtime_seq: object) -> None:
    # Zero is refused, matching provision_seq and unlike cmd_seq: a
    # liveness message is only meaningful in a strictly increasing series.
    with pytest.raises(FirmwareLivenessError):
        build_liveness_bytes(
            boot_id=1, capability_hash=HASH, device_id=DEVICE, runtime_seq=runtime_seq
        )


@pytest.mark.parametrize("boot_id", [0, -1, 2**32, True, 1.5])
def test_boot_id_zero_and_out_of_range_refused(boot_id: object) -> None:
    with pytest.raises(FirmwareLivenessError):
        build_liveness_bytes(
            boot_id=boot_id, capability_hash=HASH, device_id=DEVICE, runtime_seq=1
        )


@pytest.mark.parametrize(
    "bad_hash",
    ["sha256:" + "A" * 64, "sha512:" + "a" * 64, "sha256:" + "a" * 63, "", "a" * 64],
)
def test_capability_hash_must_be_lowercase_sha256(bad_hash: str) -> None:
    with pytest.raises(FirmwareLivenessError):
        build_liveness_bytes(
            boot_id=1, capability_hash=bad_hash, device_id=DEVICE, runtime_seq=1
        )


@pytest.mark.parametrize("bad_id", ["", "ori fw", "ori/fw", "a" * 49, 'ori"fw'])
def test_device_id_must_be_a_fleet_identifier(bad_id: str) -> None:
    with pytest.raises(FirmwareLivenessError):
        build_liveness_bytes(
            boot_id=1, capability_hash=HASH, device_id=bad_id, runtime_seq=1
        )


# ── supervision window ────────────────────────────────────────────────


def test_unsupervised_until_telemetry_arrives() -> None:
    clock = FakeClock()
    sup = FirmwareLivenessSupervisor(window_s=45.0, clock=clock)
    assert not sup.supervised(device_id=DEVICE, boot_id=41, capability_hash=HASH)


def test_supervision_expires_with_the_window() -> None:
    clock = FakeClock()
    sup = FirmwareLivenessSupervisor(window_s=45.0, clock=clock)
    sup.note_telemetry(device_id=DEVICE, boot_id=41, capability_hash=HASH)
    assert sup.supervised(device_id=DEVICE, boot_id=41, capability_hash=HASH)

    clock.advance(44.9)
    assert sup.supervised(device_id=DEVICE, boot_id=41, capability_hash=HASH)
    clock.advance(0.2)
    assert not sup.supervised(device_id=DEVICE, boot_id=41, capability_hash=HASH)


def test_reboot_or_manifest_change_ends_supervision() -> None:
    # Supervision is of a device in a specific boot under a specific
    # manifest epoch. Anything else asserts supervision of something this
    # runtime is no longer tracking.
    clock = FakeClock()
    sup = FirmwareLivenessSupervisor(window_s=45.0, clock=clock)
    sup.note_telemetry(device_id=DEVICE, boot_id=41, capability_hash=HASH)

    assert not sup.supervised(device_id=DEVICE, boot_id=42, capability_hash=HASH)
    assert not sup.supervised(device_id=DEVICE, boot_id=41, capability_hash=OTHER_HASH)
    assert sup.supervised(device_id=DEVICE, boot_id=41, capability_hash=HASH)


def test_release_stops_supervision_immediately() -> None:
    clock = FakeClock()
    sup = FirmwareLivenessSupervisor(window_s=45.0, clock=clock)
    sup.note_telemetry(device_id=DEVICE, boot_id=41, capability_hash=HASH)
    sup.release(DEVICE)
    assert not sup.supervised(device_id=DEVICE, boot_id=41, capability_hash=HASH)
    assert sup.supervised_devices() == ()


def test_supervised_devices_snapshot_carries_everything_signing_needs() -> None:
    # Bare device ids would force a scheduler to look up boot_id and
    # capability_hash per tick, turning an event-driven map back into a
    # fleet poll. The snapshot exists to make that unnecessary.
    clock = FakeClock()
    sup = FirmwareLivenessSupervisor(window_s=45.0, clock=clock)
    sup.note_telemetry(device_id=DEVICE, boot_id=41, capability_hash=HASH)
    sup.note_telemetry(device_id="ori-fw-other", boot_id=7, capability_hash=OTHER_HASH)

    snap = {d.device_id: d for d in sup.supervised_devices()}
    assert set(snap) == {DEVICE, "ori-fw-other"}
    assert snap[DEVICE].boot_id == 41
    assert snap[DEVICE].capability_hash == HASH
    assert snap["ori-fw-other"].boot_id == 7
    assert snap["ori-fw-other"].capability_hash == OTHER_HASH

    clock.advance(46.0)
    assert sup.supervised_devices() == ()


# ── signer ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_signed_message_verifies_and_wraps_the_exact_bytes() -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    store = FakeStore()
    store.register(DEVICE)
    signer = FirmwareLivenessSigner(
        store, SEED, supervisor=FirmwareLivenessSupervisor()
    )
    signer.supervisor.note_telemetry(device_id=DEVICE, boot_id=41, capability_hash=HASH)

    message = await signer.sign_liveness(
        device_id=DEVICE, boot_id=41, capability_hash=HASH
    )
    obj = json.loads(message)
    assert obj["liveness"]["runtime_seq"] == 1
    assert obj["signature"].startswith("ed25519:")

    signed = build_liveness_bytes(
        boot_id=41, capability_hash=HASH, device_id=DEVICE, runtime_seq=1
    )
    assert signed in message  # the signature covers exactly these bytes
    Ed25519PublicKey.from_public_bytes(signer.public_key_bytes()).verify(
        base64.b64decode(obj["signature"].removeprefix("ed25519:")), signed
    )


@pytest.mark.asyncio
async def test_signer_refuses_an_unsupervised_device() -> None:
    # The whole mechanism. A runtime that stopped receiving must stop
    # asserting it is watching, and the device cannot check.
    store = FakeStore()
    store.register(DEVICE)
    signer = FirmwareLivenessSigner(
        store, SEED, supervisor=FirmwareLivenessSupervisor()
    )
    with pytest.raises(FirmwareLivenessError, match="not supervised"):
        await signer.sign_liveness(device_id=DEVICE, boot_id=41, capability_hash=HASH)
    assert store.seqs[DEVICE] == 0  # no sequence spent on a refusal


@pytest.mark.asyncio
async def test_signer_stops_when_supervision_lapses() -> None:
    clock = FakeClock()
    store = FakeStore()
    store.register(DEVICE)
    sup = FirmwareLivenessSupervisor(window_s=45.0, clock=clock)
    signer = FirmwareLivenessSigner(store, SEED, supervisor=sup)
    sup.note_telemetry(device_id=DEVICE, boot_id=41, capability_hash=HASH)

    await signer.sign_liveness(device_id=DEVICE, boot_id=41, capability_hash=HASH)
    clock.advance(46.0)
    with pytest.raises(FirmwareLivenessError, match="not supervised"):
        await signer.sign_liveness(device_id=DEVICE, boot_id=41, capability_hash=HASH)

    # Fresh telemetry resumes it, without a device reboot.
    sup.note_telemetry(device_id=DEVICE, boot_id=41, capability_hash=HASH)
    await signer.sign_liveness(device_id=DEVICE, boot_id=41, capability_hash=HASH)


@pytest.mark.asyncio
async def test_sequences_strictly_increase_and_survive_runtime_restart() -> None:
    # The deadlock this guards: a device holds the last accepted value for
    # its CURRENT boot, so a runtime restarting with a reset counter would
    # have every message rejected and could not recover while the device
    # stayed booted.
    store = FakeStore()
    store.register(DEVICE)

    signer = FirmwareLivenessSigner(
        store, SEED, supervisor=FirmwareLivenessSupervisor()
    )
    signer.supervisor.note_telemetry(device_id=DEVICE, boot_id=41, capability_hash=HASH)
    first = [
        json.loads(
            await signer.sign_liveness(
                device_id=DEVICE, boot_id=41, capability_hash=HASH
            )
        )["liveness"]["runtime_seq"]
        for _ in range(3)
    ]
    assert first == [1, 2, 3]

    # Runtime restarts: new signer, new supervisor, SAME durable store.
    restarted = FirmwareLivenessSigner(
        store, SEED, supervisor=FirmwareLivenessSupervisor()
    )
    restarted.supervisor.note_telemetry(
        device_id=DEVICE, boot_id=41, capability_hash=HASH
    )
    after = json.loads(
        await restarted.sign_liveness(
            device_id=DEVICE, boot_id=41, capability_hash=HASH
        )
    )["liveness"]["runtime_seq"]
    assert after == 4, "a restarted runtime must not reissue a spent sequence"


@pytest.mark.asyncio
async def test_unknown_device_raises_rather_than_signing() -> None:
    store = FakeStore()
    signer = FirmwareLivenessSigner(
        store, SEED, supervisor=FirmwareLivenessSupervisor()
    )
    signer.supervisor.note_telemetry(device_id=DEVICE, boot_id=41, capability_hash=HASH)
    with pytest.raises(KeyError):
        await signer.sign_liveness(device_id=DEVICE, boot_id=41, capability_hash=HASH)


def test_signer_requires_a_raw_32_byte_seed() -> None:
    for bad in [b"", b"\x00" * 31, b"\x00" * 33, "not bytes"]:
        with pytest.raises(FirmwareLivenessError):
            FirmwareLivenessSigner(
                FakeStore(), bad, supervisor=FirmwareLivenessSupervisor()
            )  # type: ignore[arg-type]


# ── against the REAL store, not a fake ─────────────────────────────────
#
# Every test above this line uses FakeStore, which cannot observe whether
# an allocation was committed. A missing commit therefore passed the
# whole suite, including a test named "...survive_runtime_restart".
# Durability is a property of sqlite, so it has to be tested against
# sqlite.

import sqlite3  # noqa: E402

from ori.state.store import StateStore  # noqa: E402


def _register_sync(store, device_id: str) -> None:
    store._conn.execute(
        """
        INSERT INTO firmware_device_registry
            (device_id, public_key_b64, posture, capability_hash,
             provisioned_at_ms)
        VALUES (?, 'x', 'sealed_flash', ?, 0)
        """,
        (device_id, HASH),
    )
    store._conn.commit()


async def _register(store, device_id: str) -> None:
    """Minimal registry row; liveness only needs the device to exist."""
    await store._run_write(_register_sync, store, device_id)


def _set_seq_sync(store, device_id: str, value: int) -> None:
    store._conn.execute(
        "UPDATE firmware_device_registry SET last_runtime_seq = ? WHERE device_id = ?",
        (value, device_id),
    )
    store._conn.commit()


@pytest.mark.asyncio
async def test_real_store_sequence_survives_reopen(tmp_path) -> None:
    db = str(tmp_path / "state.db")

    store = StateStore(db_path=db)
    await store.open()
    await _register(store, DEVICE)
    first = [await store.allocate_firmware_runtime_seq(DEVICE) for _ in range(3)]
    assert first == [1, 2, 3]
    await store.close()

    # A runtime restart. Without the commit the UPDATEs sit in an open
    # transaction and roll back here, the counter returns to 1, and the
    # device rejects every message for the rest of its current boot.
    reopened = StateStore(db_path=db)
    await reopened.open()
    try:
        assert await reopened.allocate_firmware_runtime_seq(DEVICE) == 4
    finally:
        await reopened.close()


@pytest.mark.asyncio
async def test_real_store_migrates_a_database_without_the_column(tmp_path) -> None:
    db = str(tmp_path / "legacy.db")

    store = StateStore(db_path=db)
    await store.open()
    await _register(store, DEVICE)
    await store.close()

    # Simulate a database created before this column existed.
    conn = sqlite3.connect(db)
    conn.execute("ALTER TABLE firmware_device_registry DROP COLUMN last_runtime_seq")
    conn.commit()
    conn.close()

    migrated = StateStore(db_path=db)
    await migrated.open()
    try:
        assert await migrated.allocate_firmware_runtime_seq(DEVICE) == 1
    finally:
        await migrated.close()


@pytest.mark.asyncio
async def test_real_store_distinguishes_unknown_device_from_exhaustion(
    tmp_path,
) -> None:
    store = StateStore(db_path=str(tmp_path / "state.db"))
    await store.open()
    try:
        with pytest.raises(KeyError):
            await store.allocate_firmware_runtime_seq("ori-fw-nosuch")

        await _register(store, DEVICE)
        await store._run_write(_set_seq_sync, store, DEVICE, 9007199254740991)
        # Exhaustion is not a caller error and must not look like one.
        with pytest.raises(ValueError) as exc:
            await store.allocate_firmware_runtime_seq(DEVICE)
        assert not isinstance(exc.value, KeyError)
    finally:
        await store.close()


# ── the accepted-telemetry seam ───────────────────────────────────────


def test_supervision_follows_accepted_telemetry_only() -> None:
    """The seam the subscriber uses: only accepted, authenticated telemetry
    establishes supervision. An unauthenticated publisher must not be able
    to keep a device's backstop suppressed."""
    from ori.security.firmware_telemetry import TelemetryVerification

    sup = FirmwareLivenessSupervisor()
    accepted = TelemetryVerification(
        grade="attested", device_id=DEVICE, boot_id=41, capability_hash=HASH
    )
    assert accepted.accepted
    sup.note_telemetry(
        device_id=accepted.device_id,
        boot_id=accepted.boot_id,
        capability_hash=accepted.capability_hash,
    )
    assert sup.supervised(device_id=DEVICE, boot_id=41, capability_hash=HASH)

    rejected = TelemetryVerification(grade="rejected", device_id="ori-fw-other")
    assert not rejected.accepted  # the subscriber returns before noting it


def test_verification_carries_the_capability_hash_supervision_needs() -> None:
    # Without this field a scheduler would have to read the registry per
    # message to learn the epoch — the database discovery the design avoids.
    from ori.security.firmware_telemetry import TelemetryVerification

    assert "capability_hash" in TelemetryVerification.__dataclass_fields__
