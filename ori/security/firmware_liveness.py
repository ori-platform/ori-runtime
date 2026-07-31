# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Runtime liveness signing for firmware devices.

``firmware-commands/v1`` defines a signed liveness signal so a device can
tell whether an authority is alive and watching it. That is what decides
whether its Local Interlock may act on its own: broker connectivity
proves a session and nothing about this runtime, so a live broker with a
dead runtime would leave a device connected, unsupervised, and with its
backstop suppressed.

Two properties of this module carry more weight than the signing itself.

**A signature cannot prove continued supervision.** ``boot_id`` is
neither secret nor perishable, so a runtime that learned one can keep
producing valid messages whether or not it is still receiving from that
device. The contract closes that with an obligation on this side —
publish only while still accepting telemetry from the device — which
:class:`FirmwareLivenessSupervisor` enforces. **The device cannot check
it**, so nothing downstream may describe liveness as proof the runtime is
receiving; it is proof a key holder claims to be.

**Supervision state is in-memory and monotonic, deliberately.** A
restarted runtime re-earns supervision from fresh telemetry rather than
trusting a stored timestamp, and a wall clock that jumped backwards
cannot extend a window. The sequence counter is the opposite: it must be
durable, because a device holds the last accepted value for its current
boot and would otherwise reject a restarted runtime forever.
"""

from __future__ import annotations

import base64
import re
import time
from dataclasses import dataclass
from typing import Any, Callable

__all__ = [
    "FirmwareLivenessError",
    "FirmwareLivenessSigner",
    "FirmwareLivenessSupervisor",
    "SupervisedDevice",
    "build_liveness_bytes",
    "LIVENESS_EXPIRY_WINDOW_S",
    "LIVENESS_PUBLISH_INTERVAL_S",
    "LIVENESS_SUPERVISION_WINDOW_S",
    "MAX_LIVENESS_PUBLISH_INTERVAL_S",
]

_FLEET_ID = re.compile(r"^[A-Za-z0-9._-]{1,48}$")
_CAPABILITY_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_RUNTIME_SEQ_MAX = 2**53 - 1
_BOOT_ID_MAX = 2**32 - 1

# firmware-commands/v1, provisional pending bench measurement. The
# supervision window is deliberately SHORTER than the device's expiry
# window (60 s), so a device learns of lost supervision through silence
# rather than racing this runtime to the same deadline.
LIVENESS_PUBLISH_INTERVAL_S = 15.0
LIVENESS_SUPERVISION_WINDOW_S = 45.0

# Device-side, and the reason the two above are not free parameters. The
# device marks the runtime unreachable once this much time has passed
# since the last accepted liveness. It is a contract constant applied by
# the device rather than a field on the wire: a TTL a publisher could
# choose would let a compromised or misconfigured runtime suppress a
# fleet's backstops indefinitely.
LIVENESS_EXPIRY_WINDOW_S = 60.0

# The contract requires the expiry window to be at least 3x the
# publication interval, so isolated message loss cannot mark a healthy
# runtime unreachable. That makes the ceiling derived, not chosen: raising
# the interval past it means a single dropped message expires a device.
MAX_LIVENESS_PUBLISH_INTERVAL_S = LIVENESS_EXPIRY_WINDOW_S / 3.0

# These relationships are the contract, not preferences, so they are
# checked here rather than trusted to stay true as the values are ratified
# against hardware measurement.
assert LIVENESS_SUPERVISION_WINDOW_S < LIVENESS_EXPIRY_WINDOW_S, (
    "supervision window must be shorter than the device expiry window, so a "
    "device learns of lost supervision by silence rather than by the runtime "
    "racing it to the same deadline"
)
assert LIVENESS_PUBLISH_INTERVAL_S <= MAX_LIVENESS_PUBLISH_INTERVAL_S, (
    "expiry window must be at least 3x the publication interval"
)


class FirmwareLivenessError(ValueError):
    """A liveness message that must not be signed."""


@dataclass(frozen=True)
class SupervisedDevice:
    """One supervised device, with everything signing needs.

    Carrying ``boot_id`` and ``capability_hash`` here is what lets a
    scheduler publish without touching the database: the values are
    already known, because they arrived on the telemetry that established
    supervision in the first place. Returning bare device ids would force
    a per-tick registry lookup and turn an event-driven map back into a
    fleet poll.
    """

    device_id: str
    boot_id: int
    capability_hash: str


def build_liveness_bytes(
    *,
    boot_id: int,
    capability_hash: str,
    device_id: str,
    runtime_seq: int,
) -> bytes:
    """The exact signed bytes of one liveness object, per the fixed
    grammar. Raises :class:`FirmwareLivenessError` on any field the
    device verifier would refuse — never sign what cannot be accepted.
    """
    if not isinstance(device_id, str) or not _FLEET_ID.match(device_id):
        raise FirmwareLivenessError(
            f"device_id is not a fleet identifier: {device_id!r}"
        )
    if not isinstance(capability_hash, str) or not _CAPABILITY_HASH.match(
        capability_hash
    ):
        raise FirmwareLivenessError(
            "capability_hash must be sha256: + 64 lowercase hex"
        )
    # Zero is not a valid boot_id: device counters persist a boot before
    # use and issue from one upward.
    if (
        isinstance(boot_id, bool)
        or not isinstance(boot_id, int)
        or not (1 <= boot_id <= _BOOT_ID_MAX)
    ):
        raise FirmwareLivenessError(f"boot_id out of range: {boot_id!r}")
    # Zero is refused, matching provision_seq and unlike cmd_seq: a
    # liveness message is only meaningful as a member of a strictly
    # increasing series.
    if (
        isinstance(runtime_seq, bool)
        or not isinstance(runtime_seq, int)
        or not (1 <= runtime_seq <= _RUNTIME_SEQ_MAX)
    ):
        raise FirmwareLivenessError(f"runtime_seq out of range: {runtime_seq!r}")
    return (
        '{"boot_id":%d,"capability_hash":"%s","device_id":"%s",'
        '"runtime_seq":%d,"v":1}' % (boot_id, capability_hash, device_id, runtime_seq)
    ).encode("utf-8")


class FirmwareLivenessSupervisor:
    """Tracks which devices this runtime is currently receiving from.

    Liveness may be published for a device only while authenticated
    telemetry from that device, for the same boot and manifest epoch, has
    been accepted within the supervision window. Without this the signal
    would assert that a signing process exists, which is not the question
    a device is asking.
    """

    def __init__(
        self,
        *,
        window_s: float = LIVENESS_SUPERVISION_WINDOW_S,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not isinstance(window_s, (int, float)) or window_s <= 0:
            raise FirmwareLivenessError(
                f"supervision window must be positive: {window_s!r}"
            )
        self._window_s = float(window_s)
        self._clock = clock
        # device_id -> (boot_id, capability_hash, accepted_at_monotonic)
        self._seen: dict[str, tuple[int, str, float]] = {}

    def note_telemetry(
        self, *, device_id: str, boot_id: int, capability_hash: str
    ) -> None:
        """Record accepted, authenticated telemetry. Callers must not call
        this for a message that failed verification: an unauthenticated
        publisher could otherwise keep a device's backstop suppressed.
        """
        self._seen[device_id] = (int(boot_id), str(capability_hash), self._clock())

    def supervised(self, *, device_id: str, boot_id: int, capability_hash: str) -> bool:
        """Whether this runtime may publish liveness for the device now."""
        entry = self._seen.get(device_id)
        if entry is None:
            return False
        seen_boot, seen_hash, at = entry
        # A reboot or a manifest transition ends supervision until fresh
        # telemetry arrives under the new identity. Anything else would
        # assert supervision of a device this runtime is no longer
        # tracking.
        if seen_boot != int(boot_id) or seen_hash != str(capability_hash):
            return False
        return (self._clock() - at) < self._window_s

    def release(self, device_id: str) -> None:
        """Deliberately stop supervising a device — maintenance,
        decommissioning, handing authority elsewhere. Silence is the
        supported way to tell a device it is on its own; there is no
        goodbye message, because a claim of absence could not be trusted
        from an absent party.
        """
        self._seen.pop(device_id, None)

    def supervised_devices(self) -> tuple[SupervisedDevice, ...]:
        """Immutable snapshot of every device this runtime may publish for.

        Expiry is evaluated against a SINGLE captured time, so a long
        fleet does not have later entries judged against a later clock
        than earlier ones.
        """
        now = self._clock()
        return tuple(
            SupervisedDevice(
                device_id=device_id, boot_id=boot_id, capability_hash=capability_hash
            )
            for device_id, (boot_id, capability_hash, at) in self._seen.items()
            if (now - at) < self._window_s
        )


class FirmwareLivenessSigner:
    """Signs liveness messages with the runtime command key and allocates
    strictly increasing, durable per-device sequence numbers.

    The key is the same one the device already pins for commands: no new
    key material, no second trust root.
    """

    def __init__(
        self,
        store: Any,
        private_key_bytes: bytes,
        *,
        supervisor: FirmwareLivenessSupervisor,
    ) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        if not isinstance(private_key_bytes, bytes) or len(private_key_bytes) != 32:
            raise FirmwareLivenessError(
                "runtime command key must be 32 raw Ed25519 seed bytes"
            )
        # Required, with no default. A signer that quietly built its own
        # supervisor would be wired to nothing that receives telemetry, so
        # it would refuse every device forever — the feature absent rather
        # than broken, and silent either way. The caller must say which
        # supervisor this signer reads.
        if not isinstance(supervisor, FirmwareLivenessSupervisor):
            raise FirmwareLivenessError(
                "supervisor must be the FirmwareLivenessSupervisor fed by "
                "accepted telemetry"
            )
        self._store = store
        self._key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        self._supervisor = supervisor

    @property
    def supervisor(self) -> FirmwareLivenessSupervisor:
        return self._supervisor

    def public_key_bytes(self) -> bytes:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        return self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sign_liveness_bytes(self, liveness: bytes) -> bytes:
        """Wire message for pre-built liveness bytes (vector/test path)."""
        signature = self._key.sign(liveness)
        sig_b64 = base64.b64encode(signature).decode("ascii")
        return (
            b'{"liveness":'
            + liveness
            + b',"signature":"ed25519:'
            + sig_b64.encode()
            + b'"}'
        )

    async def sign_liveness(
        self,
        *,
        device_id: str,
        boot_id: int,
        capability_hash: str,
    ) -> bytes:
        """Allocate a sequence and sign one liveness message.

        Refuses when the device is not currently supervised. That refusal
        is the whole mechanism: a runtime that has stopped receiving from
        a device must stop asserting that it is watching, and the device
        has no way to check, so this side must not be able to publish by
        accident.
        """
        if not self._supervisor.supervised(
            device_id=device_id, boot_id=boot_id, capability_hash=capability_hash
        ):
            raise FirmwareLivenessError(
                f"{device_id}: not supervised — no accepted telemetry for this "
                f"boot and manifest epoch within the supervision window"
            )
        runtime_seq = await self._store.allocate_firmware_runtime_seq(device_id)
        liveness = build_liveness_bytes(
            boot_id=boot_id,
            capability_hash=capability_hash,
            device_id=device_id,
            runtime_seq=runtime_seq,
        )
        return self.sign_liveness_bytes(liveness)
