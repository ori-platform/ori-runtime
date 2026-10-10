# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""How old a firmware reading is, as the runtime that signed its liveness sees it.

firmware-telemetry/v2 How Old A Reading Is. A device signs into each reading the
nonce of the last ``v`` 2 liveness message it accepted before the measurement
began. This runtime recorded the instant it began signing that message, so it
can bound from above how long ago the device began the reading's transaction:
``now - signing_start``. Nothing else can.

Everything here is memory only and on one clock that counts suspended time. A
restart empties it, so a reading read back from storage has no bound, and a
store restore while the process runs changes nothing here. The bound dates the
device's transaction, never the measured quantity, and confers no authority.
"""

from __future__ import annotations

import bisect
import datetime
import math
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from ori.utils.platform import runtime_platform

__all__ = [
    "RETENTION_NS",
    "DEFAULT_TOTAL_BOUND",
    "AnchoredBound",
    "LivenessEntry",
    "LivenessTable",
    "ReadingAgeTracker",
    "anchor_bound",
    "default_per_device_bound",
    "measured_statement",
    "signing_clock_id",
    "signing_clock_ns",
]

#: One hour, inclusive: an entry is usable while its age is at most this.
RETENTION_NS = 3_600_000_000_000

_NS_PER_MS = 1_000_000
_NS_PER_S = 1_000_000_000

#: How many accepted messages keep their signing start for lookup by
#: ``(device_id, boot_id, seq)``. A message pushed out has no bound, which is
#: the conservative answer; each channel's latest reading is held apart from it.
DEFAULT_MESSAGE_CAPACITY = 8192

#: Entries across every device. Fixed rather than scaled by the interval, so
#: memory stays bounded however short the interval is configured.
DEFAULT_TOTAL_BOUND = 65_536


def signing_clock_id() -> int | None:
    """The clock the contract names for this host, or None where it names none.

    CLOCK_BOOTTIME on Linux and Android and CLOCK_MONOTONIC on macOS, each of
    which keeps counting while the host is suspended. Never a wall clock, and
    never a clock that stops during suspend.
    """
    platform = runtime_platform()
    if platform.startswith("linux") or platform == "android":
        return getattr(time, "CLOCK_BOOTTIME", None)
    if platform == "darwin":
        return getattr(time, "CLOCK_MONOTONIC", None)
    return None


def signing_clock_ns() -> int | None:
    """Nanoseconds on the signing clock, or None when it cannot be read."""
    clock_id = signing_clock_id()
    if clock_id is None:
        return None
    try:
        return time.clock_gettime_ns(clock_id)
    except OSError:
        return None


def default_per_device_bound(publish_interval_s: float) -> int:
    """One hour of a device's ``v`` 2 liveness messages, plus the boundary one."""
    return math.ceil(3600.0 / publish_interval_s) + 1


@dataclass(frozen=True)
class LivenessEntry:
    nonce: str
    device_id: str
    boot_id: int
    capability_hash: str
    signing_start_ns: int


class LivenessTable:
    """One entry per ``v`` 2 nonce this process signed, bounded per device and in total."""

    def __init__(self, *, per_device_bound: int, total_bound: int) -> None:
        for name, bound in (
            ("per_device_bound", per_device_bound),
            ("total_bound", total_bound),
        ):
            if isinstance(bound, bool) or not isinstance(bound, int) or bound < 1:
                raise ValueError(f"{name} must be a positive integer: {bound!r}")
        self._per_device_bound = per_device_bound
        self._total_bound = total_bound
        self._entries: dict[str, LivenessEntry] = {}
        # (signing start, nonce), sorted: the eviction order, earliest first.
        self._order: list[tuple[int, str]] = []
        self._by_device: dict[str, list[tuple[int, str]]] = {}

    @property
    def per_device_bound(self) -> int:
        return self._per_device_bound

    @property
    def total_bound(self) -> int:
        return self._total_bound

    def __len__(self) -> int:
        return len(self._entries)

    def holds(self, nonce: str) -> bool:
        return nonce in self._entries

    def device_count(self, device_id: str) -> int:
        return len(self._by_device.get(device_id, ()))

    def _remove(self, nonce: str) -> None:
        entry = self._entries.pop(nonce, None)
        if entry is None:
            return
        key = (entry.signing_start_ns, nonce)
        index = bisect.bisect_left(self._order, key)
        if index < len(self._order) and self._order[index] == key:
            del self._order[index]
        device = self._by_device.get(entry.device_id)
        if device is not None:
            index = bisect.bisect_left(device, key)
            if index < len(device) and device[index] == key:
                del device[index]
            if not device:
                del self._by_device[entry.device_id]

    def record(self, entry: LivenessEntry) -> None:
        """Record an entry as of its signing start, evicting first as the contract orders."""
        if entry.nonce in self._entries:
            raise ValueError("a nonce is recorded at most once")
        now = entry.signing_start_ns
        # Expired is an age above the hour, judged at the new signing start.
        while self._order and now - self._order[0][0] > RETENTION_NS:
            self._remove(self._order[0][1])
        device = self._by_device.get(entry.device_id, [])
        if len(device) >= self._per_device_bound:
            self._remove(device[0][1])
        if len(self._entries) >= self._total_bound:
            self._remove(self._order[0][1])
        key = (entry.signing_start_ns, entry.nonce)
        self._entries[entry.nonce] = entry
        bisect.insort(self._order, key)
        bisect.insort(self._by_device.setdefault(entry.device_id, []), key)

    def discard(self, nonce: str) -> None:
        """Drop the entry of a signing that failed; what its recording evicted stays evicted."""
        self._remove(nonce)

    def match(
        self,
        *,
        nonce: str,
        device_id: str,
        boot_id: int,
        capability_hash: str,
        now_ns: int,
    ) -> int | None:
        """The signing start an envelope accepted at ``now_ns`` takes, if any."""
        entry = self._entries.get(nonce)
        if entry is None:
            return None
        if (entry.device_id, entry.boot_id, entry.capability_hash) != (
            device_id,
            boot_id,
            capability_hash,
        ):
            return None
        if now_ns - entry.signing_start_ns > RETENTION_NS:
            return None
        return entry.signing_start_ns


@dataclass(frozen=True)
class AnchoredBound:
    """A bound as it leaves the process: A, and T, the wall-clock instant it was computed."""

    age_upper_ns: int
    as_of_ms: int

    @property
    def age_upper_ms(self) -> int:
        return -(-self.age_upper_ns // _NS_PER_MS)

    def age_text(self) -> str:
        """A in the coarsest whole unit that still reads naturally, rounded up."""
        seconds = -(-self.age_upper_ns // _NS_PER_S)
        if seconds < 120:
            return f"{seconds} s"
        minutes = -(-seconds // 60)
        if minutes < 120:
            return f"{minutes} min"
        return f"{-(-minutes // 60)} h"

    def as_of_iso(self) -> str:
        return datetime.datetime.fromtimestamp(
            self.as_of_ms / 1000, tz=datetime.UTC
        ).isoformat(timespec="seconds")

    def text(self, as_of: str | None = None) -> str:
        return f"polled no more than {self.age_text()} ago, as of {as_of or self.as_of_iso()}"

    def as_health(self) -> dict[str, Any]:
        return {
            "name": "runtime liveness bound",
            "age_upper_ms": self.age_upper_ms,
            "as_of": self.as_of_iso(),
            "text": self.text(),
        }


def wall_clock_ms() -> int:
    return time.time_ns() // _NS_PER_MS


def anchor_bound(
    signing_start_ns: int | None,
    *,
    clock: Callable[[], int | None] = signing_clock_ns,
    wall_ms: Callable[[], int] = wall_clock_ms,
) -> AnchoredBound | None:
    """Compute ``age_upper`` now, and name the wall-clock instant it was computed.

    T is read before the monotonic sample, so a suspension between the two
    reads lengthens A rather than dating a short A to a later T.
    """
    if signing_start_ns is None:
        return None
    as_of = wall_ms()
    now = clock()
    if now is None:
        return None
    return AnchoredBound(age_upper_ns=max(0, now - signing_start_ns), as_of_ms=as_of)


@dataclass(frozen=True)
class _Latest:
    boot_id: int
    seq: int
    key_epoch_id: str
    signing_start_ns: int | None


class ReadingAgeTracker:
    """Signing starts held with accepted messages, and each channel's latest reading.

    Holds no bound of its own: ``age_upper`` is computed at each use from the
    signing start and the clock, because it grows after receipt.
    """

    def __init__(
        self,
        table: LivenessTable | None,
        *,
        clock: Callable[[], int | None] = signing_clock_ns,
        wall_ms: Callable[[], int] = wall_clock_ms,
        message_capacity: int = DEFAULT_MESSAGE_CAPACITY,
    ) -> None:
        self._table = table
        self._clock = clock
        self._wall_ms = wall_ms
        self._message_capacity = message_capacity
        # Keyed by the key epoch as well as the counters: a re-keyed device
        # restarts (boot_id, seq), and one message must never take another's
        # signing start.
        self._messages: OrderedDict[tuple[str, str, int, int], int | None] = (
            OrderedDict()
        )
        self._channels: dict[tuple[str, str], _Latest] = {}
        self._devices: dict[str, _Latest] = {}

    @property
    def table(self) -> LivenessTable | None:
        return self._table

    @property
    def clock(self) -> Callable[[], int | None]:
        return self._clock

    def note_accepted(
        self,
        *,
        version: int,
        device_id: str,
        boot_id: int,
        capability_hash: str,
        seq: int,
        channels: Iterable[str],
        liveness_nonce: str | None,
        key_epoch_id: str,
        now_ns: int | None = None,
    ) -> int | None:
        """Match an accepted envelope's nonce and hold its signing start, if any."""
        signing_start: int | None = None
        if version == 2 and liveness_nonce is not None and self._table is not None:
            now = self._clock() if now_ns is None else now_ns
            if now is not None:
                signing_start = self._table.match(
                    nonce=liveness_nonce,
                    device_id=device_id,
                    boot_id=boot_id,
                    capability_hash=capability_hash,
                    now_ns=now,
                )
        key = (device_id, key_epoch_id, boot_id, seq)
        if key in self._messages:
            # Held immutably: the freshness mark admits a message once per key
            # epoch, so a second acceptance under one key changes nothing here.
            return self._messages[key]
        self._messages[key] = signing_start
        while len(self._messages) > self._message_capacity:
            self._messages.popitem(last=False)
        latest = _Latest(boot_id, seq, key_epoch_id, signing_start)
        names = list(channels)
        for channel in names:
            self._channels[(device_id, channel)] = latest
        # A heartbeat measures nothing, so it never becomes a latest reading.
        if names:
            self._devices[device_id] = latest
        return signing_start

    def message_signing_start(
        self, device_id: str, key_epoch_id: str, boot_id: int, seq: int
    ) -> int | None:
        return self._messages.get((device_id, key_epoch_id, boot_id, seq))

    def message_age_ns(
        self,
        device_id: str,
        key_epoch_id: str,
        boot_id: int,
        seq: int,
        *,
        now_ns: int | None = None,
    ) -> int | None:
        return self._age(
            self.message_signing_start(device_id, key_epoch_id, boot_id, seq), now_ns
        )

    def channel_latest(self, device_id: str, channel: str) -> tuple[int, int] | None:
        latest = self._channels.get((device_id, channel))
        return None if latest is None else (latest.boot_id, latest.seq)

    def channel_age_ns(
        self, device_id: str, channel: str, *, now_ns: int | None = None
    ) -> int | None:
        latest = self._channels.get((device_id, channel))
        return None if latest is None else self._age(latest.signing_start_ns, now_ns)

    def message_bound(
        self, device_id: str, key_epoch_id: str, boot_id: int, seq: int
    ) -> AnchoredBound | None:
        return self._anchor(
            self.message_signing_start(device_id, key_epoch_id, boot_id, seq)
        )

    def channel_bound(self, device_id: str, channel: str) -> AnchoredBound | None:
        latest = self._channels.get((device_id, channel))
        return None if latest is None else self._anchor(latest.signing_start_ns)

    def _anchor(self, signing_start: int | None) -> AnchoredBound | None:
        return anchor_bound(signing_start, clock=self._clock, wall_ms=self._wall_ms)

    def health(self) -> list[dict[str, Any]]:
        """Per device, its latest accepted reading and that reading's bound, or unbounded."""
        devices = []
        for device_id in sorted(self._devices):
            latest = self._devices[device_id]
            bound = self._anchor(latest.signing_start_ns)
            devices.append(
                {
                    "device_id": device_id,
                    "latest_reading": {
                        "key_epoch_id": latest.key_epoch_id,
                        "boot_id": latest.boot_id,
                        "seq": latest.seq,
                    },
                    "liveness_bound": "unbounded"
                    if bound is None
                    else bound.as_health(),
                }
            )
        return devices

    def _age(self, signing_start: int | None, now_ns: int | None) -> int | None:
        if signing_start is None:
            return None
        now = self._clock() if now_ns is None else now_ns
        if now is None:
            return None
        return max(0, now - signing_start)


def measured_statement(
    tracker: ReadingAgeTracker, reading: Any, device_timezone: str
) -> str | None:
    """What a Measured line may say about a firmware reading, or None for any other.

    The device reports no measurement time, so the line says so, and adds the
    bound only when this process signed the reading's liveness nonce, anchored
    to the instant it was computed (firmware-telemetry/v2 What a receiver may
    present).
    """
    metadata = getattr(reading, "metadata", None)
    if not isinstance(metadata, dict) or metadata.get("source") != "firmware":
        return None
    line = "not reported by device"
    device = metadata.get("firmware_device_id")
    key_epoch_id = metadata.get("key_epoch_id")
    boot_id = metadata.get("boot_id")
    seq = metadata.get("seq")
    if (
        isinstance(device, str)
        and isinstance(key_epoch_id, str)
        and key_epoch_id
        and type(boot_id) is int
        and type(seq) is int
    ):
        bound = tracker.message_bound(device, key_epoch_id, boot_id, seq)
        if bound is not None:
            line += f", {bound.text(_local_time(bound.as_of_ms, device_timezone))}"
    return line


def _local_time(at_ms: int, device_timezone: str) -> str:
    from zoneinfo import ZoneInfo

    zone = ZoneInfo(device_timezone or "Africa/Lagos")
    return datetime.datetime.fromtimestamp(at_ms / 1000, tz=zone).strftime(
        "%A %H:%M:%S"
    )
