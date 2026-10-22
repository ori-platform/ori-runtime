# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""gateway-api/v2 Payload Size and Payload Volume on the runtime's side.

Authentication proves the gateway sent a message, not that the gateway is
working correctly, so every gateway-to-runtime family is bounded in size and
rate here, before any parse, decode or verify. The bounds are the runtime's:
nothing the gateway sends, and no configuration, raises one.
"""

from __future__ import annotations

import logging
import math
import re
import threading
import time
from dataclasses import dataclass
from typing import Callable

from ori.security.payload_members import REASONS as MEMBER_REASONS

logger = logging.getLogger(__name__)

GATEWAY_HEALTH = "ori/gateway/health"
RUNTIME_HEARTBEAT = "ori/{device_id}/runtime/heartbeat"
RUNTIME_POSTURE = "ori/{device_id}/runtime/posture"
REASONING_REQUEST = "ori/{device_id}/reasoning/request"
REASONING_RESPONSE = "ori/{device_id}/reasoning/response"
ENRICHMENT_REQUEST = "ori/{device_id}/tier_c/enrichment/request"
ENRICHMENT_RESPONSE = "ori/{device_id}/tier_c/enrichment/response"
EXPORT_REQUEST = "ori/{device_id}/export/request"
EXPORT_RESPONSE = "ori/{device_id}/export/response/{request_id}"
EVIDENCE_OUTBOUND = "ori/{device_id}/evidence/outbound"
EVIDENCE_OUTBOUND_ACK = "ori/{device_id}/evidence/outbound/ack"
EVIDENCE_INBOUND = "ori/{device_id}/evidence/inbound"
EVIDENCE_INBOUND_ACK = "ori/{device_id}/evidence/inbound/ack"
LAN_PROPOSAL = "ori/{device_id}/lan/proposal"
LAN_REPLY = "ori/{device_id}/lan/reply"
LAN_DISCLOSURE_REQUEST = "ori/{device_id}/lan/disclosure/request"
LAN_DISCLOSURE_RESPONSE = "ori/{device_id}/lan/disclosure/response/{request_id}"

#: The Payload Size table: a topic family's maximum in bytes, as delivered.
PAYLOAD_MAXIMA: dict[str, int] = {
    GATEWAY_HEALTH: 16384,
    RUNTIME_HEARTBEAT: 65536,
    RUNTIME_POSTURE: 4096,
    REASONING_REQUEST: 262144,
    REASONING_RESPONSE: 262144,
    ENRICHMENT_REQUEST: 262144,
    ENRICHMENT_RESPONSE: 262144,
    EXPORT_REQUEST: 16384,
    EXPORT_RESPONSE: 4194304,
    EVIDENCE_OUTBOUND: 1572864,
    EVIDENCE_OUTBOUND_ACK: 16384,
    EVIDENCE_INBOUND: 1114112,
    EVIDENCE_INBOUND_ACK: 16384,
    LAN_PROPOSAL: 16384,
    LAN_REPLY: 16384,
    LAN_DISCLOSURE_REQUEST: 16384,
    LAN_DISCLOSURE_RESPONSE: 16384,
}

#: The lowest maximum a deployment may configure, which every required reply fits.
PAYLOAD_FLOOR = 4096

#: A `device_id` or `request_id` on this hop (runtime-config/v2's pattern).
ROUTING_ID = re.compile(r"[A-Za-z0-9._-]{1,128}")

#: Unicode scalar values an error response's `error` may hold.
ERROR_MAX_SCALARS = 128

#: Names a runtime node heartbeat lists in `active_triggers` at most.
ACTIVE_TRIGGERS_MAX = 64

PAYLOAD_TOO_LARGE = "payload_too_large"
RATE_EXCEEDED = "rate_exceeded"
#: Admitted by size and rate, then dropped: the family's work already in
#: flight is at its bound.
IN_FLIGHT_EXCEEDED = "in_flight_exceeded"
#: Left with the broker unread because a reconnect that redelivers it is due.
REDELIVERY_DUE = "redelivery_due"
#: The Payload Member Rule's reasons are recorded here too, the same way.
REFUSAL_REASONS = (
    PAYLOAD_TOO_LARGE,
    RATE_EXCEEDED,
    IN_FLIGHT_EXCEEDED,
    REDELIVERY_DUE,
    *MEMBER_REASONS,
)

#: Seconds between two WARNING lines for one family and reason; refusals in
#: between are counted into the next line, so a flood cannot grow the log.
_LOG_INTERVAL_S = 1.0


def routing_id(value: object) -> bool:
    """Whether *value* is a `device_id` or `request_id` this hop admits."""
    return isinstance(value, str) and ROUTING_ID.fullmatch(value) is not None


def bounded_error(text: str) -> str:
    """*text* cut to the scalars an error response's `error` may carry."""
    return text[:ERROR_MAX_SCALARS]


def size_class(length: int) -> int:
    """The least power of two not below *length*: all a refusal records of it."""
    return 1 << max(0, length - 1).bit_length()


def fits(family: str, payload: bytes) -> bool:
    """Whether a payload the runtime would publish is within its topic's maximum."""
    return len(payload) <= PAYLOAD_MAXIMA[family]


def fitting_count(total: int, fits_first: Callable[[int], bool]) -> int:
    """The most of *total* leading items for which *fits_first* holds, or 0.

    *fits_first* is monotone: fewer items never make a payload longer.
    """
    low, high = 0, total
    while low < high:
        middle = (low + high + 1) // 2
        if fits_first(middle):
            low = middle
        else:
            high = middle - 1
    return low


@dataclass(frozen=True)
class Rate:
    """Messages a family is processed at: *per_second* sustained, *burst* at once."""

    per_second: float
    burst: int


#: The runtime's rate per family it receives, chosen for a Pi-class host. A
#: gateway heartbeats every few seconds at most; reasoning answers one request
#: at a time; an export request can cost a 10,000-row read; acknowledgements
#: follow what the runtime sent.
INGRESS_RATES: dict[str, Rate] = {
    GATEWAY_HEALTH: Rate(per_second=1.0, burst=5),
    REASONING_RESPONSE: Rate(per_second=10.0, burst=20),
    EXPORT_REQUEST: Rate(per_second=2.0, burst=10),
    EVIDENCE_OUTBOUND_ACK: Rate(per_second=20.0, burst=64),
    EVIDENCE_INBOUND: Rate(per_second=10.0, burst=32),
}

#: The fewest entries a gateway replay cache holds.
REPLAY_CACHE_FLOOR = 4096
#: The most: tens of megabytes, held once per process since every route shares
#: one cache, and about 51 minutes of traffic at every family's full rate. A
#: cache sized past it by a long replay window fails closed when full,
#: refusing authentic messages as replays, rather than growing the process
#: that also runs Tier D without bound.
REPLAY_CACHE_CEILING = 131_072


def replay_capacity(ttl_ms: int) -> int:
    """Replay-cache entries every admitted gateway message fits in for *ttl_ms*.

    One cache serves every gateway family, so it must hold what all of them
    admit within a replay window. Smaller, a cache full of keys it must keep
    refuses authentic messages as replays.
    """
    window_s = max(0, int(ttl_ms)) / 1000.0
    admitted = sum(rate.per_second for rate in INGRESS_RATES.values()) * window_s
    bursts = sum(rate.burst for rate in INGRESS_RATES.values())
    return min(
        REPLAY_CACHE_CEILING, max(REPLAY_CACHE_FLOOR, math.ceil(admitted) + bursts)
    )


def refill_seconds(family: str) -> float:
    """How long *family*'s rate takes to admit a full burst again."""
    rate = INGRESS_RATES[family]
    return rate.burst / rate.per_second


class IngressBound:
    """Size, then rate, for one gateway-to-runtime family; safe from any thread.

    A refused message is counted and logged by family, reason and size class,
    never by contents or device. runtime-health/v4 does not yet name a field
    for the counts, so the log is the only report (gateway-api/v2 Payload
    Volume): refusals are written at most once a second per reason, and every
    one is in a line, the last within a second of its refusal.
    """

    def __init__(
        self, family: str, *, clock: Callable[[], float] = time.monotonic
    ) -> None:
        rate = INGRESS_RATES[family]
        self.family = family
        self.maximum = PAYLOAD_MAXIMA[family]
        self._per_second = rate.per_second
        self._burst = float(rate.burst)
        self._tokens = float(rate.burst)
        self._clock = clock
        self._last = clock()
        self._lock = threading.Lock()
        self._refusals: dict[str, int] = {PAYLOAD_TOO_LARGE: 0, RATE_EXCEEDED: 0}
        self._unlogged: dict[str, int] = dict.fromkeys(REFUSAL_REASONS, 0)
        self._classes: dict[str, set[int]] = {r: set() for r in REFUSAL_REASONS}
        self._logged_at: dict[str, float] = dict.fromkeys(
            REFUSAL_REASONS, float("-inf")
        )
        self._flush: dict[str, threading.Timer | None] = dict.fromkeys(
            REFUSAL_REASONS, None
        )

    def admit(self, payload: object) -> str | None:
        """None when *payload* may be read; otherwise the reason it is refused.

        Nothing of the payload is read but its length.
        """
        if not self.within_size(payload):
            return PAYLOAD_TOO_LARGE
        length = len(payload)  # type: ignore[arg-type]
        with self._lock:
            now = self._clock()
            elapsed = max(0.0, now - self._last)
            self._last = now
            self._tokens = min(self._burst, self._tokens + elapsed * self._per_second)
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return None
        self._refuse(RATE_EXCEEDED, length)
        return RATE_EXCEEDED

    def within_size(self, payload: object) -> bool:
        """Whether *payload* is within the maximum; a refusal is counted."""
        length = len(payload) if isinstance(payload, (bytes, bytearray)) else -1
        if length < 0 or length > self.maximum:
            self._refuse(PAYLOAD_TOO_LARGE, length)
            return False
        return True

    def refuse(self, reason: str) -> None:
        """Count and log a drop the route decided after size and rate,
        including a refusal under the Payload Member Rule."""
        if reason not in (IN_FLIGHT_EXCEEDED, REDELIVERY_DUE, *MEMBER_REASONS):
            raise ValueError(f"{reason!r} is not a route's own refusal")
        self._refuse(reason, -1)

    def refusals(self) -> dict[str, int]:
        """Messages refused so far, by reason."""
        with self._lock:
            return dict(self._refusals)

    def _refuse(self, reason: str, length: int) -> None:
        with self._lock:
            self._refusals[reason] = self._refusals.get(reason, 0) + 1
            self._unlogged[reason] += 1
            if reason == PAYLOAD_TOO_LARGE:
                self._classes[reason].add(size_class(length) if length >= 0 else -1)
            if self._flush[reason] is not None:
                return
            # Wall time, not the rate's clock: the log is paced by real seconds.
            wait = self._logged_at[reason] + _LOG_INTERVAL_S - time.monotonic()
            if wait > 0:
                timer = threading.Timer(wait, self._flush_pending, args=(reason,))
                timer.daemon = True
                try:
                    timer.start()
                except RuntimeError:
                    # No thread to flush with, as at interpreter shutdown:
                    # written now, never held back.
                    pass
                else:
                    self._flush[reason] = timer
                    return
            line = self._take(reason)
        self._log(reason, *line)

    def _flush_pending(self, reason: str) -> None:
        with self._lock:
            self._flush[reason] = None
            line = self._take(reason)
        self._log(reason, *line)

    def _take(self, reason: str) -> tuple[int, list[int]]:
        count, self._unlogged[reason] = self._unlogged[reason], 0
        classes = sorted(self._classes[reason])
        self._classes[reason].clear()
        self._logged_at[reason] = time.monotonic()
        return count, classes

    def _log(self, reason: str, count: int, classes: list[int]) -> None:
        if count == 0:
            return
        if reason == PAYLOAD_TOO_LARGE:
            logger.warning(
                "[gateway-ingress] %s refused %d message(s) as %s; size classes "
                "%s, maximum %d",
                self.family,
                count,
                reason,
                ", ".join("unknown" if c < 0 else str(c) for c in classes),
                self.maximum,
            )
        else:
            logger.warning(
                "[gateway-ingress] %s dropped %d message(s) as %s",
                self.family,
                count,
                reason,
            )
