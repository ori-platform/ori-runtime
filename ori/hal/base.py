# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import enum
import logging
import time
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

from ori.network.events import SensorReading

logger = logging.getLogger(__name__)


class AdapterConnectionError(Exception):
    """Raised when an adapter cannot establish or restore a connection."""


class AdapterTimeoutError(Exception):
    """Raised when a read or connect operation exceeds its deadline."""


class AdapterReadError(Exception):
    """Raised when a connection exists but a sensor read fails."""


class MeasurementRefusedError(AdapterReadError):
    """Raised when a sensor answered but what it returned is not a measurement.

    A distinct condition from a bus timeout or an open circuit breaker, and the
    distinction has to be carried by the type. Classifying it by matching the
    message text would mean a reworded string silently disables the degradation
    tracking and the operator alert that depend on it, while every arithmetic
    test stays green.
    """


class CircuitState(enum.Enum):
    """Three states of the circuit breaker state machine."""

    CLOSED = "closed"  # Normal operation — reads allowed.
    OPEN = "open"  # Too many failures — reads blocked.
    HALF_OPEN = "half_open"  # Recovery probe — one read allowed to test recovery.


class HardwareCircuitBreaker:
    """Per-instance circuit breaker for HAL adapters using an async context manager.

    Tracks consecutive read failures and opens the circuit when the failure
    threshold is reached, preventing cascading hardware errors from flooding
    the event loop.  After ``recovery_timeout_s`` the breaker moves to
    HALF_OPEN and allows a single probe read.  Consecutive successes in
    HALF_OPEN close the circuit again.

    Initialize once during adapter ``connect()``.
    Wrap every ``read()`` body with ``async with self._breaker:``.
    """

    def __init__(self, adapter_name: str, config: dict) -> None:
        self.adapter_name = adapter_name
        cb_cfg: dict = config.get("circuit_breaker", {})
        self.failure_threshold: int = int(cb_cfg.get("failure_threshold", 5))
        self.recovery_timeout_s: float = float(cb_cfg.get("recovery_timeout_s", 300))
        self.success_threshold: int = int(cb_cfg.get("success_threshold", 2))
        self.state: CircuitState = CircuitState.CLOSED
        self.failure_count: int = 0
        self.success_count: int = 0
        self.opened_at: float | None = None

    async def __aenter__(self):
        if not self._allow_read():
            raise AdapterReadError(f"{self.adapter_name}: circuit breaker OPEN")
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self._record_success()
            return False

        # Cancellation is an orchestration signal, not a hardware success/failure.
        if issubclass(exc_type, asyncio.CancelledError):
            return False

        if issubclass(exc_type, Exception):
            just_tripped = self._record_failure()
            if just_tripped:
                logger.warning(
                    "%s: circuit breaker tripped — hardware offline",
                    self.adapter_name,
                )
        return False

    def _allow_read(self) -> bool:
        if self.state == CircuitState.CLOSED:
            return True

        if self.state == CircuitState.OPEN:
            if self.opened_at is None:
                # Corrupted internal state: fail closed and reset the open timestamp.
                self.opened_at = time.monotonic()
                logger.error(
                    "%s: circuit breaker OPEN with missing opened_at; "
                    "resetting timer and failing closed",
                    self.adapter_name,
                )
                return False
            elapsed = time.monotonic() - self.opened_at
            if elapsed >= self.recovery_timeout_s:
                self.state = CircuitState.HALF_OPEN
                self.success_count = 0
                logger.info(
                    "%s: circuit breaker → HALF_OPEN (%.0fs elapsed, probing)",
                    self.adapter_name,
                    elapsed,
                )
                return True
            return False

        # HALF_OPEN — allow the probe read
        return True

    def _record_success(self) -> None:
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.success_threshold:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                self.success_count = 0
                logger.info(
                    "%s: circuit breaker → CLOSED (recovered after %d successes)",
                    self.adapter_name,
                    self.success_threshold,
                )
        elif self.state == CircuitState.CLOSED:
            self.failure_count = 0

    def _record_failure(self) -> bool:
        if self.state == CircuitState.OPEN:
            return False

        self.failure_count += 1

        if (
            self.state == CircuitState.HALF_OPEN
            or self.failure_count >= self.failure_threshold
        ):
            self.state = CircuitState.OPEN
            self.opened_at = time.monotonic()
            logger.warning(
                "%s: circuit breaker → OPEN (failure_count=%d)",
                self.adapter_name,
                self.failure_count,
            )
            return True

        return False


BAUD_RATE_KEY = "baud_rate"
LEGACY_BAUD_RATE_KEY = "baudrate"


def coerce_baud_rate(value: Any, key: str, adapter_name: str) -> int:
    """A baud rate is a positive whole number, or it is a refusal.

    Never a fallback to the default. A rate the runtime could not read is not
    evidence that the operator wanted 9600.
    """
    rate: int | None = None
    if isinstance(value, bool):
        rate = None
    elif isinstance(value, int):
        rate = value
    elif isinstance(value, float) and value.is_integer():
        rate = int(value)
    elif isinstance(value, str):
        try:
            rate = int(value.strip())
        except ValueError:
            rate = None

    if rate is None or rate <= 0:
        raise AdapterConnectionError(
            f"{adapter_name}: '{key}' must be a positive whole number of bits "
            f"per second, got {value!r}."
        )
    return rate


def resolve_baud_rate(
    *,
    has_canonical: bool,
    canonical: Any,
    has_legacy: bool,
    legacy: Any,
    default: int,
    adapter_name: str,
) -> int:
    """Resolve the canonical ``baud_rate``, bridging the legacy ``baudrate``.

    One setting had two spellings across two adapters, so a serial sensor
    configured with the wrong one ran at the default with nothing logged and
    nothing refused.

    Presence and value are passed in rather than the config dict, so each
    adapter keeps a literal ``config.get("baud_rate")`` where a reader can see
    it — and where the configuration-surface extractor can too. A helper that
    swallowed the dict would make both adapters appear to read nothing, and an
    inventory built from that would omit the key entirely.
    """
    if has_canonical and has_legacy:
        raise AdapterConnectionError(
            f"{adapter_name}: sensor config sets both '{BAUD_RATE_KEY}' and "
            f"'{LEGACY_BAUD_RATE_KEY}'. Refused even when the values agree — "
            f"ambiguity must not establish configuration. Keep "
            f"'{BAUD_RATE_KEY}'."
        )

    if has_canonical:
        return coerce_baud_rate(canonical, BAUD_RATE_KEY, adapter_name)

    if has_legacy:
        logger.warning(
            "%s: '%s' is deprecated; the canonical spelling is '%s'. The alias "
            "is accepted for this configuration generation and is removed when "
            "runtime-config/v2 becomes the accepted surface. Rename it now.",
            adapter_name,
            LEGACY_BAUD_RATE_KEY,
            BAUD_RATE_KEY,
        )
        return coerce_baud_rate(legacy, LEGACY_BAUD_RATE_KEY, adapter_name)

    return default


class BaseAdapter(ABC):
    """Common interface for every hardware/protocol adapter in the HAL.

    Concrete adapters (GPIO, I2C, Serial, psutil, MQTT …) must subclass this and implement the three abstract methods.  The runtime interacts exclusively through this interface so that adapters are interchangeable.
    """

    _connected: bool = False

    # Bumped by every close before it can acquire the lifecycle lock, so a
    # connect can tell that one arrived while its own worker was still
    # running. Class-level defaults because most adapters do not call
    # ``super().__init__()``; both become instance attributes on first write.
    _close_generation: int = 0
    _lifecycle_lock: "asyncio.Lock | None" = None

    # ── Lifecycle contract ────────────────────────────────────────────────────
    #
    # `connect()` does its blocking work off the event loop, and `close()`
    # releases resources with awaits of its own. Without a shared rule the two
    # interleave: a close releases what has been taken so far while the
    # connect's worker goes on taking more, and the adapter ends up believing
    # it is connected while holding resources nobody else believes are in use.
    #
    # The guarantee every adapter gets from `_connecting` and `_closing`:
    #
    #   * Only one of connect and close runs at a time, per adapter.
    #   * A connect that finds itself connected is refused, before it touches
    #     any state and before it reaches the device. Reconnecting in place
    #     would take a second resource reference against one release and move
    #     a live adapter's device under readings already being taken from it.
    #     **An adapter must therefore validate into locals and assign to
    #     `self` inside the `_connecting` body.** Assigning before it leaves a
    #     refused connect having already overwritten the live configuration:
    #     the adapter stays connected on the old handle while its fields name
    #     the new target, and `read()` then samples one device and labels the
    #     reading with another.
    #   * **A connect that was closed while it was connecting raises**
    #     `AdapterConnectionError` and leaves the adapter disconnected and
    #     holding nothing. It does not return successfully, because a connect
    #     that was closed did not connect.
    #   * A connect that fails for any reason gives back what it took.
    #
    # What the runtime does with that refusal: it connects adapters
    # sequentially and appends each to its list only after `connect()` returns,
    # closing only what is in that list, so an in-flight adapter is never
    # closed in production and the refusal is not reachable there. It is a
    # contract, held at the boundary, rather than a live bug being papered
    # over. During shutdown the refusal would surface the same way any other
    # connect failure does — logged, the adapter not added, the runtime
    # continuing — which is the correct outcome for an adapter that is being
    # torn down anyway. `ori/runtime.py` does more than log: it records the
    # sensor in `_unconnected_sensors`, calls
    # `_safety_registry.note_sensor_unavailable()` and warns the operator. A
    # refused connect therefore tells a Tier D pair that its measurement is
    # unavailable, which is the reason this refusal has to be correct rather
    # than merely tidy.
    #
    # An adapter that cannot meet this must say so in its own docstring rather
    # than inherit the guarantee silently.

    @property
    def _lifecycle(self) -> asyncio.Lock:
        """The per-adapter connect/close lock, created on first use.

        Lazily created rather than set in ``__init__`` because most adapters
        do not call ``super().__init__()``. There is no race in creating it:
        the first access happens on the event loop thread before any await.
        """
        lock = self._lifecycle_lock
        if lock is None:
            lock = asyncio.Lock()
            # Shadows the class default with an instance attribute, so every
            # adapter gets its own.
            self._lifecycle_lock = lock
        return lock

    @asynccontextmanager
    async def _connecting(
        self,
        description: str,
        *,
        release: Callable[[], Awaitable[None]] | None = None,
    ) -> AsyncIterator[None]:
        """Run an adapter's connect body under the lifecycle guarantee above.

        Args:
            description: What is being connected, for the refusal messages.
            release: Gives back everything the body may have taken. Called
                when the body raises and when a close arrived while it ran, so
                it must be idempotent and safe on a partial connect.
        """
        # Sampled before the lock is requested, not inside it. A close that
        # arrives while an earlier connect holds the lock has already declared
        # itself by the time this one is admitted, and sampling after the wait
        # would lose that: the second connect would report success for an
        # adapter a close outstanding before its body ran then tears down.
        generation = self._close_generation
        async with self._lifecycle:
            if self._connected:
                # Names what was *requested*, not what is held: the base
                # class does not know an adapter's fields, and claiming to
                # name the live device while printing the refused one is
                # worse than not naming it.
                raise AdapterConnectionError(
                    f"{self.adapter_name}: already connected; close it before "
                    f"connecting to {description}"
                )
            try:
                yield
            except BaseException:
                await self._release_quietly(release)
                raise

            if self._close_generation != generation:
                await self._release_quietly(release)
                raise AdapterConnectionError(
                    f"{self.adapter_name}: {description} was closed while it "
                    "was still connecting"
                )
            self._connected = True

    async def _release_quietly(
        self, release: Callable[[], Awaitable[None]] | None
    ) -> None:
        """Give resources back without letting that replace the real failure.

        `release` runs on the failure and abandonment paths, where an
        exception is already on its way to the caller. If it raised, it would
        become the exception `connect()` reports — a `RuntimeError` in place of
        the `AdapterConnectionError` that says what actually went wrong — and
        the remaining resources would still be held.
        """
        if release is None:
            return
        try:
            await release()
        except Exception:
            logger.exception(
                "%s: exception while releasing after a failed connect",
                self.adapter_name,
            )

    @asynccontextmanager
    async def _closing(self) -> AsyncIterator[None]:
        """Run an adapter's close body under the lifecycle guarantee above.

        The close records itself *before* requesting the lock. A connect
        holding the lock cannot be interrupted, but it can be told that a
        close is waiting, and that is what stops it reporting success.
        """
        self._close_generation += 1
        async with self._lifecycle:
            self._connected = False
            yield

    # ── Abstract methods ──────────────────────────────────────────────────────

    @abstractmethod
    async def connect(self, config: dict) -> None:
        """Open the underlying hardware or protocol connection.

        Called once during runtime start-up.  Run the body inside :meth:`_connecting`, which owns ``_connected`` and the lifecycle guarantee above; do not set the flag directly.  Raise :exc:`AdapterConnectionError` if the resource cannot be reached, or :exc:`AdapterTimeoutError` if the attempt exceeds the configured deadline.

        Args:
            config: The sensor-level config dict from ``ori.yaml`` (keys such as ``address``, ``channel``, ``port`` vary by adapter type).
        """

    @abstractmethod
    async def read(self, sensor_id: str) -> SensorReading:
        """Sample the sensor and return a single normalised reading.

        Must be callable repeatedly at ``poll_interval_ms`` frequency.
        Raise :exc:`AdapterReadError` for transient read failures.
        Raise :exc:`AdapterTimeoutError` if the hardware does not respond in time.  Never returns ``None`` — callers rely on a valid :class:`~ori.network.events.SensorReading` on success.

        Args:
            sensor_id: The logical sensor id from ``ori.yaml``, embedded in the returned :class:`~ori.network.events.SensorReading`.
        """

    @abstractmethod
    async def close(self) -> None:
        """Release the underlying hardware or protocol connection.

        Called during graceful runtime shutdown.  Run the body inside
        :meth:`_closing`, which owns ``_connected``; do not clear the flag
        directly.  Should not raise even if the connection was already lost — log and return cleanly.
        """

    # ── Concrete methods (may be overridden) ──────────────────────────────────

    async def health_check(self) -> bool:
        """Return ``True`` if the adapter is operational.

        The default implementation returns ``True`` when :attr:`is_connected` is ``True``.  Adapters with richer diagnostics (e.g. register reads, ping commands) should override this.
        """
        return self._connected

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def is_connected(self) -> bool:
        """``True`` after a successful :meth:`connect`, ``False`` after :meth:`close`."""
        return self._connected

    @property
    def adapter_name(self) -> str:
        """Human-readable adapter identifier — defaults to the class name."""
        return type(self).__name__
