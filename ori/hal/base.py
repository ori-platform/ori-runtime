# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import enum
import logging
import time
from abc import ABC, abstractmethod

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


class BaseAdapter(ABC):
    """Common interface for every hardware/protocol adapter in the HAL.

    Concrete adapters (GPIO, I2C, Serial, psutil, MQTT …) must subclass this and implement the three abstract methods.  The runtime interacts exclusively through this interface so that adapters are interchangeable.
    """

    _connected: bool = False

    # ── Abstract methods ──────────────────────────────────────────────────────

    @abstractmethod
    async def connect(self, config: dict) -> None:
        """Open the underlying hardware or protocol connection.

        Called once during runtime start-up.  Must set ``_connected = True`` on success.  Raise :exc:`AdapterConnectionError` if the resource cannot be reached, or :exc:`AdapterTimeoutError` if the attempt exceeds the configured deadline.

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

        Called during graceful runtime shutdown.  Must set
        ``_connected = False``.  Should not raise even if the connection was already lost — log and return cleanly.
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
