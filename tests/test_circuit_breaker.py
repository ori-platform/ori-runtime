# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Tests for the HardwareCircuitBreaker and its integration with HAL adapters."""

import asyncio
from unittest.mock import patch

import pytest

from ori.hal.base import (
    AdapterReadError,
    CircuitState,
    HardwareCircuitBreaker,
)
from ori.hal.psutil_adapter import PsutilAdapter

# ── Helpers ───────────────────────────────────────────────────────────────────


def _make(config: dict | None = None) -> HardwareCircuitBreaker:
    return HardwareCircuitBreaker("TestAdapter", config or {})


# ── Unit tests ────────────────────────────────────────────────────────────────


def test_starts_closed():
    cb = _make()
    assert cb.state == CircuitState.CLOSED
    assert cb._allow_read() is True


def test_success_resets_failure_count():
    cb = _make()
    # Record 3 partial failures (below threshold of 5)
    for _ in range(3):
        cb._record_failure()
    assert cb.failure_count == 3
    # One success in CLOSED should reset the counter
    cb._record_success()
    assert cb.failure_count == 0
    assert cb.state == CircuitState.CLOSED


def test_closed_to_open_after_threshold():
    cb = _make({"circuit_breaker": {"failure_threshold": 3}})
    result_1 = cb._record_failure()
    result_2 = cb._record_failure()
    assert result_1 is False
    assert result_2 is False
    result_3 = cb._record_failure()  # threshold reached
    assert result_3 is True
    assert cb.state == CircuitState.OPEN


def test_open_blocks_reads():
    cb = _make({"circuit_breaker": {"failure_threshold": 1, "recovery_timeout_s": 300}})
    cb._record_failure()
    assert cb.state == CircuitState.OPEN
    # Patch monotonic so time has NOT elapsed
    assert cb.opened_at is not None
    with patch("ori.hal.base.time.monotonic", return_value=cb.opened_at + 10):
        assert cb._allow_read() is False


def test_open_to_half_open_after_timeout():
    cb = _make({"circuit_breaker": {"failure_threshold": 1, "recovery_timeout_s": 60}})
    cb._record_failure()
    assert cb.state == CircuitState.OPEN
    # Advance monotonic past the recovery timeout
    assert cb.opened_at is not None
    with patch("ori.hal.base.time.monotonic", return_value=cb.opened_at + 61):
        allowed = cb._allow_read()
    assert allowed is True
    assert cb.state == CircuitState.HALF_OPEN


def test_half_open_to_closed_after_successes():
    cb = _make({"circuit_breaker": {"failure_threshold": 1, "success_threshold": 2}})
    cb._record_failure()  # → OPEN
    # Manually transition to HALF_OPEN
    cb.state = CircuitState.HALF_OPEN
    cb.success_count = 0

    cb._record_success()
    assert cb.state == CircuitState.HALF_OPEN  # still waiting
    cb._record_success()
    assert cb.state == CircuitState.CLOSED
    assert cb.success_count == 0
    assert cb.failure_count == 0


def test_half_open_to_open_on_failure():
    cb = _make({"circuit_breaker": {"failure_threshold": 10}})  # high threshold
    cb._record_failure()  # push failure count up but stay under threshold
    # Manually force into HALF_OPEN
    cb.state = CircuitState.HALF_OPEN
    cb.failure_count = 0

    just_tripped = cb._record_failure()
    assert just_tripped is True
    assert cb.state == CircuitState.OPEN


def test_record_failure_returns_false_when_already_open():
    cb = _make({"circuit_breaker": {"failure_threshold": 1}})
    cb._record_failure()  # → OPEN, returns True
    assert cb.state == CircuitState.OPEN
    # Subsequent failures while OPEN must return False (no double-trip)
    for _ in range(3):
        result = cb._record_failure()
        assert result is False


def test_default_config():
    cb = _make({})
    assert cb.failure_threshold == 5
    assert cb.recovery_timeout_s == 300
    assert cb.success_threshold == 2


def test_custom_config():
    cb = _make({"circuit_breaker": {"failure_threshold": 3}})
    assert cb.failure_threshold == 3
    assert cb.recovery_timeout_s == 300  # default
    assert cb.success_threshold == 2  # default


@pytest.mark.asyncio
async def test_unexpected_exception_counts_as_failure():
    cb = _make({"circuit_breaker": {"failure_threshold": 1}})

    class UnexpectedReadError(Exception):
        pass

    with pytest.raises(UnexpectedReadError):
        async with cb:
            raise UnexpectedReadError("boom")

    assert cb.state == CircuitState.OPEN


@pytest.mark.asyncio
async def test_cancelled_error_is_neutral():
    cb = _make()
    cb._record_failure()
    assert cb.failure_count == 1

    with pytest.raises(asyncio.CancelledError):
        async with cb:
            raise asyncio.CancelledError()

    assert cb.state == CircuitState.CLOSED
    assert cb.failure_count == 1


def test_open_state_without_opened_at_fails_closed():
    cb = _make()
    cb.state = CircuitState.OPEN
    cb.opened_at = None

    assert cb._allow_read() is False
    assert cb.opened_at is not None


# ── Integration: PsutilAdapter ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_psutil_adapter_integration():
    """Circuit breaker trips after failure_threshold consecutive read errors."""
    adapter = PsutilAdapter()
    config = {
        "sensor_id": "test-cpu",
        "sensor_type": "cpu_percent",
        "circuit_breaker": {"failure_threshold": 3, "recovery_timeout_s": 300},
    }
    await adapter.connect(config)
    assert adapter._breaker.state == CircuitState.CLOSED

    # Patch the internal sync read so every call raises AdapterReadError
    error = AdapterReadError("simulated hardware failure")
    with patch.object(adapter, "_read_sync", side_effect=error):
        for i in range(2):
            with pytest.raises(AdapterReadError):
                await adapter.read("test-cpu")
            assert adapter._breaker.state == CircuitState.CLOSED, (
                f"should still be CLOSED after failure {i + 1}"
            )

        # Third failure should trip the breaker
        with pytest.raises(AdapterReadError):
            await adapter.read("test-cpu")

    assert adapter._breaker.state == CircuitState.OPEN

    # Subsequent reads must be blocked immediately (no hardware call)
    with pytest.raises(AdapterReadError, match="circuit breaker OPEN"):
        await adapter.read("test-cpu")
