# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Tests for the canonical `baud_rate` spelling and its legacy bridge.

`ori.yaml.example` configured a serial sensor with `baud_rate`, and
`SerialAdapter` read `baudrate`. The key was silently dropped and the port
opened at the adapter's default, which looked correct only because the
example's value happened to equal that default (ori-runtime #411).

A key the runtime discards reads, to whoever wrote it, as a setting that took
effect. So these tests assert on the rate the serial library was actually
opened with, not on the attribute the adapter stored: an adapter that parses
the value correctly and then opens the port at 9600 would pass the weaker
check.
"""

from __future__ import annotations

import logging
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from ori.config import ConfigValidationError, _parse_sensors
from ori.hal.base import AdapterConnectionError
from ori.hal.serial_adapter import SerialAdapter
from ori.hal.usb_serial_adapter import UsbSerialAdapter


def _serial_config(**overrides: Any) -> dict:
    return {"sensor_type": "voltage", "port": "/dev/ttyUSB0", **overrides}


def _usb_config(**overrides: Any) -> dict:
    return {"sensor_type": "usb_power", "device_path": "/dev/ttyUSB0", **overrides}


async def _open_serial(config: dict) -> tuple[SerialAdapter, dict]:
    """Connect a SerialAdapter and return the kwargs pyserial was called with."""
    adapter = SerialAdapter()
    with (
        patch("ori.hal.serial_adapter._SERIAL_AVAILABLE", True),
        patch("ori.hal.serial_adapter.serial", create=True) as mod,
    ):
        mod.Serial.return_value = MagicMock(is_open=True)
        await adapter.connect(config)
        kwargs = mod.Serial.call_args.kwargs if mod.Serial.call_args else {}
    return adapter, kwargs


async def _open_usb(config: dict) -> tuple[UsbSerialAdapter, dict]:
    adapter = UsbSerialAdapter()
    with (
        patch("ori.hal.usb_serial_adapter._PYSERIAL_AVAILABLE", True),
        patch("ori.hal.usb_serial_adapter._serial_module", create=True) as mod,
    ):
        mod.Serial.return_value = MagicMock(is_open=True)
        await adapter.connect(config)
        kwargs = mod.Serial.call_args.kwargs if mod.Serial.call_args else {}
    return adapter, kwargs


# ── The canonical spelling reaches the port ──────────────────────────────────


async def test_serial_adapter_opens_at_the_requested_baud_rate() -> None:
    """The defect: this key was read as `baudrate` and dropped."""
    adapter, kwargs = await _open_serial(_serial_config(baud_rate=19200))
    assert adapter._baudrate == 19200
    assert kwargs["baudrate"] == 19200


async def test_usb_serial_adapter_opens_at_the_requested_baud_rate() -> None:
    adapter, kwargs = await _open_usb(_usb_config(baud_rate=19200))
    assert adapter._baud_rate == 19200
    assert kwargs["baudrate"] == 19200


async def test_a_default_is_used_only_when_the_key_is_absent() -> None:
    adapter, kwargs = await _open_serial(_serial_config())
    assert adapter._baudrate == 9600
    assert kwargs["baudrate"] == 9600


# ── The legacy alias works, and says so ──────────────────────────────────────


async def test_legacy_spelling_still_opens_at_the_requested_rate(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        adapter, kwargs = await _open_serial(_serial_config(baudrate=19200))
    assert adapter._baudrate == 19200
    assert kwargs["baudrate"] == 19200
    assert "baudrate" in caplog.text
    assert "baud_rate" in caplog.text


async def test_legacy_spelling_warns_on_the_usb_adapter_too(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The forgiving adapter is why the inconsistency survived unnoticed."""
    with caplog.at_level(logging.WARNING):
        adapter, kwargs = await _open_usb(_usb_config(baudrate=19200))
    assert adapter._baud_rate == 19200
    assert kwargs["baudrate"] == 19200
    assert "deprecated" in caplog.text


async def test_canonical_spelling_warns_about_nothing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        await _open_serial(_serial_config(baud_rate=19200))
    assert "deprecated" not in caplog.text


# ── Ambiguity is refused, not resolved ───────────────────────────────────────


@pytest.mark.parametrize("values", [(9600, 19200), (9600, 9600)])
async def test_both_spellings_are_refused(values: tuple[int, int]) -> None:
    """Refused even when the two agree.

    Picking a winner would mean the runtime decides which of two conflicting
    declarations the operator meant. Agreement today is not agreement after
    the next edit, and a precedence rule is invisible in the file that has it.
    """
    canonical, legacy = values
    with pytest.raises(AdapterConnectionError, match="both"):
        await _open_serial(_serial_config(baud_rate=canonical, baudrate=legacy))


async def test_both_spellings_are_refused_on_the_usb_adapter() -> None:
    with pytest.raises(AdapterConnectionError, match="both"):
        await _open_usb(_usb_config(baud_rate=9600, baudrate=9600))


# ── A value that cannot be read is a refusal, never the default ──────────────


@pytest.mark.parametrize(
    "bad", ["fast", "", 0, -1, 9600.5, True, False, None, [9600], {"rate": 9600}]
)
async def test_an_unreadable_rate_is_refused_rather_than_defaulted(bad: Any) -> None:
    """9600 must never be the answer to a value the runtime could not parse.

    `True` is here because Python makes it an instance of `int`, so a naive
    check reads it as 1 baud.
    """
    with pytest.raises(AdapterConnectionError):
        await _open_serial(_serial_config(baud_rate=bad))


@pytest.mark.parametrize(
    "good, expected", [(19200, 19200), ("19200", 19200), (9600.0, 9600)]
)
async def test_a_rate_that_reads_as_a_whole_number_is_accepted(
    good: Any, expected: int
) -> None:
    """A quoted or float-typed rate is an existing YAML spelling, not an error."""
    adapter, kwargs = await _open_serial(_serial_config(baud_rate=good))
    assert adapter._baudrate == expected
    assert kwargs["baudrate"] == expected


# ── The config boundary refuses before any hardware is touched ───────────────
#
# The adapter check alone is not enough: without `pyserial`, `connect()` raises
# before it ever resolves a baud rate, so an ambiguous config would load clean
# on a developer machine and surface only on the Pi.


def _sensor(protocol: str = "serial", **overrides: Any) -> list[dict]:
    return [
        {
            "id": "meter",
            "type": "voltage",
            "protocol": protocol,
            "port": "/dev/ttyUSB0",
            **overrides,
        }
    ]


def test_config_load_refuses_both_spellings() -> None:
    with pytest.raises(ConfigValidationError, match="both"):
        _parse_sensors(_sensor(baud_rate=9600, baudrate=9600))


def test_config_load_refuses_an_unreadable_rate() -> None:
    with pytest.raises(ConfigValidationError):
        _parse_sensors(_sensor(baud_rate="fast"))


def test_config_load_rewrites_the_legacy_key(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Normalised at the boundary, so the deprecation is logged once."""
    with caplog.at_level(logging.WARNING):
        sensors = _parse_sensors(_sensor(baudrate=19200))
    assert sensors[0].metadata["baud_rate"] == 19200
    assert "baudrate" not in sensors[0].metadata
    assert "deprecated" in caplog.text


def test_config_load_leaves_the_canonical_key_alone() -> None:
    sensors = _parse_sensors(_sensor(baud_rate=19200))
    assert sensors[0].metadata["baud_rate"] == 19200


def test_config_load_covers_the_usb_serial_protocol() -> None:
    with pytest.raises(ConfigValidationError, match="both"):
        _parse_sensors(_sensor(protocol="usb_serial", baud_rate=9600, baudrate=9600))


def test_config_load_does_not_invent_a_rate_where_none_was_set() -> None:
    sensors = _parse_sensors(_sensor())
    assert sensors[0].metadata["baud_rate"] == 9600


def test_a_non_serial_protocol_is_left_untouched() -> None:
    """An unclaimed key is refused rather than forwarded to no consumer."""
    with pytest.raises(ConfigValidationError, match="baudrate"):
        _parse_sensors(
            [
                {
                    "id": "cpu",
                    "type": "cpu_percent",
                    "protocol": "psutil",
                    "baudrate": 123,
                }
            ]
        )


# ── The shipped examples ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "example", ["ori.yaml.example", "ori.yaml.phone.example", "ori.linux.yaml.example"]
)
def test_shipped_examples_use_only_the_canonical_spelling(example: str) -> None:
    """The example is what operators copy, so it is the surface that teaches."""
    import pathlib

    path = pathlib.Path(__file__).resolve().parents[1] / example
    if not path.exists():
        pytest.skip(f"{example} is not shipped")
    text = path.read_text()
    assert "baudrate" not in text
