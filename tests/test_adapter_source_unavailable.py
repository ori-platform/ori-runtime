# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""An adapter tells a source not yet there from a configuration that is wrong.

The runtime retries `AdapterUnavailableError` and nothing else, so each
adapter whose connect opens its source raises it exactly when the source
cannot be reached, and a plain `AdapterConnectionError` for its configuration.
"""

from __future__ import annotations

import asyncio
import errno
import socket
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from ori.hal.base import (
    AdapterConnectionError,
    AdapterUnavailableError,
    source_absent,
)
from ori.hal.i2c_adapter import I2CAdapter
from ori.hal.opcua_adapter import OpcUaAdapter
from ori.hal.serial_adapter import SerialAdapter
from ori.hal.usb_serial_adapter import UsbSerialAdapter
from tests.test_i2c_adapter import _config as i2c_config
from tests.test_opcua_adapter import _config as opcua_config
from tests.test_serial_adapter import _config as serial_config
from tests.test_usb_serial_adapter import _config as usb_config


def _unreachable(*_args: Any, **_kwargs: Any) -> Any:
    raise FileNotFoundError(errno.ENOENT, "No such file or directory")


def _forbidden(*_args: Any, **_kwargs: Any) -> Any:
    raise PermissionError(errno.EACCES, "Permission denied")


class _UnreachableClient:
    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        pass

    async def connect(self) -> None:
        raise ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused")

    def get_node(self, node_id: str) -> Any:
        raise AssertionError("never reached")


class _ReachableClient(_UnreachableClient):
    async def connect(self) -> None:
        return None

    async def disconnect(self) -> None:
        return None

    def get_node(self, node_id: str) -> Any:
        raise ValueError(f"Error parsing string {node_id!r}")


async def _refusal(adapter: Any, config: dict[str, Any]) -> AdapterConnectionError:
    with pytest.raises(AdapterConnectionError) as refusal:
        await adapter.connect(config)
    return refusal.value


async def test_a_serial_port_that_is_not_there_is_unavailable() -> None:
    with (
        patch("ori.hal.serial_adapter._SERIAL_AVAILABLE", True),
        patch("ori.hal.serial_adapter.serial", create=True) as module,
    ):
        module.Serial.side_effect = _unreachable
        absent = await _refusal(SerialAdapter(), serial_config())
        wrong = await _refusal(SerialAdapter(), serial_config(port=""))
    assert isinstance(absent, AdapterUnavailableError)
    assert not isinstance(wrong, AdapterUnavailableError)


async def test_a_usb_serial_device_that_is_not_there_is_unavailable() -> None:
    with (
        patch("ori.hal.usb_serial_adapter._PYSERIAL_AVAILABLE", True),
        patch(
            "ori.hal.usb_serial_adapter._serial_module",
            SimpleNamespace(Serial=_unreachable, serial_for_url=_unreachable),
        ),
    ):
        absent = await _refusal(UsbSerialAdapter(), usb_config())
        wrong = await _refusal(UsbSerialAdapter(), usb_config(sensor_type="nope"))
    assert isinstance(absent, AdapterUnavailableError)
    assert not isinstance(wrong, AdapterUnavailableError)


async def test_an_opcua_server_that_is_not_there_is_unavailable() -> None:
    with (
        patch("ori.hal.opcua_adapter._ASYNCUA_AVAILABLE", True),
        patch("ori.hal.opcua_adapter._AsyncUaClient", _UnreachableClient),
    ):
        absent = await _refusal(OpcUaAdapter(), opcua_config())
        wrong = await _refusal(OpcUaAdapter(), opcua_config(url=""))
    assert isinstance(absent, AdapterUnavailableError)
    assert not isinstance(wrong, AdapterUnavailableError)


async def test_an_i2c_device_that_is_not_there_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(I2CAdapter, "_connect_sync", _unreachable)
    absent = await _refusal(I2CAdapter(), i2c_config())
    wrong = await _refusal(I2CAdapter(), i2c_config(sensor_type="nope"))
    assert isinstance(absent, AdapterUnavailableError)
    assert not isinstance(wrong, AdapterUnavailableError)


async def test_a_permission_or_a_malformed_value_is_final() -> None:
    with (
        patch("ori.hal.serial_adapter._SERIAL_AVAILABLE", True),
        patch("ori.hal.serial_adapter.serial", create=True) as module,
    ):
        module.Serial.side_effect = _forbidden
        denied = await _refusal(SerialAdapter(), serial_config())
    with (
        patch("ori.hal.opcua_adapter._ASYNCUA_AVAILABLE", True),
        patch("ori.hal.opcua_adapter._AsyncUaClient", _ReachableClient),
    ):
        malformed = await _refusal(OpcUaAdapter(), opcua_config(node_id="not a node"))
    assert not isinstance(denied, AdapterUnavailableError)
    assert not isinstance(malformed, AdapterUnavailableError)


async def test_an_i2c_refusal_of_the_chip_stays_final(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def wrong_chip(*_args: Any, **_kwargs: Any) -> Any:
        raise AdapterConnectionError("I2CAdapter: chip identity mismatch")

    monkeypatch.setattr(I2CAdapter, "_connect_sync", wrong_chip)
    refusal = await _refusal(I2CAdapter(), i2c_config())
    assert not isinstance(refusal, AdapterUnavailableError)


async def test_a_usb_device_to_auto_detect_that_is_not_plugged_in_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "ori.hal.usb_serial_adapter._find_direct_serial_device", lambda: ""
    )
    config = {**usb_config(device_path=""), "auto_detect_device_path": True}
    with patch("ori.hal.usb_serial_adapter._PYSERIAL_AVAILABLE", True):
        refusal = await _refusal(UsbSerialAdapter(), config)
    assert isinstance(refusal, AdapterUnavailableError)


def _chained(error: Exception, *, context_only: bool) -> Exception:
    try:
        try:
            raise error
        except Exception as inner:
            if context_only:
                raise RuntimeError("wrapped without a cause")  # noqa: B904
            raise RuntimeError("wrapped") from inner
    except RuntimeError as outer:
        return outer


@pytest.mark.parametrize(
    ("error", "absent"),
    [
        (TimeoutError(), True),
        (socket.gaierror(socket.EAI_AGAIN, "try again"), True),
        (socket.gaierror(socket.EAI_NONAME, "no such name"), False),
        (OSError(getattr(errno, "EREMOTEIO", 121), "Remote I/O error"), True),
        (PermissionError(errno.EACCES, "Permission denied"), False),
        (ValueError("bad node"), False),
        (
            OSError(
                f"Multiple exceptions: [Errno {errno.ECONNREFUSED}] refused, "
                f"[Errno {errno.ECONNREFUSED}] refused"
            ),
            True,
        ),
        (
            OSError(
                f"Multiple exceptions: [Errno {errno.ECONNREFUSED}] refused, "
                f"[Errno {errno.EACCES}] denied"
            ),
            False,
        ),
        (
            _chained(
                ConnectionRefusedError(errno.ECONNREFUSED, "x"), context_only=True
            ),
            True,
        ),
        (_chained(TimeoutError(), context_only=False), True),
    ],
    ids=[
        "timeout",
        "dns-try-again",
        "dns-no-name",
        "remote-io",
        "permission",
        "value",
        "every-address-refused",
        "one-address-denied",
        "context-only",
        "cause",
    ],
)
def test_source_absent_reads_the_cause(error: BaseException, absent: bool) -> None:
    assert source_absent(error) is absent


async def test_a_host_by_name_with_every_address_refused_is_absent() -> None:
    try:
        await asyncio.open_connection("localhost", 1)
    except OSError as refused:
        assert source_absent(refused)
    else:  # pragma: no cover - something listens on port 1
        pytest.skip("port 1 answered")


async def test_an_i2c_chip_blinka_cannot_find_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def no_device(*_args: Any, **_kwargs: Any) -> Any:
        raise ValueError("No I2C device at address: 0x76")

    monkeypatch.setattr(I2CAdapter, "_connect_sync", no_device)
    refusal = await _refusal(I2CAdapter(), i2c_config())
    assert isinstance(refusal, AdapterUnavailableError)


def _wrapped_readback(*_args: Any, **_kwargs: Any) -> Any:
    try:
        raise OSError(getattr(errno, "EREMOTEIO", 121), "Remote I/O error")
    except OSError as exc:
        raise AdapterConnectionError(
            "I2CAdapter: could not read back the ADS1115 configuration"
        ) from exc


async def test_a_wrapped_readback_failure_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(I2CAdapter, "_connect_sync", _wrapped_readback)
    refusal = await _refusal(I2CAdapter(), i2c_config())
    assert isinstance(refusal, AdapterUnavailableError)


async def test_a_wrapped_port_failure_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def wrapped(*_args: Any, **_kwargs: Any) -> Any:
        try:
            _unreachable()
        except OSError as exc:
            raise AdapterConnectionError("could not open") from exc

    monkeypatch.setattr(SerialAdapter, "_open_port", wrapped)
    monkeypatch.setattr(UsbSerialAdapter, "_open_port_sync", wrapped)
    with patch("ori.hal.serial_adapter._SERIAL_AVAILABLE", True):
        serial_refusal = await _refusal(SerialAdapter(), serial_config())
    with (
        patch("ori.hal.usb_serial_adapter._PYSERIAL_AVAILABLE", True),
        patch("ori.hal.usb_serial_adapter._serial_module", SimpleNamespace()),
    ):
        usb_refusal = await _refusal(UsbSerialAdapter(), usb_config())
    assert isinstance(serial_refusal, AdapterUnavailableError)
    assert isinstance(usb_refusal, AdapterUnavailableError)
