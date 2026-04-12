# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Shared protocol registry used by config validation and runtime adapter wiring."""

from ori.hal.base import BaseAdapter

SUPPORTED_SENSOR_PROTOCOLS: frozenset[str] = frozenset(
    {
        "psutil",
        "i2c",
        "serial",
        "growatt",
        "victron",
        "zigbee",
        "lorawan",
        "mqtt_perception",
        "usb_serial",
        "http",
        "opcua",
        "smart",
    }
)


class UnknownProtocolError(ValueError):
    """Raised when a sensor protocol is not registered in the runtime."""


def make_adapter(protocol: str) -> BaseAdapter:
    """Instantiate the HAL adapter for *protocol*."""
    if protocol == "psutil":
        from ori.hal.psutil_adapter import PsutilAdapter

        return PsutilAdapter()
    if protocol == "i2c":
        from ori.hal.i2c_adapter import I2CAdapter

        return I2CAdapter()
    if protocol == "growatt":
        from ori.hal.growatt_adapter import GrowattAdapter

        return GrowattAdapter()
    if protocol == "victron":
        from ori.hal.victron_adapter import VictronAdapter

        return VictronAdapter()
    if protocol == "zigbee":
        from ori.hal.zigbee_adapter import ZigbeeAdapter

        return ZigbeeAdapter()
    if protocol == "lorawan":
        from ori.hal.lorawan_adapter import LoraWanAdapter

        return LoraWanAdapter()
    if protocol == "mqtt_perception":
        from ori.hal.mqtt_perception_adapter import MqttPerceptionAdapter

        return MqttPerceptionAdapter()
    if protocol == "serial":
        from ori.hal.serial_adapter import SerialAdapter

        return SerialAdapter()
    if protocol == "usb_serial":
        from ori.hal.usb_serial_adapter import UsbSerialAdapter

        return UsbSerialAdapter()
    if protocol == "http":
        from ori.hal.http_adapter import HttpAdapter

        return HttpAdapter()
    if protocol == "opcua":
        from ori.hal.opcua_adapter import OpcUaAdapter

        return OpcUaAdapter()
    if protocol == "smart":
        from ori.hal.smart_adapter import SmartAdapter

        return SmartAdapter()

    raise UnknownProtocolError(
        f"Unknown sensor protocol '{protocol}'. "
        f"Supported: {sorted(SUPPORTED_SENSOR_PROTOCOLS)}. "
        "Check ori.yaml sensors configuration."
    )
