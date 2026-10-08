# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""An MQTT-family sensor reads one concrete topic, and a wildcard never loads.

A value is cached under the topic of the message that carried it and read back
under the configured one, so a sensor subscribed to a filter never reads.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from ori.config import Config, ConfigValidationError
from ori.hal.base import AdapterConnectionError
from ori.hal.mqtt_base import topic_wildcards
from ori.hal.protocol_registry import MQTT_FAMILY_PROTOCOLS, make_adapter
from tests.test_config import TestSensorValidation, _write_yaml

# protocol -> (sensor type, the key its subscription is built from)
SENSORS = {
    "victron": ("victron_battery_soc", "portal_id"),
    "zigbee": ("temperature", "topic"),
    "lorawan": ("lorawan_temperature", "topic"),
    "mqtt_perception": ("ppe_hardhat_violation_score", "topic"),
    "mqtt": ("temperature", "topic"),
}
WILDCARDS = ["w/+", "w/#", "+/w", "#", "w/+/t", "w+"]


def _load(tmp_path, protocol: str, value: str) -> Config:
    sensor_type, key = SENSORS[protocol]
    sensor = (
        f"  - id: s1\n    type: {sensor_type}\n    protocol: {protocol}\n"
        f'    broker_host: 192.168.1.50\n    {key}: "{value}"\n'
        "    poll_interval_ms: 1000\n"
    )
    return Config.load(_write_yaml(tmp_path, TestSensorValidation()._base_yaml(sensor)))


def test_every_family_protocol_is_covered() -> None:
    assert set(SENSORS) == MQTT_FAMILY_PROTOCOLS


@pytest.mark.parametrize(
    ("topic", "expected"),
    [("w/a", ()), ("w/+", ("+",)), ("w/#", ("#",)), ("+/#", ("+", "#"))],
)
def test_topic_wildcards_names_what_a_topic_carries(topic, expected) -> None:
    assert topic_wildcards(topic) == expected


@pytest.mark.parametrize("protocol", sorted(SENSORS))
@pytest.mark.parametrize("value", WILDCARDS)
def test_a_wildcard_is_refused_at_load(tmp_path, protocol, value) -> None:
    with pytest.raises(ConfigValidationError, match="MQTT wildcard") as caught:
        _load(tmp_path, protocol, value)
    assert f"sensors[s1].{SENSORS[protocol][1]}" in str(caught.value)
    assert repr(value) in str(caught.value)


@pytest.mark.parametrize("protocol", sorted(SENSORS))
def test_a_concrete_topic_loads(tmp_path, protocol) -> None:
    assert _load(tmp_path, protocol, "w/a").sensors[0].protocol == protocol


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", sorted(SENSORS))
@pytest.mark.parametrize("value", ["w/+", "w/#"])
async def test_the_adapter_refuses_a_wildcard_before_dialling(protocol, value) -> None:
    sensor_type, key = SENSORS[protocol]
    dialled: list[dict] = []

    def _client(**kwargs: object) -> None:
        dialled.append(kwargs)
        raise AssertionError("a wildcard subscription must not reach the broker")

    adapter = make_adapter(protocol)
    with (
        patch("ori.hal.mqtt_base._AIOMQTT_AVAILABLE", True),
        patch("ori.hal.mqtt_base._aiomqtt", SimpleNamespace(Client=_client)),
    ):
        with pytest.raises(AdapterConnectionError, match="wildcard subscription"):
            await adapter.connect(
                {
                    "sensor_id": "s1",
                    "sensor_type": sensor_type,
                    "broker_host": "192.168.1.50",
                    key: value,
                }
            )
    assert dialled == []
    assert not adapter.is_connected
