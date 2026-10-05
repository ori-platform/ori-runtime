# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""An MQTT-family sensor connects with a clean session, and nothing else loads.

A broker queues messages for a persistent session and delivers them on
reconnect; the freshness bound times a value from its delivery, so a queued
value would read as live.
"""

from __future__ import annotations

import importlib
import inspect

import pytest

from ori.config import Config, ConfigValidationError
from ori.hal.base import AdapterConnectionError
from ori.hal.mqtt_adapter import MqttAdapter
from ori.hal.mqtt_base import MqttCachedAdapter
from ori.hal.protocol_registry import MQTT_FAMILY_PROTOCOLS, PROTOCOL_DEFINITIONS
from tests.test_config import TestSensorValidation, _write_yaml

SENSORS = {
    "victron": "  - id: s1\n    type: victron_battery_soc\n    protocol: victron\n"
    "    broker_host: 192.168.1.50\n    portal_id: abc\n    poll_interval_ms: 5000\n",
    "zigbee": "  - id: s1\n    type: temperature\n    protocol: zigbee\n"
    "    broker_host: 192.168.1.50\n    topic: z/t\n    poll_interval_ms: 1000\n",
    "lorawan": "  - id: s1\n    type: lorawan_temperature\n    protocol: lorawan\n"
    "    broker_host: 192.168.1.50\n    topic: v3/up\n    poll_interval_ms: 5000\n",
    "mqtt_perception": "  - id: s1\n    type: ppe_hardhat_violation_score\n"
    "    protocol: mqtt_perception\n    broker_host: 192.168.1.50\n"
    "    topic: ori/p\n    poll_interval_ms: 1000\n",
    "mqtt": "  - id: s1\n    type: temperature\n    protocol: mqtt\n"
    "    broker_host: 192.168.1.50\n    topic: b/c\n    poll_interval_ms: 1000\n",
}
SPELLINGS = {
    "mqtt.clean_session": "    mqtt:\n      clean_session: {v}\n",
    "mqtt.mqtt_clean_session": "    mqtt:\n      mqtt_clean_session: {v}\n",
    "mqtt_clean_session": "    mqtt_clean_session: {v}\n",
    "clean_session": "    clean_session: {v}\n",
}


def _load(tmp_path, protocol: str, extra: str) -> Config:
    yaml = TestSensorValidation()._base_yaml(SENSORS[protocol] + extra)
    return Config.load(_write_yaml(tmp_path, yaml))


def test_the_family_set_matches_the_registry() -> None:
    family = {
        name
        for name, definition in PROTOCOL_DEFINITIONS.items()
        if issubclass(
            getattr(importlib.import_module(definition.module), definition.class_name),
            MqttCachedAdapter,
        )
    }
    assert family == MQTT_FAMILY_PROTOCOLS


@pytest.mark.parametrize("protocol", sorted(SENSORS))
@pytest.mark.parametrize("spelling", sorted(SPELLINGS))
def test_a_persistent_session_is_refused_at_load(tmp_path, protocol, spelling):
    with pytest.raises(ConfigValidationError, match="clean session") as caught:
        _load(tmp_path, protocol, SPELLINGS[spelling].format(v="false"))
    assert "sensors[s1]" in str(caught.value)


@pytest.mark.parametrize("protocol", sorted(SENSORS))
@pytest.mark.parametrize("extra", ["", "    mqtt:\n      clean_session: true\n"])
def test_a_clean_or_absent_session_loads(tmp_path, protocol, extra):
    assert _load(tmp_path, protocol, extra).sensors[0].protocol == protocol


@pytest.mark.parametrize(
    "config",
    [
        {"mqtt": {"clean_session": False}},
        {"mqtt_clean_session": "false"},
        {"clean_session": 0},
    ],
)
def test_the_adapter_refuses_a_persistent_session(config) -> None:
    with pytest.raises(AdapterConnectionError, match="persistent MQTT session"):
        MqttAdapter()._build_mqtt_client_kwargs(config)


@pytest.mark.parametrize("config", [{}, {"mqtt": {"clean_session": True}}])
def test_the_adapter_always_connects_clean(config) -> None:
    assert MqttAdapter()._build_mqtt_client_kwargs(config)["clean_session"] is True


def test_the_evidence_links_keep_their_persistent_sessions() -> None:
    from ori.gateway import evidence_inbound, evidence_outbound

    for module in (evidence_inbound, evidence_outbound):
        assert '"clean_session": False' in inspect.getsource(module)
