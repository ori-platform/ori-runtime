# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import ssl

import pytest

from ori.gateway.mqtt_security import (
    GatewayBrokerConfig,
    apply_tls_context,
    parse_gateway_broker_url,
)


def test_parse_gateway_broker_url_defaults_mqtt_to_1883():
    broker = parse_gateway_broker_url("mqtt://operator:secret@broker.local")

    assert broker.host == "broker.local"
    assert broker.port == 1883
    assert broker.username == "operator"
    assert broker.password == "secret"
    assert broker.tls_context is None


def test_parse_gateway_broker_url_defaults_mqtts_to_8883():
    broker = parse_gateway_broker_url("mqtts://broker.local")

    assert broker.host == "broker.local"
    assert broker.port == 8883
    assert isinstance(broker.tls_context, ssl.SSLContext)


def test_parse_gateway_broker_url_uses_tls_config_on_mqtt_scheme():
    broker = parse_gateway_broker_url(
        "mqtt://broker.local:1884",
        tls_config={"enabled": True},
    )

    assert broker.port == 1884
    assert isinstance(broker.tls_context, ssl.SSLContext)


def test_parse_gateway_broker_url_rejects_unsupported_scheme():
    with pytest.raises(ValueError, match="mqtt://, tcp://, or mqtts://"):
        parse_gateway_broker_url("http://broker.local")


def test_parse_gateway_broker_url_rejects_incomplete_client_cert_config():
    with pytest.raises(ValueError, match="certfile"):
        parse_gateway_broker_url(
            "mqtt://broker.local",
            tls_config={"keyfile": "/etc/ori/certs/runtime.key"},
        )


def test_parse_gateway_broker_url_rejects_missing_key_password_env(monkeypatch):
    monkeypatch.delenv("MQTT_KEY_PASSWORD", raising=False)

    with pytest.raises(ValueError, match="MQTT_KEY_PASSWORD"):
        parse_gateway_broker_url(
            "mqtt://broker.local",
            tls_config={
                "certfile": "/etc/ori/certs/runtime.crt",
                "keyfile": "/etc/ori/certs/runtime.key",
                "keyfile_password_env": "MQTT_KEY_PASSWORD",
            },
        )


def test_apply_tls_context_configures_paho_client():
    context = ssl.create_default_context()
    broker = GatewayBrokerConfig(
        host="broker.local",
        port=8883,
        scheme="mqtts",
        tls_context=context,
    )

    class _Client:
        def __init__(self):
            self.context = None

        def tls_set_context(self, tls_context):
            self.context = tls_context

    client = _Client()

    apply_tls_context(client, broker)

    assert client.context is context


def test_apply_tls_context_requires_paho_tls_support():
    broker = GatewayBrokerConfig(
        host="broker.local",
        port=8883,
        scheme="mqtts",
        tls_context=ssl.create_default_context(),
    )

    with pytest.raises(RuntimeError, match="tls_set_context"):
        apply_tls_context(object(), broker)
