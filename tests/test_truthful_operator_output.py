# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The runtime must not report a claim that is not true.

Three defects shared that shape, and each cost a debugging cycle during
firmware bring-up because the output was believed:

1. A credentialed loopback broker was classified as public, so the runtime
   logged, at ERROR, that MQTT traffic was unauthenticated while it was
   authenticated. Production posture *requires* those credentials, so the
   configuration the runtime asks for was the one that triggered the alarm.
2. The provisioner printed `publish RETAINED on ...` after publishing
   nothing, on a security-critical step.
3. An unexpanded `${VAR}` in `gateway.broker_url` passed config load and
   surfaced only as a connection refusal from every client, naming nothing.

These tests assert the corrected behaviour rather than the wording, so a
future rephrasing does not silently reopen any of them. Defect 2 is covered
by command-level tests in tests/firmware/test_provisioner.py.
"""

from __future__ import annotations

import logging

import pytest
import yaml

from ori.config import Config, ConfigValidationError
from ori.runtime import _warn_gateway_security_posture
from ori.utils.net_utils import is_loopback_host

# --- 1. loopback classification -------------------------------------------


@pytest.mark.parametrize(
    "host,expected",
    [
        ("127.0.0.1", True),
        ("127.1.2.3", True),
        ("localhost", True),
        ("::1", True),
        ("192.168.1.10", False),
        ("broker.example.com", False),
        # Registrable DNS names that a prefix test called loopback. Under
        # production posture that skipped TLS, the broker deployment check,
        # anonymous_access, per-device ACLs, require_credentials, and the
        # username/password requirement — all six, from one hostname.
        ("127.attacker.example", False),
        ("127.0.0.1.evil.com", False),
        ("127.evil", False),
        ("localhost.evil.com", False),
        ("[::1]", True),
        ("", False),
        (None, False),
    ],
)
def test_loopback_host_classification(host, expected):
    assert is_loopback_host(host) is expected


class _StubGateway:
    def __init__(self, broker_url: str) -> None:
        self.enabled = True
        self.broker_url = broker_url
        self.auth: dict = {"enabled": False}
        self.tls: dict = {"enabled": False}


class _StubConfig:
    def __init__(self, broker_url: str) -> None:
        self.gateway = _StubGateway(broker_url)


@pytest.mark.parametrize(
    "broker_url",
    [
        "mqtt://user:pass@127.0.0.1:1883",
        "mqtts://ori-runtime:secret@localhost:8883",
        "mqtt://127.0.0.1:1883",
        "mqtt://[::1]:1883",
    ],
)
def test_credentialed_loopback_broker_logs_no_security_error(broker_url, caplog):
    """Credentials in the URL must not make a loopback broker read as public.

    This is the regression: the old check prefix-matched the whole URL, and
    `mqtt://user:pass@127.0.0.1:1883` carries userinfo ahead of the host, so
    it matched no prefix and was reported as an unauthenticated public broker.
    """
    with caplog.at_level(logging.WARNING):
        _warn_gateway_security_posture(_StubConfig(broker_url))

    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert errors == [], f"false security ERROR for loopback broker: {errors}"


def test_non_loopback_broker_without_auth_still_logs_error(caplog):
    """The fix must not silence the alarm it exists to make accurate."""
    with caplog.at_level(logging.WARNING):
        _warn_gateway_security_posture(_StubConfig("mqtt://user:pass@10.0.0.5:1883"))

    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert errors, "a real public unauthenticated broker must still raise ERROR"


# --- 2. unexpanded environment variables ----------------------------------


def _minimal_config(tmp_path, broker_url: str) -> str:
    document = {
        "device": {"id": "test-device", "name": "Test", "location": "Lab"},
        "sensors": [
            {
                "id": "cpu",
                "type": "cpu_percent",
                "protocol": "psutil",
                "poll_interval_ms": 1000,
            }
        ],
        "gateway": {"enabled": True, "broker_url": broker_url},
    }
    path = tmp_path / "ori.yaml"
    path.write_text(yaml.safe_dump(document))
    return str(path)


def test_unexpanded_broker_url_variable_is_refused_at_load(tmp_path, monkeypatch):
    monkeypatch.delenv("ORI_TEST_BROKER_HOST", raising=False)
    path = _minimal_config(tmp_path, "mqtt://${ORI_TEST_BROKER_HOST}:1883")

    with pytest.raises(ConfigValidationError) as excinfo:
        Config.load(path)

    message = str(excinfo.value)
    assert "unexpanded" in message.lower()
    assert "ORI_TEST_BROKER_HOST" in message, "the missing variable must be named"


def test_expanded_broker_url_loads(tmp_path, monkeypatch):
    monkeypatch.setenv("ORI_TEST_BROKER_HOST", "127.0.0.1")
    path = _minimal_config(tmp_path, "mqtt://${ORI_TEST_BROKER_HOST}:1883")

    config = Config.load(path)
    assert config.gateway.broker_url == "mqtt://127.0.0.1:1883"


def test_disabled_gateway_tolerates_unexpanded_variable(tmp_path, monkeypatch):
    """A disabled gateway is not a configuration the runtime will act on."""
    monkeypatch.delenv("ORI_TEST_BROKER_HOST", raising=False)
    document = {
        "device": {"id": "test-device", "name": "Test", "location": "Lab"},
        "sensors": [
            {
                "id": "cpu",
                "type": "cpu_percent",
                "protocol": "psutil",
                "poll_interval_ms": 1000,
            }
        ],
        "gateway": {"enabled": False, "broker_url": "mqtt://${ORI_TEST_BROKER_HOST}"},
    }
    path = tmp_path / "ori.yaml"
    path.write_text(yaml.safe_dump(document))

    Config.load(str(path))


# --- 3. the provisioner claims no publication it did not perform ----------


# Command-level coverage for the provisioner lives in
# tests/firmware/test_provisioner.py, next to the `bench` fixture that builds
# a keyed registry. Help text was never the thing that lied, so asserting on
# it here would have proved nothing about what the command prints.


# --- 4. the bypass the split implementation allowed -----------------------


@pytest.mark.parametrize(
    "host,expect_hardening_demanded",
    [
        ("127.attacker.example", True),
        ("127.0.0.1.evil.com", True),
        ("localhost.evil.com", True),
        ("127.0.0.1", False),
        ("localhost", False),
    ],
)
def test_hostname_resembling_loopback_still_demands_hardening(
    tmp_path, caplog, host, expect_hardening_demanded
):
    """A registrable DNS name must not take the loopback branch.

    Config validation used to test `value.startswith("127.")`, so
    `127.attacker.example` was classified loopback and the entire non-loopback
    hardening branch was skipped: TLS, the broker deployment check,
    `anonymous_access: disabled`, per-device ACLs, `require_credentials`, and
    the username/password requirement. The runtime's own diagnostics used
    `ip_address()` and called the same host public, so the two halves of the
    system disagreed about whether a deployment was hardened.

    Asserted in development posture, where the same classification produces a
    warning rather than a raise. Production posture reaches this branch only
    after several earlier requirements pass, and building a config hardened
    enough to get there would test those instead of this.
    """
    document = {
        "device": {"id": "test-device", "name": "Test", "location": "Lab"},
        "sensors": [
            {
                "id": "cpu",
                "type": "cpu_percent",
                "protocol": "psutil",
                "poll_interval_ms": 1000,
            }
        ],
        "gateway": {"enabled": True, "broker_url": f"mqtt://{host}:1883"},
    }
    path = tmp_path / "ori.yaml"
    path.write_text(yaml.safe_dump(document))

    with caplog.at_level(logging.WARNING):
        Config.load(str(path))

    demanded = any(
        "non-loopback gateway broker is missing hardening" in record.getMessage()
        for record in caplog.records
    )
    assert demanded is expect_hardening_demanded


def test_config_and_runtime_share_one_loopback_implementation():
    """Two implementations disagreeing is the defect, not the strictness.

    Import identity is the assertion because a copied-but-equivalent helper
    would drift again, which is exactly what happened the first time.
    """
    from ori import config as config_module
    from ori import runtime as runtime_module

    assert config_module.is_loopback_host is runtime_module.is_loopback_host
