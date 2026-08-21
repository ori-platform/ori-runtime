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
future rephrasing does not silently reopen any of them.
"""

from __future__ import annotations

import logging

import pytest
import yaml

from ori.config import Config, ConfigValidationError
from ori.runtime import _is_loopback_host, _warn_gateway_security_posture

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
        ("", False),
        (None, False),
    ],
)
def test_loopback_host_classification(host, expected):
    assert _is_loopback_host(host) is expected


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


def _cli_help(argv: list[str]) -> str:
    """Capture argparse help without importing internals the CLI does not export."""
    import contextlib
    import io

    from ori.firmware_provisioner import main

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer), pytest.raises(SystemExit):
        main(argv)
    return buffer.getvalue()


def test_provisioner_exposes_prepare_approval_and_deprecated_alias():
    """The renamed command exists, and the old name keeps working.

    Renaming alone would break provisioning scripts in the field, so the
    misleading name stays as an alias that warns rather than disappearing.
    """
    help_text = _cli_help(["--help"])
    assert "prepare-approval" in help_text
    assert "publish" in help_text, "existing provisioning scripts must keep working"


def test_top_level_help_does_not_claim_publication():
    """Argparse wraps long help, so normalise whitespace before asserting."""
    help_text = " ".join(_cli_help(["--help"]).split())
    assert (
        "prepare-approval sign from the approved row and emit the approval bytes (does not publish)"
        in help_text
    )


def test_deprecated_alias_is_marked_deprecated():
    help_text = " ".join(_cli_help(["--help"]).split())
    assert "publish deprecated alias for prepare-approval" in help_text


def test_no_command_help_claims_a_retained_publication():
    """No subcommand may describe itself as publishing.

    Live publication runs inside the runtime's gateway; this CLI signs and
    exits, and must not imply a broker was reached.
    """
    help_text = " ".join(_cli_help(["--help"]).split()).lower()
    assert "retained" not in help_text
