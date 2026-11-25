# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""A test broker is never yielded once it has exited, nor mistaken for another."""

from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest

from tests import test_dispatch_never_waits_on_delivery as delivery


def _refusing_broker(tmp_path: Path) -> str:
    binary = tmp_path / "refusing-broker"
    binary.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        "print('broker config refused', file=sys.stderr, flush=True)\n"
        "raise SystemExit(3)\n"
    )
    binary.chmod(0o700)
    return str(binary)


def test_broker_startup_refuses_an_exited_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(delivery, "_mosquitto", lambda: _refusing_broker(tmp_path))
    # The stub exits at once, but under load its interpreter can take longer
    # to start than a broker is given to listen; this test is of the exit.
    monkeypatch.setattr(delivery, "_BROKER_LISTEN_S", 120.0)
    with pytest.raises(pytest.fail.Exception, match="broker config refused"):
        with delivery._broker_on(tmp_path, delivery._free_port()):
            pytest.fail("a dead broker was yielded to its client")


def test_a_listener_that_is_not_the_broker_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(delivery, "_mosquitto", lambda: _refusing_broker(tmp_path))
    with socket.socket() as other:
        other.bind(("127.0.0.1", 0))
        other.listen()
        port = int(other.getsockname()[1])
        with pytest.raises(pytest.fail.Exception, match="already listening"):
            with delivery._broker_on(tmp_path, port):
                pytest.fail("another listener was taken for the broker")
