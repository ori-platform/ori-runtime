# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""A failed test broker reports its own error before a client can connect."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from tests import test_dispatch_never_waits_on_delivery as delivery
from tests.firmware import test_command_publisher_queue as firmware


@pytest.mark.parametrize("family", ["delivery", "firmware"])
def test_broker_startup_refuses_an_exited_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, family: str
) -> None:
    binary = tmp_path / "refusing-broker"
    binary.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        "print('broker config refused', file=sys.stderr, flush=True)\n"
        "raise SystemExit(3)\n"
    )
    binary.chmod(0o700)
    module = delivery if family == "delivery" else firmware
    monkeypatch.setattr(module, "_mosquitto", lambda: str(binary))
    manager = (
        delivery._broker(tmp_path)
        if family == "delivery"
        else firmware._broker_on(tmp_path, delivery._free_port())
    )
    with pytest.raises(pytest.fail.Exception, match="broker config refused"):
        with manager:
            pytest.fail("a dead broker was yielded to its client")
