# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import Mock, patch

import psutil
import pytest

from ori.actions.process_manager import _SYSTEM_PROCESS_BLOCKLIST, ProcessManagerAction


@pytest.mark.asyncio
async def test_system_process_blocked():
    action = ProcessManagerAction()
    ok = await action.terminate_process(pid=1, name="systemd")
    assert ok is False


@pytest.mark.asyncio
async def test_pid_reuse_check():
    action = ProcessManagerAction()
    with patch("ori.actions.process_manager.psutil.Process") as process_cls:
        proc = Mock()
        proc.name.return_value = "DifferentProcess"
        process_cls.return_value = proc
        ok = await action.terminate_process(pid=1234, name="ExpectedProcess")
    assert ok is False


@pytest.mark.asyncio
async def test_successful_terminate():
    action = ProcessManagerAction()
    with patch("ori.actions.process_manager.psutil.Process") as process_cls:
        proc = Mock()
        proc.name.return_value = "Zoom"
        process_cls.return_value = proc
        ok = await action.terminate_process(pid=4321, name="Zoom")
    assert ok is True
    proc.terminate.assert_called_once()


@pytest.mark.asyncio
async def test_already_exited_returns_true():
    action = ProcessManagerAction()
    with patch(
        "ori.actions.process_manager.psutil.Process",
        side_effect=psutil.NoSuchProcess(pid=55),
    ):
        ok = await action.terminate_process(pid=55, name="Zoom")
    assert ok is True


@pytest.mark.asyncio
async def test_access_denied_returns_false():
    action = ProcessManagerAction()
    with patch(
        "ori.actions.process_manager.psutil.Process",
        side_effect=psutil.AccessDenied(pid=77),
    ):
        ok = await action.terminate_process(pid=77, name="Zoom")
    assert ok is False


@pytest.mark.asyncio
async def test_missing_psutil_disables_process_control():
    action = ProcessManagerAction()
    with (
        patch("ori.actions.process_manager._PSUTIL_AVAILABLE", False),
        patch("ori.actions.process_manager.psutil", None),
    ):
        ok = await action.terminate_process(pid=4321, name="Zoom")

    assert ok is False


def test_blocklist_is_frozen():
    assert isinstance(_SYSTEM_PROCESS_BLOCKLIST, frozenset)
