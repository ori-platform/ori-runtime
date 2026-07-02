# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from ori.actions.system_control import (
    _ALLOWED_SUBSYSTEMS,
    SystemControlAction,
)


class _FakeProcess:
    def __init__(self, returncode: int = 0, delay_s: float = 0.0):
        self.returncode = returncode
        self._delay_s = delay_s

    async def communicate(self, _input: bytes):
        if self._delay_s > 0:
            await asyncio.sleep(self._delay_s)
        return b"", b""


class TestSystemControlAction:
    @pytest.mark.asyncio
    async def test_allowed_subsystem_executes(self):
        action = SystemControlAction()
        create_proc = AsyncMock(
            side_effect=[_FakeProcess(returncode=0), _FakeProcess(returncode=0)]
        )
        with (
            patch(
                "ori.actions.system_control.asyncio.create_subprocess_exec",
                new=create_proc,
            ),
            patch("ori.actions.system_control.asyncio.sleep", new=AsyncMock()),
        ):
            ok = await action.reset_kernel_subsystem("i2c-bcm2835")

        assert ok is True
        assert create_proc.await_count == 2
        first = create_proc.await_args_list[0].args
        second = create_proc.await_args_list[1].args
        assert first[0:3] == (
            "sudo",
            "tee",
            "/sys/bus/platform/drivers/i2c-bcm2835/unbind",
        )
        assert second[0:3] == (
            "sudo",
            "tee",
            "/sys/bus/platform/drivers/i2c-bcm2835/bind",
        )

    @pytest.mark.asyncio
    async def test_disallowed_subsystem_refused(self):
        action = SystemControlAction()
        create_proc = AsyncMock()
        with patch(
            "ori.actions.system_control.asyncio.create_subprocess_exec",
            new=create_proc,
        ):
            ok = await action.reset_kernel_subsystem("arbitrary_driver")

        assert ok is False
        create_proc.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_subprocess_timeout(self):
        action = SystemControlAction()
        create_proc = AsyncMock(side_effect=[_FakeProcess(returncode=0, delay_s=0.05)])
        with (
            patch(
                "ori.actions.system_control.asyncio.create_subprocess_exec",
                new=create_proc,
            ),
            patch("ori.actions.system_control._STEP_TIMEOUT_S", 0.01),
            patch("ori.actions.system_control.asyncio.sleep", new=AsyncMock()),
        ):
            ok = await action.reset_kernel_subsystem("i2c-bcm2835")

        assert ok is False

    @pytest.mark.asyncio
    async def test_subprocess_failure(self):
        action = SystemControlAction()
        create_proc = AsyncMock(side_effect=[_FakeProcess(returncode=1)])
        with (
            patch(
                "ori.actions.system_control.asyncio.create_subprocess_exec",
                new=create_proc,
            ),
            patch("ori.actions.system_control.asyncio.sleep", new=AsyncMock()),
        ):
            ok = await action.reset_kernel_subsystem("serial8250")

        assert ok is False
        assert create_proc.await_count == 1

    def test_allowlist_is_frozen(self):
        assert isinstance(_ALLOWED_SUBSYSTEMS, frozenset)
