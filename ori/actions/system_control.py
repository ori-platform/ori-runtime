# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Kernel subsystem reset action (Tier C).

Unbinds and rebinds a whitelisted Linux platform driver to recover from
kernel-level bus lockups that cannot be fixed by restarting the process.
"""

import asyncio
import logging

from ori.utils.path_utils import shown

logger = logging.getLogger(__name__)

_ALLOWED_SUBSYSTEMS = frozenset({"i2c-bcm2835", "i2c-bcm2708", "serial8250"})
_DRIVER_BASE = "/sys/bus/platform/drivers"
_STEP_TIMEOUT_S = 10.0
_REBOUND_DELAY_S = 1.0


class SystemControlAction:
    """Perform guarded kernel subsystem resets.

    All methods are fail-safe and never raise exceptions to callers.
    """

    async def reset_kernel_subsystem(self, subsystem: str) -> bool:
        """Unbind and rebind a kernel subsystem driver.

        Returns:
            ``True`` on successful unbind+rebind, else ``False``.
        """
        target = str(subsystem or "").strip()
        if target not in _ALLOWED_SUBSYSTEMS:
            logger.error(
                "SystemControlAction: refusing reset for disallowed subsystem %r",
                target,
            )
            return False

        unbind_path = f"{_DRIVER_BASE}/{target}/unbind"
        bind_path = f"{_DRIVER_BASE}/{target}/bind"

        try:
            if not await self._write_driver_node(unbind_path, target):
                return False
            await asyncio.sleep(_REBOUND_DELAY_S)
            if not await self._write_driver_node(bind_path, target):
                return False
            logger.info(
                "SystemControlAction: reset completed for subsystem=%s",
                target,
            )
            return True
        except Exception:
            logger.exception(
                "SystemControlAction: unexpected failure resetting subsystem=%r",
                target,
            )
            return False

    async def _write_driver_node(self, node_path: str, value: str) -> bool:
        """Write one value into a privileged sysfs driver bind/unbind node."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "sudo",
                "tee",
                node_path,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(
                proc.communicate(f"{value}\n".encode("utf-8")),
                timeout=_STEP_TIMEOUT_S,
            )
            if proc.returncode != 0:
                err_text = (
                    stderr.decode("utf-8", errors="ignore").strip() if stderr else ""
                )
                logger.error(
                    "SystemControlAction: command failed for %s (rc=%s): %s",
                    shown(node_path),
                    proc.returncode,
                    err_text,
                )
                return False
            return True
        except asyncio.TimeoutError:
            logger.error(
                "SystemControlAction: timeout writing subsystem node %s",
                shown(node_path),
            )
            return False
        except Exception:
            logger.exception(
                "SystemControlAction: failed writing subsystem node %s",
                shown(node_path),
            )
            return False
