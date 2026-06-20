# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""PC-Ori process manager action (Tier C): terminate user processes safely."""

import logging

try:
    import psutil

    _PSUTIL_AVAILABLE = True
except Exception:
    psutil = None
    _PSUTIL_AVAILABLE = False

logger = logging.getLogger(__name__)

_SYSTEM_PROCESS_BLOCKLIST = frozenset(
    {
        "kernel",
        "launchd",
        "systemd",
        "init",
        "kthreadd",
        "sshd",
        "cron",
        "cupsd",
        "bluetoothd",
        "configd",
    }
)


class ProcessManagerAction:
    """Terminate a process by PID after strict safety checks.

    All methods are fail-safe and never raise exceptions to callers.
    """

    async def terminate_process(self, pid: int, name: str) -> bool:
        """Attempt graceful SIGTERM on a user process.

        Security invariants:
        - Block known system-owned process names.
        - Enforce PID reuse check: process name at *pid* must match *name*.
        """
        requested_name = str(name or "").strip()
        if not requested_name:
            logger.error("ProcessManagerAction: empty process name")
            return False

        if requested_name.lower() in _SYSTEM_PROCESS_BLOCKLIST:
            logger.error(
                "ProcessManagerAction: refusing termination of system process %r",
                requested_name,
            )
            return False
        if not _PSUTIL_AVAILABLE or psutil is None:
            logger.warning(
                "ProcessManagerAction: psutil is not installed; process control disabled."
            )
            return False

        try:
            proc = psutil.Process(int(pid))
            actual_name = str(proc.name() or "").strip()
            if actual_name.lower() != requested_name.lower():
                logger.error(
                    "ProcessManagerAction: PID reuse/name mismatch (pid=%s requested=%r actual=%r)",
                    pid,
                    requested_name,
                    actual_name,
                )
                return False
            proc.terminate()
            return True
        except psutil.NoSuchProcess:
            return True
        except psutil.AccessDenied:
            logger.error(
                "ProcessManagerAction: access denied terminating pid=%s name=%r",
                pid,
                requested_name,
            )
            return False
        except Exception:
            logger.exception(
                "ProcessManagerAction: unexpected failure terminating pid=%s name=%r",
                pid,
                requested_name,
            )
            return False
