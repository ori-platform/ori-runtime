# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Run one command, and kill it the moment the process that started it is gone.

Usage: process_supervisor.py PARENT_PID STATUS_PATH -- COMMAND...

The child starts once a file named `go` exists beside STATUS_PATH.

A test's own cleanup cannot run when its worker is killed outright, and a
child does not die with its parent on its own, so this sits between them. The
child runs in a process group of its own, and every kill is of that group, so
its own children go with it, those that stay in its group: one that starts a
session of its own has left it. The supervisor writes the child's pid, then its
exit status, to STATUS_PATH, and exits once the child does. When its parent is
no longer PARENT_PID, or it is sent SIGTERM, SIGINT or SIGHUP, at any moment
from its start, it kills the group with SIGKILL, which reaches even a stopped
process. On Linux the child is also killed by the kernel if this supervisor
itself dies; elsewhere a supervisor killed from outside is the one case left.
A group kill after its leader is reaped can, in principle, reach a group a
reused pid leads; the window is microseconds, which a test harness accepts.
"""

from __future__ import annotations

import contextlib
import ctypes
import importlib.util
import os
import shutil
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from types import ModuleType


def _platform_module() -> ModuleType:
    """`ori.utils.platform`, loaded by path: importing the `ori` package would
    run its start-up, which sets environment every child would inherit."""
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "ori",
        "utils",
        "platform.py",
    )
    spec = importlib.util.spec_from_file_location("_ori_platform", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runtime_platform = _platform_module().runtime_platform

POLL_S = float(os.environ.get("ORI_SUPERVISOR_POLL_S", "0.1"))


def _write(path: str, text: str) -> None:
    partial = f"{path}.partial"
    with open(partial, "w", encoding="ascii") as handle:
        handle.write(text)
    os.replace(partial, path)


# Loaded before any fork: a forked child must not load a library.
_LIBC = (
    ctypes.CDLL(None, use_errno=True)
    if runtime_platform().startswith("linux")
    else None
)


def _die_with(supervisor: int) -> Callable[[], None]:
    """Linux: the kernel kills the child if this supervisor dies first.

    The signal is registered, then the parent checked: a supervisor that died
    before the registration is never signalled for, so the child ends itself.
    """

    def register() -> None:
        if _LIBC is None:
            return
        pr_set_pdeathsig = 1
        if _LIBC.prctl(pr_set_pdeathsig, signal.SIGKILL) != 0:
            raise OSError(ctypes.get_errno(), "prctl(PR_SET_PDEATHSIG) failed")
        if os.getppid() != supervisor:
            os.kill(os.getpid(), signal.SIGKILL)

    return register


def _kill_group(pid: int) -> None:
    # Already gone, or its leader reaped and the pid not ours to signal.
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pid, signal.SIGKILL)


def main(argv: list[str]) -> int:
    parent, status, separator, *command = argv
    if separator != "--" or not command:
        raise SystemExit(
            "usage: process_supervisor.py PARENT_PID STATUS_PATH -- COMMAND..."
        )
    stopping = False
    started: list[int] = []

    def stop(_signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True
        if started:
            _kill_group(started[0])

    # Before the child exists, so no signal can find the supervisor without
    # its handler: one that arrives early is acted on once the child exists.
    for handled in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(handled, stop)
    # No child until the owner holds this supervisor: an owner interrupted
    # before then removes the status directory, and no child is ever started.
    directory = os.path.dirname(status)
    go = os.path.join(directory, "go")
    while not os.path.exists(go):
        if stopping or not os.path.isdir(directory) or os.getppid() != int(parent):
            shutil.rmtree(directory, ignore_errors=True)
            return 0
        time.sleep(0.01)
    try:
        child = subprocess.Popen(
            command, start_new_session=True, preexec_fn=_die_with(os.getpid())
        )
    except (OSError, subprocess.SubprocessError) as exc:
        _write(status, f"error {exc.__class__.__name__}: {exc}\n")
        return 0
    started.append(child.pid)
    try:
        return _watch(child, status, int(parent), directory, lambda: stopping)
    except FileNotFoundError:
        # The owner removed the directory: it no longer reads the status.
        return 0


def _watch(
    child: subprocess.Popen[bytes],
    status: str,
    parent: int,
    directory: str,
    stopping: Callable[[], bool],
) -> int:
    orphaned = False
    try:
        _write(status, f"{child.pid}\n")
        while child.poll() is None:
            if stopping():
                break
            if os.getppid() != parent:
                orphaned = True
                break
            # Returns the moment the child exits; the parent is checked between.
            try:
                child.wait(POLL_S)
            except subprocess.TimeoutExpired:
                continue  # still running: check the parent and stop again
    finally:
        # Whatever ends the watch, a failed status write included: the group
        # goes, the child is reaped, and anything it left in its group with it.
        _kill_group(child.pid)
        code = child.wait()
        _kill_group(child.pid)
    if orphaned:
        # No one is left to read the status, so nothing of it stays behind.
        shutil.rmtree(directory, ignore_errors=True)
    else:
        _write(status, f"{child.pid}\n{code}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
