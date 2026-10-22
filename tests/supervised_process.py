# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Long-running processes a test starts, which never outlive the test run.

Every such process runs under `process_supervisor.py`, in a process group of
its own, which the supervisor kills when the test's own process is gone, so a
worker killed outright, a timeout or an interrupted run cannot leave it, or
anything it started, behind holding a port. Cleanup that does run, the
caller's `finally` and this module's `atexit` hook, kills the group at once.
Tests start their brokers and payloads through here
(`tests/test_supervised_process.py` holds them to it).
"""

from __future__ import annotations

import atexit
import contextlib
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

SUPERVISOR = Path(__file__).with_name("process_supervisor.py")
#: Long, because a loaded host can start a process slowly; an expiry asks the
#: supervisor to stop its child rather than abandoning either.
START_S = 60.0
#: Decided here, or by the supervisor: its own `close_fds` would close any
#: `pass_fds` before the child, so neither reaches the child as asked.
_REFUSED = frozenset(
    {
        "start_new_session",
        "process_group",
        "preexec_fn",
        "shell",
        "pass_fds",
        "close_fds",
    }
)

_LIVE: set[Supervised] = set()


class Supervised:
    """A Popen-like handle on the supervised child, not on its supervisor."""

    def __init__(self, argv: list[str], **popen_kwargs: Any) -> None:
        refused = _REFUSED & popen_kwargs.keys()
        if refused:
            raise TypeError(f"Supervised decides {sorted(refused)} itself")
        self.args = list(argv)
        self._dir = tempfile.mkdtemp(prefix="ori-supervised-")
        self._status = os.path.join(self._dir, "status")
        try:
            self._supervisor = subprocess.Popen(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(SUPERVISOR),
                    str(os.getpid()),
                    self._status,
                    "--",
                    *argv,
                ],
                start_new_session=True,
                **popen_kwargs,
            )
            self.stdin = self._supervisor.stdin
            self.stdout = self._supervisor.stdout
            self.stderr = self._supervisor.stderr
            self.returncode: int | None = None
            # Held now: only from here may the supervisor start the child.
            Path(self._dir, "go").touch()
            self.pid = self._await_pid()
            _LIVE.add(self)
        except BaseException:
            # Interrupted before the caller holds a handle. Without `go` the
            # supervisor sees its directory gone and exits having started
            # nothing, even when the interruption left no handle on it; with
            # it, its handler kills the child.
            shutil.rmtree(self._dir, ignore_errors=True)
            supervisor = self.__dict__.get("_supervisor")
            if supervisor is not None:
                if supervisor.poll() is None:
                    supervisor.terminate()
                self._reap_supervisor()
            raise

    def _fields(self) -> list[str]:
        try:
            return Path(self._status).read_text(encoding="ascii").split()
        except FileNotFoundError:
            return []

    def _await_pid(self) -> int:
        deadline = time.monotonic() + START_S
        while True:
            fields = self._fields()
            if fields and fields[0] == "error":
                self._reap_supervisor()
                shutil.rmtree(self._dir, ignore_errors=True)
                raise FileNotFoundError(" ".join(fields[1:]))
            if fields:
                return int(fields[0])
            if self._supervisor.poll() is not None:
                shutil.rmtree(self._dir, ignore_errors=True)
                raise RuntimeError("the supervisor exited before its child started")
            if time.monotonic() >= deadline:
                # Its handler kills the child once it exists: never abandon it.
                self._supervisor.terminate()
                self._reap_supervisor()
                shutil.rmtree(self._dir, ignore_errors=True)
                raise RuntimeError(f"the supervised child did not start in {START_S}s")
            time.sleep(0.01)

    def _reap_supervisor(self) -> None:
        try:
            self._supervisor.wait(30.0)
        except subprocess.TimeoutExpired:
            self._supervisor.kill()
            self._supervisor.wait()

    def _exited(self) -> int | None:
        """The child's own exit status, once its supervisor has recorded it."""
        fields = self._fields()
        return int(fields[1]) if len(fields) > 1 else None

    def _settle(self, code: int) -> int:
        self.returncode = code
        _LIVE.discard(self)
        shutil.rmtree(self._dir, ignore_errors=True)
        return code

    def poll(self) -> int | None:
        if self.returncode is not None:
            return self.returncode
        code = self._exited()
        if code is not None:
            self._supervisor.wait()
            return self._settle(code)
        if self._supervisor.poll() is not None:
            # The supervisor died without recording the child: never assume the
            # child exited with it. Kill its group, and report it killed.
            self._kill_group()
            return self._settle(-signal.SIGKILL)
        return None

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is not None:
            return self.returncode
        self._supervisor.wait(timeout)
        code = self.poll()
        assert code is not None
        return code

    def _kill_group(self) -> None:
        # Already gone, or its leader reaped and the pid not ours to signal.
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(self.pid, signal.SIGKILL)

    def send_signal(self, signum: int) -> None:
        # Only while no exit status is recorded, so a pid the supervisor has
        # reaped, and the system may reuse, is never signalled.
        if self.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.kill(self.pid, signum)

    def terminate(self) -> None:
        self.send_signal(signal.SIGTERM)

    def kill(self) -> None:
        self.send_signal(signal.SIGKILL)

    def stop(self) -> None:
        """Kill the child's whole group if it still runs, and reap the supervisor."""
        if self.returncode is not None:
            return
        if self._exited() is None:
            self._kill_group()
        try:
            self.wait(30.0)
        except subprocess.TimeoutExpired:
            # The child is gone with its group; a wedged supervisor goes too.
            self._supervisor.kill()
            self._supervisor.wait()
            self._settle(-signal.SIGKILL)


def leaked_children(grace_s: float = 5.0) -> list[str]:
    """Children of this process still running that no live Supervised holds.

    Each gets *grace_s* to finish exiting, then is killed with its children
    and reported. This sees a leak however it was spawned; it cannot see a
    child that daemonised, which its parent no longer is.
    """
    import psutil

    held = {live._supervisor.pid for live in _LIVE}
    candidates = [
        child
        for child in psutil.Process().children()
        if child.pid not in held and _running(child)
    ]
    _gone, alive = psutil.wait_procs(candidates, timeout=grace_s)
    leaked: list[str] = []
    for child in alive:
        try:
            leaked.append(f"{child.pid} {' '.join(child.cmdline())}")
            for process in [*child.children(recursive=True), child]:
                process.kill()
        except psutil.Error:
            continue
    return leaked


def _running(process: Any) -> bool:
    import psutil

    try:
        return process.status() != psutil.STATUS_ZOMBIE
    except psutil.Error:
        return False


def run(
    argv: list[str],
    *,
    timeout: float,
    input: Any = None,
    check: bool = False,
    capture_output: bool = False,
    **popen_kwargs: Any,
) -> subprocess.CompletedProcess[Any]:
    """`subprocess.run` under supervision, for a command that runs long.

    A waiting call outside it stops its child only while its caller lives;
    this one stops it if the caller is killed outright too.
    """
    if capture_output:
        if "stdout" in popen_kwargs or "stderr" in popen_kwargs:
            raise ValueError("stdout and stderr may not be used with capture_output")
        popen_kwargs["stdout"] = popen_kwargs["stderr"] = subprocess.PIPE
    if input is not None:
        if "stdin" in popen_kwargs:
            raise ValueError("stdin and input arguments may not both be used")
        popen_kwargs["stdin"] = subprocess.PIPE
    child = Supervised(argv, **popen_kwargs)
    try:
        stdout, stderr = child._supervisor.communicate(input, timeout=timeout)
    except subprocess.TimeoutExpired as expired:
        child.stop()
        raise subprocess.TimeoutExpired(
            argv, timeout, output=expired.output, stderr=expired.stderr
        ) from None
    except BaseException:
        child.stop()
        raise
    code = child.wait()
    completed = subprocess.CompletedProcess(argv, code, stdout, stderr)
    if check:
        completed.check_returncode()
    return completed


@atexit.register
def _stop_every_live_process() -> None:
    for live in list(_LIVE):
        live.stop()
