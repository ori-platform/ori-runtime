# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A process a test starts never outlives the process that started it."""

from __future__ import annotations

import ast
import asyncio
import contextlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path
from typing import Any

import pytest

from tests.supervised_process import Supervised
from tests.test_dispatch_never_waits_on_delivery import _free_port, _mosquitto
from tests.waiting import wait_until

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent


def _gone(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


ALLOWED_PATHS = {TESTS / "supervised_process.py", TESTS / "process_supervisor.py"}
#: Calls that can leave a long-running child behind, by module; `spawn` stands
#: for every `os.spawn*`. Waiting calls are judged by their timeout instead,
#: under `WAITING` below. asyncio subprocesses are not here: the tests run them
#: briefly, awaited with a deadline, and their transport reaps them.
SPAWNERS: dict[str, frozenset[str]] = {
    "subprocess": frozenset({"Popen"}),
    "os": frozenset(
        {"fork", "forkpty", "posix_spawn", "posix_spawnp", "system", "popen", "spawn"}
    ),
    "pty": frozenset({"spawn", "fork"}),
    "multiprocessing": frozenset({"Process", "Pool", "get_context"}),
    "concurrent.futures": frozenset({"ProcessPoolExecutor"}),
    "pexpect": frozenset({"spawn"}),
}


def _covered(module: str) -> str | None:
    """The SPAWNERS entry *module* is, or is a submodule of."""
    for root in SPAWNERS:
        if module == root or module.startswith(f"{root}."):
            return root
    return None


def _spawner(module: str, name: str) -> bool:
    root = _covered(module)
    if root is None:
        return False
    return name in SPAWNERS[root] or (root == "os" and name.startswith("spawn"))


def _dotted(node: ast.AST) -> list[str] | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return parts[::-1]


def _modules(node: ast.AST, bound: dict[str, set[str]]) -> set[str]:
    """The modules a dotted name can be, through every binding of its head."""
    parts = _dotted(node)
    if parts is None or parts[0] not in bound:
        return set()
    return {".".join([head, *parts[1:]]) for head in bound[parts[0]]}


def _spawns(source: str) -> list[int]:
    """Lines that start a process the supervisor does not hold.

    Names are resolved through every import and plain assignment in the
    module, in any scope, and a name keeps every module it was ever bound to,
    so an alias, a submodule, a rebinding or a shadowing import elsewhere
    cannot hide a spawn. A first look only: `no_child_outlives_its_test` in
    `tests/conftest.py` catches a leak however it is spelled.
    """
    tree = ast.parse(source)
    # Unimported names stand for themselves.
    bound: dict[str, set[str]] = {
        root.split(".")[0]: {root.split(".")[0]} for root in SPAWNERS
    }
    lines: list[int] = []

    def bind(name: str, module: str) -> bool:
        known = bound.setdefault(name, set())
        if module in known:
            return False
        known.add(module)
        return True

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    bind(alias.asname, alias.name)
                else:
                    top = alias.name.split(".")[0]
                    bind(top, top)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                if alias.name == "*" and _covered(node.module):
                    lines.append(node.lineno)
                elif _spawner(node.module, alias.name):
                    lines.append(node.lineno)
                else:
                    bind(alias.asname or alias.name, f"{node.module}.{alias.name}")
    assignments = [
        (target.id, node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
    ]
    changed = True
    while changed:
        changed = False
        for name, value in assignments:
            for module in _modules(value, bound):
                changed |= bind(name, module)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and any(
            _spawner(module, node.attr) for module in _modules(node.value, bound)
        ):
            lines.append(node.lineno)
        elif isinstance(node, ast.Call) and _modules(node.func, bound) & WAITING:
            if _may_wait_long(node):
                lines.append(node.lineno)
    return lines


#: Calls that return only once their child has exited, while their caller
#: lives: one killed outright leaves the child to run to its own end.
WAITING = frozenset(
    {
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
    }
)
#: The longest a waiting call may run unsupervised; longer goes through
#: `tests.supervised_process.run`.
WAIT_LIMIT_S = 120


def _may_wait_long(call: ast.Call) -> bool:
    """A literal timeout within the limit, or none at all for a command that
    ends on its own; a longer or computed one is refused. A timeout forwarded
    in `**kwargs` is its caller's, which this cannot see."""
    timeout = next((k.value for k in call.keywords if k.arg == "timeout"), None)
    if timeout is None:
        return False
    return not (
        isinstance(timeout, ast.Constant)
        and isinstance(timeout.value, (int, float))
        and timeout.value <= WAIT_LIMIT_S
    )


def test_every_long_running_child_is_supervised() -> None:
    found = [
        f"{path.relative_to(ROOT)}:{line}"
        for path in sorted(TESTS.rglob("*.py"))
        if path not in ALLOWED_PATHS
        for line in _spawns(path.read_text(encoding="utf-8"))
    ]
    assert found == [], (
        "a test starts a process outside tests/supervised_process.py, so a "
        "killed worker can leave it running: use Supervised. This scan follows "
        "imports and aliases to subprocess.Popen, os.fork/spawn*/posix_spawn*/"
        "system/popen, pty, multiprocessing, ProcessPoolExecutor and pexpect; "
        "waiting calls such as subprocess.run are allowed with no timeout or "
        "a literal one of at most WAIT_LIMIT_S, for a child that ends on its "
        "own and does not daemonise: if the worker is killed outright, such a "
        "child runs to its own end, however long, since nothing judges a "
        "call with no timeout (nor one forwarded in **kwargs); a command "
        "declared long uses "
        "tests.supervised_process.run. asyncio subprocesses are allowed; a "
        "dynamic lookup "
        "(getattr, importlib, __import__, sys.modules) is invisible to it, and "
        "the autouse no_child_outlives_its_test fixture catches what it misses."
    )


@pytest.mark.parametrize(
    "source",
    [
        "import subprocess\nsubprocess.Popen(['x'])\n",
        "from subprocess import Popen as P\nP(['x'])\n",
        "import subprocess as sp\nsp.Popen(['x'])\n",
        "from subprocess import *\nPopen(['x'])\n",
        "import os\nos.fork()\n",
        "import os as o\no.fork()\n",
        "import os\nos.spawnv(os.P_NOWAIT, 'x', ['x'])\n",
        "import os\nos.system('mosquitto -d')\n",
        "import os\nos.popen('x')\n",
        "from os import posix_spawn\n",
        "import pty\npty.spawn(['x'])\n",
        "import multiprocessing\nmultiprocessing.Process(target=f)\n",
        "import multiprocessing as mp\nmp.get_context('spawn').Process()\n",
        "from concurrent.futures import ProcessPoolExecutor\n",
        "import concurrent.futures\nconcurrent.futures.ProcessPoolExecutor()\n",
        "import concurrent.futures as cf\ncf.ProcessPoolExecutor()\n",
        "from concurrent import futures\nfutures.ProcessPoolExecutor()\n",
        "import subprocess\nsubprocess.run(['cargo'], timeout=900)\n",
        "from subprocess import run\nrun(['x'], timeout=t)\n",
        "from multiprocessing.pool import Pool\n",
        "import multiprocessing.pool\nmultiprocessing.pool.Pool()\n",
        "from multiprocessing import context as c\nc.Process()\n",
        "from concurrent.futures.process import ProcessPoolExecutor\n",
        "import subprocess\nsp = subprocess\nsp.Popen(['x'])\n",
        "import subprocess\ndef f():\n    import json as subprocess\n"
        + "subprocess.Popen(['x'])\n",
    ],
)
def test_the_guard_sees_a_spawn(source: str) -> None:
    assert _spawns(source)


@pytest.mark.parametrize(
    "source",
    [
        "import subprocess\nsubprocess.run(['x'])\n",
        "import subprocess\nsubprocess.run(['x'], timeout=120)\n",
        "import os\nos.path.join('a')\n",
        "from os import path\n",
    ],
)
def test_the_guard_passes_a_call_that_waits(source: str) -> None:
    assert not _spawns(source)


def _orphan(argv: list[str], *, tmpdir: Path | None = None) -> int:
    """Start *argv* supervised in a process that then dies by SIGKILL."""
    script = textwrap.dedent(
        f"""
        import os, signal, sys
        sys.path.insert(0, {str(ROOT)!r})
        from tests.supervised_process import Supervised
        child = Supervised({argv!r})
        print(child.pid, flush=True)
        os.kill(os.getpid(), signal.SIGKILL)
        """
    )
    env = None if tmpdir is None else {**os.environ, "TMPDIR": str(tmpdir)}
    owner = subprocess.run(
        [sys.executable, "-B", "-c", script],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    assert owner.returncode == -signal.SIGKILL
    return int(owner.stdout.split()[0])


async def test_a_child_dies_with_the_process_that_started_it(tmp_path: Path) -> None:
    pid = _orphan(["sleep", "600"])
    await wait_until(lambda: _gone(pid), what="the orphaned child exiting")


async def test_no_broker_survives_its_worker_being_killed(tmp_path: Path) -> None:
    binary = _mosquitto()
    if binary is None:
        pytest.skip("mosquitto is not installed")
    config = tmp_path / "mosquitto.conf"
    config.write_text(
        f"listener {_free_port()} 127.0.0.1\nallow_anonymous true\npersistence false\n"
    )
    pid = _orphan([binary, "-c", str(config)])
    await wait_until(lambda: _gone(pid), what="the orphaned broker exiting")


async def test_a_normal_exit_stops_the_child(tmp_path: Path) -> None:
    script = textwrap.dedent(
        f"""
        import sys
        sys.path.insert(0, {str(ROOT)!r})
        from tests.supervised_process import Supervised
        print(Supervised(["sleep", "600"]).pid, flush=True)
        """
    )
    owner = subprocess.run(
        [sys.executable, "-B", "-c", script], capture_output=True, text=True, timeout=30
    )
    pid = int(owner.stdout.split()[0])
    await wait_until(lambda: _gone(pid), what="the child stopped at exit")


async def test_a_stopped_child_is_still_killed() -> None:
    """SIGTERM would wait for a SIGSTOPped broker forever; stop() does not."""
    child = Supervised(["sleep", "600"])
    child.send_signal(signal.SIGSTOP)
    child.stop()
    assert child.returncode == -signal.SIGKILL
    await wait_until(lambda: _gone(child.pid), what="the stopped child exiting")


def test_the_exit_status_is_the_childs() -> None:
    exits = Supervised(["sh", "-c", "exit 3"])
    assert exits.wait(10) == 3
    terminated = Supervised(["sleep", "600"])
    terminated.terminate()
    assert terminated.wait(10) == -signal.SIGTERM


def test_output_passes_through() -> None:
    child = Supervised(["sh", "-c", "echo hello"], stdout=subprocess.PIPE, text=True)
    assert child.stdout is not None
    assert child.stdout.read() == "hello\n"
    assert child.wait(10) == 0


def test_the_exit_hook_stops_every_live_child() -> None:
    """At interpreter exit each live child is stopped at once, before the
    supervisor would notice its parent is gone."""
    from tests import supervised_process

    child = Supervised(["sleep", "600"])
    assert child in supervised_process._LIVE
    supervised_process._stop_every_live_process()
    assert child not in supervised_process._LIVE
    assert child.returncode == -signal.SIGKILL


def test_a_killed_supervisor_takes_its_child_with_it() -> None:
    child = Supervised(["sleep", "605"])
    os.kill(child._supervisor.pid, signal.SIGKILL)
    child._supervisor.wait(10)
    assert child.poll() == -signal.SIGKILL
    assert _gone(child.pid) or _zombie(child.pid)


def _zombie(pid: int) -> bool:
    found = subprocess.run(
        ["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True
    ).stdout.strip()
    return found.startswith("Z") or not found


async def test_a_grandchild_goes_with_the_child() -> None:
    child = Supervised(
        ["sh", "-c", "sleep 606 & echo $!; wait"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    assert child.stdout is not None
    grandchild = int(child.stdout.readline())
    child.stop()
    await wait_until(lambda: _gone(grandchild), what="the grandchild exiting")


async def test_a_grandchild_goes_when_the_owner_is_killed() -> None:
    script = textwrap.dedent(
        f"""
        import os, signal, subprocess, sys
        sys.path.insert(0, {str(ROOT)!r})
        from tests.supervised_process import Supervised
        child = Supervised(["sh", "-c", "sleep 607 & echo $!; wait"],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        print(child.stdout.readline().strip(), flush=True)
        os.kill(os.getpid(), signal.SIGKILL)
        """
    )
    owner = subprocess.run(
        [sys.executable, "-B", "-c", script], capture_output=True, text=True, timeout=30
    )
    grandchild = int(owner.stdout.split()[0])
    await wait_until(lambda: _gone(grandchild), what="the orphaned grandchild exiting")


@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT, signal.SIGHUP])
def test_a_signal_to_the_supervisor_kills_the_child(signum: int) -> None:
    child = Supervised(["sleep", "608"])
    os.kill(child._supervisor.pid, signum)
    assert child.wait(10) == -signal.SIGKILL


async def test_the_exit_hook_is_what_stops_the_child_at_exit() -> None:
    """With the parent poll out of reach, only the registered hook can stop
    the child before the owner's exit is over."""
    script = textwrap.dedent(
        f"""
        import os, sys
        os.environ["ORI_SUPERVISOR_POLL_S"] = "3600"
        sys.path.insert(0, {str(ROOT)!r})
        from tests.supervised_process import Supervised
        print(Supervised(["sleep", "609"]).pid, flush=True)
        """
    )
    owner = subprocess.run(
        [sys.executable, "-B", "-c", script], capture_output=True, text=True, timeout=30
    )
    pid = int(owner.stdout.split()[0])
    assert _gone(pid) or _zombie(pid)


def test_a_missing_binary_is_reported_as_missing() -> None:
    with pytest.raises(FileNotFoundError):
        Supervised(["/nonexistent/ori-binary"])


def test_supervised_refuses_what_it_decides_itself() -> None:
    with pytest.raises(TypeError):
        Supervised(["sleep", "1"], start_new_session=False)


def _running(marker: str) -> bool:
    found = subprocess.run(["pgrep", "-f", marker], capture_output=True, text=True)
    return bool(found.stdout.strip())


@pytest.mark.parametrize("when", ["before", "after"])
async def test_a_signal_while_the_child_starts_still_kills_it(when: str) -> None:
    """A SIGTERM delivered as the child is spawned, just before or just after,
    is the supervisor's handler's to act on, never its default action's."""
    marker = f"61{os.getpid() % 1000:03d}{0 if when == 'before' else 1}"
    script = textwrap.dedent(
        f"""
        import os, signal, subprocess, sys
        sys.path.insert(0, {str(TESTS)!r})
        import process_supervisor
        real = subprocess.Popen
        def popen(*args, **kwargs):
            if {when!r} == "before":
                os.kill(os.getpid(), signal.SIGTERM)
            child = real(*args, **kwargs)
            if {when!r} == "after":
                os.kill(os.getpid(), signal.SIGTERM)
            return child
        process_supervisor.subprocess.Popen = popen
        sys.exit(process_supervisor.main(sys.argv[1:]))
        """
    )
    status = Path(tempfile.mkdtemp(prefix="ori-supervised-test-")) / "status"
    (status.parent / "go").touch()
    try:
        supervisor = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                script,
                str(os.getpid()),
                str(status),
                "--",
                "sleep",
                marker,
            ],
            timeout=30,
        )
        assert supervisor.returncode == 0
        await wait_until(lambda: not _running(f"sleep {marker}"), what="no child left")
    finally:
        subprocess.run(["pkill", "-KILL", "-f", f"sleep {marker}"])
        shutil.rmtree(status.parent, ignore_errors=True)


async def test_what_the_child_leaves_in_its_group_goes_when_it_exits() -> None:
    child = Supervised(
        ["sh", "-c", "sleep 612 & echo $!; exit 0"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    assert child.stdout is not None
    grandchild = int(child.stdout.readline())
    assert child.wait(10) == 0
    await wait_until(lambda: _gone(grandchild), what="the grandchild exiting")


async def test_an_orphaned_supervisor_leaves_no_status_behind(tmp_path: Path) -> None:
    pid = _orphan(["sleep", "613"], tmpdir=tmp_path)
    await wait_until(lambda: _gone(pid), what="the orphaned child exiting")
    await wait_until(
        lambda: not list(tmp_path.glob("ori-supervised-*")),
        what="the orphan's status removed",
    )


async def test_an_interrupted_start_leaves_no_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests import supervised_process

    def interrupted(_self: Supervised) -> list[str]:
        raise KeyboardInterrupt

    monkeypatch.setattr(supervised_process.Supervised, "_fields", interrupted)
    before = set(supervised_process._LIVE)
    with pytest.raises(KeyboardInterrupt):
        Supervised(["sleep", "614"])
    assert supervised_process._LIVE == before
    await wait_until(lambda: not _running("sleep 614"), what="no child left")


def test_fds_are_refused_rather_than_dropped() -> None:
    with pytest.raises(TypeError):
        Supervised(["sleep", "1"], pass_fds=(0,))


async def test_a_leak_the_scan_cannot_see_is_still_caught() -> None:
    """The autouse fixture's check: a child left running, by a spelling the
    scan allows, is reported and killed."""
    from tests.supervised_process import leaked_children

    child = await asyncio.create_subprocess_exec("sleep", "616")
    try:
        leaked = leaked_children(grace_s=0.5)
        assert [line.split()[0] for line in leaked] == [str(child.pid)]
        assert await asyncio.wait_for(child.wait(), 10) == -signal.SIGKILL
    finally:
        if child.returncode is None:
            child.kill()
            await child.wait()
    assert leaked_children(grace_s=0.5) == []


def test_a_held_supervised_child_is_not_a_leak() -> None:
    """A broker a module fixture holds across tests stays running."""
    from tests.supervised_process import leaked_children

    child = Supervised(["sleep", "617"])
    try:
        assert leaked_children(grace_s=0.5) == []
        assert child.poll() is None
    finally:
        child.stop()


def test_the_child_inherits_the_callers_environment_unchanged() -> None:
    child = Supervised(
        [
            sys.executable,
            "-I",
            "-c",
            "import json, os; print(json.dumps(dict(os.environ)))",
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert child.stdout is not None
    seen = json.loads(child.stdout.read())
    assert child.wait(10) == 0
    # The interpreter itself may add these on start.
    for added in ("__CF_USER_TEXT_ENCODING", "LC_CTYPE"):
        seen.pop(added, None)
    expected = {
        k: v
        for k, v in os.environ.items()
        if k not in ("__CF_USER_TEXT_ENCODING", "LC_CTYPE")
    }
    assert seen == expected


_LEAKING_TEST = """
import subprocess, time
from pathlib import Path

def test_leaks():
    pids = Path({pids!r})
    subprocess.Popen(["sh", "-c", "trap '' TERM; sleep 6181 & echo $$ $! > {pids}; wait"])
    while not pids.exists() or len(pids.read_text().split()) < 2:
        time.sleep(0.01)
"""


async def test_a_test_that_leaks_fails_and_its_children_go(tmp_path: Path) -> None:
    """Through pytest itself: the autouse fixture runs, fails the test at
    teardown, and kills the leaked child with its own children."""
    pids = tmp_path / "pids"
    inner = tmp_path / "test_inner.py"
    inner.write_text(_LEAKING_TEST.format(pids=str(pids)))
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    run = subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "pytest",
            "-p",
            "tests.conftest",
            "-p",
            "no:cacheprovider",
            "-c",
            str(tmp_path / "pytest.ini"),
            "--rootdir",
            str(tmp_path),
            "-q",
            str(inner),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    child, grandchild = (int(pid) for pid in pids.read_text().split())
    try:
        assert "1 passed, 1 error" in run.stdout, run.stdout + run.stderr
        assert "no Supervised holds" in run.stdout
        await wait_until(
            lambda: _gone(child) or _zombie(child), what="the child killed"
        )
        await wait_until(lambda: _gone(grandchild), what="the grandchild killed")
    except BaseException:
        # Only when the fixture did not kill them: a passing run's pids are
        # gone, and may since name another process.
        for pid in (child, grandchild):
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
        raise


async def test_a_status_that_cannot_be_written_still_stops_the_child() -> None:
    marker = f"62{os.getpid() % 1000:03d}0"
    directory = Path(tempfile.mkdtemp(prefix="ori-supervised-test-"))
    (directory / "go").touch()
    # A non-empty directory where the status goes: replacing it fails.
    (directory / "status" / "held").mkdir(parents=True)
    try:
        supervisor = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(TESTS / "process_supervisor.py"),
                str(os.getpid()),
                str(directory / "status"),
                "--",
                "sleep",
                marker,
            ],
            capture_output=True,
            timeout=30,
        )
        assert supervisor.returncode != 0
        await wait_until(lambda: not _running(f"sleep {marker}"), what="no child left")
    finally:
        subprocess.run(["pkill", "-KILL", "-f", f"sleep {marker}"])
        shutil.rmtree(directory, ignore_errors=True)


async def test_an_interruption_as_the_supervisor_launches_leaves_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Interrupted after the supervisor exists but before the handle is held:
    without `go` it starts no child, and exits once its directory is gone."""
    from tests import supervised_process

    marker = f"62{os.getpid() % 1000:03d}1"
    real = supervised_process.subprocess.Popen

    def launched_then_interrupted(*args: Any, **kwargs: Any) -> Any:
        real(*args, **kwargs)
        # Late enough that a supervisor not waiting for `go` has already
        # started its child and recorded it.
        status = Path(args[0][5])
        deadline = time.monotonic() + 2.0
        while not status.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        raise KeyboardInterrupt

    monkeypatch.setattr(
        supervised_process.subprocess, "Popen", launched_then_interrupted
    )
    try:
        with pytest.raises(KeyboardInterrupt):
            Supervised(["sleep", marker])
        monkeypatch.undo()  # the module is subprocess itself, which pgrep uses
        await wait_until(
            lambda: not _running(f"process_supervisor.py .* sleep {marker}"),
            what="the supervisor exiting",
        )
        assert not _running(f"^sleep {marker}")
    finally:
        subprocess.run(["pkill", "-KILL", "-f", marker])


def test_a_supervised_run_returns_what_run_would() -> None:
    from tests.supervised_process import run

    done = run(
        ["sh", "-c", "cat; echo err >&2; exit 4"],
        input="in",
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert (done.returncode, done.stdout, done.stderr) == (4, "in", "err\n")
    with pytest.raises(subprocess.CalledProcessError):
        run(["false"], check=True, timeout=30)


async def test_a_supervised_run_past_its_timeout_stops_its_child() -> None:
    from tests.supervised_process import run

    marker = f"62{os.getpid() % 1000:03d}2"
    with pytest.raises(subprocess.TimeoutExpired):
        run(["sleep", marker], timeout=0.5)
    await wait_until(lambda: not _running(f"^sleep {marker}"), what="the child stopped")


async def test_a_supervised_run_dies_with_its_owner_killed_outright() -> None:
    marker = f"62{os.getpid() % 1000:03d}3"
    script = textwrap.dedent(
        f"""
        import os, signal, sys, threading
        sys.path.insert(0, {str(ROOT)!r})
        from tests.supervised_process import run
        threading.Timer(1.0, os.kill, (os.getpid(), signal.SIGKILL)).start()
        run(["sleep", {marker!r}], timeout=600)
        """
    )
    owner = subprocess.run(
        [sys.executable, "-B", "-c", script], capture_output=True, timeout=60
    )
    try:
        assert owner.returncode == -signal.SIGKILL
        await wait_until(
            lambda: not _running(f"^sleep {marker}"), what="the child gone"
        )
    finally:
        subprocess.run(["pkill", "-KILL", "-f", f"^sleep {marker}"])


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="PR_SET_PDEATHSIG is Linux's"
)
async def test_a_child_whose_supervisor_is_already_gone_ends_itself() -> None:
    from tests.process_supervisor import _die_with

    # Its parent is this process, never pid 1: it must take itself down.
    child = await asyncio.create_subprocess_exec("sleep", "30", preexec_fn=_die_with(1))
    assert await asyncio.wait_for(child.wait(), 10) == -signal.SIGKILL


def test_a_supervised_run_refuses_what_run_refuses() -> None:
    from tests.supervised_process import run

    with pytest.raises(ValueError):
        run(["true"], capture_output=True, stdout=subprocess.PIPE, timeout=30)
    with pytest.raises(ValueError):
        run(["cat"], input="x", stdin=subprocess.PIPE, timeout=30)


def test_a_supervised_run_times_out_naming_its_own_command() -> None:
    from tests.supervised_process import run

    with pytest.raises(subprocess.TimeoutExpired) as expired:
        run(["sleep", "624"], timeout=0.5)
    assert expired.value.cmd == ["sleep", "624"]


def test_a_supervisor_whose_directory_is_gone_exits_quietly() -> None:
    """The owner removing the directory means it no longer reads the status."""
    child = Supervised(["sleep", "625"], stderr=subprocess.PIPE)
    shutil.rmtree(child._dir)
    child.stop()
    assert child._supervisor.stderr is not None
    assert child._supervisor.stderr.read() == b""
    assert child._supervisor.returncode == 0
