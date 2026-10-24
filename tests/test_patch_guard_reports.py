# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The patch guard's refusal reaches the test report, through real pytest.

The guard's own tests call it directly; these run pytest on a generated file
under this conftest, so the report a refused patch produces is what is read,
``xfail`` and skips included.
"""

from __future__ import annotations

import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent

PROBE = """
import importlib
from unittest import mock

import pytest


def _f(*args, **kwargs):
    return None


# Written while the file is collected: the first test to start reports it.
importlib.import_module("ori.config._device").checked_device_id = _f


def test_first_after_collection():
    pass


def _partial():
    with mock.patch("ori.config._actions.parse_actions", _f):
        pass


def test_partial():
    _partial()


@pytest.mark.xfail
def test_partial_under_xfail():
    _partial()
    assert False


@pytest.mark.xfail(strict=True)
def test_partial_under_strict_xfail():
    _partial()
    assert False


def test_partial_then_skip():
    _partial()
    pytest.skip("skipped after the patch")


def test_partial_and_a_failing_body():
    _partial()
    assert False, "the body's own failure"


@pytest.fixture
def partial_in_setup():
    _partial()
    yield


@pytest.fixture
def partial_in_teardown():
    yield
    _partial()


@pytest.fixture
def partial_then_setup_error():
    _partial()
    raise RuntimeError("the fixture's own error")


def test_partial_in_setup(partial_in_setup):
    pass


def test_partial_in_teardown(partial_in_teardown):
    pass


def test_partial_and_a_setup_error(partial_then_setup_error):
    pass


def test_patched_by_another_plugin():
    pass


def test_clean():
    pass


@pytest.mark.xfail
def test_clean_xfail():
    assert False
"""


#: A plugin whose own wrapper, outside this conftest's, patches between the
#: call's check and teardown.
OUTER_PLUGIN = """
from unittest import mock

import pytest


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_teardown(item):
    if item.name == "test_patched_by_another_plugin":
        with mock.patch("ori.config._actions.parse_actions", print):
            pass
    return (yield)


@pytest.hookimpl(wrapper=True)
def pytest_sessionfinish(session):
    result = yield
    # In a serial run, or on an xdist worker: never on the xdist controller,
    # so a worker's finding must reach the controller to fail the run.
    if not session.config.pluginmanager.hasplugin("dsession"):
        with mock.patch("ori.config._fields.require_str", print):
            pass
    return result
"""


AFTER_THE_LAST_TEST = (
    "After the last test: patched or deleted ori.config._fields.require_str"
)


def _run_probe(
    tmp_path: Path, probe: str, *args: str, xdist: bool = False, outer: bool = True
) -> subprocess.CompletedProcess[str]:
    """Run pytest on *probe* with this conftest and the outer plugin loaded.

    Outside tests/, where the suite's own scanners read every file, and with
    nothing inherited that changes the run.
    """
    (tmp_path / "test_probe.py").write_text(probe, encoding="utf-8")
    (tmp_path / "outer_plugin.py").write_text(OUTER_PLUGIN, encoding="utf-8")
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    env = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith("PYTEST_")
    }
    env["PYTHONPATH"] = os.pathsep.join([str(TESTS.parent), str(tmp_path)])
    return subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "pytest",
            str(tmp_path / "test_probe.py"),
            "-p",
            "tests.conftest",
            *(["-p", "outer_plugin"] if outer else []),
            "-p",
            "no:cacheprovider",
            *(["-n", "2"] if xdist else ["-p", "no:xdist"]),
            "-p",
            "no:randomly",
            "-rA",
            *args,
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_a_refused_patch_fails_its_report_whatever_else_the_test_does(
    tmp_path: Path,
) -> None:
    junit = tmp_path / "report.xml"
    run = _run_probe(tmp_path, PROBE, f"--junitxml={junit}")
    outcomes = {
        (line.split("::")[1].split()[0], line.split()[0])
        for line in run.stdout.splitlines()
        if "::" in line
        and line.split()[0] in {"PASSED", "FAILED", "ERROR", "XFAIL", "XPASS"}
    }
    assert outcomes == {
        ("test_first_after_collection", "ERROR"),
        ("test_partial", "FAILED"),
        ("test_partial_under_xfail", "FAILED"),
        ("test_partial_under_strict_xfail", "FAILED"),
        ("test_partial_then_skip", "FAILED"),
        ("test_partial_and_a_failing_body", "FAILED"),
        ("test_partial_in_setup", "ERROR"),
        ("test_partial_in_teardown", "PASSED"),
        ("test_partial_in_teardown", "ERROR"),
        ("test_partial_and_a_setup_error", "ERROR"),
        ("test_patched_by_another_plugin", "PASSED"),
        ("test_patched_by_another_plugin", "ERROR"),
        ("test_clean", "PASSED"),
        ("test_clean_xfail", "XFAIL"),
    }, run.stdout + run.stderr
    assert AFTER_THE_LAST_TEST in run.stdout, run.stdout
    # Added beside the body's and the fixture's own failures.
    sections = [
        line
        for line in run.stdout.splitlines()
        if line.startswith("-") and " patch targets " in line
    ]
    assert len(sections) == 2, run.stdout
    recorded = {
        case.get("name"): [child.tag for child in case]
        for case in ET.parse(junit).getroot().iter("testcase")
    }
    # A failed report still marked xfail would be written as skipped.
    assert recorded["test_partial_under_xfail"] == ["failure"], recorded


@pytest.mark.parametrize("xdist", [False, True], ids=["serial", "xdist"])
def test_a_patch_after_the_last_test_fails_the_run(tmp_path: Path, xdist: bool) -> None:
    """No test's report is left to carry it, so the exit status does; an xdist
    worker's finding reaches the controller's."""
    run = _run_probe(tmp_path, "def test_passes():\n    pass\n", xdist=xdist)
    assert run.returncode == pytest.ExitCode.TESTS_FAILED, run.stdout + run.stderr
    assert "1 passed" in run.stdout
    assert AFTER_THE_LAST_TEST in run.stdout, run.stdout


def test_a_clean_run_under_xdist_passes(tmp_path: Path) -> None:
    run = _run_probe(
        tmp_path, "def test_passes():\n    pass\n", xdist=True, outer=False
    )
    assert run.returncode == pytest.ExitCode.OK, run.stdout + run.stderr
    assert "patch targets" not in run.stdout


def test_a_worker_that_stops_before_its_check_fails_the_run(tmp_path: Path) -> None:
    """A worker that never reports is not a clean one."""
    probe = (
        "import os\n\n"
        "import pytest\n\n\n"
        "@pytest.hookimpl(trylast=True)\n"
        "def pytest_sessionfinish(session):\n"
        "    if hasattr(session.config, 'workerinput'):\n"
        "        os._exit(0)\n"
    )
    (tmp_path / "conftest.py").write_text(probe, encoding="utf-8")
    run = _run_probe(tmp_path, "def test_passes():\n    pass\n", xdist=True)
    assert run.returncode == pytest.ExitCode.TESTS_FAILED, run.stdout + run.stderr
    assert "stopped before its check of the bindings finished" in run.stdout


def test_a_worker_stopped_after_it_finished_fails_the_run(tmp_path: Path) -> None:
    """A worker still in its last hooks when execnet's exit grace runs out is
    stopped after telling the controller it finished; that is no report."""
    probe = (
        "import time\n\n"
        "import pytest\n\n\n"
        "@pytest.hookimpl(wrapper=True, tryfirst=True)\n"
        "def pytest_sessionfinish(session):\n"
        "    result = yield\n"
        "    if hasattr(session.config, 'workerinput'):\n"
        "        time.sleep(15)\n"
        "    return result\n"
    )
    (tmp_path / "conftest.py").write_text(probe, encoding="utf-8")
    run = _run_probe(
        tmp_path, "def test_passes():\n    pass\n", xdist=True, outer=False
    )
    assert run.returncode == pytest.ExitCode.TESTS_FAILED, run.stdout + run.stderr
    assert "stopped before its check of the bindings finished" in run.stdout


def test_a_worker_stopped_while_writing_fails_the_run(tmp_path: Path) -> None:
    """A file cut off as it was written is not an empty, clean one."""
    probe = (
        "import pathlib\n"
        "import time\n\n\n"
        "def _stalled(self, data, *args, **kwargs):\n"
        "    open(self, 'w').close()\n"
        "    time.sleep(15)\n\n\n"
        "def pytest_configure(config):\n"
        "    if hasattr(config, 'workerinput'):\n"
        "        pathlib.Path.write_text = _stalled\n"
    )
    (tmp_path / "conftest.py").write_text(probe, encoding="utf-8")
    run = _run_probe(tmp_path, "def test_passes():\n    pass\n", xdist=True)
    assert run.returncode == pytest.ExitCode.TESTS_FAILED, run.stdout + run.stderr
    assert "stopped before its check of the bindings finished" in run.stdout


def test_an_interrupted_run_keeps_its_exit_status(tmp_path: Path) -> None:
    probe = (
        "import pytest\n\n\n"
        "def test_stops():\n"
        "    pytest.exit('stopped', returncode=pytest.ExitCode.INTERRUPTED)\n"
    )
    run = _run_probe(tmp_path, probe)
    assert run.returncode == pytest.ExitCode.INTERRUPTED, run.stdout + run.stderr
    assert AFTER_THE_LAST_TEST in run.stdout, run.stdout


def test_the_late_check_is_the_outermost_sessionfinish_wrapper(
    request: pytest.FixtureRequest,
) -> None:
    """Registered when the session starts, after the plugins pytest registers
    while it configures, its logging plugin's wrapper among them."""
    outermost = request.config.hook.pytest_sessionfinish.get_hookimpls()[-1]
    assert outermost.plugin_name == "ori-late-patch-check"
    assert outermost.tryfirst and outermost.wrapper


def test_the_reporter_is_the_outermost_makereport_wrapper(
    request: pytest.FixtureRequest,
) -> None:
    """Called first, so every other wrapper, ``xfail``'s and a rerun plugin's
    among them, has finished with the report before the refusal is set."""
    outermost = request.config.hook.pytest_runtest_makereport.get_hookimpls()[-1]
    source = Path(outermost.function.__code__.co_filename).resolve()
    assert source == TESTS / "conftest.py"
    assert outermost.tryfirst and outermost.wrapper
