# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The patch guard's refusal reaches the test report, through real pytest.

The guard's own tests call it directly; these run pytest on a generated file
under this conftest, so the report a refused patch produces is what is read,
``xfail`` and skips included.
"""

from __future__ import annotations

import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent

PROBE = """
from unittest import mock

import pytest


def _f(*args, **kwargs):
    return None


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


def test_clean():
    pass


@pytest.mark.xfail
def test_clean_xfail():
    assert False
"""


def test_a_refused_patch_fails_its_report_whatever_else_the_test_does(
    tmp_path: Path,
) -> None:
    # Under tests/, so this conftest is the one pytest loads; the name keeps
    # the suite's own collection from picking it up.
    probe = TESTS / f"_patch_guard_probe_{uuid.uuid4().hex}.py"
    junit = tmp_path / "report.xml"
    probe.write_text(PROBE, encoding="utf-8")
    try:
        run = subprocess.run(
            [
                sys.executable,
                "-B",
                "-m",
                "pytest",
                str(probe),
                "-p",
                "no:cacheprovider",
                "-p",
                "no:xdist",
                "-p",
                "no:randomly",
                "-rA",
                f"--junitxml={junit}",
            ],
            cwd=TESTS.parent,
            capture_output=True,
            text=True,
            timeout=120,
        )
    finally:
        probe.unlink()
    outcomes = {
        line.split("::")[1].split()[0]: line.split()[0]
        for line in run.stdout.splitlines()
        if "::" in line and line.split()[0] in {"PASSED", "FAILED", "XFAIL", "XPASS"}
    }
    assert outcomes == {
        "test_partial": "FAILED",
        "test_partial_under_xfail": "FAILED",
        "test_partial_under_strict_xfail": "FAILED",
        "test_partial_then_skip": "FAILED",
        "test_partial_and_a_failing_body": "FAILED",
        "test_clean": "PASSED",
        "test_clean_xfail": "XFAIL",
    }, run.stdout + run.stderr
    assert "patch targets" in run.stdout  # added beside the body's own failure
    recorded = {
        case.get("name"): [child.tag for child in case]
        for case in ET.parse(junit).getroot().iter("testcase")
    }
    # A failed report still marked xfail would be written as skipped.
    assert recorded["test_partial_under_xfail"] == ["failure"], recorded


def test_the_reporter_is_the_outermost_makereport_wrapper(
    request: pytest.FixtureRequest,
) -> None:
    """Called first, so every other wrapper, ``xfail``'s and a rerun plugin's
    among them, has finished with the report before the refusal is set."""
    outermost = request.config.hook.pytest_runtest_makereport.get_hookimpls()[-1]
    assert outermost.function.__code__.co_filename == str(TESTS / "conftest.py")
    assert outermost.tryfirst and outermost.wrapper
