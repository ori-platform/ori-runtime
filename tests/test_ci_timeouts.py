# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Every CI job and every package-manager step is bounded in time.

A job without ``timeout-minutes`` inherits GitHub's six-hour default, so one
hung mirror holds a runner and a pull request's checks for hours. These tests
read the workflows as YAML; a step reached through a reusable workflow or a
composite action is outside what they see.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
#: The longest any job may be bounded at.
MAX_JOB_MINUTES = 60
#: The longest a package-manager step may be bounded at.
MAX_INSTALL_MINUTES = 10
APT_OPTIONS = ("Acquire::Retries=", "Acquire::http::Timeout=")


def _jobs() -> list[tuple[str, str, dict[str, Any]]]:
    out = []
    for path in WORKFLOWS:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        for name, job in (doc.get("jobs") or {}).items():
            out.append((path.name, name, job))
    return out


JOBS = _jobs()


def test_there_are_workflows_to_check() -> None:
    assert JOBS, "no workflow jobs found; the guard would pass vacuously"


@pytest.mark.parametrize(
    ("workflow", "name", "job"), JOBS, ids=[f"{w}:{n}" for w, n, _ in JOBS]
)
def test_every_job_is_bounded(workflow: str, name: str, job: dict[str, Any]) -> None:
    if "uses" in job:
        pytest.skip("a reusable workflow call carries its own jobs' bounds")
    minutes = job.get("timeout-minutes")
    assert isinstance(minutes, int) and 0 < minutes <= MAX_JOB_MINUTES, (
        f"{workflow}:{name} must set timeout-minutes to an integer in "
        f"1..{MAX_JOB_MINUTES}; without it a hung step holds the runner for six "
        f"hours. Found {minutes!r}. This guard reads YAML only: an expression "
        "or a value set through a composite action is not seen."
    )


@pytest.mark.parametrize(
    ("workflow", "name", "job"), JOBS, ids=[f"{w}:{n}" for w, n, _ in JOBS]
)
def test_every_apt_step_is_bounded_and_retries(
    workflow: str, name: str, job: dict[str, Any]
) -> None:
    for step in job.get("steps") or []:
        script = step.get("run") or ""
        if "apt-get" not in script and "apt " not in script:
            continue
        label = f"{workflow}:{name}:{step.get('name', '<unnamed>')}"
        minutes = step.get("timeout-minutes")
        assert isinstance(minutes, int) and 0 < minutes <= MAX_INSTALL_MINUTES, (
            f"{label} runs apt and must set its own timeout-minutes in "
            f"1..{MAX_INSTALL_MINUTES}, so a hung mirror fails fast. Found {minutes!r}."
        )
        for line in script.replace("\\\n", " ").splitlines():
            if "apt-get" in line:
                missing = [o for o in APT_OPTIONS if o not in line]
                assert not missing, (
                    f"{label}: apt-get without {missing}: {line.strip()}"
                )
