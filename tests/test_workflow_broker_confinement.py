# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Every workflow job that installs Mosquitto lets it read pytest's configs.

Ubuntu confines Mosquitto with AppArmor, and the tests start brokers whose
configs pytest writes under `/tmp/pytest-of-*`. A job that installs the broker
without the local rule fails every broker test, as the load proof did.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
RULE = "owner /tmp/pytest-of-*/**/mosquitto*.conf r,"
INSTALLS = re.compile(r"install\b[^\n]*\bmosquitto\b|dpkg -i [^\n]*broker-debs")


def _jobs_installing_the_broker(workflow: dict[str, Any]) -> list[tuple[str, list]]:
    found = []
    for name, job in (workflow.get("jobs") or {}).items():
        steps = job.get("steps") or []
        if any(INSTALLS.search(str(step.get("run", ""))) for step in steps):
            found.append((name, steps))
    return found


@pytest.mark.parametrize("path", sorted(WORKFLOWS.glob("*.yml")), ids=lambda p: p.name)
def test_a_job_that_installs_mosquitto_lets_it_read_pytest_configs(path: Path) -> None:
    workflow = yaml.safe_load(path.read_text())
    for name, steps in _jobs_installing_the_broker(workflow):
        runs = [str(step.get("run", "")) for step in steps]
        first = next(i for i, run in enumerate(runs) if INSTALLS.search(run))
        assert any(RULE in run for run in runs[first:]), (
            f"{path.name} job {name!r} installs Mosquitto without the AppArmor rule"
        )


def test_the_check_sees_the_workflows_that_install_the_broker() -> None:
    installing = {
        path.name
        for path in WORKFLOWS.glob("*.yml")
        if _jobs_installing_the_broker(yaml.safe_load(path.read_text()))
    }
    assert {"ci.yml", "load-proof.yml"} <= installing
