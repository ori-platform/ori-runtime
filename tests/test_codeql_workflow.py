# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""CodeQL scans every pull request to main, a fork's included."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "codeql.yml"
LANGUAGES = {"actions", "python", "rust"}
LIMIT = (
    "This checks the workflow file only. Whether code scanning accepts its "
    "results also depends on default setup being disabled in the repository "
    "settings, which no test can see."
)


def _workflow() -> dict[Any, Any]:
    loaded = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def test_codeql_runs_on_pull_requests_to_main_and_pushes() -> None:
    # PyYAML reads the bare key `on` as the boolean True.
    triggers = _workflow()[True]
    assert triggers["pull_request"]["branches"] == ["main"], (
        "CodeQL must run on pull requests to main; default setup skips forks. " + LIMIT
    )
    assert triggers["push"]["branches"] == ["main"], LIMIT
    assert triggers.get("schedule"), LIMIT


def test_codeql_does_not_skip_forks_or_languages() -> None:
    jobs = _workflow()["jobs"]
    languages: set[str] = set()
    for name, job in jobs.items():
        condition = str(job.get("if", ""))
        assert "fork" not in condition and "head.repo" not in condition, (
            f"job {name} is conditioned on the pull request's origin. " + LIMIT
        )
        languages |= set(job.get("strategy", {}).get("matrix", {}).get("language", []))
        for step in job.get("steps", []):
            assert "fork" not in str(step.get("if", "")), (
                f"a step of {name} is conditioned on a fork. " + LIMIT
            )
    assert languages == LANGUAGES, (
        f"CodeQL analyses {sorted(languages)}, expected {sorted(LANGUAGES)}. " + LIMIT
    )
