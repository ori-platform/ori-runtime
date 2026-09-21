# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Which checks a change reaches, held as a test rather than a belief.

Every heavy step in CI is gated on a changed-paths decision so that a change
outside the runtime's blast radius does not spend the matrix. Each pattern is
a judgement about that radius, and the cost of a wrong one is a check that
silently skips what it should have run. These tests pin the wiring: the
decision precedes every gated step, no step is ungated by accident, the paths
that must reach a job do, the documents a test reads run the docs step, and
the decision's own shell logic behaves on a real repository.
"""

from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / ".github" / "workflows" / "ci.yml"
ACTION = ROOT / ".github" / "actions" / "changed-paths" / "action.yml"
SCOPE_ACTION = "./.github/actions/changed-paths"
GATE = "steps.scope.outputs.run"

#: Steps that run for every change, by job: the ones the gated steps need, and
#: the ones that are cheap and about the change itself rather than the code.
ALWAYS: dict[str, set[str]] = {
    "test": {
        "Harden runner",
        "Checkout",
        "Decide whether this change reaches the runtime's checks",
        "Decide whether this change touches a document",
        "Set up Python ${{ matrix.python-version }}",
        "Show pip version",
        "Install hash-locked dependencies",
        "Pre-commit (lint + format + hygiene)",
        "Guard Capability Matrix Updated",
    },
    "mobile-payload": {
        "Harden runner",
        "Checkout",
        "Decide whether this change reaches the payload",
    },
}
DOCS_STEP = "Run the tests that read documents"

#: One changed path, and every job whose checks it must reach.
SCENARIOS: list[tuple[str, set[str] | str]] = [
    ("ori/state/store.py", {"test"}),
    ("tests/test_store.py", {"test"}),
    ("skills/energy-anomaly-detector/skill.yaml", {"test"}),
    ("scripts/pyright_ratchet.py", {"test"}),
    ("packaging/systemd/ori-runtime.service.in", {"test"}),
    ("requirements/runtime.txt", {"test"}),
    ("requirements/dev.txt", {"test"}),
    ("pyproject.toml", {"test"}),
    ("pyright-baseline.json", {"test"}),
    (".pre-commit-config.yaml", {"test"}),
    (".python-version", {"test"}),
    ("ori.yaml.example", {"test"}),
    ("ori.yaml.phone.victron.example", {"test"}),
    # The payload's Rust tree, and the Python tests that read it.
    ("mobile/ori-runtime-mobile/src/lib.rs", {"test", "mobile-payload"}),
    # A workflow change reaches the supply-chain guard, which lives in the test job.
    (".github/workflows/release.yml", {"test"}),
    (".github/dependabot.yml", {"test"}),
    # A change to CI itself, or to the decision, reaches every job.
    (".github/workflows/ci.yml", "ALL"),
    (".github/actions/changed-paths/action.yml", "ALL"),
    # The local mirror of the workflow reaches every job, as the workflow does.
    ("scripts/ci_local.sh", "ALL"),
    # Documents reach the docs step and nothing else.
    ("docs/COMMISSIONING.md", set()),
    ("docs/releases/v2.5.0.md", set()),
    ("README.md", set()),
    ("CLAUDE.md", set()),
]

#: Top-level entries that reach no job and are not documents: nothing reads them.
OUTSIDE_EVERY_JOB = {".env.example", ".gitignore", "LICENSE"}

_DOCUMENT = re.compile(
    r"^(?:docs/[^\s]+|(?:AGENTS|CLAUDE|CONTRIBUTING|DECISIONS|PRINCIPLES|README|SECURITY)\.md)$"
)


def _workflow() -> dict:
    return yaml.safe_load(CI.read_text(encoding="utf-8"))


def _steps(job: str) -> list[dict]:
    return _workflow()["jobs"][job]["steps"]


def _pattern(job: str, step_id: str) -> str:
    for step in _steps(job):
        if step.get("id") == step_id:
            assert step.get("uses") == SCOPE_ACTION, (
                f"{job}: step {step_id} is not the decision"
            )
            return step["with"]["pattern"]
    raise AssertionError(f"{job}: no step with id {step_id}")


@pytest.mark.parametrize("job", sorted(ALWAYS))
def test_the_decision_precedes_every_gated_step_and_nothing_is_ungated(
    job: str,
) -> None:
    """A step added after the decision is gated, or it is declared as always-on."""
    steps = _steps(job)
    names = [step.get("name", "") for step in steps]
    decision = next(i for i, step in enumerate(steps) if step.get("id") == "scope")
    unknown_always = ALWAYS[job] - set(names)
    assert not unknown_always, (
        f"{job}: ALWAYS names steps that do not exist: {unknown_always}"
    )
    offenders: list[str] = []
    for i, step in enumerate(steps):
        name = step.get("name", "")
        if name in ALWAYS[job] or name == DOCS_STEP:
            continue
        condition = str(step.get("if", ""))
        if i < decision:
            offenders.append(f"{name!r} runs before the decision")
        elif f"{GATE} == 'true'" not in condition:
            offenders.append(f"{name!r} is not gated on {GATE}")
    assert not offenders, (
        f"{job}: {offenders}. Gate the step on the decision, or add it to ALWAYS with "
        "the reason it must run for every change."
    )


def test_the_docs_step_runs_only_when_documents_changed_and_nothing_else_did() -> None:
    step = next(s for s in _steps("test") if s.get("name") == DOCS_STEP)
    assert step["if"] == f"{GATE} != 'true' && steps.docs.outputs.run == 'true'"


def test_every_scenario_reaches_exactly_the_jobs_it_must() -> None:
    patterns = {job: _pattern(job, "scope") for job in ALWAYS}
    failures: list[str] = []
    for path, expected in SCENARIOS:
        want = set(patterns) if expected == "ALL" else set(expected)
        got = {job for job, pattern in patterns.items() if re.search(pattern, path)}
        for job in sorted(want - got):
            failures.append(
                f"{path!r} must reach {job!r} and its pattern does not match"
            )
        for job in sorted(got - want):
            failures.append(
                f"{path!r} reaches {job!r}, which the scenario does not expect"
            )
    assert not failures, failures


def test_every_top_level_entry_is_placed() -> None:
    """A new top-level tree reaches some job, or is a document, or is declared outside."""
    entries = subprocess.run(
        ["git", "ls-tree", "--name-only", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    assert entries, "git ls-tree returned nothing; the scan would pass vacuously"
    code = _pattern("test", "scope")
    docs = _pattern("test", "docs")
    unplaced = sorted(
        entry
        for entry in entries
        if not re.search(code, entry + "/")
        and not re.search(code, entry)
        and not re.search(docs, entry + "/")
        and not re.search(docs, entry)
        and entry not in OUTSIDE_EVERY_JOB
    )
    assert not unplaced, (
        f"top-level entries no decision places: {unplaced}. Add each to the test job's "
        "pattern, the docs pattern, or OUTSIDE_EVERY_JOB with the reason nothing reads it."
    )


def _tests_that_read_documents() -> set[str]:
    """Test modules holding a document path as a string the code uses, not as prose."""
    found: set[str] = set()
    for path in sorted((ROOT / "tests").rglob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        docstrings = {
            id(node.value)
            for node in ast.walk(tree)
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
        }
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and id(node) not in docstrings
                and _DOCUMENT.match(node.value)
            ):
                found.add(path.relative_to(ROOT).as_posix())
                break
    return found


def test_the_docs_step_runs_every_test_that_reads_a_document() -> None:
    step = next(s for s in _steps("test") if s.get("name") == DOCS_STEP)
    listed = set(re.findall(r"tests/[\w/]+\.py", step["run"]))
    reading = _tests_that_read_documents()
    assert reading, "no test reads a document; the derivation is broken"
    assert listed == reading, (
        f"the docs step lists {sorted(listed)} but the tests that hold a document path "
        f"are {sorted(reading)}. A test that reads a document must run when only "
        "documents change."
    )


# ─── The decision's own logic, on a real repository ─────────────────────────


def _decision_script() -> str:
    action = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
    (step,) = action["runs"]["steps"]
    return step["run"]


def _repo(tmp_path: Path) -> tuple[Path, str, str]:
    """A repository with two commits: docs and code, then docs only."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-C", str(repo)]
    subprocess.run(git + ["init", "-q", "-b", "main"], check=True)
    (repo / "docs").mkdir()
    (repo / "docs" / "a.md").write_text("one\n")
    (repo / "ori").mkdir()
    (repo / "ori" / "x.py").write_text("x = 1\n")
    subprocess.run(git + ["add", "."], check=True)
    subprocess.run(git + ["commit", "-q", "-m", "base"], check=True)
    base = subprocess.run(
        git + ["rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    (repo / "docs" / "a.md").write_text("two\n")
    subprocess.run(git + ["commit", "-q", "-am", "docs"], check=True)
    head = subprocess.run(
        git + ["rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    # The action fetches the base from `origin`; here the repository is its own origin.
    subprocess.run(git + ["remote", "add", "origin", str(repo)], check=True)
    return repo, base, head


def _decide(repo: Path, tmp_path: Path, **env: str) -> tuple[str, str]:
    out = tmp_path / "output"
    out.write_text("")
    proc = subprocess.run(
        ["bash", "-c", _decision_script()],
        cwd=repo,
        env={**os.environ, "GITHUB_OUTPUT": str(out), "REASON": "testing", **env},
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    value = dict(line.split("=", 1) for line in out.read_text().splitlines())["run"]
    return value, proc.stdout


@pytest.mark.skipif(sys.platform == "win32", reason="the decision runs under bash")
def test_the_decision_skips_a_job_whose_paths_did_not_change(tmp_path: Path) -> None:
    repo, base, _ = _repo(tmp_path)
    run, log = _decide(
        repo, tmp_path, EVENT_NAME="pull_request", PR_BASE_SHA=base, PATTERN="^ori/"
    )
    assert run == "false", log
    run, log = _decide(
        repo, tmp_path, EVENT_NAME="pull_request", PR_BASE_SHA=base, PATTERN="^docs/"
    )
    assert run == "true", log
    run, log = _decide(
        repo, tmp_path, EVENT_NAME="push", PUSH_BEFORE_SHA=base, PATTERN="^ori/"
    )
    assert run == "false", log


@pytest.mark.skipif(sys.platform == "win32", reason="the decision runs under bash")
@pytest.mark.parametrize(
    "env",
    [
        {"EVENT_NAME": "workflow_dispatch"},
        {"EVENT_NAME": "push", "PUSH_BEFORE_SHA": "0" * 40},
        {"EVENT_NAME": "pull_request", "PR_BASE_SHA": "f" * 40},
    ],
    ids=["no-base-event", "first-push", "unreachable-base"],
)
def test_the_decision_fails_open_without_a_usable_base(
    tmp_path: Path, env: dict[str, str]
) -> None:
    repo, _, _ = _repo(tmp_path)
    run, log = _decide(repo, tmp_path, PATTERN="^ori/", **env)
    assert run == "true", log
