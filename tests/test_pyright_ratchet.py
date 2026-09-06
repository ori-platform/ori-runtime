# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The ratchet that holds the pyright count against a committed baseline.

Driven as a module rather than by running pyright: a test that shelled out to
the checker would take minutes and would fail whenever the tree's real count
moved, which is the thing the baseline exists to absorb.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from scripts import pyright_ratchet

REPO_ROOT = Path(__file__).resolve().parents[1]
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"
BASELINE = REPO_ROOT / "pyright-baseline.json"


def _diagnostic(
    severity: str = "error",
    rule: str = "reportArgumentType",
    path: str = "tests/x.py",
) -> dict:
    return {
        "file": str(REPO_ROOT / path),
        "severity": severity,
        "rule": rule,
        "message": "something",
        "range": {"start": {"line": 0}},
    }


def _report(diagnostics: list[dict]) -> dict:
    return {
        "generalDiagnostics": diagnostics,
        "summary": {
            "errorCount": len([d for d in diagnostics if d["severity"] == "error"])
        },
    }


def _fixed(monkeypatch: pytest.MonkeyPatch, diagnostics: list[dict]) -> None:
    monkeypatch.setattr(pyright_ratchet, "run_pyright", lambda: _report(diagnostics))


def _running_steps() -> list[dict]:
    """Every step of the test job that CI actually runs.

    Parsed rather than grepped: a step commented out, deleted, or disabled with
    `if: false` still leaves its text in the file, so a substring assertion
    passes over a workflow that enforces nothing.
    """
    workflow = yaml.safe_load(CI.read_text())
    steps = []
    for job in workflow["jobs"].values():
        for step in job.get("steps") or []:
            condition = str(step.get("if", "")).strip().lower()
            if condition in {"false", "${{ false }}"}:
                continue
            steps.append(step)
    return steps


def _run_lines() -> list[str]:
    return [str(step.get("run", "")).strip() for step in _running_steps()]


# --------------------------------------------------------------------------
# Counting
# --------------------------------------------------------------------------


def test_only_errors_are_counted() -> None:
    """A warning is not a diagnostic this holds, so it cannot consume headroom."""
    report = {
        "generalDiagnostics": [
            _diagnostic("error"),
            _diagnostic("warning"),
            _diagnostic("information"),
        ]
    }
    assert len(pyright_ratchet.error_diagnostics(report)) == 1


def test_the_committed_baseline_records_a_total_and_a_breakdown() -> None:
    baseline = json.loads(BASELINE.read_text())
    assert isinstance(baseline["total"], int) and baseline["total"] >= 0
    assert baseline["by_area"]
    assert sum(baseline["by_area"].values()) == baseline["total"]
    assert baseline["note"].strip()


def test_the_committed_baseline_is_free_of_gated_trees() -> None:
    """`ori/` and `scripts/` are gated at zero, so neither may appear here.

    A diagnostic recorded under a gated tree would mean the baseline had
    absorbed something the zero gate is supposed to refuse.
    """
    baseline = json.loads(BASELINE.read_text())
    for area in baseline["by_area"]:
        assert not area.startswith("ori"), area
        assert not area.startswith("scripts"), area


@pytest.mark.parametrize(
    "total,recorded,expected",
    [(478, 478, 0), (479, 478, 1), (477, 478, 1)],
)
def test_the_ratchet_is_strict_in_both_directions(
    monkeypatch: pytest.MonkeyPatch, total: int, recorded: int, expected: int
) -> None:
    """Unspent headroom is a rise someone else gets for free later."""
    _fixed(monkeypatch, [_diagnostic() for _ in range(total)])
    monkeypatch.setattr(
        pyright_ratchet, "read_baseline", lambda: {"total": recorded, "by_area": {}}
    )
    assert pyright_ratchet.main([]) == expected


@pytest.mark.parametrize("summary", [None, {}, {"warningCount": 0}, "not a dict"])
def test_a_report_without_an_error_summary_is_refused(
    monkeypatch: pytest.MonkeyPatch, summary
) -> None:
    """A count whose meaning is not established is not compared to anything."""
    monkeypatch.setattr(
        pyright_ratchet,
        "run_pyright",
        lambda: {"generalDiagnostics": [_diagnostic()], "summary": summary},
    )
    monkeypatch.setattr(pyright_ratchet, "read_baseline", lambda: {"total": 1})
    assert pyright_ratchet.main([]) == 2


def test_a_summary_disagreeing_with_the_diagnostics_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        pyright_ratchet,
        "run_pyright",
        lambda: {"generalDiagnostics": [_diagnostic()], "summary": {"errorCount": 400}},
    )
    monkeypatch.setattr(pyright_ratchet, "read_baseline", lambda: {"total": 400})
    assert pyright_ratchet.main([]) == 2


# --------------------------------------------------------------------------
# The failure has to say where to look
# --------------------------------------------------------------------------


def test_a_rise_names_the_area_that_moved(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The area that changed, not the distribution of everything.

    A small rise leaves the overall breakdown almost identical, so printing it
    whole tells an author nothing about the diagnostics they just added.
    """
    diagnostics = [_diagnostic(path="tests/x.py") for _ in range(334)]
    diagnostics += [_diagnostic(path="tests/firmware/y.py") for _ in range(88)]
    _fixed(monkeypatch, diagnostics)
    monkeypatch.setattr(
        pyright_ratchet,
        "read_baseline",
        lambda: {"total": 420, "by_area": {"tests": 334, "tests/firmware": 86}},
    )

    assert pyright_ratchet.main([]) == 1

    err = capsys.readouterr().err
    assert "422" in err and "420" in err and "+2" in err
    assert "--list" in err
    # Only the area that moved, named with both counts.
    assert "86 -> 88" in err and "tests/firmware" in err
    assert "tests\n" not in err.replace("tests/firmware", "")


def test_a_fall_says_to_lower_the_baseline_rather_than_to_look_for_diagnostics(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _fixed(monkeypatch, [_diagnostic() for _ in range(470)])
    monkeypatch.setattr(
        pyright_ratchet,
        "read_baseline",
        lambda: {"total": 478, "by_area": {"tests": 478}},
    )

    assert pyright_ratchet.main([]) == 1

    err = capsys.readouterr().err
    assert "-8" in err
    assert "--update" in err
    assert "--list" not in err


# --------------------------------------------------------------------------
# --update is the only mutating path
# --------------------------------------------------------------------------


def test_update_refuses_to_raise_the_baseline(
    monkeypatch: pytest.MonkeyPatch, tmp_path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The remediation a failure prints must not be a way to bank a rise.

    A fall is a hard failure whose printed fix is `--update`. An author whose
    branch removed some diagnostics and added others would otherwise run what
    they were told to run and record the net rise without seeing it.
    """
    target = tmp_path / "baseline.json"
    target.write_text(json.dumps({"total": 478, "by_area": {"tests": 478}}))
    monkeypatch.setattr(pyright_ratchet, "BASELINE_PATH", target)
    _fixed(monkeypatch, [_diagnostic() for _ in range(600)])

    assert pyright_ratchet.main(["--update"]) == 1
    assert json.loads(target.read_text())["total"] == 478
    assert "refusing to raise" in capsys.readouterr().err


def test_update_records_a_rise_only_when_asked_deliberately(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    target = tmp_path / "baseline.json"
    target.write_text(json.dumps({"total": 478, "by_area": {"tests": 478}}))
    monkeypatch.setattr(pyright_ratchet, "BASELINE_PATH", target)
    _fixed(monkeypatch, [_diagnostic() for _ in range(600)])

    assert pyright_ratchet.main(["--update", "--allow-raise"]) == 0
    assert json.loads(target.read_text())["total"] == 600


def test_update_lowers_without_ceremony(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """Lowering is the direction that needs no permission."""
    target = tmp_path / "baseline.json"
    target.write_text(json.dumps({"total": 478, "by_area": {"tests": 478}}))
    monkeypatch.setattr(pyright_ratchet, "BASELINE_PATH", target)
    _fixed(monkeypatch, [_diagnostic() for _ in range(400)])

    assert pyright_ratchet.main(["--update"]) == 0
    recorded = json.loads(target.read_text())
    assert recorded["total"] == 400
    assert recorded["by_area"] == {"tests": 400}


def test_a_missing_baseline_is_an_error_rather_than_an_empty_one(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """Treating absence as zero would fail every run; as infinity, none."""
    monkeypatch.setattr(pyright_ratchet, "BASELINE_PATH", tmp_path / "absent.json")
    _fixed(monkeypatch, [_diagnostic()])
    with pytest.raises(SystemExit) as raised:
        pyright_ratchet.main([])
    assert raised.value.code == 2


def test_list_prints_every_diagnostic_and_changes_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "baseline.json"
    target.write_text(json.dumps({"total": 1, "by_area": {"tests": 1}}))
    monkeypatch.setattr(pyright_ratchet, "BASELINE_PATH", target)
    _fixed(monkeypatch, [_diagnostic(), _diagnostic(path="tests/firmware/y.py")])

    assert pyright_ratchet.main(["--list"]) == 0

    out = capsys.readouterr().out
    assert "tests/x.py:1" in out and "tests/firmware/y.py:1" in out
    assert "reportArgumentType" in out
    assert json.loads(target.read_text())["total"] == 1


# --------------------------------------------------------------------------
# What CI enforces, read from the workflow rather than from its text
# --------------------------------------------------------------------------


def test_ci_runs_the_ratchet() -> None:
    assert "python scripts/pyright_ratchet.py" in _run_lines()


def test_ci_gates_every_tree_the_ratchet_counts_at_zero() -> None:
    """A rise in a gated tree must not be absorbable by a fall in the test tree.

    The ratchet holds one total across `ori`, `tests` and `scripts`, so on its
    own it would let one tree pay for another. The zero gate has to cover every
    counted tree except the one the baseline exists for, or the absorption it
    forbids simply moves to whichever tree the gate missed.
    """
    import tomllib

    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_bytes().decode())
    counted = set(pyproject["tool"]["pyright"]["include"])

    gate = next((line for line in _run_lines() if line.startswith("pyright ")), None)
    assert gate is not None, "no pyright zero gate runs in CI"
    gated = set(gate.removeprefix("pyright ").split())

    assert counted - {tree.rstrip("/") for tree in gated} == {"tests"}


def test_ci_gates_the_test_tree_with_mypy_rather_than_a_ratchet() -> None:
    """The explicit decision #532 asks for, asserted where it is enforced.

    mypy is already clean over both trees, so it takes a gate at zero instead
    of a baseline. A ratchet exists to hold a number that cannot yet be zero;
    using one where zero is achievable would license a first regression.
    """
    runs = _run_lines()
    assert "python -m mypy ori/" in runs
    assert "python -m mypy tests/" in runs
    assert not any("mypy" in line and "ratchet" in line for line in runs)


def test_the_analysis_environment_is_pinned() -> None:
    """The count is a property of the environment as much as of the code.

    Unpinned, the same tree reports a different number on macOS and Linux, and
    no single committed value is correct on both: one platform reads a fall and
    the other a rise, forever.
    """
    import tomllib

    pyright = tomllib.loads((REPO_ROOT / "pyproject.toml").read_bytes().decode())[
        "tool"
    ]["pyright"]

    assert pyright["pythonPlatform"] == "Linux"
    assert pyright["pythonVersion"]
