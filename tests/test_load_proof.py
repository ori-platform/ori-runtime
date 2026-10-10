# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The load-proof workflow runs what it claims, and its report counts nothing short."""

from __future__ import annotations

import importlib.util
import shlex
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "load-proof.yml"
CI = ROOT / ".github" / "workflows" / "ci.yml"


def _report() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "load_proof_report", ROOT / "scripts" / "load_proof_report.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())


def _steps() -> dict[str, dict]:
    return {step["name"]: step for step in _workflow()["jobs"]["load-proof"]["steps"]}


def test_it_runs_only_by_hand_and_reads_only():
    workflow = _workflow()
    # PyYAML reads the bare key `on` as True.
    triggers = workflow.get("on", workflow.get(True))
    assert triggers is not None
    assert set(triggers) == {"workflow_dispatch"}
    assert workflow["permissions"] == {"contents": "read", "id-token": "none"}
    assert workflow["jobs"]["load-proof"]["timeout-minutes"] < 360


def test_the_burners_are_stopped_and_the_evidence_kept_whatever_happens():
    steps = _steps()
    for name in (
        "Stop the burners and the sampler",
        "Report what each run held",
        "Upload the evidence",
    ):
        assert steps[name].get("if") == "always()", name


def test_the_budgets_are_ci_s_own_step_and_it_exists():
    argv = _report().budgets_argv(str(CI))
    assert argv[0] == "pytest"
    assert any(arg.startswith("tests/") for arg in argv)


def test_nothing_skips_the_phone_tests_and_nothing_retries():
    text = WORKFLOW.read_text()
    assert "ORI_SKIP_PHONE_E2E" not in text
    assert "--reruns" not in text
    run = _steps()["Run the full suite under load"]["run"]
    assert "pytest tests/ " in run
    assert "timeout " in run


def test_every_scheduler_delay_target_exists():
    run = _steps()["Run the scheduler-delay regressions, unloaded"]["run"]
    targets = [
        t.strip('"') for t in shlex.split(run) if t.strip('"').startswith("tests/")
    ]
    assert targets
    for target in targets:
        path, _, node = target.partition("::")
        source = (ROOT / path).read_text()
        assert node.split("::")[0] in source, target


def test_the_unloaded_passes_run_before_any_burner_starts():
    names = list(_steps())
    burners = names.index("Start the burners and the load sampler")
    assert names.index("Run the latency budgets alone, unloaded") < burners
    assert names.index("Run the scheduler-delay regressions, unloaded") < burners
    assert names.index("Run the full suite under load") > burners


def _junit(
    path: Path,
    passed: list[str],
    skipped: Sequence[str] = (),
    failed: Sequence[str] = (),
) -> None:
    root = ET.Element("testsuites")
    suite = ET.SubElement(root, "testsuite")
    for case_id, outcome in (
        [(c, None) for c in passed]
        + [(c, "skipped") for c in skipped]
        + [(c, "failure") for c in failed]
    ):
        classname, _, name = case_id.partition("::")
        case = ET.SubElement(suite, "testcase", classname=classname, name=name)
        if outcome:
            ET.SubElement(case, outcome)
    ET.ElementTree(root).write(path)


SHA = "a" * 40
PHONE = "tests.test_runtime_mobile_delivery_e2e::test_delivers"
HELD = (
    "tests.test_runtime_mobile_delivery_e2e::"
    "test_faults_land_at_their_polls_however_slowly_the_output_is_read"
)


def _nodeid(case: str) -> str:
    module, _, name = case.partition("::")
    return module.replace(".", "/") + ".py::" + name


def _inventory(path: Path, cases: list[str]) -> None:
    path.write_text(
        "".join(_nodeid(c) + "\n" for c in cases) + f"\n{len(cases)} tests collected\n"
    )


def _proof(
    tmp_path: Path,
    *,
    runs: int = 5,
    finished: int | None = None,
    load: float = 26.0,
    tail_load: float | None = None,
    sample_every: int = 5,
    run_status: int = 0,
    phone_skipped_from: int | None = None,
    budgets: str = "passed",
    held_reader: bool = True,
    held_reader_module: str = "tests.test_runtime_mobile_delivery_e2e",
    phone_module: str = "tests.test_runtime_mobile_delivery_e2e",
    last_samples_s: int = 600,
    junit_failure_in: int | None = None,
    missing_case_in: int | None = None,
    bad_sample: str | None = None,
    duplicate_samples: bool = False,
    commit: str | None = SHA,
    stress_lines: tuple[str, ...] = (
        "cores=4",
        "pytest_workers=4",
        "stress-ng --cpu 22 --hdd 1 --hdd-bytes 256m --timeout 320m",
    ),
    inventories: bool = True,
    stall_failure: bool = False,
    clustered: bool = False,
) -> Path:
    proof = tmp_path / "proof"
    proof.mkdir()
    if commit is not None:
        (proof / "commit.txt").write_text(commit + " subject\n")
    (proof / "stress.txt").write_text("\n".join(stress_lines) + "\n")
    if budgets == "passed":
        _junit(proof / "budgets.xml", ["tests.c::b1"])
    elif budgets == "skipped":
        _junit(proof / "budgets.xml", [], skipped=["tests.c::b1"])
    held = held_reader_module + "::" + HELD.split("::")[1]
    stall_cases = ["tests.d::s1"] + ([held] if held_reader else [])
    _junit(
        proof / "stall.xml",
        stall_cases[1:] if stall_failure else stall_cases,
        failed=["tests.d::s1"] if stall_failure else [],
    )
    phone = phone_module + "::test_delivers"
    suite = ["tests.a::t1", "tests.a::t2", phone]
    if inventories:
        _inventory(proof / "inventory-budgets.txt", ["tests.c::b1"])
        _inventory(proof / "inventory-stall.txt", ["tests.d::s1", HELD])
        _inventory(proof / "inventory-suite.txt", suite)
    lines, samples = [], []
    for i in range(1, runs + 1):
        start = 10_000 * i
        lines.append(f"{start} start {i}")
        if finished is None or i <= finished:
            lines.append(f"{start + 600} end {i} {run_status if i == runs else 0}")
        offsets = (
            [b + k for b in range(0, last_samples_s + 1, 30) for k in range(5)]
            if clustered
            else range(0, last_samples_s + 1, sample_every)
        )
        for t in offsets:
            value = tail_load if tail_load is not None and t > 480 else load
            text = (
                bad_sample
                if bad_sample is not None and i == 2 and t == 300
                else f"{value:.2f}"
            )
            samples.append(f"{start + t} {text} 0 0")
            if duplicate_samples:
                samples.append(f"{start + t} {text} 0 0")
        skip_phone = phone_skipped_from is not None and i >= phone_skipped_from
        passed = ["tests.a::t1", "tests.a::t2"] + ([] if skip_phone else [phone])
        if missing_case_in == i:
            passed.remove("tests.a::t2")
        failed = []
        if junit_failure_in == i:
            passed.remove("tests.a::t1")
            failed = ["tests.a::t1"]
        _junit(
            proof / f"run-{i}.xml",
            passed,
            skipped=[phone] if skip_phone else [],
            failed=failed,
        )
    (proof / "runs.txt").write_text("\n".join(lines) + "\n")
    (proof / "loadavg.txt").write_text("\n".join(samples) + "\n")
    return proof


def _judge(
    proof: Path,
    floor: str = "5.0",
    target: str = "6.5",
    runs: str = "5",
    sha: str = SHA,
) -> int:
    return _report().main(["", str(proof), floor, target, runs, sha])


def test_a_proof_that_held_its_load_and_passed_counts(tmp_path, capsys):
    assert _judge(_proof(tmp_path)) == 0
    out = capsys.readouterr().out
    assert "**Counts.**" in out
    assert "Target 6.5 load per core; floor 5.0" in out


@pytest.mark.parametrize(
    ("proof_kwargs", "judge_kwargs", "problem"),
    [
        ({"run_status": 1}, {}, "run 5 did not pass"),
        ({"load": 12.0}, {}, "held less than 5.0 load per core"),
        ({"runs": 1}, {"runs": "1"}, "1 runs asked for, fewer than 5"),
        ({"runs": 3}, {}, "3 of 5 runs finished"),
        ({"finished": 4}, {}, "4 of 5 runs finished"),
        ({"phone_skipped_from": 2}, {}, "run 2 did not pass every phone delivery case"),
        (
            {"phone_skipped_from": 2},
            {},
            "ran different tests, or to different outcomes",
        ),
        (
            {"budgets": "missing"},
            {},
            "Latency budgets, unloaded: no readable JUnit result",
        ),
        ({"budgets": "skipped"}, {}, "Latency budgets, unloaded: nothing passed"),
        (
            {"held_reader": False},
            {},
            "Scheduler delay, unloaded: " + HELD + " did not pass",
        ),
        ({}, {"floor": "0"}, "floor 0.0 is outside 1.0..6.5"),
        ({}, {"floor": "7"}, "floor 7.0 is outside 1.0..6.5"),
        ({}, {"floor": "nan"}, "floor nan is outside 1.0..6.5"),
        ({"sample_every": 120}, {}, "slots"),
        ({"clustered": True}, {}, "slots"),
        ({"tail_load": 0.4}, {}, "held less than 5.0 load per core"),
        ({"runs": 0}, {}, "0 of 5 runs finished"),
        ({"last_samples_s": 480}, {}, "gap in its load samples over 30 s"),
        (
            {"held_reader_module": "tests.test_load_proof"},
            {},
            "Scheduler delay, unloaded: tests.test_runtime_mobile_delivery_e2e::",
        ),
        (
            {"phone_module": "tests.test_runtime_mobile_delivery_e2e_extra"},
            {},
            "the suite's inventory holds no phone delivery case",
        ),
        ({"junit_failure_in": 3}, {}, "run 3: 1 failed"),
        ({"missing_case_in": 4}, {}, "run 4: 1 collected tests did not run"),
        ({"stall_failure": True}, {}, "Scheduler delay, unloaded: 1 failed"),
        ({"bad_sample": "nan"}, {}, "is not a finite, non-negative load"),
        ({"bad_sample": "inf"}, {}, "is not a finite, non-negative load"),
        ({"bad_sample": "-1"}, {}, "is not a finite, non-negative load"),
        ({"bad_sample": "x"}, {}, "is malformed"),
        (
            {"duplicate_samples": True, "sample_every": 30},
            {},
            "does not advance in time",
        ),
        ({"commit": None}, {}, "the recorded commit is not " + SHA),
        ({}, {"sha": "b" * 40}, "the recorded commit is not " + "b" * 40),
        (
            {"stress_lines": ("cores=4", "stress-ng --cpu 22 --timeout 320m")},
            {},
            "the pytest worker count was not recorded",
        ),
        (
            {"stress_lines": ("pytest_workers=4", "stress-ng --cpu 22 --timeout 320m")},
            {},
            "the CPU count was not recorded",
        ),
        (
            {
                "stress_lines": (
                    "cores=0",
                    "pytest_workers=4",
                    "stress-ng --cpu 1 --timeout 1m",
                )
            },
            {},
            "the CPU count was not recorded",
        ),
        (
            {"stress_lines": ("cores=4", "pytest_workers=4")},
            {},
            "the stress command was not recorded",
        ),
        ({"inventories": False}, {}, "no collected inventory"),
    ],
)
def test_a_proof_short_of_anything_does_not_count(
    tmp_path, capsys, proof_kwargs, judge_kwargs, problem
):
    assert _judge(_proof(tmp_path, **proof_kwargs), **judge_kwargs) == 1
    out = capsys.readouterr().out
    assert "**Does not count:**" in out
    assert problem in out


@pytest.mark.parametrize(
    ("nodeid", "expected"),
    [
        ("tests/test_x.py::test_y", "tests.test_x::test_y"),
        ("tests/sub/test_x.py::TestA::test_y", "tests.sub.test_x.TestA::test_y"),
        ("tests/test_x.py::test_y[a::b-c]", "tests.test_x::test_y[a::b-c]"),
    ],
)
def test_a_collected_node_id_maps_to_its_junit_id(nodeid, expected):
    assert _report().junit_id(nodeid) == expected


def test_inputs_refuse_fewer_than_five_runs_and_a_floor_off_its_range():
    run = _steps()["Validate inputs"]["run"]
    assert "^([5-9]|[1-9][0-9])$" in run
    assert "1.0 <= f <= t <= 20.0" in run
    assert "os.environ" in run


def test_one_failed_unloaded_pass_does_not_cost_the_loaded_runs():
    steps = _steps()
    for name in (
        "Start the burners and the load sampler",
        "Run the full suite under load",
    ):
        assert steps[name].get("if") == (
            "${{ !cancelled() && steps.validate.outcome == 'success' "
            "&& steps.confirm.outcome == 'success' }}"
        ), name
    for step in steps.values():
        for line in step.get("run", "").splitlines():
            if "python" in line:
                assert "${TARGET}" not in line and "$TARGET" not in line, line
                assert "${FLOOR}" not in line and "$FLOOR" not in line, line
    run = steps["Run the full suite under load"]["run"]
    assert "-n auto" not in run
    assert "upload" not in run
    assert "run_attempt" in steps["Upload the evidence"]["with"]["name"]


def test_every_pass_collects_its_inventory_before_it_runs():
    steps = _steps()
    names = list(steps)
    assert names.index("Collect the suite's inventory") < names.index(
        "Run the full suite under load"
    )
    assert "inventory-suite.txt" in steps["Collect the suite's inventory"]["run"]
    stall = steps["Run the scheduler-delay regressions, unloaded"]["run"]
    assert stall.index("inventory-stall.txt") < stall.index("stall.xml")
    budgets = steps["Run the latency budgets alone, unloaded"]["run"]
    assert budgets.index("inventory-budgets.txt") < budgets.index("budgets.xml")
    assert '"$SHA"' in steps["Report what each run held"]["run"]


def test_an_inventory_ignores_the_warning_lines_beneath_a_node_id(tmp_path):
    inventory = tmp_path / "inventory.txt"
    inventory.write_text(
        "tests/test_x.py::test_y\n"
        "  /lib/mod.py:10: DeprecationWarning: see tests/test_z.py::test_w\n"
        "\n1 test collected\n"
    )
    assert _report().read_inventory(inventory) == {"tests.test_x::test_y"}


def test_the_budgets_collection_lists_node_ids(tmp_path):
    report = _report()
    argv = report.budgets_argv(str(CI))
    command = report.collect_argv(argv)
    assert command.count("-q") == 1 and "-qq" not in command
    inventory = tmp_path / "inventory-budgets.txt"
    with inventory.open("w") as out:
        subprocess.run(
            [sys.executable, "-m", *command], stdout=out, check=True, cwd=ROOT
        )
    collected = report.read_inventory(inventory)
    assert collected
    modules = {
        a.removesuffix(".py").replace("/", ".")
        for a in argv[1:]
        if a.startswith("tests/")
    }
    for case in collected:
        classname = case.split("::")[0]
        assert classname in modules or classname.rsplit(".", 1)[0] in modules, case


def test_the_workflow_collects_budgets_through_the_judge_s_helpers():
    run = _steps()["Run the latency budgets alone, unloaded"]["run"]
    assert "budgets_argv(" in run and "collect_argv(argv)" in run
    assert '"--collect-only", "-q"' not in run


@pytest.mark.parametrize(("omitted", "counts"), [(25, False), (24, True)])
def test_a_sample_at_a_run_s_end_opens_no_slot(tmp_path, capsys, omitted, counts):
    proof = _proof(tmp_path)
    # Each run is 600 s, so 120 five-second slots; drop slots spread through
    # the run, never two adjacent, so no gap exceeds the bound.
    dropped = {i for i in range(120) if i % 5 == 2} | (
        {118} if omitted == 25 else set()
    )
    assert len(dropped) == omitted
    lines = []
    for i in range(1, 6):
        start = 10_000 * i
        lines += [
            f"{start + 5 * slot} 26.00 0 0"
            for slot in range(120)
            if slot not in dropped
        ]
        lines.append(f"{start + 600} 26.00 0 0")
    (proof / "loadavg.txt").write_text("\n".join(lines) + "\n")
    assert (_judge(proof) == 0) is counts
    out = capsys.readouterr().out
    assert ("cover 95 of 120 slots" in out) is not counts


def test_only_main_runs_and_only_the_dispatched_commit_is_checked_out():
    workflow = _workflow()
    job = workflow["jobs"]["load-proof"]
    assert job["if"] == "github.ref == 'refs/heads/main'"
    triggers = workflow.get("on", workflow.get(True))
    assert "sha" not in (triggers["workflow_dispatch"].get("inputs") or {})
    assert "inputs.sha" not in WORKFLOW.read_text()
    checkouts = [
        s
        for s in job["steps"]
        if str(s.get("uses", "")).startswith("actions/checkout@")
    ]
    assert [c["with"]["ref"] for c in checkouts] == ["${{ github.sha }}"]


def test_the_judge_leaves_the_checkout_before_anything_from_it_runs():
    steps = _steps()
    names = list(steps)
    confirm = steps["Confirm the commit and keep the judge outside the checkout"]
    assert confirm["id"] == "confirm"
    assert 'test "$(git rev-parse HEAD)" = "$SHA"' in confirm["run"]
    assert confirm["env"]["SHA"] == "${{ github.sha }}"
    assert 'cp scripts/load_proof_report.py "${RUNNER_TEMP}/judge/"' in confirm["run"]
    assert names.index(
        "Confirm the commit and keep the judge outside the checkout"
    ) < names.index("Install hash-locked dependencies")
    report = steps["Report what each run held"]["run"]
    assert "${RUNNER_TEMP}/judge/load_proof_report.py" in report
