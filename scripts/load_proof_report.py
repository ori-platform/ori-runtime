# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Summarise a load-proof run's evidence, and fail unless all of it is valid.

Reads the directory the load-proof workflow fills: ``commit.txt``,
``stress.txt``, ``runs.txt`` (start and end of each loaded run, with its exit
status), ``loadavg.txt`` (one-minute load sampled every few seconds), one
``inventory-<pass>.txt`` of collected node ids per pass, and one JUnit file per
pass: ``budgets``, ``stall`` and ``run-<n>``. Prints Markdown.

Evidence is refused, not repaired. A proof counts only if:

- it is for the requested commit, with a recorded CPU count, worker count and
  stress command;
- at least five runs were requested, and every one finished with exit status
  zero and no failure or error in its JUnit;
- every pass ran its whole collected inventory, nothing failing, anything not
  passed only skipped, and the loaded runs to the same outcomes as each other,
  with every collected phone delivery case passed; the scheduler-delay pass
  passed the held-back progress reader;
- the load samples are finite, non-negative and strictly increasing in time;
  each run's samples occupy most of its five-second slots with no gap over half a minute;
  and its tenth percentile of load per core after its first minute holds the
  floor, which itself lies from 1.0 to the target.

It is hosted stress evidence, never a claim about another host or about
physical safety latency.

    python scripts/load_proof_report.py <proof-dir> <floor> <target> <runs> <sha>
"""

from __future__ import annotations

import math
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

MIN_RUNS = 5
MIN_FLOOR = 1.0
SAMPLE_INTERVAL_S = 5
SAMPLE_COVERAGE = 0.8
SETTLE_S = 60
MAX_SAMPLE_GAP_S = 30
PHONE_MODULE = "tests.test_runtime_mobile_delivery_e2e"
HELD_READER = (
    f"{PHONE_MODULE}::test_faults_land_at_their_polls_however_slowly_the_output_is_read"
)


@dataclass(frozen=True)
class JUnit:
    passed: frozenset[str]
    skipped: frozenset[str]
    failed: frozenset[str]


@dataclass(frozen=True)
class Run:
    index: int
    start: int
    end: int | None
    status: int | None


def junit_id(nodeid: str) -> str:
    """The JUnit ``classname::name`` pytest writes for a collected node id."""
    base, bracket, params = nodeid.partition("[")
    parts = base.split("::")
    module = parts[0].removesuffix(".py").replace("/", ".")
    return f"{'.'.join([module, *parts[1:-1]])}::{parts[-1]}{bracket}{params}"


def budgets_argv(ci_workflow: str) -> list[str]:
    """CI's own "Run the latency budgets alone" command, as an argument list."""
    import shlex

    import yaml

    with open(ci_workflow) as handle:
        steps = yaml.safe_load(handle)["jobs"]["test"]["steps"]
    (step,) = [s for s in steps if s.get("name") == "Run the latency budgets alone"]
    argv = shlex.split(step["run"])
    if argv[0] != "pytest":
        raise ValueError(f"the budgets step does not run pytest: {argv[0]!r}")
    return argv


def collect_argv(argv: list[str]) -> list[str]:
    """*argv* collecting its node ids, one per line, instead of running them.

    Exactly one ``-q``: a second one makes pytest print per-file counts rather
    than node ids, which would leave the inventory empty.
    """
    kept = [arg for arg in argv if arg not in {"-q", "-qq", "--quiet"}]
    return [*kept, "-q", "--collect-only"]


def read_inventory(path: Path) -> frozenset[str] | None:
    if not path.is_file():
        return None
    return frozenset(
        junit_id(line.strip())
        for line in path.read_text().splitlines()
        if "::" in line and not line.startswith(" ")
    )


def read_junit(path: Path) -> JUnit | None:
    if not path.is_file():
        return None
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return None
    passed: set[str] = set()
    skipped: set[str] = set()
    failed: set[str] = set()
    for case in root.iter("testcase"):
        case_id = f"{case.get('classname', '')}::{case.get('name', '')}"
        tags = {child.tag for child in case}
        if tags & {"failure", "error"}:
            failed.add(case_id)
        elif "skipped" in tags:
            skipped.add(case_id)
        else:
            passed.add(case_id)
    return JUnit(frozenset(passed), frozenset(skipped), frozenset(failed))


def read_runs(path: Path) -> list[Run]:
    starts: dict[int, int] = {}
    ends: dict[int, tuple[int, int]] = {}
    if path.is_file():
        for line in path.read_text().splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "start":
                starts[int(parts[2])] = int(parts[0])
            elif len(parts) >= 4 and parts[1] == "end":
                ends[int(parts[2])] = (int(parts[0]), int(parts[3]))
    return [
        Run(
            i,
            starts[i],
            ends[i][0] if i in ends else None,
            ends[i][1] if i in ends else None,
        )
        for i in sorted(starts)
    ]


def read_load(path: Path) -> tuple[list[tuple[int, float]], list[str]]:
    """Samples, and what is wrong with them; an invalid file yields no samples."""
    if not path.is_file():
        return [], ["no load samples were recorded"]
    samples: list[tuple[int, float]] = []
    for number, line in enumerate(path.read_text().splitlines(), 1):
        parts = line.split()
        try:
            at, value = int(parts[0]), float(parts[1])
        except (IndexError, ValueError):
            return [], [f"load sample line {number} is malformed"]
        if not math.isfinite(value) or value < 0:
            return [], [f"load sample line {number} is not a finite, non-negative load"]
        if samples and at <= samples[-1][0]:
            return [], [f"load sample line {number} does not advance in time"]
        samples.append((at, value))
    return samples, []


def recorded(stress: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if stress.is_file():
        for line in stress.read_text().splitlines():
            if line.startswith("stress-ng "):
                values["command"] = line
            key, sep, value = line.partition("=")
            if sep:
                values[key] = value
    return values


def positive(value: str | None) -> int | None:
    return (
        int(value) if value is not None and value.isdigit() and int(value) > 0 else None
    )


def tenth_percentile(values: list[float]) -> float:
    ordered = sorted(values)
    return ordered[int(0.1 * (len(ordered) - 1))]


def judge_pass(
    label: str, result: JUnit | None, inventory: frozenset[str] | None
) -> list[str]:
    if result is None:
        return [f"{label}: no readable JUnit result"]
    if inventory is None:
        return [f"{label}: no collected inventory"]
    problems: list[str] = []
    if not inventory:
        problems.append(f"{label}: collected nothing")
    if result.failed:
        problems.append(f"{label}: {len(result.failed)} failed")
    missing = inventory - result.passed - result.skipped
    if missing:
        problems.append(f"{label}: {len(missing)} collected tests did not run")
    if not result.passed:
        problems.append(f"{label}: nothing passed")
    return problems


def main(argv: list[str]) -> int:
    proof = Path(argv[1])
    floor, target, expected, sha = float(argv[2]), float(argv[3]), int(argv[4]), argv[5]
    stress = recorded(proof / "stress.txt")
    cores = positive(stress.get("cores"))
    workers = positive(stress.get("pytest_workers"))
    load, problems = read_load(proof / "loadavg.txt")
    runs = read_runs(proof / "runs.txt")

    print("## Load proof: hosted stress evidence\n")
    commit = proof / "commit.txt"
    commit_line = commit.read_text().strip() if commit.is_file() else ""
    print(f"Commit: `{commit_line or 'not recorded'}`\n")
    print(
        f"Target {target} load per core; floor {floor} on each run's tenth "
        f"percentile after its first minute; {expected} runs asked for.\n"
    )
    if stress:
        print("```text\n" + (proof / "stress.txt").read_text().strip() + "\n```\n")
    if not commit_line or commit_line.split()[0] != sha:
        problems.append(f"the recorded commit is not {sha}")
    if cores is None:
        problems.append("the CPU count was not recorded")
    if workers is None:
        problems.append("the pytest worker count was not recorded")
    if "command" not in stress:
        problems.append("the stress command was not recorded")
    if expected < MIN_RUNS:
        problems.append(f"{expected} runs asked for, fewer than {MIN_RUNS}")
    if not MIN_FLOOR <= floor <= target:
        problems.append(f"floor {floor} is outside {MIN_FLOOR}..{target}")

    for name, label in (
        ("budgets", "Latency budgets, unloaded"),
        ("stall", "Scheduler delay, unloaded"),
    ):
        result = read_junit(proof / f"{name}.xml")
        problems += judge_pass(
            label, result, read_inventory(proof / f"inventory-{name}.txt")
        )
        if name == "stall" and (result is None or HELD_READER not in result.passed):
            problems.append(f"{label}: {HELD_READER} did not pass")
        if result is not None:
            print(
                f"- {label}: {len(result.passed)} passed, {len(result.failed)} failed, "
                f"{len(result.skipped)} skipped"
            )
    print()

    inventory = read_inventory(proof / "inventory-suite.txt")
    phone = frozenset(
        case for case in inventory or () if case.split("::", 1)[0] == PHONE_MODULE
    )
    if inventory is not None and not phone:
        problems.append("the suite's inventory holds no phone delivery case")

    print(
        "| Run | Exit | Minutes | Samples | Mean load/core | P10 load/core "
        "| Passed | Failed | Skipped |"
    )
    print("|---|---|---|---|---|---|---|---|---|")
    reference: JUnit | None = None
    finished = [run for run in runs if run.end is not None]
    if len(finished) != expected or len(runs) != expected:
        problems.append(f"{len(finished)} of {expected} runs finished")
    for run in runs:
        result = read_junit(proof / f"run-{run.index}.xml")
        window = [
            (at, value)
            for at, value in load
            if run.end is not None and run.start <= at <= run.end
        ]
        settled = [value for at, value in window if at >= run.start + SETTLE_S]
        mean = p10 = None
        if window and cores:
            mean = sum(value for _, value in window) / len(window) / cores
        if settled and cores:
            p10 = tenth_percentile(settled) / cores
        minutes = f"{(run.end - run.start) / 60:.1f}" if run.end is not None else "–"
        print(
            f"| {run.index} | {run.status if run.status is not None else 'unfinished'} "
            f"| {minutes} | {len(window)} "
            f"| {f'{mean:.2f}' if mean is not None else '–'} "
            f"| {f'{p10:.2f}' if p10 is not None else '–'} "
            f"| {len(result.passed) if result else '–'} "
            f"| {len(result.failed) if result else '–'} "
            f"| {len(result.skipped) if result else '–'} |"
        )
        if run.status != 0:
            problems.append(f"run {run.index} did not pass")
        if run.end is not None:
            slots = math.ceil((run.end - run.start) / SAMPLE_INTERVAL_S) or 1
            occupied = {(at - run.start) // SAMPLE_INTERVAL_S for at, _ in window}
            if len(occupied) < slots * SAMPLE_COVERAGE:
                problems.append(
                    f"run {run.index}'s load samples cover {len(occupied)} of {slots} slots"
                )
            edges = [run.start] + [at for at, _ in window] + [run.end]
            if max(b - a for a, b in zip(edges, edges[1:])) > MAX_SAMPLE_GAP_S:
                problems.append(
                    f"run {run.index} has a gap in its load samples over {MAX_SAMPLE_GAP_S} s"
                )
        if p10 is None or p10 < floor:
            problems.append(f"run {run.index} held less than {floor} load per core")
        problems += judge_pass(f"run {run.index}", result, inventory)
        if result is None:
            continue
        if not phone <= result.passed:
            problems.append(f"run {run.index} did not pass every phone delivery case")
        if reference is None:
            reference = result
        elif (result.passed, result.skipped) != (reference.passed, reference.skipped):
            problems.append(
                f"run {run.index} ran different tests, or to different outcomes"
            )
    print()

    if problems:
        print("**Does not count:**\n")
        for problem in problems:
            print(f"- {problem}")
        return 1
    print(
        "**Counts.** Every run passed its whole inventory, held the floor and "
        "matched every other run. This is hosted stress evidence, not a "
        "reproduction of another host, and not a claim about physical safety "
        "latency."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
