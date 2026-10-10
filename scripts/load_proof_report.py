# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Summarise a load-proof run's evidence, and fail unless every run counts.

Reads the directory the load-proof workflow fills: ``runs.txt`` (start and end
of each loaded run, with its exit status), ``loadavg.txt`` (one-minute load
sampled every few seconds), ``stress.txt``, ``commit.txt`` and one JUnit file
per run, plus the unloaded budgets and scheduler-delay passes. Prints Markdown.

A proof counts only if it asked for at least five runs and finished all of
them, and each of them passed; held its load, judged on the tenth percentile
of samples taken after the first minute, with samples covering the run; ran
the same tests to the same outcome as every other run, the phone delivery
tests among the passed; and both unloaded passes ran tests that passed, the
held-back progress reader among them. It is hosted stress evidence, never a
claim about another host or about physical safety latency.

    python scripts/load_proof_report.py <proof-dir> <floor> <target> <runs>
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

MIN_RUNS = 5
MIN_FLOOR = 1.0
SAMPLE_INTERVAL_S = 5
SAMPLE_COVERAGE = 0.8
SETTLE_S = 60
PHONE_MODULE = "test_runtime_mobile_delivery_e2e"
HELD_READER = "test_faults_land_at_their_polls_however_slowly_the_output_is_read"


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


def read_junit(path: Path) -> JUnit | None:
    if not path.is_file():
        return None
    passed: set[str] = set()
    skipped: set[str] = set()
    failed: set[str] = set()
    for case in ET.parse(path).getroot().iter("testcase"):
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


def read_load(path: Path) -> list[tuple[int, float]]:
    samples: list[tuple[int, float]] = []
    if path.is_file():
        for line in path.read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                try:
                    samples.append((int(parts[0]), float(parts[1])))
                except ValueError:
                    continue
    return samples


def recorded(stress: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if stress.is_file():
        for line in stress.read_text().splitlines():
            key, sep, value = line.partition("=")
            if sep:
                values[key] = value
    return values


def tenth_percentile(values: list[float]) -> float:
    ordered = sorted(values)
    return ordered[int(0.1 * (len(ordered) - 1))]


def main(argv: list[str]) -> int:
    proof = Path(argv[1])
    floor, target, expected = float(argv[2]), float(argv[3]), int(argv[4])
    stress = recorded(proof / "stress.txt")
    cores = int(stress["cores"]) if stress.get("cores", "").isdigit() else None
    load = read_load(proof / "loadavg.txt")
    runs = read_runs(proof / "runs.txt")
    problems: list[str] = []

    print("## Load proof: hosted stress evidence\n")
    commit = proof / "commit.txt"
    print(
        f"Commit: `{commit.read_text().strip() if commit.is_file() else 'unknown'}`\n"
    )
    print(
        f"Target {target} load per core; floor {floor} on each run's tenth "
        f"percentile after its first minute; {expected} runs asked for.\n"
    )
    if (proof / "stress.txt").is_file():
        print("```text\n" + (proof / "stress.txt").read_text().strip() + "\n```\n")
    if cores is None:
        problems.append("the stress configuration was not recorded")
    if expected < MIN_RUNS:
        problems.append(f"{expected} runs asked for, fewer than {MIN_RUNS}")
    if not MIN_FLOOR <= floor <= target:
        problems.append(f"floor {floor} is outside {MIN_FLOOR}..{target}")

    unloaded = (
        ("budgets", "Latency budgets, unloaded", None),
        ("stall", "Scheduler delay, unloaded", HELD_READER),
    )
    for name, label, required in unloaded:
        result = read_junit(proof / f"{name}.xml")
        if result is None:
            problems.append(f"{label}: no result")
            print(f"- {label}: no result")
            continue
        if result.failed or not result.passed:
            problems.append(f"{label}: failed or passed nothing")
        if required and not any(
            case.endswith(f"::{required}") for case in result.passed
        ):
            problems.append(f"{label}: {required} did not pass")
        print(
            f"- {label}: {len(result.passed)} passed, {len(result.failed)} failed, "
            f"{len(result.skipped)} skipped"
        )
    print()

    print(
        "| Run | Exit | Minutes | Samples | Mean load/core | P10 load/core | Passed | Failed | Skipped |"
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
            f"| {run.index} | {run.status if run.status is not None else 'unfinished'} | {minutes} "
            f"| {len(window)} "
            f"| {f'{mean:.2f}' if mean is not None else '–'} "
            f"| {f'{p10:.2f}' if p10 is not None else '–'} "
            f"| {len(result.passed) if result else '–'} "
            f"| {len(result.failed) if result else '–'} "
            f"| {len(result.skipped) if result else '–'} |"
        )
        if run.status != 0:
            problems.append(f"run {run.index} did not pass")
        if run.end is not None:
            due = (run.end - run.start) / SAMPLE_INTERVAL_S * SAMPLE_COVERAGE
            if len(window) < due:
                problems.append(f"run {run.index} has too few load samples")
        if p10 is None or p10 < floor:
            problems.append(f"run {run.index} held less than {floor} load per core")
        if result is None or not result.passed:
            problems.append(f"run {run.index} recorded no passing tests")
            continue
        if not any(PHONE_MODULE in case for case in result.passed) or any(
            PHONE_MODULE in case for case in result.skipped
        ):
            problems.append(f"run {run.index} did not run the phone delivery tests")
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
        "**Counts.** Every run passed, held the floor and ran the same tests "
        "to the same outcomes. This is hosted stress evidence, not a "
        "reproduction of another host, and not a claim about physical safety "
        "latency."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
