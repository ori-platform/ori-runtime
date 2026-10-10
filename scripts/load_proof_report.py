# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Summarise a load-proof run's evidence, and fail unless every run counts.

Reads the directory the load-proof workflow fills: ``runs.txt`` (start and end
of each loaded run, with its exit status), ``loadavg.txt`` (one-minute load
sampled every few seconds), ``stress.txt``, ``commit.txt`` and one JUnit file
per run, plus the unloaded budgets and scheduler-delay passes. Prints Markdown.

A loaded run counts only if it passed, held a mean load per core at or above
the floor, and ran the same tests as every other run. A proof counts only if
every run counts and both unloaded passes passed. It is hosted stress
evidence, never a claim about another host or about physical safety latency.

    python scripts/load_proof_report.py <proof-dir> <floor-per-core>
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class JUnit:
    tests: int
    failures: int
    errors: int
    skipped: int
    ids: frozenset[str]


@dataclass(frozen=True)
class Run:
    index: int
    start: int
    end: int | None
    status: int | None


def read_junit(path: Path) -> JUnit | None:
    if not path.is_file():
        return None
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    tests = sum(int(s.get("tests", 0)) for s in suites)
    failures = sum(int(s.get("failures", 0)) for s in suites)
    errors = sum(int(s.get("errors", 0)) for s in suites)
    skipped = sum(int(s.get("skipped", 0)) for s in suites)
    ids = frozenset(
        f"{case.get('classname', '')}::{case.get('name', '')}"
        for case in root.iter("testcase")
    )
    return JUnit(tests, failures, errors, skipped, ids)


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


def cores_of(stress: Path) -> int | None:
    if stress.is_file():
        for line in stress.read_text().splitlines():
            if line.startswith("cores="):
                return int(line.split("=", 1)[1])
    return None


def main(argv: list[str]) -> int:
    proof, floor = Path(argv[1]), float(argv[2])
    cores = cores_of(proof / "stress.txt")
    load = read_load(proof / "loadavg.txt")
    runs = read_runs(proof / "runs.txt")
    problems: list[str] = []

    print("## Load proof: hosted stress evidence\n")
    commit = proof / "commit.txt"
    print(
        f"Commit: `{commit.read_text().strip() if commit.is_file() else 'unknown'}`\n"
    )
    if (proof / "stress.txt").is_file():
        print("```text\n" + (proof / "stress.txt").read_text().strip() + "\n```\n")
    if cores is None:
        problems.append("the stress configuration was not recorded")

    for name, label in (
        ("budgets", "Latency budgets, unloaded"),
        ("stall", "Scheduler delay, unloaded"),
    ):
        result = read_junit(proof / f"{name}.xml")
        if result is None:
            problems.append(f"{label}: no result")
            print(f"- {label}: no result")
            continue
        ok = result.tests > 0 and result.failures == 0 and result.errors == 0
        if not ok:
            problems.append(f"{label}: failed or ran nothing")
        print(
            f"- {label}: {result.tests} tests, {result.failures} failures, "
            f"{result.errors} errors, {result.skipped} skipped"
        )
    print()

    print(
        "| Run | Exit | Minutes | Mean load/core | Min load/core | Tests | Failed | Skipped |"
    )
    print("|---|---|---|---|---|---|---|---|")
    reference: frozenset[str] | None = None
    if not runs:
        problems.append("no loaded run started")
    for run in runs:
        result = read_junit(proof / f"run-{run.index}.xml")
        window = [
            value
            for at, value in load
            if run.end is not None and run.start <= at <= run.end
        ]
        mean = min_ = None
        if window and cores:
            mean = sum(window) / len(window) / cores
            min_ = min(window) / cores
        minutes = f"{(run.end - run.start) / 60:.1f}" if run.end is not None else "–"
        print(
            f"| {run.index} | {run.status if run.status is not None else 'unfinished'} | {minutes} "
            f"| {f'{mean:.2f}' if mean is not None else '–'} "
            f"| {f'{min_:.2f}' if min_ is not None else '–'} "
            f"| {result.tests if result else '–'} "
            f"| {(result.failures + result.errors) if result else '–'} "
            f"| {result.skipped if result else '–'} |"
        )
        if run.status != 0:
            problems.append(f"run {run.index} did not pass")
        if mean is None or mean < floor:
            problems.append(f"run {run.index} held less than {floor} load per core")
        if result is None or result.tests == 0:
            problems.append(f"run {run.index} recorded no tests")
        elif reference is None:
            reference = result.ids
        elif result.ids != reference:
            problems.append(f"run {run.index} ran a different set of tests")
    print()

    if problems:
        print("**Does not count:**\n")
        for problem in problems:
            print(f"- {problem}")
        return 1
    print(
        "**Counts.** Every run passed at or above the floor, over the same tests. "
        "This is hosted stress evidence, not a reproduction of another host, "
        "and not a claim about physical safety latency."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
