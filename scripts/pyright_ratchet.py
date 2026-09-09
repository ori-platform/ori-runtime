# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Hold the pyright count over the analysed trees at or below a baseline.

`pyright ori/ scripts/` is gated at zero and stays that way. The test tree is
not zero, and paying it down is separate work; what this stops is the number
growing while that work waits. A count nothing prints is a number no reviewer
sees, and a rule every author has to remember is the control that fails when
someone is in a hurry.

The ratchet is strict in both directions. A rise fails, which is the point. A
fall fails too, asking for the baseline to be lowered, because a baseline left
above the real count is headroom someone later spends without noticing.

That strictness has a cost, and it is the reason the alternative exists: every
change that moves the count in either direction carries a one-line baseline
commit, two such changes conflict on that line, deleting a test file becomes a
failure until the baseline follows, and a pyright upgrade moves the number for
everyone until someone re-measures. The alternative — failing only on a rise —
trades those for headroom that accumulates silently and is spent by whoever
comes next.

The count is a property of the analysis environment as much as of the code, so
`pythonPlatform` and `pythonVersion` are pinned in `pyproject.toml`. Without
that the same tree reports a different number on macOS and Linux and no single
committed value is correct on both.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINE_PATH = REPO_ROOT / "pyright-baseline.json"

BASELINE_NOTE = (
    "pyright error count over the trees pyright analyses (ori, tests, scripts; "
    "skills/ is outside its include). Lower it whenever the real count falls. "
    "Raising it needs --allow-raise and is a decision, not a step. "
    "`pyright ori/ scripts/` is separately gated at zero, so a rise there "
    "cannot be absorbed by a fall in tests/. The count depends on "
    "pythonPlatform and pythonVersion, both pinned in pyproject.toml."
)


def run_pyright() -> dict:
    """Every diagnostic pyright reports for the analysed trees, as JSON.

    Invoked through this interpreter rather than whatever `pyright` is first on
    PATH: a globally installed copy of another version reports another number,
    and the whole mechanism rests on the count being the pinned one.
    """
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "pyright", "--outputjson"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:  # pragma: no cover - environment failure
        sys.stderr.write(f"could not run pyright: {exc}\n")
        raise SystemExit(2) from exc

    # A non-zero exit is the normal case: it means diagnostics exist. Only
    # unparseable output means pyright itself failed.
    try:
        report: dict = json.loads(completed.stdout)
    except json.JSONDecodeError:
        sys.stderr.write(
            "pyright did not produce JSON. It may not be installed in this "
            "environment, or it failed before analysing.\n"
        )
        sys.stderr.write(completed.stdout[-2000:])
        sys.stderr.write(completed.stderr[-2000:])
        raise SystemExit(2) from None
    return report


def error_diagnostics(report: dict) -> list[dict]:
    return [
        diagnostic
        for diagnostic in report.get("generalDiagnostics", [])
        if diagnostic.get("severity") == "error"
    ]


def relative(raw: str) -> str:
    try:
        return str(Path(raw).resolve().relative_to(REPO_ROOT))
    except (ValueError, OSError):
        return raw or "unknown"


def by_area(diagnostics: list[dict]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for diagnostic in diagnostics:
        counts[str(Path(relative(diagnostic.get("file") or "")).parent)] += 1
    return dict(sorted(counts.items()))


def read_baseline() -> dict:
    if not BASELINE_PATH.exists():
        sys.stderr.write(f"no baseline at {BASELINE_PATH.name}; run --update\n")
        raise SystemExit(2)
    baseline: dict = json.loads(BASELINE_PATH.read_text())
    return baseline


def write_baseline(diagnostics: list[dict]) -> None:
    BASELINE_PATH.write_text(
        json.dumps(
            {
                "total": len(diagnostics),
                "by_area": by_area(diagnostics),
                "note": BASELINE_NOTE,
            },
            indent=2,
        )
        + "\n"
    )


def describe_change(
    diagnostics: list[dict], recorded_areas: dict[str, int]
) -> list[str]:
    """The areas that moved, so a failure names where to look.

    The whole distribution would be nearly the same before and after a small
    rise, which is what makes a bare breakdown useless for finding one.
    """
    current = by_area(diagnostics)
    lines: list[str] = []
    for area in sorted(set(current) | set(recorded_areas)):
        now, before = current.get(area, 0), recorded_areas.get(area, 0)
        if now != before:
            lines.append(f"    {before:>5} -> {now:<5}  {area}")
    if not lines:
        lines.append("    (no area changed; the recorded breakdown may be stale)")
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="pyright count ratchet")
    parser.add_argument(
        "--update", action="store_true", help="record the current count"
    )
    parser.add_argument(
        "--allow-raise",
        action="store_true",
        help="with --update, permit recording a higher count",
    )
    parser.add_argument(
        "--list", action="store_true", help="print every diagnostic and exit"
    )
    args = parser.parse_args(argv)

    report = run_pyright()
    diagnostics = error_diagnostics(report)
    total = len(diagnostics)

    # Two counts that disagree mean one is being read wrong, and a report with
    # no summary is not a report this can check. Neither is compared.
    summary = report.get("summary")
    if not isinstance(summary, dict) or "errorCount" not in summary:
        sys.stderr.write("pyright reported no error summary; refusing to compare.\n")
        return 2
    if int(summary["errorCount"]) != total:
        sys.stderr.write(
            f"pyright reported {summary['errorCount']} errors in its summary "
            f"but {total} diagnostics; refusing to compare an ambiguous count.\n"
        )
        return 2

    if args.list:
        for diagnostic in diagnostics:
            line = int(diagnostic.get("range", {}).get("start", {}).get("line", 0)) + 1
            rule = diagnostic.get("rule") or "unclassified"
            message = str(diagnostic.get("message", "")).splitlines()[0]
            print(f"{relative(diagnostic.get('file') or '')}:{line}  {rule}  {message}")
        return 0

    baseline = read_baseline()
    recorded = int(baseline["total"])
    recorded_areas = {
        str(k): int(v) for k, v in (baseline.get("by_area") or {}).items()
    }

    if args.update:
        if total > recorded and not args.allow_raise:
            print(
                f"refusing to raise the baseline from {recorded} to {total}. "
                "A rise is a decision, not a step:",
                file=sys.stderr,
            )
            print(
                *describe_change(diagnostics, recorded_areas), sep="\n", file=sys.stderr
            )
            print(
                "  Fix them, or pass --allow-raise to record the rise deliberately.",
                file=sys.stderr,
            )
            return 1
        write_baseline(diagnostics)
        direction = "raised" if total > recorded else "lowered"
        if total == recorded:
            direction = "unchanged at"
        print(f"baseline {direction} {total}")
        return 0

    if total != recorded:
        verb = "rose" if total > recorded else "fell"
        delta = f"+{total - recorded}" if total > recorded else f"-{recorded - total}"
        print(
            f"pyright diagnostics {verb}: {total}, baseline {recorded} ({delta}).",
            file=sys.stderr,
        )
        print(*describe_change(diagnostics, recorded_areas), sep="\n", file=sys.stderr)
        if total > recorded:
            print(
                "  List them with: python scripts/pyright_ratchet.py --list",
                file=sys.stderr,
            )
        else:
            print(
                "  Lower the baseline so the difference cannot be spent later:\n"
                "    python scripts/pyright_ratchet.py --update",
                file=sys.stderr,
            )
        return 1

    print(f"pyright diagnostics: {total}, baseline {recorded}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
