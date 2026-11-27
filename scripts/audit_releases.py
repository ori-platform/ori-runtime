#!/usr/bin/env python3
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Audit the locks of every supported release against OSV.

A supported release line is a `Yes` row of SECURITY.md's *Supported Versions*
table, such as `2.5.x`; it is audited at its newest final tag. What the tag
puts on devices is audited: every Python lock under `requirements/` except the
development and build locks, which no device installs, and the Android
payload's `Cargo.lock`. They are read from git as data, never checked out or
run, and audited by `audit_locks.py`'s own rules. A finding names the release
it was found in.

It fails closed: no supported line, a line with no final tag, a release with
no runtime lock, and any audit failure all fail it.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import audit_locks

SECURITY = Path("SECURITY.md")
#: A supported row of the table: | `2.5.x` (stable) | Yes |
SUPPORTED_ROW_RE = re.compile(r"^\|\s*`(\d+)\.(\d+)\.x`[^|]*\|\s*Yes\s*\|\s*$")
RUNTIME_LOCK = "requirements/runtime.txt"
CARGO_LOCK = "mobile/ori-runtime-mobile/Cargo.lock"
#: Tooling locks: CI and the build backend, never installed on a device.
NOT_ON_DEVICES = frozenset({"requirements/dev.txt", "requirements/build.txt"})


#: The header row of the *Supported Versions* table, the only table read.
VERSION_HEADER_RE = re.compile(r"^\|\s*Version\s*\|\s*Supported\s*\|\s*$")
#: A line that reads as a version row, wherever it is: `| `2.5.x` ...` or `| <2.5.0`.
VERSION_LIKE_RE = re.compile(r"^\s*\|\s*`?<?\d")


def _version_rows(security_text: str) -> list[str]:
    """The rows of the table headed `| Version | Supported |`, separator excluded.

    Fails on no such table, and on any version-like line outside it, such as one
    past a blank line or a note inside the table, or in another such table: a
    row that is not read must not be a supported line silently dropped.
    """
    text = [line.rstrip("\r") for line in security_text.splitlines()]
    headers = [i for i, line in enumerate(text) if VERSION_HEADER_RE.match(line)]
    if not headers:
        raise ValueError("SECURITY.md has no | Version | Supported | table")
    end = headers[0] + 1
    while end < len(text) and text[end].startswith("|"):
        end += 1
    stray = [
        line
        for i, line in enumerate(text)
        if not headers[0] < i < end and VERSION_LIKE_RE.match(line)
    ]
    if stray:
        raise ValueError(
            f"SECURITY.md has a version row outside its table: {stray[0]!r}"
        )
    rows = text[headers[0] + 1 : end]
    return [row for row in rows if not re.fullmatch(r"[|\s:-]+", row)]


def supported_lines(security_text: str) -> list[tuple[int, int]]:
    """The `(major, minor)` of every release line SECURITY.md supports.

    Only the *Supported Versions* table is read. A row there of two cells whose
    second is not exactly `Yes` (and parsed) or `No` fails, rather than dropping
    a supported line.
    """
    lines: list[tuple[int, int]] = []
    for row in _version_rows(security_text):
        cells = [cell.strip() for cell in row.strip().strip("|").split("|")]
        if m := SUPPORTED_ROW_RE.match(row):
            lines.append((int(m.group(1)), int(m.group(2))))
        elif len(cells) != 2 or cells[1] != "No":
            raise ValueError(f"SECURITY.md has a version row it cannot read: {row!r}")
    if not lines:
        raise ValueError("SECURITY.md names no supported release line")
    return lines


def newest_final_tag(tags: list[str], line: tuple[int, int]) -> str:
    """The newest `vMAJOR.MINOR.PATCH` tag of *line*; a pre-release never counts."""
    pattern = re.compile(rf"v{line[0]}\.{line[1]}\.(0|[1-9]\d*)")
    patches = [(int(m.group(1)), tag) for tag in tags if (m := pattern.fullmatch(tag))]
    if not patches:
        raise ValueError(f"no final tag for supported line {line[0]}.{line[1]}.x")
    return max(patches)[1]


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], capture_output=True, text=True, check=True
    ).stdout


def release_packages(tag: str) -> list[audit_locks.Package]:
    """Every package of the locks *tag* puts on devices, read from git as data."""
    paths = _git("ls-tree", "--name-only", tag, "requirements/").split()
    locks = sorted(p for p in paths if p.endswith(".txt") and p not in NOT_ON_DEVICES)
    if RUNTIME_LOCK not in locks:
        raise ValueError(f"{tag} has no {RUNTIME_LOCK}")
    packages: list[audit_locks.Package] = []
    for lock in locks:
        packages += audit_locks.python_pins(_git("show", f"{tag}:{lock}"))
    if _git("ls-tree", "--name-only", tag, CARGO_LOCK).strip():
        packages += audit_locks.locked_crates(_git("show", f"{tag}:{CARGO_LOCK}"))
    return sorted(set(packages))


def main() -> int:
    try:
        tags = _git("tag", "--list", "v*").split()
        releases = [
            newest_final_tag(tags, line)
            for line in supported_lines(SECURITY.read_text(encoding="utf-8"))
        ]
    except Exception as exc:  # noqa: BLE001 - any failure fails the audit
        print(f"Release audit could not complete: {exc!r}", file=sys.stderr)
        return 1
    failed = False
    for tag in releases:
        try:
            failing, notices = audit_locks.audit(release_packages(tag))
        except Exception as exc:  # noqa: BLE001 - one release's failure fails it
            print(f"{tag}: audit could not complete: {exc!r}", file=sys.stderr)
            failed = True
            continue
        for line in notices:
            print(f"{tag}: unmaintained crate notice, not failing: {line}")
        for line in failing:
            print(f"{tag}: {line}", file=sys.stderr)
        failed = failed or bool(failing)
        print(f"{tag}: {'OSV records found' if failing else 'no OSV records'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
