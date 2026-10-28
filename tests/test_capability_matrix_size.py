# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The capability matrix stays a summary every contributor can read whole.

Full notes belong in docs/CAPABILITY_DETAILS.md; a running changelog belongs in
the release notes.
"""

from __future__ import annotations

from pathlib import Path

MATRIX = Path(__file__).resolve().parents[1] / "docs" / "CAPABILITY_MATRIX.md"
DETAILS = MATRIX.with_name("CAPABILITY_DETAILS.md")
MAX_NOTES = 600


def _rows() -> list[list[str]]:
    rows = []
    for line in MATRIX.read_text(encoding="utf-8").splitlines():
        if line.startswith("| ") and not line.startswith(("| :--", "| Capability |")):
            rows.append(line.split(" | "))
    return rows


def test_every_notes_cell_is_a_summary() -> None:
    long = [
        (cells[0][2:], len(" | ".join(cells[3:])) - 2)
        for cells in _rows()
        if len(" | ".join(cells[3:])) - 2 > MAX_NOTES
    ]
    assert not long, f"Notes over {MAX_NOTES} characters; move the detail: {long}"


def test_the_matrix_carries_no_changelog() -> None:
    headings = [
        line
        for line in MATRIX.read_text(encoding="utf-8").splitlines()
        if line.startswith("#")
    ]
    assert headings == ["# Capability Matrix"], headings


def test_every_details_link_names_a_section() -> None:
    sections = {
        line[3:].strip()
        for line in DETAILS.read_text(encoding="utf-8").splitlines()
        if line.startswith("## ")
    }
    linked = [
        cells[0][2:] for cells in _rows() if "CAPABILITY_DETAILS.md#" in cells[-1]
    ]
    assert linked and set(linked) <= sections, set(linked) - sections
