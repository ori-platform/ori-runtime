# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Every registration status a current document names is one the runtime reports.

A status value removed from the runtime lingers in prose long after the code
and tests moved: the capability matrix advertised `refused` after the
vocabulary lost it. Any line that names `registration_status` may only pair it
with values of `RegistrationStatus`.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from ori.security.evidence.registration import RegistrationStatus

ROOT = pathlib.Path(__file__).resolve().parent.parent
#: Release notes of shipped versions are history and are not rewritten.
CURRENT_DOCS = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))] + [
    ROOT / "docs" / "releases" / "unreleased.md"
]
#: Every value the field has ever been documented with, so a removed one is
#: refused by name rather than passing as an unrelated token.
EVER_DOCUMENTED = {
    "disabled",
    "pending_authorisation",
    "pending_confirmation",
    "confirmed",
    "refused",
}
CURRENT = {status.value for status in RegistrationStatus}
TOKEN = re.compile(r"`([a-z_]+)`")
#: The values written beside the field: a parenthesised list right after it,
#: otherwise the rest of that sentence. `refused` elsewhere on the same line
#: names courier outcomes and attestation states, which are not this field.
BESIDE = re.compile(r"`registration_status`(?:\s*\(([^)]*)\)|([^.]*))")


@pytest.mark.parametrize("path", CURRENT_DOCS, ids=[p.name for p in CURRENT_DOCS])
def test_documented_registration_statuses_are_ones_the_runtime_reports(path) -> None:
    offenders = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        for match in BESIDE.finditer(line):
            window = match.group(1) or match.group(2) or ""
            for token in TOKEN.findall(window):
                if token in EVER_DOCUMENTED and token not in CURRENT:
                    offenders.append(f"{path.relative_to(ROOT)}:{number}: `{token}`")
    assert not offenders, (
        "a registration status the runtime no longer reports is still documented:\n  "
        + "\n  ".join(offenders)
    )


def test_the_guard_reads_the_documents_it_names() -> None:
    assert all(path.is_file() for path in CURRENT_DOCS)
    assert EVER_DOCUMENTED > CURRENT
