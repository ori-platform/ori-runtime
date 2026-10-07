# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The unreleased notes are reset to the newest release at its prep commit."""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
RELEASES = ROOT / "docs" / "releases"
UNRELEASED = RELEASES / "unreleased.md"
RELEASE_NOTE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)\.md$")
HEADER = re.compile(r"Changes merged to `main` after `(v[^`]+)`")


def newest_release(names: list[str]) -> str:
    """The highest semver among `vX.Y.Z.md` names; pre-release names never match."""
    versions = [
        tuple(int(part) for part in match.groups())
        for match in (RELEASE_NOTE.match(name) for name in names)
        if match
    ]
    if not versions:
        raise AssertionError("no release notes named vX.Y.Z.md in docs/releases/")
    return "v" + ".".join(str(part) for part in max(versions))


def named_baseline(text: str) -> str | None:
    match = HEADER.search(" ".join(text.split()))
    return match.group(1) if match else None


def test_unreleased_names_the_newest_release() -> None:
    newest = newest_release([path.name for path in RELEASES.iterdir()])
    named = named_baseline(UNRELEASED.read_text(encoding="utf-8"))
    assert named == newest, (
        f"docs/releases/unreleased.md collects changes after {named!r}, but the "
        f"newest release note is {newest}.md. Reset unreleased.md in the release "
        f"prep commit: header 'Changes merged to `main` after `{newest}` are "
        "collected here until the next release is cut.', with only changes "
        "merged after that tag below it. This guard checks the header only; it "
        "cannot tell whether each entry below it is actually unreleased."
    )


def test_newest_release_ignores_pre_releases_and_orders_numerically() -> None:
    names = [
        "v2.5.0.md",
        "v2.10.0.md",
        "v3.0.0-rc.1.md",
        "v0.9.0-beta.2.md",
        "unreleased.md",
        "stable-release-notes.md",
    ]
    assert newest_release(names) == "v2.10.0"


def test_the_header_is_read_across_a_line_wrap() -> None:
    text = "Changes merged to `main` after\n`v2.5.0-rc.7` are collected here"
    assert named_baseline(text) == "v2.5.0-rc.7"
    assert named_baseline("_No changes yet._") is None
