#!/usr/bin/env python3
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Refuse a pull request unless GitHub verifies the signature on every commit.

Branch protection holds the same rule at merge time. This reports it as a named
check on every push, lists each commit GitHub does not verify with GitHub's
reason, and fails closed on anything it cannot read in full.

    python3 scripts/check_signed_commits.py --repo OWNER/NAME --pr N --head-sha SHA
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys

# The pull request commits endpoint lists at most this many, paginated or not.
API_COMMIT_LIMIT = 250
SIGNING_DOCS = "https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits"


class CheckError(Exception):
    """The commit list could not be established in full."""


def _gh_api(*args: str) -> str:
    try:
        completed = subprocess.run(
            ["gh", "api", *args],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise CheckError(f"could not run gh: {exc}") from exc
    if completed.returncode != 0:
        raise CheckError(
            f"gh api {' '.join(args)} exited {completed.returncode}: "
            f"{completed.stderr.strip()}"
        )
    return completed.stdout


def _json_values(text: str) -> list[object]:
    """Every JSON value in a stream; --paginate prints one array per page."""
    decoder = json.JSONDecoder()
    values: list[object] = []
    index = 0
    while True:
        while index < len(text) and text[index].isspace():
            index += 1
        if index == len(text):
            return values
        try:
            value, index = decoder.raw_decode(text, index)
        except json.JSONDecodeError as exc:
            raise CheckError(f"the API returned malformed JSON: {exc}") from exc
        values.append(value)


def _expected_commits(repo: str, pr: int, head_sha: str) -> int:
    values = _json_values(_gh_api(f"repos/{repo}/pulls/{pr}"))
    if len(values) != 1 or not isinstance(values[0], dict):
        raise CheckError("the pull request response is not a single object")
    pull = values[0]
    head = pull.get("head")
    current = head.get("sha") if isinstance(head, dict) else None
    if current != head_sha:
        raise CheckError(
            f"the pull request head is {current!r}, not the {head_sha} this run "
            "was started for; the run for the newer head is the one that counts"
        )
    count = pull.get("commits")
    if type(count) is not int or count < 1:
        raise CheckError(f"the pull request reports {count!r} commits")
    if count > API_COMMIT_LIMIT:
        raise CheckError(
            f"the pull request has {count} commits; GitHub lists at most "
            f"{API_COMMIT_LIMIT}, so the rest cannot be checked. Split it."
        )
    return count


def _list_commits(repo: str, pr: int) -> list[object]:
    pages = _json_values(
        _gh_api("--paginate", f"repos/{repo}/pulls/{pr}/commits?per_page=100")
    )
    commits: list[object] = []
    for page in pages:
        if not isinstance(page, list):
            raise CheckError("a page of the commit list is not an array")
        commits.extend(page)
    return commits


def unverified(commits: list[object]) -> list[tuple[str, str]]:
    """Each commit GitHub does not verify, with the reason it gives."""
    failures: list[tuple[str, str]] = []
    for entry in commits:
        sha = entry.get("sha") if isinstance(entry, dict) else None
        if not isinstance(sha, str):
            failures.append(("<no sha>", "the API entry carries no sha"))
            continue
        commit = entry.get("commit") if isinstance(entry, dict) else None
        verification = commit.get("verification") if isinstance(commit, dict) else None
        if not isinstance(verification, dict):
            failures.append((sha, "no verification object"))
            continue
        if verification.get("verified") is not True:
            failures.append((sha, str(verification.get("reason", "no reason given"))))
    return failures


def check(repo: str, pr: int, head_sha: str) -> int:
    try:
        expected = _expected_commits(repo, pr, head_sha)
        commits = _list_commits(repo, pr)
        if len(commits) != expected:
            raise CheckError(
                f"the API listed {len(commits)} commits, the pull request reports "
                f"{expected}"
            )
        shas = {entry.get("sha") for entry in commits if isinstance(entry, dict)}
        if head_sha not in shas:
            raise CheckError(f"the head {head_sha} is not among the listed commits")
    except CheckError as exc:
        print(f"Cannot establish the pull request's commits: {exc}")
        return 1

    failures = unverified(commits)
    if failures:
        print(f"{len(failures)} of {len(commits)} commits are not verified by GitHub:")
        for sha, reason in failures:
            print(f"   {sha}  {reason}")
        print(f"Sign every commit and push again. See {SIGNING_DOCS}")
        return 1
    print(f"All {len(commits)} commits are verified by GitHub.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--pr", required=True, type=int)
    parser.add_argument("--head-sha", required=True)
    args = parser.parse_args()
    return check(args.repo, args.pr, args.head_sha)


if __name__ == "__main__":
    sys.exit(main())
