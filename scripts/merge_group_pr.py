#!/usr/bin/env python3
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Print the pull request number a merge-queue run was started for.

A `merge_group` event carries no pull request, only the queue's branch,
`refs/heads/gh-readonly-queue/<base>/pr-<number>-<sha>`. A check that judges
the pull request itself (its title, its commits' signatures) reads the number
from that ref. Anything else is refused, so a check never judges a pull request
it guessed.

    MERGE_GROUP_HEAD_REF=refs/heads/gh-readonly-queue/main/pr-823-<sha> \\
        python3 scripts/merge_group_pr.py
"""

from __future__ import annotations

import os
import re
import sys

QUEUE_REF = re.compile(
    r"refs/heads/gh-readonly-queue/main/pr-([1-9][0-9]*)-[0-9a-f]{40}"
)


def pull_request_number(ref: str) -> int:
    match = QUEUE_REF.fullmatch(ref)
    if match is None:
        raise ValueError(f"{ref!r} is not a merge-queue ref for main")
    return int(match.group(1))


def main() -> int:
    ref = os.environ.get("MERGE_GROUP_HEAD_REF", "")
    try:
        print(pull_request_number(ref))
    except ValueError as exc:
        print(f"merge_group_pr: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
