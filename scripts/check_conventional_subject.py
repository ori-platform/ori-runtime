# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Hold a commit subject, or a pull request title, to Conventional Commits.

Both are checked because they are the same artifact. GitHub's squash merge uses
the pull request title as the commit message whenever a pull request carries
more than one commit, and the first commit's message only when it carries
exactly one — so a prose title on a multi-commit pull request lands a
non-conventional commit on the default branch, having passed every commit-level
gate on the way.

The pattern lives here rather than inline in the hook so the commit-message
check and the pull request check cannot drift apart.

    python3 scripts/check_conventional_subject.py --commit-msg-file <path>
    python3 scripts/check_conventional_subject.py --env PR_TITLE
"""

from __future__ import annotations

import argparse
import os
import re
import sys

TYPES = (
    "feat",
    "fix",
    "docs",
    "test",
    "skill",
    "refactor",
    "perf",
    "build",
    "ci",
    "chore",
    "revert",
    "security",
)
PATTERN = re.compile(r"^(" + "|".join(TYPES) + r")(\([a-z0-9/-]+\))?: .{1,100}$")


def check(subject: str, source: str) -> int:
    subject = subject.split("\n")[0].strip()
    if PATTERN.match(subject):
        return 0
    print(f"{source} does not follow Conventional Commits format.")
    print(f"   Got: {subject!r}")
    print("   Expected: type(scope): description")
    print(f"   Valid types: {' '.join(TYPES)}")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--commit-msg-file")
    group.add_argument(
        "--env",
        help="Name of an environment variable holding the subject. The value is "
        "read from the environment rather than passed as an argument, so a "
        "title containing shell metacharacters cannot reach a shell.",
    )
    args = parser.parse_args()

    if args.commit_msg_file:
        with open(args.commit_msg_file, encoding="utf-8") as handle:
            return check(handle.read(), "Commit message")

    value = os.environ.get(args.env)
    if value is None:
        print(f"{args.env} is not set; nothing to check.")
        return 1
    return check(value, "Pull request title")


if __name__ == "__main__":
    sys.exit(main())
