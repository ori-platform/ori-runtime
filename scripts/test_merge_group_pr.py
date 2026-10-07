#!/usr/bin/env python3
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Drive merge_group_pr.py through its command line."""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().with_name("merge_group_pr.py")
SHA = "c" * 40


def run(ref: str | None) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if k != "MERGE_GROUP_HEAD_REF"}
    if ref is not None:
        env["MERGE_GROUP_HEAD_REF"] = ref
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


class MergeGroupPrTest(unittest.TestCase):
    def test_a_queue_ref_names_its_pull_request(self) -> None:
        result = run(f"refs/heads/gh-readonly-queue/main/pr-823-{SHA}")
        self.assertEqual((result.returncode, result.stdout), (0, "823\n"))

    def test_anything_else_is_refused(self) -> None:
        for ref in (
            None,
            "",
            f"gh-readonly-queue/main/pr-823-{SHA}",
            f"refs/heads/gh-readonly-queue/release/pr-823-{SHA}",
            f"refs/heads/gh-readonly-queue/main/pr-0-{SHA}",
            f"refs/heads/gh-readonly-queue/main/pr-08-{SHA}",
            f"refs/heads/gh-readonly-queue/main/pr-823-{SHA[:39]}",
            f"refs/heads/gh-readonly-queue/main/pr-823-{SHA.upper()}",
            f"refs/heads/gh-readonly-queue/main/pr-823-{SHA}\n",
            f"refs/heads/gh-readonly-queue/main/pr-823-{SHA}x",
            "refs/heads/main",
        ):
            with self.subTest(ref=ref):
                result = run(ref)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertIn("not a merge-queue ref", result.stderr)


if __name__ == "__main__":
    unittest.main()
