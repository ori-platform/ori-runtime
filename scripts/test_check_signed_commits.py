#!/usr/bin/env python3
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Drive the signed-commits check through its command line against a fake gh."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().with_name("check_signed_commits.py")
HEAD = "b" * 40

FAKE_GH = """#!/usr/bin/env python3
import os, sys
key = "COMMITS" if "--paginate" in sys.argv else "PULL"
sys.stdout.write(os.environ["FAKE_" + key])
sys.stderr.write(os.environ.get("FAKE_" + key + "_ERR", ""))
sys.exit(int(os.environ.get("FAKE_" + key + "_RC", "0")))
"""


def commit(
    sha: str, verified: object = True, reason: str = "valid"
) -> dict[str, object]:
    return {
        "sha": sha,
        "commit": {"verification": {"verified": verified, "reason": reason}},
    }


def pull(commits: object = 2, head: str = HEAD) -> str:
    return json.dumps({"commits": commits, "head": {"sha": head}})


GOOD = [commit("a" * 40), commit(HEAD)]


class SignedCommitsTest(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        gh = Path(self._dir.name) / "gh"
        gh.write_text(FAKE_GH, encoding="utf-8")
        gh.chmod(0o755)

    def run_check(
        self, pull_json: str, commits_out: str, **extra: str
    ) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env["PATH"] = self._dir.name + os.pathsep + env.get("PATH", "")
        env["FAKE_PULL"] = pull_json
        env["FAKE_COMMITS"] = commits_out
        env.update(extra)
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--repo",
                "o/r",
                "--pr",
                "7",
                "--head-sha",
                HEAD,
            ],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

    def assert_refused(
        self, result: subprocess.CompletedProcess[str], text: str
    ) -> None:
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(text, result.stdout)
        self.assertNotIn("Traceback", result.stderr)

    def test_every_commit_verified_passes(self) -> None:
        result = self.run_check(pull(), json.dumps(GOOD))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("All 2 commits are verified", result.stdout)

    def test_pages_are_concatenated(self) -> None:
        result = self.run_check(
            pull(), json.dumps(GOOD[:1]) + "\n" + json.dumps(GOOD[1:])
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_unverified_commit_is_named_with_its_reason(self) -> None:
        bad = [commit("a" * 40, False, "unsigned"), commit(HEAD)]
        result = self.run_check(pull(), json.dumps(bad))
        self.assert_refused(result, "a" * 40 + "  unsigned")
        self.assertIn("signing-commits", result.stdout)

    def test_truthy_but_not_true_is_refused(self) -> None:
        result = self.run_check(
            pull(), json.dumps([commit("a" * 40, "true"), commit(HEAD)])
        )
        self.assert_refused(result, "a" * 40)

    def test_missing_verification_object_is_refused(self) -> None:
        bad = [{"sha": "a" * 40, "commit": {}}, commit(HEAD)]
        self.assert_refused(
            self.run_check(pull(), json.dumps(bad)), "no verification object"
        )

    def test_entry_without_sha_is_refused(self) -> None:
        bad = [{"commit": {"verification": {"verified": True}}}, commit(HEAD)]
        self.assert_refused(self.run_check(pull(), json.dumps(bad)), "<no sha>")

    def test_empty_list_is_refused(self) -> None:
        self.assert_refused(self.run_check(pull(), "[]"), "listed 0 commits")

    def test_no_output_is_refused(self) -> None:
        self.assert_refused(self.run_check(pull(), ""), "listed 0 commits")

    def test_zero_commit_pull_request_is_refused(self) -> None:
        self.assert_refused(self.run_check(pull(0), "[]"), "reports 0 commits")

    def test_list_api_error_is_refused(self) -> None:
        result = self.run_check(
            pull(), "", FAKE_COMMITS_RC="1", FAKE_COMMITS_ERR="HTTP 502"
        )
        self.assert_refused(result, "HTTP 502")

    def test_pull_api_error_is_refused(self) -> None:
        result = self.run_check(
            "", json.dumps(GOOD), FAKE_PULL_RC="1", FAKE_PULL_ERR="HTTP 404"
        )
        self.assert_refused(result, "HTTP 404")

    def test_malformed_json_is_refused(self) -> None:
        self.assert_refused(
            self.run_check(pull(), json.dumps(GOOD)[:-1]), "malformed JSON"
        )

    def test_non_array_page_is_refused(self) -> None:
        self.assert_refused(self.run_check(pull(), '{"message": "x"}'), "not an array")

    def test_over_the_api_limit_is_refused(self) -> None:
        self.assert_refused(self.run_check(pull(251), json.dumps(GOOD)), "at most 250")

    def test_truncated_listing_is_refused(self) -> None:
        self.assert_refused(
            self.run_check(pull(3), json.dumps(GOOD)), "listed 2 commits"
        )

    def test_moved_head_is_refused(self) -> None:
        self.assert_refused(
            self.run_check(pull(head="c" * 40), json.dumps(GOOD)), "not the"
        )

    def test_head_absent_from_listing_is_refused(self) -> None:
        stale = [commit("a" * 40), commit("c" * 40)]
        self.assert_refused(
            self.run_check(pull(), json.dumps(stale)), "not among the listed"
        )

    def test_missing_gh_is_refused(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--repo",
                "o/r",
                "--pr",
                "7",
                "--head-sha",
                HEAD,
            ],
            capture_output=True,
            text=True,
            env={"PATH": self._dir.name + "-absent"},
            check=False,
        )
        self.assert_refused(result, "could not run gh")


if __name__ == "__main__":
    unittest.main()
