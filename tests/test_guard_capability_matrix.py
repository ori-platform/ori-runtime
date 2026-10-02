# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The capability-matrix guard fails closed and is bypassed only by a reasoned line."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

GUARD = Path(__file__).resolve().parents[1] / "scripts" / "guard-capability-matrix.sh"
TEMPLATE = Path(__file__).resolve().parents[1] / ".github" / "PULL_REQUEST_TEMPLATE.md"
# The checklist line every pull request carried before the template changed.
OLD_TEMPLATE_LINE = (
    "- [x] If capability-impacting files changed but matrix update is intentionally "
    "not needed, add `[skip-cap-matrix]` in PR body with rationale"
)
REASONED = "[skip-cap-matrix] a log message wording change; no behaviour moves"


def _git(repo: Path, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    return subprocess.run(
        ["git", "-c", "commit.gpgsign=false", *args],
        cwd=repo,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "README.md").write_text("base\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "-m", "base")
    return tmp_path


def _change(repo: Path, *paths: str) -> tuple[str, str]:
    base = _git(repo, "rev-parse", "HEAD")
    for path in paths:
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"changed {path}\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "change")
    return base, _git(repo, "rev-parse", "HEAD")


def _guard(repo: Path, *refs: str, body: str = "") -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "GUARD_CAP_MATRIX_BYPASS_TEXT": body}
    raw = subprocess.run(
        ["bash", str(GUARD), *refs], cwd=repo, env=env, capture_output=True
    )
    # Decoded without newline translation, so a carriage return that reaches
    # the output stays visible to the assertions.
    return subprocess.CompletedProcess(
        raw.args, raw.returncode, raw.stdout.decode(), raw.stderr.decode()
    )


@pytest.mark.parametrize(
    "path",
    [
        "ori/reasoning/x.py",
        "ori/actions/x.py",
        "ori/security/x.py",
        "ori/safety/x.py",
        "ori/policy/x.py",
        "ori/runtime.py",
        "ori/skills/loader.py",
        "ori/config.py",
    ],
)
def test_a_capability_change_without_the_matrix_fails(repo: Path, path: str) -> None:
    result = _guard(repo, *_change(repo, path))
    assert result.returncode == 1, result.stdout
    assert path in result.stdout


def test_the_matrix_updated_alongside_passes(repo: Path) -> None:
    refs = _change(repo, "ori/safety/x.py", "docs/CAPABILITY_MATRIX.md")
    assert _guard(repo, *refs).returncode == 0


def test_a_change_outside_capability_code_passes(repo: Path) -> None:
    assert _guard(repo, *_change(repo, "docs/other.md", "ori/hal/x.py")).returncode == 0


@pytest.mark.parametrize(
    "body",
    [
        TEMPLATE.read_text(),
        OLD_TEMPLATE_LINE,
        "See [skip-cap-matrix] above.",
        "[skip-cap-matrix]",
        "[skip-cap-matrix] too short",
        "  - [x] [skip-cap-matrix] inside a checklist item, not a line of its own",
    ],
    ids=["template", "old-template-line", "quoted", "bare", "short", "checklist"],
)
def test_the_token_without_a_reasoned_line_does_not_bypass(
    repo: Path, body: str
) -> None:
    result = _guard(repo, *_change(repo, "ori/runtime.py"), body=body)
    assert result.returncode == 1, result.stdout


@pytest.mark.parametrize(
    "body",
    [REASONED, f"Intro.\n\n{REASONED}\n\nMore.", f"Intro.\r\n{REASONED}\r\n"],
    ids=["alone", "among-paragraphs", "crlf"],
)
def test_a_reasoned_bypass_line_passes_and_is_echoed(repo: Path, body: str) -> None:
    result = _guard(repo, *_change(repo, "ori/runtime.py"), body=body)
    assert result.returncode == 0, result.stdout
    assert f"  {REASONED}\n" in result.stdout


def test_missing_refs_fail(repo: Path) -> None:
    assert _guard(repo).returncode == 2
    assert _guard(repo, "HEAD").returncode == 2


def test_an_unresolvable_ref_fails(repo: Path) -> None:
    head = _git(repo, "rev-parse", "HEAD")
    assert _guard(repo, "0" * 40, head).returncode == 2
    assert _guard(repo, head, "no-such-ref").returncode == 2
