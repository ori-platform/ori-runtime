# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The release workflow must build every tag its trigger accepts.

`release.yml` triggers on `v*.*.*` **and** `v*.*.*-*`, so a release candidate
is a tag the workflow invites. Its identity step compared the whole tag against
the version in `pyproject.toml`, which no pre-release tag can equal — so
`v2.4.0-rc.1` passed the protection preflight, ran the tests, and then failed
all four bundle builds. Tags are immutable, so that spent the candidate.

These tests execute the step exactly as it ships, extracted from the workflow
by parsing the YAML rather than by pattern-matching the file.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

_WORKFLOW = (
    Path(__file__).resolve().parents[1] / ".github" / "workflows" / "release.yml"
)


def _identity_script() -> str:
    """The `run:` body of the build job's identity step, as it ships."""
    workflow = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    for job in workflow["jobs"].values():
        for step in job.get("steps") or []:
            if step.get("id") == "identity":
                return str(step["run"])
    raise AssertionError("no step with id 'identity' in release.yml")


def _run_identity(tmp_path: Path, tag: str, declared: str):
    """Run the step against *declared* in pyproject with *tag* as the ref."""
    (tmp_path / "pyproject.toml").write_text(
        f'[project]\nname = "ori-runtime"\nversion = "{declared}"\n', encoding="utf-8"
    )
    output = tmp_path / "github_output"
    output.touch()
    # The step reads the tagged commit's timestamp, so it needs a repository.
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "t"],
        cwd=tmp_path,
        check=True,
    )
    # The step calls `python`, which the CI runner provides via setup-python.
    # A shim supplies the same name here without altering the shipped script.
    shim_dir = tmp_path / "bin"
    shim_dir.mkdir()
    shim = shim_dir / "python"
    shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    shim.chmod(0o755)

    completed = subprocess.run(
        ["bash", "-c", _identity_script()],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env={
            "PATH": f"{shim_dir}:{os.environ.get('PATH', '')}",
            "GITHUB_REF_NAME": tag,
            "GITHUB_OUTPUT": str(output),
            "HOME": str(tmp_path),
        },
    )
    return completed, output.read_text(encoding="utf-8")


pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("git") is None,
    reason="bash and git are required to execute the workflow step",
)


@pytest.mark.parametrize(
    "tag",
    ["v2.4.0", "v2.4.0-rc.1", "v2.4.0-rc.2", "v2.4.0-beta.1"],
    ids=["final", "rc1", "rc2", "beta"],
)
def test_identity_accepts_every_tag_shape_the_trigger_allows(tmp_path, tag):
    """A candidate for 2.4.0 must build against a pyproject declaring 2.4.0.

    The workflow trigger accepts these tags; rejecting them here made the two
    disagree, so a tag could be published and then never built.
    """
    completed, output = _run_identity(tmp_path, tag, "2.4.0")

    assert completed.returncode == 0, completed.stderr
    assert f"version={tag[1:]}" in output


@pytest.mark.parametrize(
    "tag", ["v2.5.0", "v2.4.1", "v2.4.1-rc.1"], ids=["minor", "patch", "patch_rc"]
)
def test_identity_rejects_a_tag_for_a_different_release(tmp_path, tag):
    """Loosening the comparison must not let an unrelated version through."""
    completed, _ = _run_identity(tmp_path, tag, "2.4.0")

    assert completed.returncode == 1
    assert "does not match pyproject version" in completed.stderr


def test_bundle_version_keeps_the_prerelease_suffix(tmp_path):
    """The emitted version names the bundle, so a candidate must stay distinct.

    Comparing on the release portion must not also *strip* the suffix: an rc
    bundle named `ori-runtime-2.4.0-...` would be indistinguishable from the
    final artifact.
    """
    _, output = _run_identity(tmp_path, "v2.4.0-rc.1", "2.4.0")

    assert "version=2.4.0-rc.1" in output
    assert "version=2.4.0\n" not in output


def test_trigger_and_identity_agree_on_prerelease_tags():
    """Pin the relationship, not just the behaviour.

    If the trigger stops accepting pre-release tags, this check becomes dead
    weight; if it accepts a shape the identity step rejects, candidates break
    after the tag is already immutable.
    """
    workflow = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    # `on` parses as the boolean True in YAML 1.1.
    triggers = workflow.get("on") or workflow.get(True)
    tag_patterns = triggers["push"]["tags"]

    assert any("-" in pattern for pattern in tag_patterns), (
        "the trigger no longer accepts pre-release tags; the identity step's "
        "suffix handling should be revisited together with it"
    )
    assert "base=" in _identity_script(), (
        "the identity step no longer separates the release portion from a "
        "pre-release suffix, but the trigger still accepts pre-release tags"
    )
