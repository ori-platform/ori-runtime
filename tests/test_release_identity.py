# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A release tag and the packaged version must name exactly one build.

The release pipeline carries two version vocabularies — SemVer for the git tag,
the signature envelope, the bundle manifest and the artifact name; PEP 440 for
the wheel, its metadata and what the installer reads back on the device. They
agree for every final release and diverge for every candidate, so nothing about
`v2.3.0` exercised the disagreement.

`v2.4.0-rc.1` and `v2.4.0-rc.2` were spent finding that out. Both cleared the
protection preflight and the full test matrix; the first failed because the
build compared the whole tag against the packaged version, the second because
the wheel and the bundle were compared as strings. Each failure landed after the
tag was immutable, so neither candidate could be rebuilt.

These tests pin the invariant that would have caught both: one conversion
authority, consulted at every site where the vocabularies meet, and consulted in
preflight before a bundle or a signing credential exists.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from ori.security.release_bundles import ReleaseBundleError, distribution_version

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from check_release_identity import resolve_release_identity  # noqa: E402

_REPO = Path(__file__).resolve().parents[1]
_WORKFLOW = _REPO / ".github" / "workflows" / "release.yml"
_SCRIPT = _REPO / "scripts" / "check_release_identity.py"


def _pyproject(tmp_path: Path, version: str) -> Path:
    path = tmp_path / "pyproject.toml"
    path.write_text(
        f'[project]\nname = "ori-runtime"\nversion = "{version}"\n', encoding="utf-8"
    )
    return path


def _workflow() -> dict:
    return yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))


# ── The conversion authority ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("runtime_version", "expected"),
    [
        ("2.4.0", "2.4.0"),
        ("2.4.0-rc.3", "2.4.0rc3"),
        ("2.4.0-rc.10", "2.4.0rc10"),
        ("10.0.0-rc.1", "10.0.0rc1"),
    ],
)
def test_canonical_identities_map_to_their_pep440_spelling(
    runtime_version: str, expected: str
) -> None:
    assert distribution_version(runtime_version) == expected


@pytest.mark.parametrize(
    "runtime_version",
    [
        "2.4.0-rc3",  # the same candidate under a second spelling
        "2.4.0rc3",  # the PEP 440 spelling is not a release identity
        "2.4.0-beta.1",  # only rc is canonical
        "2.4.0-RC.3",
        "2.4.0-rc.0",
        "2.4.0-rc.03",
        "02.4.0",
        "2.4.0-rc.3+build",
        "v2.4.0",
        "2.4.0-rc.1-rc.2",
        "",
    ],
)
def test_ambiguous_or_malformed_identities_are_refused(runtime_version: str) -> None:
    """One build must have one spelling.

    Accepting `2.4.0-rc3` alongside `2.4.0-rc.3` would let one candidate be
    published under two artifact names, each with its own signature.
    """
    with pytest.raises(ReleaseBundleError):
        distribution_version(runtime_version)


# ── Tag against packaged version ──────────────────────────────────────────────


@pytest.mark.parametrize(
    ("tag", "declared"),
    [("v2.4.0", "2.4.0"), ("v2.4.0-rc.3", "2.4.0rc3"), ("v3.0.0-rc.1", "3.0.0rc1")],
)
def test_a_tag_matching_its_packaged_version_resolves(
    tmp_path: Path, tag: str, declared: str
) -> None:
    assert resolve_release_identity(tag, _pyproject(tmp_path, declared)) == tag[1:]


@pytest.mark.parametrize(
    ("tag", "declared", "reason"),
    [
        ("v2.4.0-rc.3", "2.4.0", "the candidate would carry the final wheel"),
        ("v2.4.0", "2.4.0rc3", "the final would carry a candidate wheel"),
        ("v2.4.0-rc.3", "2.4.0rc2", "a candidate must not build another candidate"),
        ("v2.5.0", "2.4.0", "an unrelated release"),
        ("v2.4.1", "2.4.0", "an unrelated patch"),
    ],
)
def test_a_tag_naming_a_different_build_is_refused(
    tmp_path: Path, tag: str, declared: str, reason: str
) -> None:
    with pytest.raises(ValueError, match="version"):
        resolve_release_identity(tag, _pyproject(tmp_path, declared))
    assert reason


def test_a_non_canonical_tag_is_refused_before_the_version_is_read(
    tmp_path: Path,
) -> None:
    """The trigger is a glob, so it admits tags this authority must reject."""
    with pytest.raises(ValueError, match="canonical release identity"):
        resolve_release_identity("v2.4.0-rc3", _pyproject(tmp_path, "2.4.0rc3"))


def test_a_tag_without_its_v_prefix_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="does not start with"):
        resolve_release_identity("2.4.0", _pyproject(tmp_path, "2.4.0"))


# ── The shipped script, as the workflow invokes it ────────────────────────────


def test_the_script_emits_the_version_the_bundle_is_built_with(tmp_path: Path) -> None:
    """The build step appends this to GITHUB_OUTPUT verbatim.

    A stray line on stdout becomes a step output, so the contract is the whole
    stream, not a substring of it.
    """
    _pyproject(tmp_path, "2.4.0rc3")

    completed = subprocess.run(
        [sys.executable, str(_SCRIPT), "--tag", "v2.4.0-rc.3"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "version=2.4.0-rc.3\n"


def test_the_script_fails_without_emitting_a_version(tmp_path: Path) -> None:
    """A refused tag must leave GITHUB_OUTPUT empty, not partially written."""
    _pyproject(tmp_path, "2.4.0")

    completed = subprocess.run(
        [sys.executable, str(_SCRIPT), "--tag", "v2.4.0-rc.3"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert completed.stdout == ""
    assert "2.4.0rc3" in completed.stderr


def test_the_repository_tag_and_packaged_version_agree() -> None:
    """The checked-in version must be releasable under some canonical tag.

    A packaged version no tag can name is a release that cannot be cut.
    """
    declared = (_REPO / "pyproject.toml").read_text(encoding="utf-8")
    version = next(
        line.split("=", 1)[1].strip().strip('"')
        for line in declared.splitlines()
        if line.startswith("version = ")
    )
    candidates = [version, version.replace("rc", "-rc.")]
    assert any(
        distribution_version(candidate) == version
        for candidate in candidates
        if _is_canonical(candidate)
    ), f"packaged version {version!r} is not reachable from any canonical tag"


def _is_canonical(runtime_version: str) -> bool:
    try:
        distribution_version(runtime_version)
    except ReleaseBundleError:
        return False
    return True


# ── The workflow must consult the authority, and consult it early ─────────────


def test_preflight_refuses_a_bad_tag_before_any_bundle_or_credential() -> None:
    """Both spent candidates failed in the build job, after the tag was fixed.

    Preflight runs before any bundle exists and before the signing environment
    issues a credential, so it is the only place where refusing a tag still
    leaves something recoverable.
    """
    preflight = _workflow()["jobs"]["preflight"]
    steps = [step.get("run", "") for step in preflight["steps"]]

    assert any("check_release_identity.py" in step for step in steps), (
        "preflight does not verify that the tag and the packaged version agree"
    )


def test_the_build_takes_its_version_from_the_same_authority() -> None:
    """Re-deriving the version in shell is how the two checks disagreed."""
    jobs = _workflow()["jobs"]
    build = next(job for name, job in jobs.items() if name.startswith("build"))
    identity = next(step for step in build["steps"] if step.get("id") == "identity")

    assert "check_release_identity.py" in identity["run"]
    assert "%%-" not in identity["run"], (
        "the build step still truncates the tag in shell instead of resolving "
        "it through the release-identity authority"
    )


def test_the_trigger_admits_tags_only_the_authority_can_refuse() -> None:
    """The glob cannot express the canonical form, so the authority must exist.

    If the trigger were ever narrowed to final releases only, the pre-release
    handling here would be dead weight and should be revisited with it.
    """
    triggers = _workflow().get("on") or _workflow().get(True)
    patterns = triggers["push"]["tags"]

    assert any("-" in pattern for pattern in patterns), (
        "the trigger no longer accepts pre-release tags; the release-identity "
        "authority should be revisited together with it"
    )
