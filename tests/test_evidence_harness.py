# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The evidence harness must not be able to report a false green.

A harness that prints PASS without asserting anything produces evidence that
looks identical to real evidence. These checks pin the properties that make its
output trustworthy, so a later edit cannot quietly remove them.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

HARNESS = (
    Path(__file__).resolve().parent.parent
    / "docs"
    / "releases"
    / "evidence"
    / "harness-linux-functional.sh"
)


@pytest.fixture(scope="module")
def source() -> str:
    return HARNESS.read_text(encoding="utf-8")


def test_the_harness_is_committed_and_executable() -> None:
    """Prose without its proof procedure is a claim, not evidence."""
    assert HARNESS.is_file()
    assert HARNESS.stat().st_mode & 0o111


def test_it_is_valid_shell(source: str) -> None:
    completed = subprocess.run(
        ["bash", "-n", str(HARNESS)], capture_output=True, text=True
    )
    assert completed.returncode == 0, completed.stderr


def test_it_stops_on_the_first_failure(source: str) -> None:
    """`set -u` alone lets a failed step scroll past and still exit 0."""
    assert "set -euo pipefail" in source


def test_a_failed_claim_terminates_the_run(source: str) -> None:
    assert re.search(r"^fail\(\).*exit 1", source, re.M), "fail() must exit non-zero"


def test_blocked_claims_change_the_exit_status(source: str) -> None:
    """Partial coverage must never be mistaken for full coverage."""
    assert "BLOCKED=1" in source
    assert "exit 3" in source


def test_determinism_is_measured_not_asserted(source: str) -> None:
    """Building once proves nothing about reproducibility."""
    assert "build_once /tmp/b1" in source
    assert "build_once /tmp/b2" in source
    assert 'sha256sum "$ARTIFACT"' in source
    assert '[ "$h1" = "$h2" ]' in source


def test_provenance_comes_from_a_digest_verified_archive(source: str) -> None:
    """A worktree pointer or dirty tree makes an in-container commit ambiguous.

    The caller archives an exact commit; the harness only confirms it received
    those bytes, and refuses to run if it cannot.
    """
    # Prose may mention git; what must be absent is any invocation of it.
    # `git archive` appears in the usage hint telling the caller how to
    # produce the archive; that is guidance, not an invocation.
    for invocation in ("git rev-parse", "git -C", "$(git ", "git status"):
        assert invocation not in source, f"harness must not run {invocation!r}"
    assert 'sha256sum "$ARCHIVE"' in source
    assert '"$actual_sha" = "$ARCHIVE_SHA256"' in source
    assert '[ "${#EXPECTED_COMMIT}" -eq 40 ]' in source


def test_the_ephemeral_key_is_removed_on_exit(source: str) -> None:
    assert "trap cleanup EXIT" in source
    assert "rm -f /tmp/dev-key.pem" in source


def test_no_fixed_signing_seed_is_embedded(source: str) -> None:
    """A reusable private seed does not belong in a committed artefact."""
    assert "from_private_bytes" not in source
    assert "Ed25519PrivateKey.generate()" in source


@pytest.mark.parametrize(
    "mode",
    ["original name", "renamed copy", "absolute path", "relative path", "piped"],
)
def test_every_dispatch_mode_asserts_an_exact_exit_status(
    source: str, mode: str
) -> None:
    """`PASS(exit $?)` prints PASS whatever happened, so each mode is pinned.

    Relative-path dispatch was silently dropped in one revision while the
    evidence record still claimed it; enumerating the modes prevents that.
    """
    lines = [
        line
        for line in source.splitlines()
        if f"dispatch: {mode}" in line and "assert_exit" in line
    ]
    assert lines, f"no exact-exit assertion for dispatch mode {mode!r}"


def test_piped_without_arguments_is_asserted_separately(source: str) -> None:
    assert "dispatch: piped without arguments exits 2" in source


@pytest.mark.parametrize(
    ("case", "code"),
    [
        ("tampered artifact", "artifact_integrity_mismatch"),
        ("malformed envelope", "invalid_signature_envelope"),
        ("incorrect signature", "signature_verification_failed"),
    ],
)
def test_each_tamper_case_expects_its_own_stable_code(
    source: str, case: str, code: str
) -> None:
    """Three distinct rejection paths; a broad grep would conflate them."""
    assert f'assert_contains "{case} code" "{code}"' in source


def test_the_incorrect_signature_case_stays_well_formed(source: str) -> None:
    """Blanking the field tests envelope parsing, not the cryptography."""
    assert 'removeprefix("ed25519:")' in source
    assert "raw[0] ^= 0xFF" in source


def test_no_claim_prints_pass_without_asserting(source: str) -> None:
    """Guards against reintroducing `P "label" "PASS(exit $?)"`."""
    assert not re.search(r"PASS\(exit", source)


def test_the_stale_path_check_cannot_be_vacuous(source: str) -> None:
    """It passed once because venv/bin did not exist. It must be reachable
    only where the installed release demonstrably survived."""
    index = source.index("no stale staging paths")
    preceding = source[:index]
    assert "console script $script executes" in preceding, (
        "the stale-path check must sit after console scripts have been proven "
        "to exist, so it cannot pass on an absent directory"
    )


def test_the_artifact_tamper_writes_a_real_null_byte(source: str) -> None:
    """`printf '\\x00'` writes four literal characters, corrupting the file
    with the wrong bytes and passing for an unintended reason."""
    assert "printf '\\\\x00'" not in source
    assert "printf '\\x00'" in source


def test_the_artifact_tamper_proves_the_file_changed(source: str) -> None:
    assert '[ "$before_tamper" != "$after_tamper" ]' in source


def test_the_driver_derives_the_digest_from_the_commit() -> None:
    """A separately typed commit is not proof of archive identity."""
    driver = HARNESS.parent / "run-evidence.sh"
    assert driver.is_file() and driver.stat().st_mode & 0o111
    text = driver.read_text(encoding="utf-8")
    assert "archive --format=tar" in text and "--output=" in text
    assert "rev-parse " in text
    assert "STATUS=$?" in text, "harness status must be captured directly"
    assert "| tail" not in text, "status must not come through a pipeline"


def test_the_platform_tuple_is_verified_not_just_labelled(source: str) -> None:
    """Otherwise the record could describe Pi evidence produced on x86_64."""
    assert '[ "$actual_arch" = "$tuple_arch" ]' in source
    assert '[ "$actual_python" = "$tuple_python" ]' in source
    assert '[ "$actual_distro" = "$EXPECTED_DISTRO" ]' in source
    assert "/etc/os-release" in source


def test_os_release_cannot_clobber_the_harness_version(source: str) -> None:
    """/etc/os-release defines VERSION; sourcing it into the harness shell
    overwrote the runtime version and was built into the bundle."""
    assert "\n. /etc/os-release" not in source, "must not source into this shell"
    assert '"$(. /etc/os-release && echo' in source


def test_piped_without_arguments_proves_it_showed_usage(source: str) -> None:
    """Exit 2 alone could come from any unrelated failure."""
    assert 'assert_contains "dispatch: piped without arguments shows usage"' in source


def test_the_driver_records_immutable_image_identity() -> None:
    """A tag can later point at different bytes."""
    text = (HARNESS.parent / "run-evidence.sh").read_text(encoding="utf-8")
    assert "docker image inspect --format '{{.Id}}'" in text
    assert "RepoDigests" in text
    assert "image id" in text


def test_the_driver_hashes_both_scripts() -> None:
    """Evidence must describe the bytes that ran; an edit afterwards
    invalidates the run rather than silently inheriting it."""
    text = (HARNESS.parent / "run-evidence.sh").read_text(encoding="utf-8")
    assert 'HARNESS_SHA256="$(digest_of "$HARNESS")"' in text
    assert 'DRIVER_SHA256="$(digest_of "${BASH_SOURCE[0]}")"' in text
    assert "harness sha256  $HARNESS_SHA256" in text
    assert "driver sha256   $DRIVER_SHA256" in text


def test_the_digest_helper_is_defined_before_use() -> None:
    text = (HARNESS.parent / "run-evidence.sh").read_text(encoding="utf-8")
    assert text.index("digest_of() {") < text.index('digest_of "$ARCHIVE"')
    assert text.index("digest_of() {") < text.index('digest_of "$HARNESS"')


def test_the_harness_revision_is_current() -> None:
    """A run is evidence for one revision; bump it whenever bytes change."""
    source = HARNESS.read_text(encoding="utf-8")
    assert 'HARNESS_REVISION="7"' in source


def test_the_driver_runs_the_resolved_image_not_the_tag() -> None:
    """A tag can be repointed between `docker image inspect` and `docker run`,
    recording one image while running another."""
    text = (HARNESS.parent / "run-evidence.sh").read_text(encoding="utf-8")
    assert '    "$IMAGE_ID" \\\n    bash /evidence/harness' in text, (
        "docker run must be given $IMAGE_ID, not the mutable $IMAGE tag"
    )


def test_the_driver_uses_a_temporary_directory() -> None:
    """`mktemp ... .tar` appends to the created path, leaking the original."""
    text = (HARNESS.parent / "run-evidence.sh").read_text(encoding="utf-8")
    assert "mktemp -d" in text
    assert "trap 'rm -rf \"$WORKDIR\"' EXIT" in text
    assert 'mktemp -t "ori-evidence-XXXXXX").tar' not in text


def test_it_declares_what_it_cannot_prove(source: str) -> None:
    header = source[: source.index("set -euo pipefail")]
    for absent in ("KMS", "redirect", "reverification"):
        assert absent in header, f"header must disclaim {absent}"
