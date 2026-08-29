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
    Path(__file__).resolve().parent.parent.parent
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
    assert 'HARNESS_REVISION="8"' in source


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


# --- the systemd-host harness and the artifact builder -----------------------
#
# These run as root on an operator's machine. Nothing here executes them; each
# claim is a property of the text that would run, chosen because getting it
# wrong produces a PASS for something never tested.

HOST_HARNESS = Path("docs/releases/evidence/harness-systemd-host.sh")
ARTIFACT_BUILDER = Path("docs/releases/evidence/build-local-artifact.sh")
RUNBOOK = Path("docs/releases/evidence/systemd-host-runbook.md")


def _host_harness() -> str:
    return HOST_HARNESS.read_text(encoding="utf-8")


def _phase(name: str) -> str:
    """One phase's body, so a claim cannot be satisfied by another phase.

    Matching anywhere in the file lets `--device-id` in the rollback phase
    vouch for an install phase that omits it.
    """
    source = _host_harness()
    start = source.index(f"phase_{name}() {{")
    remainder = source[start + 1 :]
    following = [
        remainder.index(f"phase_{other}() {{")
        for other in ("install", "persist", "rollback", "uninstall")
        if f"phase_{other}() {{" in remainder
    ]
    return remainder[: min(following)] if following else remainder


def test_the_install_phase_supplies_the_identity_unattended_mode_requires() -> None:
    """`--unattended` without identity is rejected before anything installs.

    A phase that omits them cannot reach activation at all, so every claim
    after it would describe an installation that never happened.
    """
    install = _phase("install")

    for option in ("--device-id", "--name", "--location"):
        assert option in install, f"install phase omits {option}"


def test_the_install_phase_asserts_the_identity_it_supplied() -> None:
    """Producing a config is not evidence that it holds the right values."""
    source = _host_harness()

    assert "config carries the evidence device id" in source
    assert "doctor reports the evidence device" in source


def test_every_install_asserts_the_release_under_test() -> None:
    """Each phase must bind its claims to the requested version.

    Reboot persistence for some other active release is not persistence for
    this candidate.
    """
    assert "install reports the requested version" in _phase("install")
    persist = _phase("persist")
    # The record is version-bound inside `evidence_host.require_reboot_since`,
    # which is tested there. What remains a property of the shell is that it
    # passes the version at all: omit it and the phase would vouch for
    # whichever release the host happens to be running.
    assert '--version "$version"' in persist, (
        "persistence does not bind its claim to the release under test"
    )
    assert "doctor still reports the release under test" in persist


def test_rollback_requires_the_exact_stable_failure_code() -> None:
    """ "Some nonzero exit" is satisfied by never activating anything.

    An argument error, a signature rejection or a target mismatch all exit
    nonzero without installing, and `current` would not have moved — which is
    indistinguishable from a successful rollback unless the code is checked.
    """
    source = _host_harness()

    assert "post_install_health_failed" in source
    assert "the failed candidate was removed" in source


def test_rollback_passes_the_expected_version() -> None:
    """Without it the candidate can be refused for the wrong reason."""
    source = _host_harness()
    rollback = source[
        source.index("phase_rollback()") : source.index("phase_uninstall()")
    ]

    assert "--expected-version" in rollback


def test_the_artifact_is_verified_before_it_is_extracted_or_executed() -> None:
    """Otherwise the artifact's own code is what vouches for the artifact.

    This harness runs as root: digest and signature are checked with tooling
    that predates the bundle, before `tar` or `pip` touch it.
    """
    # The call site inside each phase, not the function definition, which
    # necessarily precedes everything and therefore proves nothing.
    for name in ("install", "rollback"):
        body = _phase(name)
        if "tar -C" not in body:
            continue
        assert "verify_artifact " in body, f"{name} extracts without verifying"
        assert body.index("verify_artifact ") < body.index("tar -C"), (
            f"{name} extracts before it verifies"
        )
    # The digest and signature checks themselves live in `evidence_host.py`,
    # against tooling that predates the artifact; they are exercised there
    # with real Ed25519 material rather than asserted as text here.
    assert "openssl" in Path("scripts/evidence_host.py").read_text(encoding="utf-8")


def test_the_release_tooling_is_installed_with_hashes_enforced() -> None:
    """The bootstrap's sequence: hash-locked dependencies, then the one wheel."""
    source = _host_harness()

    assert "--require-hashes" in source
    assert "--no-deps" in source


def test_the_harness_writes_only_to_a_private_root_owned_workspace() -> None:
    """A predictable /tmp path is writable by every account on the host.

    A root process writing there can be aimed elsewhere by a symlink planted
    in advance.
    """
    source = _host_harness()

    assert "mktemp -d" in source
    assert "chmod 700" in source
    assert "/tmp/rollback" not in source


def test_the_builder_does_not_claim_byte_identity_with_production() -> None:
    """It substitutes the packaged registry, so the bytes genuinely differ."""
    source = ARTIFACT_BUILDER.read_text(encoding="utf-8")

    # Matched on the word alone: the sentence wraps across comment lines, and
    # an assertion on the wrapped phrasing would fail on reflow rather than on
    # the claim it is meant to police.
    assert "byte-for-byte" not in source
    assert "byte-identical" in source


def test_the_builder_resolves_its_output_directory_before_changing_directory() -> None:
    """A relative outdir would land inside the tree the cleanup trap removes."""
    source = ARTIFACT_BUILDER.read_text(encoding="utf-8")
    resolve = source.index('OUTDIR="$(cd "$OUTDIR" && pwd)"')
    change = source.index('cd "$SOURCE"')

    assert resolve < change


def test_both_new_scripts_state_what_they_do_not_prove() -> None:
    """Evidence that overstates itself is worse than none."""
    for path in (HOST_HARNESS, ARTIFACT_BUILDER):
        source = path.read_text(encoding="utf-8")
        assert "KMS" in source, f"{path} does not disclaim signing custody"
        assert "publication" in source, f"{path} does not disclaim publication"


def test_the_builder_enforces_the_target_tuple_it_labels() -> None:
    """A tuple is a claim about this machine, not a filename.

    Building with the host default interpreter while naming the artifact for
    another version produces a bundle that fails only once it reaches a device.
    """
    source = ARTIFACT_BUILDER.read_text(encoding="utf-8")

    # The comparison, not the mention: `uname -m` survives having its result
    # compared against nothing.
    assert '[ "$HOST_ARCH" = "$TUPLE_ARCH" ]' in source, (
        "the builder never compares the architecture it claims"
    )
    assert 'BUILD_PYTHON="$(command -v "python$TUPLE_PYTHON"' in source
    assert '[ "$BUILD_PYTHON_VERSION" = "$TUPLE_PYTHON" ]' in source, (
        "the selected interpreter is never asked its own version"
    )


def test_the_builder_builds_with_the_interpreter_it_verified() -> None:
    """`build-wheelhouse.sh` defaults to ambient python3 without ORI_PYTHON.

    Verifying one interpreter and building with another leaves the tuple as
    decoration.
    """
    source = ARTIFACT_BUILDER.read_text(encoding="utf-8")

    # The venv the hashes were enforced into, not the bare system interpreter:
    # `pip download` and `pip wheel` run from ORI_PYTHON, so pointing it at
    # $BUILD_PYTHON leaves ambient packages in control of the build.
    assert 'ORI_PYTHON="$PY"' in source
    assert 'ORI_PYTHON="$BUILD_PYTHON"' not in source
    assert 'venv "$WORKDIR/venv"' in source
    assert '"$BUILD_PYTHON" -m venv' in source


def test_the_builder_installs_hash_locked_tooling() -> None:
    """Live resolution puts unpinned code into what signs the artifact."""
    source = ARTIFACT_BUILDER.read_text(encoding="utf-8")

    assert "--require-hashes" in source
    assert "requirements/dev.txt" in source
    assert "pip install --quiet cryptography" not in source


def test_persistence_requires_a_different_boot_not_a_low_uptime() -> None:
    """Installing just after a boot and running the phase at once passes any
    uptime bound while nothing has restarted.

    Comparing the boot ids is `require_reboot_since`, tested against both
    outcomes in `test_host.py`. The shell must reach it, and must not
    substitute a weaker signal of its own.
    """
    install = _phase("install")
    persist = _phase("persist")

    assert "evidence record" in install, "the install phase records no boot"
    assert "evidence require-reboot" in persist, "persistence checks no boot"
    assert "/proc/uptime" not in persist, "uptime is not evidence of a reboot"


def test_the_install_phase_proves_the_launcher_works() -> None:
    """A launcher conflict is non-fatal, so an install can report healthy with
    no `ori` command at all — invisible to a doctor run by absolute path."""
    install = _phase("install")

    assert 'assert_field "launcher was installed" launcher_installed true' in install
    assert "doctor runs through the launcher" in install
    assert '"$launcher" doctor' in install


def test_the_clean_state_check_rejects_a_pre_existing_launcher() -> None:
    """An `ori` already on PATH would be the thing the run then exercises."""
    install = _phase("install")

    # The guard itself: the path and the label both survive the condition
    # being replaced with one that is always true.
    assert "[ ! -e /usr/local/bin/ori ]" in install, (
        "the clean-state phase does not reject a pre-existing launcher"
    )


def test_the_builder_checks_the_version_with_the_tuple_interpreter() -> None:
    """The host default may be older than the source supports.

    Reading pyproject with a 3.10 default fails on `tomllib` before the 3.12 the
    tuple asked for is ever discovered — a failure about the machine dressed as
    a failure about the release.
    """
    source = ARTIFACT_BUILDER.read_text(encoding="utf-8")
    discovery = source.index('BUILD_PYTHON="$(command -v')
    check = source.index('- "$RELEASE_VERSION"')

    assert discovery < check, "the version check runs before interpreter discovery"
    assert '"$BUILD_PYTHON" - "$RELEASE_VERSION"' in source, (
        "the version check does not use the tuple's interpreter"
    )


def test_the_host_harness_derives_its_interpreter_from_the_signed_target() -> None:
    """A correctly built 3.12 artifact driven by a 3.10 installer is refused
    with `unsupported_target` before installation is ever attempted.

    Reading the target, matching the host architecture and asking the
    interpreter its own version are `evidence_host.py`, tested there against a
    fake interpreter that lies. The shell must derive the interpreter from the
    signature rather than name one itself.
    """
    install = _phase("install")

    assert "select_tooling_interpreter" in install
    assert 'select-python --signature "$signature"' in _host_harness(), (
        "the interpreter is not derived from the signed envelope"
    )


def test_the_host_harness_builds_tooling_with_that_interpreter() -> None:
    """Selecting an interpreter and then using another leaves it decorative."""
    source = _host_harness()

    assert "python3 -m venv" not in source, "the host default still builds tooling"
    assert '"${TOOLING_PYTHON:?' in source


def test_the_install_phase_records_its_boot_only_after_every_assertion() -> None:
    """A record written early survives the assertions after it failing.

    The persistence phase would then treat a failed installation as its
    provenance — the run it vouches for never having completed.
    """
    install = _phase("install")
    record = install.index("evidence record")

    for label in (
        "launcher was installed",
        "config carries the evidence device id",
        "unit is enabled for boot",
        "health socket exists",
        "installed doctor reports no blocking failure",
    ):
        assert label in install, f"install no longer asserts {label!r}"
        assert install.index(label) < record, (
            f"the boot record is written before {label!r} is asserted"
        )


def test_the_host_harness_revision_is_current() -> None:
    """A run is evidence for one revision; bump it whenever bytes change.

    The container harness carries this pin already. Without the same one here,
    a record naming revision 6 could describe any of several scripts.
    """
    assert 'HARNESS_REVISION="14"' in _host_harness()


def _uninstall_commands() -> str:
    """Lines the uninstall phase executes, without its closing report.

    `userdel` appears there as guidance; matching the whole phase would confuse
    printing an instruction with carrying it out.
    """
    return "\n".join(
        line
        for line in _phase("uninstall").splitlines()
        if not line.lstrip().startswith(("printf", "#"))
    )


def test_the_uninstall_phase_removes_nothing_recursively() -> None:
    """As root, `rm -rf` on a system path needs stronger authority than a grep.

    Authorising it on the evidence device id appearing anywhere in the YAML
    would rest on a string that can occur in any field, including a real
    deployment's. `rmdir` needs no such judgement: it removes a directory only
    when the directory is already empty.
    """
    executed = _uninstall_commands()

    assert "rm -rf" not in executed, "the phase removes a tree recursively"
    assert "rm -r " not in executed
    assert 'grep -q "$EVIDENCE_DEVICE_ID"' not in executed, (
        "a string match is not proof the harness owns this installation"
    )
    assert 'rmdir "$SYSTEM_ROOT"' in executed


def test_the_installer_empties_the_root_before_rmdir_takes_it() -> None:
    """`rmdir` refuses a non-empty directory, so its success is the proof.

    It cannot say *which* path survived, so each managed path is named. The
    installer does the deleting; the harness only takes away what is left.
    """
    executed = _uninstall_commands()
    removal = executed.index('rmdir "$SYSTEM_ROOT"')

    assert "--remove-data" in executed, "data would survive and block a re-run"
    named = re.search(r"for leftover in ([\w ]+); do", executed)
    assert named, "the managed paths are never enumerated"
    assert set(named.group(1).split()) == {"current", "releases", "data"}, (
        f"the phase checks {named.group(1)!r}, not every managed path"
    )
    assert '[ ! -e "$SYSTEM_ROOT/$leftover" ]' in executed, "presence is not checked"
    assert executed.index("for leftover in") < removal


def test_a_non_empty_install_root_is_reported_not_forced() -> None:
    """Something the installer kept is a finding, not something to destroy."""
    uninstall = _phase("uninstall")

    # BLOCKED, so partial coverage changes the exit status rather than the
    # phase quietly deciding on its own to force the removal through.
    assert 'blocked "install root removed"' in uninstall
    assert "rmdir -p" not in uninstall, "rmdir -p would climb out of the root"


def test_the_harness_leaves_the_host_able_to_run_again() -> None:
    """A retained install root makes the next install refuse the clean-state
    check, which is exactly the protection that must not be weakened."""
    executed = _uninstall_commands()

    assert 'rm -f "$STATE_FILE"' in executed
    # The account is reused as found by `ensure_service_account`, so it does
    # not block a further run and is not the harness's to delete.
    assert "userdel" not in executed, "the uninstall phase deletes the account itself"


def test_the_host_harness_delegates_binding_rather_than_reimplementing_it() -> None:
    """Shell keeps sudo, systemctl and phase dispatch.

    Every check the module owns is exercised in `test_host.py` against
    real Ed25519 material and a lying interpreter. A shell copy alongside it
    would be the untested one.
    """
    source = _host_harness()
    # Command lines only. The header explains the trust model and names the
    # tooling by design; matching the whole file would fail on the explanation
    # rather than on a duplicated check.
    commands = "\n".join(
        line for line in source.splitlines() if not line.lstrip().startswith("#")
    )

    assert "evidence_host.py" in commands
    for reimplemented in ("sha256sum", "openssl", "/proc/sys/kernel/random/boot_id"):
        assert reimplemented not in commands, (
            f"{reimplemented} is checked in shell as well as in the module"
        )


def test_the_signed_wheel_is_built_with_the_pinned_backend() -> None:
    """`pyproject` declares `setuptools>=68`, so without this pip builds in an
    environment it populates from PyPI at build time — and the code being
    signed is produced by tooling outside the hash lock."""
    source = Path("scripts/build-wheelhouse.sh").read_text(encoding="utf-8")
    # The runtime wheel specifically. `pip wheel` is invoked three times here,
    # and the dependency builds already carried the flag — slicing from the
    # first occurrence validates an unrelated command and passes whatever the
    # runtime wheel does.
    marker = "Build the ori-runtime wheel itself"
    block = source[source.index(marker) :].split("\n\n")[0]
    # Command lines only. The comment beside the flag explains why it is there
    # and contains the flag's name, so matching the whole block is satisfied by
    # the explanation surviving its own removal.
    command = "\n".join(
        line for line in block.splitlines() if not line.lstrip().startswith("#")
    )

    assert "-m pip wheel" in command, "the runtime wheel build moved"
    assert "--no-build-isolation" in command, (
        "the signed wheel is built with live-resolved build tooling"
    )


def _invokes_build_wheelhouse(text: str) -> bool:
    """A line that runs it, not one that mentions it.

    `install-pi.sh` and the docs print the command as a hint; treating those as
    callers would demand a build backend from scripts that never build.
    """
    return any(
        "build-wheelhouse.sh" in line
        and not line.lstrip().startswith(("#", "echo"))
        and "echo " not in line
        for line in text.splitlines()
    )


def test_every_caller_that_builds_the_wheel_installs_the_pinned_backend() -> None:
    """`--no-build-isolation` uses whatever is already installed.

    The flag lives on the shared script, so every caller inherits the
    requirement. Checking only the workflow missed the container harness, which
    built evidence bundles with the distribution's own setuptools.
    """
    import yaml

    callers: dict[str, str] = {}
    workflow = yaml.safe_load(
        Path(".github/workflows/release.yml").read_text(encoding="utf-8")
    )
    for name, job in workflow["jobs"].items():
        commands = "\n".join(
            str(step.get("run", "")) for step in job.get("steps") or []
        )
        if _invokes_build_wheelhouse(commands):
            callers[f"job {name!r}"] = commands
    for script in sorted(Path("docs/releases/evidence").glob("*.sh")) + sorted(
        Path("scripts").glob("*.sh")
    ):
        text = script.read_text(encoding="utf-8")
        if _invokes_build_wheelhouse(text):
            callers[str(script)] = text

    assert len(callers) >= 3, (
        f"expected the workflow and both harnesses: {sorted(callers)}"
    )
    for name, text in callers.items():
        assert "--require-hashes" in text and "requirements/dev.txt" in text, (
            f"{name} builds the signed wheel without the pinned build backend"
        )


def test_the_pinned_build_backend_is_actually_pinned() -> None:
    """`--no-build-isolation` is only as good as the lock behind it.

    setuptools and wheel are in `dev.txt` transitively, by way of pip-tools.
    A future compile that drops those edges would remove the pin and break the
    release build at signing time — the furthest possible point from the cause.
    """
    locked = Path("requirements/dev.txt").read_text(encoding="utf-8")

    for package in ("setuptools", "wheel"):
        assert re.search(rf"^{package}==", locked, re.M), (
            f"requirements/dev.txt no longer pins {package}, which "
            "--no-build-isolation requires; declare it in dev.in"
        )


# --- the runbook, bound to the scripts it describes ---------------------------
#
# A runbook drifts the way the shell variables did. These bind each instruction
# to the thing it instructs: a wrong command here costs an operator a reboot
# cycle on a machine that has to be reset by hand before it can be retried.


def _runbook() -> str:
    return RUNBOOK.read_text(encoding="utf-8")


def test_the_runbook_names_only_phases_the_harness_dispatches() -> None:
    dispatched = set(re.findall(r"^\s{4}(\w+)\)\s+phase_", _host_harness(), re.M))
    instructed = set(
        re.findall(r"harness-systemd-host\.sh \\?\s*\n?\s*(\w+)", _runbook())
    )

    assert instructed, "the runbook invokes the harness nowhere"
    assert instructed <= dispatched, (
        f"the runbook invokes phases the harness does not dispatch: "
        f"{sorted(instructed - dispatched)}"
    )


def test_the_runbook_passes_install_arguments_in_the_harness_order() -> None:
    """The harness reads them positionally; a swap installs the wrong thing."""
    runbook = _runbook()

    assert 'install "$BUNDLE" "$SIG" "$KEYS" "$SHA" "$VERSION"' in runbook
    for phase in ("install", "rollback"):
        body = _phase(phase)
        for position, name in enumerate(
            ("bundle", "signature", "registry", "expected_sha", "version"), start=2
        ):
            assert f'{name}="${{{position}' in body, (
                f"{phase} no longer reads {name} from position {position}"
            )


def test_the_runbook_derives_the_filenames_the_builder_writes() -> None:
    """Derived by hand, so a rename in the builder silently breaks the run."""
    builder = ARTIFACT_BUILDER.read_text(encoding="utf-8")
    runbook = _runbook()

    produced = re.search(r'ARTIFACT_NAME="([^"]+)"', builder).group(1)
    assert produced.replace("$RELEASE_VERSION", "$VERSION") in runbook, (
        f"the runbook does not derive the artifact name the builder writes: {produced}"
    )
    registry = re.search(r'"\$OUTDIR/(release-keys[^"]*)"', builder).group(1)
    assert registry in runbook, "the runbook names a registry the builder never writes"


def test_the_runbook_calls_the_builder_with_its_declared_argument_order() -> None:
    builder = ARTIFACT_BUILDER.read_text(encoding="utf-8")

    assert "build-local-artifact.sh <commit> <target> <release-version>" in builder
    assert '"$COMMIT" "$TARGET" "$VERSION" "$OUT"' in _runbook()


def test_every_runbook_block_that_pipes_sets_pipefail_itself() -> None:
    """The reboot ends the shell that ran the install.

    A fresh shell pasting a later block inherits no options, and `$?` after a
    pipe is `tee`'s status — always 0. Relying on an option set in an earlier
    block reports every post-reboot phase as a pass. `PIPESTATUS` is the
    bash-only alternative and expands to nothing under zsh, failing the same
    way silently.
    """
    blocks = re.findall(r"```bash\n(.*?)```", _runbook(), re.S)
    piping = [block for block in blocks if "| tee" in block]

    assert len(piping) >= 4, f"expected a block per phase, found {len(piping)}"
    for block in piping:
        assert "set -o pipefail" in block, (
            f"this block reports tee's status, not the harness's:\n{block}"
        )
        assert "${PIPESTATUS" not in block, "PIPESTATUS is empty under zsh"


def test_the_runbook_states_the_exit_status_that_means_partial_coverage() -> None:
    """Reading only "it finished" turns untested claims into apparent passes."""
    runbook = _runbook()

    assert "| 3 |" in runbook, "the runbook does not explain exit 3"
    assert "BLOCKED" in runbook


def test_the_runbook_repeats_what_the_run_cannot_prove() -> None:
    runbook = _runbook()

    for absent in ("KMS", "publication", "byte-identical"):
        assert absent in runbook, f"the runbook does not disclaim {absent}"


def test_the_host_scripts_stay_executable() -> None:
    """The runbook invokes both as `./script`, and git records the mode.

    A lost execute bit turns every documented command into "permission
    denied" on the operator's machine, after they have already built an
    artifact and are about to install as root.
    """
    for script in (HOST_HARNESS, ARTIFACT_BUILDER):
        assert script.is_file(), f"{script} is missing"
        assert script.stat().st_mode & 0o111, f"{script} is not executable"


def test_the_host_scripts_are_valid_shell() -> None:
    """`bash -n` is a whole-file parse, which these are: unlike the polyglot
    bootstrap, nothing here hands off to another interpreter."""
    for script in (HOST_HARNESS, ARTIFACT_BUILDER):
        completed = subprocess.run(
            ["bash", "-n", str(script)], capture_output=True, text=True, check=False
        )
        assert completed.returncode == 0, f"{script}: {completed.stderr}"


def test_field_assertions_accept_compact_and_indented_json(tmp_path: Path) -> None:
    """The installer prints compact JSON and the doctor indented JSON; a claim
    about either must not depend on the emitter's spacing."""
    harness = _host_harness()
    start = harness.index("assert_field() {")
    end = harness.index("\n}\n", start) + 3
    script = tmp_path / "probe.sh"
    script.write_text(
        'pass() { echo PASS; }\nfail() { echo "FAIL $2"; exit 1; }\n'
        + harness[start:end]
        + 'assert_field a status healthy \'{"status":"healthy","x":1}\'\n'
        + "assert_field b launcher_installed true '{\"launcher_installed\": true}'\n"
        + 'assert_field c version 2.5.0-rc.7 \'{"version": "2.5.0-rc.7"}\'\n'
        + 'assert_field e version 2.5.0-rc.7 \'{"version":"2.5.0-rc.7","x":1}\'\n'
        + 'assert_field f version 2.5.0-rc.7 $\'{\\n  "version": "2.5.0-rc.7"\\n}\'\n'
        + 'assert_field g version 2.5.0-rc.7 \'{"version":"2.5.0-rc.71"}\'\n'
    )
    result = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 1
    assert result.stdout.splitlines() == [
        "PASS",
        "PASS",
        "PASS",
        "PASS",
        "PASS",
        'FAIL expected "version": "2.5.0-rc.7" in: {"version":"2.5.0-rc.71"}',
    ]


def test_field_assertions_match_the_value_literally(tmp_path: Path) -> None:
    """A version is full of regex metacharacters; `2.5.0-rc.7` must not match
    `2x5x0-rcx7`, and a bare `true` must not match the string `"true"`."""
    harness = _host_harness()
    start = harness.index("assert_field() {")
    end = harness.index("\n}\n", start) + 3
    script = tmp_path / "probe.sh"
    script.write_text(
        'pass() { echo PASS; }\nfail() { echo "FAIL $2"; exit 1; }\n'
        + harness[start:end]
        + 'assert_field a version 2.5.0-rc.7 \'{"version":"2x5x0-rcx7"}\'\n'
    )
    result = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 1
    assert result.stdout.splitlines() == [
        'FAIL expected "version": "2.5.0-rc.7" in: {"version":"2x5x0-rcx7"}'
    ]


def test_the_rollback_phase_prints_the_installer_refusal() -> None:
    """The record must be able to quote the refusal from the log, not from the
    workspace file the phase deletes."""
    rollback = _phase("rollback")
    assert "installer reported" in rollback
    assert rollback.index("installer reported") < rollback.index(
        "the candidate failed after activation"
    )


def test_the_host_block_prints_the_boot_id() -> None:
    """Each phase's boot id belongs in the log, so a persist claim can be
    read against the boot it followed rather than inferred."""
    harness = _host_harness()
    assert "evidence boot-id" in harness
    assert harness.index("boot id") < harness.index("assert_exit() {")


def test_the_rollback_phase_proves_the_launcher_and_records_the_boot() -> None:
    """Issue #335 asks for two things beyond restoration: the launcher, which
    resolves at execution time, must reach the restored release, and a later
    reboot must be provable against the rollback rather than the install."""
    rollback = _phase("rollback")

    assert "/usr/local/bin/ori doctor --scope system --json" in rollback
    assert 'assert_contains "launcher reports the restored release"' in rollback
    assert 'evidence record --path "$STATE_FILE" --version "$restored"' in rollback
    assert rollback.index("launcher resolves the restored release") < rollback.index(
        "rollback boot recorded"
    )


def test_the_extracted_bundle_is_found_by_name() -> None:
    """The verify step leaves its own directory in the workspace; picking the
    first directory `find` returns installed tooling from the wrong tree."""
    harness = _host_harness()
    assert harness.count("-type d -name 'ori-runtime-*' | head -1") == 2
    assert "-type d | head -1" not in harness


def test_the_rollback_phase_upgrades_without_identity_flags() -> None:
    """An upgrade keeps the installed identity and refuses a differing
    --device-id before activation; passing the evidence identity would make
    the phase fail early against any installation that is not the harness's
    own, and never reach the rollback it exists to prove."""
    rollback = _phase("rollback")
    install_call = rollback[rollback.index('ori-install-linux" install') :]
    install_call = install_call[: install_call.index("rollback.json")]
    assert "--device-id" not in install_call
    assert "--name" not in install_call
    assert 'assert_field "rollback kept the installed identity" device_id' in rollback
