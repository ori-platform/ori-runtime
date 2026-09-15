# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import fnmatch
import hashlib
import os
import re
import runpy
import subprocess
import urllib.error
import warnings
import zipfile
from pathlib import Path
from typing import Any

import pytest
import yaml

from ori.installer import cli

WORKFLOW_PATH = Path(".github/workflows/release.yml")
SHA_PIN_RE = re.compile(r"^[^\s@]+@[0-9a-f]{40}$")


@pytest.fixture(scope="module")
def verifier() -> dict[str, Any]:
    return runpy.run_path("scripts/verify_published_release.py")


@pytest.fixture(scope="module")
def workflow() -> dict[str, Any]:
    document = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def _steps(workflow: dict[str, Any], job: str) -> list[dict[str, Any]]:
    steps = workflow["jobs"][job]["steps"]
    assert isinstance(steps, list)
    return steps


def test_checksum_file_binds_exactly_one_named_entry(verifier: dict[str, Any]) -> None:
    parse = verifier["parse_checksum_file"]
    digest = "a" * 64

    assert parse(f"{digest}  install-linux.sh\n", "install-linux.sh") == digest
    assert parse(f"{digest} *install-linux.sh\n", "install-linux.sh") == digest


@pytest.mark.parametrize(
    "text",
    [
        "",
        f"{'a' * 64}  other.sh\n",
        f"{'a' * 64}  install-linux.sh\n{'b' * 64}  install-linux.sh\n",
        f"{'A' * 64}  install-linux.sh\n",
        f"{'a' * 63}  install-linux.sh\n",
        "not-a-checksum install-linux.sh\n",
    ],
)
def test_malformed_checksum_files_fail_closed(
    verifier: dict[str, Any], text: str
) -> None:
    with pytest.raises(verifier["PublicationError"]) as error:
        verifier["parse_checksum_file"](text, "install-linux.sh")
    assert error.value.code == "artifact_integrity_mismatch"


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/ori-platform/ori-runtime/releases/download/v2.3.0/x",
        "https://example.com/ori-runtime/releases/download/v2.3.0/x",
        "https://github.com.evil.test/x",
        "file:///etc/passwd",
    ],
)
def test_download_rejects_unapproved_origins(
    verifier: dict[str, Any], tmp_path: Path, url: str
) -> None:
    with pytest.raises(verifier["PublicationError"]) as error:
        verifier["download_asset"](url, tmp_path / "asset", 1024)
    assert error.value.code == "artifact_integrity_mismatch"


@pytest.mark.parametrize(
    "target",
    [
        "http://github.com/asset",
        "https://evil.test/asset",
        "https://notgithubusercontent.com/asset",
    ],
)
def test_redirects_leaving_github_are_refused(
    verifier: dict[str, Any], target: str
) -> None:
    handler = verifier["_HttpsOnlyRedirect"]()
    with pytest.raises(verifier["PublicationError"]) as error:
        handler.redirect_request(None, None, 302, "Found", None, target)
    assert "untrusted origin" in error.value.detail


def _stage_bootstrap(directory: Path, script: bytes, declared: bytes) -> None:
    (directory / "install-linux.sh").write_bytes(script)
    digest = hashlib.sha256(declared).hexdigest()
    (directory / "install-linux.sh.sha256").write_text(
        f"{digest}  install-linux.sh\n", encoding="utf-8"
    )


def test_bootstrap_must_match_the_checksum_shipped_beside_it(
    verifier: dict[str, Any], tmp_path: Path
) -> None:
    _stage_bootstrap(
        tmp_path, b"#!/usr/bin/env bash\n# injected\n", b"#!/usr/bin/env bash\n"
    )

    with pytest.raises(verifier["PublicationError"]) as error:
        verifier["verify_bootstrap"](verifier["staged_resolver"](tmp_path))
    assert "does not match its published checksum" in error.value.detail


def test_matching_bootstrap_checksum_is_accepted(
    verifier: dict[str, Any], tmp_path: Path
) -> None:
    script = b"#!/usr/bin/env bash\n"
    _stage_bootstrap(tmp_path, script, script)

    verifier["verify_bootstrap"](verifier["staged_resolver"](tmp_path))


def test_staged_resolver_refuses_missing_oversized_and_symlinked_assets(
    verifier: dict[str, Any], tmp_path: Path
) -> None:
    resolve = verifier["staged_resolver"](tmp_path)
    (tmp_path / "big.bin").write_bytes(b"x" * 64)
    (tmp_path / "real.bin").write_bytes(b"ok")
    (tmp_path / "link.bin").symlink_to(tmp_path / "real.bin")

    assert resolve("real.bin", 1024) == tmp_path / "real.bin"
    for name, limit, expected in [
        ("absent.bin", 1024, "is missing"),
        ("big.bin", 8, "is oversized"),
        ("link.bin", 1024, "is missing"),
    ]:
        with pytest.raises(verifier["PublicationError"]) as error:
            resolve(name, limit)
        assert expected in error.value.detail


def _stage_checked_asset(directory: Path, name: str, payload: bytes) -> None:
    (directory / name).write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    (directory / f"{name}.sha256").write_text(f"{digest}  {name}\n", encoding="utf-8")


BUNDLE = "ori-runtime-2.3.0-linux-x86_64-python3.12.tar.gz"


def test_bundle_checksum_pair_accepts_a_matching_asset(
    verifier: dict[str, Any], tmp_path: Path
) -> None:
    _stage_checked_asset(tmp_path, BUNDLE, b"bundle-bytes")

    resolved = verifier["verify_checksum_pair"](
        verifier["staged_resolver"](tmp_path), BUNDLE, 4096
    )
    assert resolved == tmp_path / BUNDLE


def test_missing_bundle_checksum_is_refused(
    verifier: dict[str, Any], tmp_path: Path
) -> None:
    (tmp_path / BUNDLE).write_bytes(b"bundle-bytes")

    with pytest.raises(verifier["PublicationError"]) as error:
        verifier["verify_checksum_pair"](
            verifier["staged_resolver"](tmp_path), BUNDLE, 4096
        )
    assert f"staged asset is missing: {BUNDLE}.sha256" in error.value.detail


@pytest.mark.parametrize(
    ("checksum_text", "expected"),
    [
        ("not-a-checksum\n", "checksum file entry is malformed"),
        (f"{'a' * 64}  other-name.tar.gz\n", "checksum file entry is malformed"),
        (f"{'a' * 64}  {BUNDLE}\n", "does not match its published checksum"),
        ("", "checksum file must contain exactly one entry"),
    ],
    ids=["malformed", "wrong-name", "mismatching", "empty"],
)
def test_bad_bundle_checksums_fail_closed(
    verifier: dict[str, Any], tmp_path: Path, checksum_text: str, expected: str
) -> None:
    (tmp_path / BUNDLE).write_bytes(b"bundle-bytes")
    (tmp_path / f"{BUNDLE}.sha256").write_text(checksum_text, encoding="utf-8")

    with pytest.raises(verifier["PublicationError"]) as error:
        verifier["verify_checksum_pair"](
            verifier["staged_resolver"](tmp_path), BUNDLE, 4096
        )
    assert expected in error.value.detail


def _wheel(path: Path, entries: list[tuple[str, bytes]]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, payload in entries:
            archive.writestr(name, payload)


def test_packaged_anchor_must_equal_the_reviewed_anchor(
    verifier: dict[str, Any], tmp_path: Path
) -> None:
    anchor = verifier["reviewed_anchor_bytes"]()
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    _wheel(
        wheelhouse / "ori_runtime-2.3.0-py3-none-any.whl",
        [("ori/installer/release-keys.json", anchor)],
    )

    verifier["verify_packaged_anchor"](tmp_path, anchor)


@pytest.mark.parametrize(
    ("entries", "wheels", "expected"),
    [
        ([], 1, "must contain exactly one"),
        ([("ori/installer/release-keys.json", b'{"keys": []}')], 1, "does not match"),
        ([("ori/installer/release-keys.json", b"{malformed")], 1, "does not match"),
        ([("ori/installer/release-keys.json", b"anchor")], 0, "found 0"),
        ([("ori/installer/release-keys.json", b"anchor")], 2, "found 2"),
    ],
    ids=["missing", "mismatching", "malformed", "no-wheel", "duplicate-wheel"],
)
def test_bad_packaged_anchors_fail_closed(
    verifier: dict[str, Any],
    tmp_path: Path,
    entries: list[tuple[str, bytes]],
    wheels: int,
    expected: str,
) -> None:
    anchor = verifier["reviewed_anchor_bytes"]()
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    for index in range(wheels):
        _wheel(wheelhouse / f"ori_runtime-2.3.{index}-py3-none-any.whl", entries)

    with pytest.raises(verifier["PublicationError"]) as error:
        verifier["verify_packaged_anchor"](tmp_path, anchor)
    assert expected in error.value.detail


def test_duplicated_packaged_registry_entries_are_refused(
    verifier: dict[str, Any], tmp_path: Path
) -> None:
    anchor = verifier["reviewed_anchor_bytes"]()
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    path = wheelhouse / "ori_runtime-2.3.0-py3-none-any.whl"
    with warnings.catch_warnings():
        # A duplicate member is exactly the shape under test.
        warnings.simplefilter("ignore", UserWarning)
        _wheel(
            path,
            [
                ("ori/installer/release-keys.json", anchor),
                ("ori/installer/release-keys.json", b'{"keys": []}'),
            ],
        )

    with pytest.raises(verifier["PublicationError"]) as error:
        verifier["verify_packaged_anchor"](tmp_path, anchor)
    assert "found 2" in error.value.detail


def test_transient_delivery_failures_are_retried_under_a_deadline(
    verifier: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts = 0

    def flaky(_url: str, destination: Path, _limit: int) -> None:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise urllib.error.HTTPError(_url, 404, "Not Found", None, None)  # type: ignore[arg-type]
        destination.write_bytes(b"payload")

    monkeypatch.setitem(verifier["download_asset"].__globals__, "_fetch_once", flaky)
    verifier["download_asset"](
        "https://github.com/asset",
        tmp_path / "asset",
        1024,
        sleeper=lambda _seconds: None,
    )
    assert attempts == 3


def test_integrity_failures_are_never_retried(
    verifier: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts = 0

    def oversized(_url: str, _destination: Path, _limit: int) -> None:
        nonlocal attempts
        attempts += 1
        raise verifier["PublicationError"](
            "artifact_integrity_mismatch", "published asset is outside bounds"
        )

    monkeypatch.setitem(
        verifier["download_asset"].__globals__, "_fetch_once", oversized
    )
    with pytest.raises(verifier["PublicationError"]):
        verifier["download_asset"](
            "https://github.com/asset",
            tmp_path / "asset",
            1024,
            sleeper=lambda _seconds: None,
        )
    assert attempts == 1


def test_retries_stop_at_the_total_deadline(
    verifier: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts = 0
    clock = [0.0]

    def always_503(_url: str, _destination: Path, _limit: int) -> None:
        nonlocal attempts
        attempts += 1
        raise urllib.error.HTTPError(_url, 503, "Unavailable", None, None)  # type: ignore[arg-type]

    monkeypatch.setitem(
        verifier["download_asset"].__globals__, "_fetch_once", always_503
    )
    with pytest.raises(verifier["PublicationError"]):
        verifier["download_asset"](
            "https://github.com/asset",
            tmp_path / "asset",
            1024,
            sleeper=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
            monotonic=lambda: clock[0],
        )
    assert 1 < attempts < 20


def test_origin_resolver_downloads_into_the_workspace(
    verifier: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    requested: list[str] = []

    def fake_download(url: str, destination: Path, _limit: int) -> None:
        requested.append(url)
        destination.write_bytes(b"payload")

    monkeypatch.setitem(
        verifier["origin_resolver"].__globals__, "download_asset", fake_download
    )
    resolve = verifier["origin_resolver"]("https://github.com/base", tmp_path)

    assert resolve("asset.bin", 1024) == tmp_path / "asset.bin"
    assert requested == ["https://github.com/base/asset.bin"]


@pytest.mark.parametrize(
    ("arguments", "code"),
    [
        (["--version", "../evil", "--target", "linux-x86_64-python3.12"], 2),
        (["--version", "2.3.0", "--target", "linux-x86_64-python3.12"], 2),
    ],
)
def test_main_maps_bad_input_to_stable_exit_code(
    verifier: dict[str, Any], arguments: list[str], code: int
) -> None:
    assert verifier["main"]([*arguments, "--workspace", "relative"]) == code


def _triggers(workflow: dict[str, Any]) -> Any:
    """The workflow's `on:` block, whichever key YAML parsed it under.

    YAML 1.1 reads a bare `on` as the boolean true, so a document loaded with
    `yaml.safe_load` may carry the trigger block under `True` rather than
    `"on"`. Both are looked up, and the key type is widened at the boundary so
    the lookup does not depend on which one this parser happened to produce.
    """
    keys: dict[Any, Any] = workflow
    if True in keys:
        return keys[True]
    return keys["on"]


def test_release_runs_only_on_immutable_version_tags(workflow: dict[str, Any]) -> None:
    triggers = _triggers(workflow)

    assert set(triggers) == {"push"}
    assert set(triggers["push"]) == {"tags"}
    assert all(tag.startswith("v[0-9]") for tag in triggers["push"]["tags"])


def test_workflow_denies_token_privileges_by_default(workflow: dict[str, Any]) -> None:
    assert workflow["permissions"] == {"contents": "read", "id-token": "none"}
    assert workflow["jobs"]["build"]["permissions"]["id-token"] == "none"
    assert workflow["jobs"]["publish"]["permissions"]["id-token"] == "none"
    assert workflow["jobs"]["reverify"]["permissions"]["id-token"] == "none"


def test_only_the_protected_signing_job_can_federate_to_aws(
    workflow: dict[str, Any],
) -> None:
    sign = workflow["jobs"]["sign"]

    assert sign["permissions"]["id-token"] == "write"
    # The environment may be a bare name or a mapping carrying a url; what must
    # never change is the name, which the protection rules, the
    # environment-scoped signer variables and the AWS OIDC subject all key off.
    environment = sign["environment"]
    name = environment if isinstance(environment, str) else environment["name"]
    assert name == "release-signing"
    assert "${{" not in name
    assert sign["permissions"]["contents"] == "read"
    federation = [
        step
        for step in _steps(workflow, "sign")
        if "configure-aws-credentials" in str(step.get("uses", ""))
    ]
    assert len(federation) == 1
    assert "role-to-assume" in federation[0]["with"]
    assert "aws-access-key-id" not in federation[0]["with"]
    assert "aws-secret-access-key" not in federation[0]["with"]


def test_release_stages_are_strictly_ordered(workflow: dict[str, Any]) -> None:
    jobs = workflow["jobs"]

    assert jobs["build"]["needs"] == "test"
    assert jobs["build-android-payload"]["needs"] == "test"
    assert sorted(jobs["sign"]["needs"]) == ["build", "build-android-payload"]
    assert jobs["publish"]["needs"] == "sign"
    assert jobs["reverify"]["needs"] == "publish"


def test_the_android_payload_build_holds_no_signing_authority(
    workflow: dict[str, Any],
) -> None:
    """runtime-mobile/v2: the toolchain that compiles a payload never signs it.

    The payloads are signed in the one job that holds the credential, which
    builds nothing, so the build and signing boundaries stay separate.
    """
    build = workflow["jobs"]["build-android-payload"]
    assert build["permissions"] == {"contents": "read", "id-token": "none"}
    assert "environment" not in build
    assert not any(
        "configure-aws-credentials" in str(step.get("uses", ""))
        for step in build["steps"]
    )

    sign_steps = " ".join(str(step.get("run", "")) for step in _steps(workflow, "sign"))
    assert "sign-android-runtime-payload-aws-kms.py" in sign_steps
    assert "build-android-runtime-mobile.sh" not in sign_steps


# --- Android payload steps, run as the runner runs them -----------------------

ANDROID_WORKFLOW_PATH = Path(".github/workflows/android-payload.yml")
ANDROID_TARGETS = (
    "android-arm64-v8a-api21",
    "android-armeabi-v7a-api21",
    "android-x86_64-api21",
)


def _step(workflow: dict[str, Any], job: str, name: str) -> dict[str, Any]:
    matches = [step for step in _steps(workflow, job) if step.get("name") == name]
    assert len(matches) == 1, f"{job} has no single step named {name!r}"
    return matches[0]


def _run_step(
    step: dict[str, Any],
    tmp_path: Path,
    *,
    env: dict[str, str],
    fake_commands: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a step's script under the shell options a GitHub runner uses."""
    script = str(step["run"])
    script = script.replace("${{ runner.temp }}", str(tmp_path / "runner-temp"))
    script = script.replace("${{ steps.assets.outputs.targets }}", "")
    assert "${{" not in script, "an expression this harness does not substitute"
    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir(exist_ok=True)
    for command, body in (fake_commands or {}).items():
        path = bin_dir / command
        path.write_text("#!/usr/bin/env bash\n" + body)
        path.chmod(0o755)
    environment = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "GITHUB_ENV": str(tmp_path / "github-env"),
    }
    for key, value in {**step.get("env", {}), **env}.items():
        environment[key] = str(value)
    (tmp_path / "runner-temp").mkdir(exist_ok=True)
    return subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


def _release_env(workflow: dict[str, Any]) -> dict[str, str]:
    return {key: str(value) for key, value in workflow["env"].items()}


def test_the_api_level_pin_is_the_level_every_v2_target_names(
    workflow: dict[str, Any],
) -> None:
    from ori.security.android_payloads import TARGETS

    level = str(workflow["env"]["ORI_ANDROID_API_LEVEL"])
    assert {target.rsplit("-api", 1)[1] for target in TARGETS} == {level}
    assert set(TARGETS) == set(ANDROID_TARGETS)


def test_staging_publishes_every_target_under_its_derived_name(
    workflow: dict[str, Any], tmp_path: Path
) -> None:
    step = _step(
        workflow, "build-android-payload", "Stage payloads under their published names"
    )
    build = tmp_path / "runner-temp" / "android-build"
    for abi in ("arm64-v8a", "armeabi-v7a", "x86_64"):
        (build / abi).mkdir(parents=True)
        (build / abi / "libori_runtime_exec.so").write_bytes(abi.encode())
    result = _run_step(
        step, tmp_path, env={**_release_env(workflow), "VERSION": "v2.5.0"}
    )
    assert result.returncode == 0, result.stderr
    stage = tmp_path / "runner-temp" / "android-payload"
    expected = {f"ori-runtime-2.5.0-{target}.so" for target in ANDROID_TARGETS}
    assert {p.name for p in stage.iterdir()} == expected | {
        f"{name}.sha256" for name in expected
    }
    for name in expected:
        digest = hashlib.sha256((stage / name).read_bytes()).hexdigest()
        assert (stage / f"{name}.sha256").read_text() == f"{digest}  {name}\n"


@pytest.mark.parametrize("missing", ["arm64-v8a", "armeabi-v7a", "x86_64"])
def test_staging_fails_when_any_payload_did_not_build(
    workflow: dict[str, Any], tmp_path: Path, missing: str
) -> None:
    step = _step(
        workflow, "build-android-payload", "Stage payloads under their published names"
    )
    build = tmp_path / "runner-temp" / "android-build"
    for abi in ("arm64-v8a", "armeabi-v7a", "x86_64"):
        if abi != missing:
            (build / abi).mkdir(parents=True)
            (build / abi / "libori_runtime_exec.so").write_bytes(b"payload")
    result = _run_step(
        step, tmp_path, env={**_release_env(workflow), "VERSION": "v2.5.0"}
    )
    assert result.returncode != 0


def test_the_ndk_step_points_both_ndk_variables_at_the_pinned_ndk(
    workflow: dict[str, Any], tmp_path: Path
) -> None:
    step = _step(workflow, "build-android-payload", "Install the pinned NDK")
    sdk = tmp_path / "sdk"
    sdkmanager = sdk / "cmdline-tools" / "latest" / "bin" / "sdkmanager"
    sdkmanager.parent.mkdir(parents=True)
    sdkmanager.write_text(
        "#!/usr/bin/env bash\n"
        'package="${2#ndk;}"\n'
        'mkdir -p "$(dirname "$0")/../../../ndk/${package}"\n'
    )
    sdkmanager.chmod(0o755)
    result = _run_step(
        step,
        tmp_path,
        env={
            **_release_env(workflow),
            "ANDROID_SDK_ROOT": str(sdk),
            "ANDROID_NDK_HOME": "/image/ndk/other",
            "ANDROID_NDK_ROOT": "/image/ndk/other",
        },
    )
    assert result.returncode == 0, result.stderr
    pinned = f"{sdk}/ndk/{workflow['env']['ORI_ANDROID_NDK_VERSION']}"
    exported = (tmp_path / "github-env").read_text().splitlines()
    assert f"ANDROID_NDK_HOME={pinned}" in exported
    assert f"ANDROID_NDK_ROOT={pinned}" in exported


def test_the_published_digest_is_produced_twice_before_anything_is_staged(
    workflow: dict[str, Any],
) -> None:
    """A digest nobody reproduced is a claim, not a fact."""
    names = [step.get("name", "") for step in _steps(workflow, "build-android-payload")]
    build = names.index("Build every payload, stripped, at the pinned API level")
    rebuild = names.index("Rebuild every payload and confirm the digests reproduce")
    stage = names.index("Stage payloads under their published names")
    assert build < rebuild < stage
    step = _step(
        workflow,
        "build-android-payload",
        "Rebuild every payload and confirm the digests reproduce",
    )
    built = _step(
        workflow,
        "build-android-payload",
        "Build every payload, stripped, at the pinned API level",
    )
    assert step["env"]["ORI_ANDROID_RUNTIME_PAYLOAD_STRIP"] == "1"
    assert (
        step["env"]["ORI_ANDROID_RUNTIME_PAYLOAD_OUT"]
        != built["env"]["ORI_ANDROID_RUNTIME_PAYLOAD_OUT"]
    ), "a rebuild into the same directory proves nothing"
    assert "sha256sum" in step["run"] and "did not reproduce" in step["run"]
    for abi in ("arm64-v8a", "armeabi-v7a", "x86_64"):
        assert abi in step["run"], abi


def test_the_build_step_strips_at_the_pinned_api_level(
    workflow: dict[str, Any],
) -> None:
    step = _step(
        workflow,
        "build-android-payload",
        "Build every payload, stripped, at the pinned API level",
    )
    assert step["env"]["ORI_ANDROID_RUNTIME_PAYLOAD_STRIP"] == "1"
    assert (
        step["env"]["ORI_ANDROID_RUNTIME_PAYLOAD_PLATFORM"]
        == "${{ env.ORI_ANDROID_API_LEVEL }}"
    )
    assert step["env"]["RUSTUP_TOOLCHAIN"] == "${{ env.ORI_ANDROID_RUST_TOOLCHAIN }}"


_RECORDING_PYTHON = (
    'printf "%s\\n" "$*" >> "${HOME}/python-calls"\nexit "${FAKE_EXIT:-0}"\n'
)


@pytest.mark.parametrize(
    ("job", "name"),
    [
        ("sign", "Sign every Android payload"),
        ("publish", "Verify staged assets before publication"),
        ("reverify", "Reverify published assets"),
    ],
)
def test_a_refusing_payload_command_fails_its_step(
    workflow: dict[str, Any], tmp_path: Path, job: str, name: str
) -> None:
    step = _step(workflow, job, name)
    result = _run_step(
        step,
        tmp_path,
        env={**_release_env(workflow), "VERSION": "v2.5.0", "FAKE_EXIT": "2"},
        fake_commands={"python": _RECORDING_PYTHON},
    )
    assert result.returncode != 0, f"{name} passed although its command refused"


def test_signing_names_the_staged_set_and_no_strip_flag(
    workflow: dict[str, Any], tmp_path: Path
) -> None:
    step = _step(workflow, "sign", "Sign every Android payload")
    result = _run_step(
        step,
        tmp_path,
        env={**_release_env(workflow), "VERSION": "v2.5.0"},
        fake_commands={"python": _RECORDING_PYTHON},
    )
    assert result.returncode == 0, result.stderr
    calls = (tmp_path / "python-calls").read_text().splitlines()
    assert len(calls) == 1
    arguments = calls[0].split()
    assert arguments[0] == "scripts/sign-android-runtime-payload-aws-kms.py"
    assert arguments[arguments.index("--payload-dir") + 1] == str(
        tmp_path / "runner-temp" / "android-payload"
    )
    assert arguments[arguments.index("--runtime-version") + 1] == "2.5.0"
    assert arguments[arguments.index("--key-registry") + 1] == (
        "ori/installer/android-payload-keys.json"
    )
    assert "--stripped" not in arguments, "strip state is measured, never asserted"


@pytest.mark.parametrize(
    ("job", "name"),
    [
        ("publish", "Verify staged assets before publication"),
        ("reverify", "Reverify published assets"),
    ],
)
def test_every_android_target_is_verified_before_and_after_publication(
    workflow: dict[str, Any], tmp_path: Path, job: str, name: str
) -> None:
    step = _step(workflow, job, name)
    result = _run_step(
        step,
        tmp_path,
        env={**_release_env(workflow), "VERSION": "v2.5.0"},
        fake_commands={"python": _RECORDING_PYTHON},
    )
    assert result.returncode == 0, result.stderr
    (call,) = (tmp_path / "python-calls").read_text().splitlines()
    arguments = call.split()
    assert arguments[0] == "scripts/verify_published_release.py"
    android = [
        arguments[i + 1]
        for i, value in enumerate(arguments)
        if value == "--android-target"
    ]
    assert sorted(android) == sorted(ANDROID_TARGETS)


def test_payloads_are_downloaded_before_staged_verification_and_the_draft(
    workflow: dict[str, Any],
) -> None:
    names = [step.get("name", "") for step in _steps(workflow, "publish")]
    download = names.index("Download Android payloads and their envelopes")
    verify = names.index("Verify staged assets before publication")
    draft = names.index("Create draft release with the complete asset set")
    assert download < verify < draft
    pattern = _step(
        workflow, "publish", "Download Android payloads and their envelopes"
    )["with"]["pattern"]
    uploaded = {
        step["with"]["name"]
        for job in ("build-android-payload", "sign")
        for step in _steps(workflow, job)
        if "upload-artifact" in str(step.get("uses", ""))
        and str(step["with"]["name"]).startswith("android-payload")
    }
    assert uploaded == {"android-payload", "android-payload-signatures"}
    assert all(fnmatch.fnmatchcase(name, pattern) for name in uploaded)


def test_no_android_payload_step_can_fail_quietly(workflow: dict[str, Any]) -> None:
    checked = 0
    for job in ("build-android-payload", "sign", "publish"):
        for step in _steps(workflow, job):
            text = (
                f"{step.get('name', '')} {step.get('run', '')} {step.get('with', '')}"
            )
            if job != "build-android-payload" and not re.search(
                r"android|payload|verify_published_release", text, re.IGNORECASE
            ):
                continue
            checked += 1
            assert "continue-on-error" not in step, (job, step.get("name"))
            run = str(step.get("run", ""))
            assert "|| true" not in run and "|| :" not in run, (job, step.get("name"))
            if "upload-artifact" in str(step.get("uses", "")):
                assert step["with"]["if-no-files-found"] == "error", (
                    job,
                    step.get("name"),
                )
    assert checked >= 10


def test_pull_requests_build_payloads_with_the_release_steps_and_pins(
    workflow: dict[str, Any],
) -> None:
    """A tag is not the first place the release's build steps run."""
    document = yaml.safe_load(ANDROID_WORKFLOW_PATH.read_text(encoding="utf-8"))
    for pin in (
        "ORI_ANDROID_RUST_TOOLCHAIN",
        "ORI_ANDROID_CARGO_NDK_VERSION",
        "ORI_ANDROID_NDK_VERSION",
        "ORI_ANDROID_API_LEVEL",
    ):
        assert document["env"][pin] == workflow["env"][pin], pin

    assert (
        document["jobs"]["build-android-payload"]["runs-on"]
        == workflow["jobs"]["build-android-payload"]["runs-on"]
    ), "the same runner image, or the pull request proves nothing about the release"

    # YAML 1.1 reads a bare `on` key as the boolean true.
    events = document.get("on", document.get(True))
    triggers = events["pull_request"]["paths"]
    assert triggers == events["push"]["paths"]
    for path in (
        "mobile/**",
        "scripts/build-android-runtime-mobile.sh",
        "scripts/sign-android-runtime-payload-aws-kms.py",
        "scripts/verify-android-runtime-payload.py",
        "scripts/verify_published_release.py",
        "ori/security/android_payloads.py",
        "ori/security/release_bundles.py",
        "ori/security/aws_kms_release_signer.py",
        "pyproject.toml",
        "requirements/**",
        ".github/workflows/release.yml",
        ".github/workflows/android-payload.yml",
    ):
        assert path in triggers, path

    release_steps = [
        step
        for step in _steps(workflow, "build-android-payload")
        if "upload-artifact" not in str(step.get("uses", ""))
    ]
    pull_request_steps = document["jobs"]["build-android-payload"]["steps"][
        : len(release_steps)
    ]
    for release_step, pull_request_step in zip(
        release_steps, pull_request_steps, strict=True
    ):
        release_env = dict(release_step.get("env", {}))
        pull_request_env = dict(pull_request_step.get("env", {}))
        if "VERSION" in release_env:
            # A release stages under the tag; a pull request has no tag to
            # stage under, so that one value differs and nothing else may.
            release_version = release_env.pop("VERSION")
            pull_request_version = pull_request_env.pop("VERSION")
            assert release_version == "${{ github.ref_name }}"
            assert pull_request_version == "v0.0.0-ci"
        assert {**release_step, "env": release_env} == {
            **pull_request_step,
            "env": pull_request_env,
        }, release_step.get("name")
    final = document["jobs"]["build-android-payload"]["steps"][-1]
    assert "scripts/check-android-payload-build.py" in final["run"]
    assert document["jobs"]["build-android-payload"]["permissions"] == {
        "contents": "read",
        "id-token": "none",
    }


@pytest.mark.parametrize(
    "gate",
    [
        "pytest tests/",
        "pre-commit run",
        "scripts/typecheck-boundaries.sh",
        "scripts/check_workflows.py",
        "scripts/check_rust_supply_chain.sh",
        "scripts/smoke-release-wheel.sh",
        "pip_audit",
        "TestCapabilityTierGuard",
        "test_missing_defaults_mapping_for_trigger_raises",
    ],
)
def test_tag_pushes_cannot_reach_signing_without_the_release_gates(
    workflow: dict[str, Any], gate: str
) -> None:
    commands = "\n".join(str(step.get("run", "")) for step in _steps(workflow, "test"))

    assert gate in commands


@pytest.mark.parametrize("job", ["test", "build", "sign", "publish", "reverify"])
def test_every_release_job_is_time_bounded(workflow: dict[str, Any], job: str) -> None:
    assert isinstance(workflow["jobs"][job]["timeout-minutes"], int)


def test_signing_covers_whatever_the_build_matrix_produced(
    workflow: dict[str, Any],
) -> None:
    commands = "\n".join(str(step.get("run", "")) for step in _steps(workflow, "sign"))
    targets = [
        entry["target"]
        for entry in workflow["jobs"]["build"]["strategy"]["matrix"]["include"]
    ]

    # Targets are globbed from the built bundles rather than restated, so the
    # sign step cannot silently drift away from the build matrix.
    for target in targets:
        assert target not in commands
    assert 'for artifact in "${bundles}"/ori-runtime-"${version}"-*.tar.gz' in commands
    assert 'if [ "${found}" -eq 0 ]' in commands


def test_assets_are_verified_before_they_become_public(
    workflow: dict[str, Any],
) -> None:
    steps = _steps(workflow, "publish")
    names = [str(step.get("name", "")) for step in steps]
    verify_index = names.index("Verify staged assets before publication")
    draft_index = names.index("Create draft release with the complete asset set")
    publish_index = names.index("Publish the verified draft without promoting it")

    assert verify_index < draft_index < publish_index
    verify = str(steps[verify_index]["run"])
    assert "--from-staged" in verify
    assert "scripts/verify_published_release.py" in verify


def test_a_release_is_only_public_after_its_full_asset_set_lands(
    workflow: dict[str, Any],
) -> None:
    commands = "\n".join(
        str(step.get("run", "")) for step in _steps(workflow, "publish")
    )

    # Draft-first is what keeps a failed publication out of public view.
    assert "--draft" in commands
    assert "--draft=false" in commands
    assert "gh release view" in commands


def test_release_protections_gate_every_later_stage(workflow: dict[str, Any]) -> None:
    # `environment:` alone gates nothing: GitHub creates a missing environment
    # unprotected on first use, so preflight must precede all other work.
    assert workflow["jobs"]["test"]["needs"] == "preflight"
    assert workflow["jobs"]["preflight"].get("needs") is None
    assert "environment" not in workflow["jobs"]["preflight"]


def test_bundle_checksums_are_carried_through_every_stage(
    workflow: dict[str, Any],
) -> None:
    build = "\n".join(
        str(step.get("run", "")) + str(step.get("with", {}))
        for step in _steps(workflow, "build")
    )
    sign = "\n".join(str(step.get("run", "")) for step in _steps(workflow, "sign"))

    assert "ori-runtime-*.tar.gz.sha256" in build
    assert "sha256sum -c" in build
    assert '[ -f "${artifact}.sha256" ]' in sign


def test_prerelease_tags_are_not_published_as_latest(workflow: dict[str, Any]) -> None:
    commands = "\n".join(
        str(step.get("run", "")) for step in _steps(workflow, "publish")
    )

    assert 'if [ "${version}" != "${version%%-*}" ]' in commands
    assert "--prerelease" in commands
    assert "--verify-tag" in commands


def test_release_never_restores_a_dependency_cache(workflow: dict[str, Any]) -> None:
    for job in workflow["jobs"]:
        for step in _steps(workflow, job):
            uses = str(step.get("uses", ""))
            assert "actions/cache" not in uses
            if "setup-python" in uses:
                assert "cache" not in step.get("with", {})


def test_every_release_action_is_pinned_to_a_full_commit_sha(
    workflow: dict[str, Any],
) -> None:
    for job in workflow["jobs"]:
        for step in _steps(workflow, job):
            uses = step.get("uses")
            if uses is not None:
                assert SHA_PIN_RE.fullmatch(uses), uses


def test_publication_ships_the_bootstrap_with_its_checksum(
    workflow: dict[str, Any],
) -> None:
    publish = "\n".join(
        str(step.get("run", "")) for step in _steps(workflow, "publish")
    )

    assert "install-linux.sh" in publish
    assert "sha256sum install-linux.sh > install-linux.sh.sha256" in publish
    assert "gh release create" in publish


def _built_targets(workflow: dict[str, Any]) -> list[str]:
    """Every target the build matrix produces a signed bundle for."""
    matrix = workflow["jobs"]["build"]["strategy"]["matrix"]["include"]
    targets = [str(entry["target"]) for entry in matrix]
    assert targets, "the build matrix names no targets"
    return targets


def test_publication_is_reverified_from_the_public_origin(
    workflow: dict[str, Any],
) -> None:
    """Every built target is reverified, with the list taken from the matrix.

    Naming the targets here instead would make this assertion a copy of the
    matrix rather than a check on it: adding a release target and forgetting
    the reverification step would leave a bundle published to the public origin
    and never re-fetched from it, with this test still green. The matrix is the
    only place a target is declared, so it is the only place to read it from.
    """
    reverify = "\n".join(
        str(step.get("run", "")) for step in _steps(workflow, "reverify")
    )

    assert "scripts/verify_published_release.py" in reverify
    for target in _built_targets(workflow):
        assert target in reverify, f"built target {target} is never reverified"


def test_the_installer_accepts_exactly_the_versions_that_are_published(
    workflow: dict[str, Any],
) -> None:
    """`detected_release_target` must admit a host iff a bundle exists for it.

    The two failures this catches are opposite and both silent. A version in
    the installer's set with no target built is a host told it is supported
    and then handed a 404 mid-install. A target built with no version in the
    set is a bundle nobody can install, published every release.

    Deriving the installer's edges from its own set — which is the tempting
    way to write this — asserts nothing: widen the set and the edges widen
    with it. The matrix is the independent fact, because it is what actually
    gets built, signed and published.
    """
    published = {target.rsplit("python", 1)[1] for target in _built_targets(workflow)}

    assert cli.SUPPORTED_PYTHON_VERSIONS == published


def test_every_supported_tuple_is_actually_built(workflow: dict[str, Any]) -> None:
    """Both dimensions, not just the version one.

    Checking versions alone leaves the architecture dimension unguarded:
    dropping `linux-x86_64-python3.13` while keeping the aarch64 build still
    contributes `3.13` to the published version set, so the version assertion
    stays green while half a release goes missing. The installer promises a
    bundle for every combination it admits, so the product is the invariant.
    """
    expected = {
        f"linux-{architecture}-python{version}"
        for architecture in cli.SUPPORTED_ARCHITECTURES
        for version in cli.SUPPORTED_PYTHON_VERSIONS
    }

    assert set(_built_targets(workflow)) == expected


@pytest.fixture(scope="module")
def protections() -> dict[str, Any]:
    return runpy.run_path("scripts/check_release_protections.py")


def _api(overrides: dict[str, Any]) -> Any:
    defaults: dict[str, Any] = {
        "repos/o/r/immutable-releases": {"enabled": True, "enforced_by_owner": False},
        "repos/o/r/environments/release-signing": {
            "protection_rules": [
                {
                    "type": "required_reviewers",
                    "prevent_self_review": True,
                    "reviewers": [{"type": "User"}],
                }
            ],
            "deployment_branch_policy": {
                "protected_branches": False,
                "custom_branch_policies": True,
            },
        },
        "repos/o/r/environments/release-signing/deployment-branch-policies": {
            "branch_policies": [{"name": "v*", "type": "tag"}]
        },
        "repos/o/r/rulesets": [{"id": 1, "target": "tag", "enforcement": "active"}],
        "repos/o/r/rulesets/1": {
            "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
            "rules": [{"type": "deletion"}, {"type": "update"}],
        },
    }
    defaults.update(overrides)

    def call(path: str) -> Any:
        return defaults[path]

    return call


def test_fully_protected_repository_passes_preflight(
    protections: dict[str, Any],
) -> None:
    assert protections["run_checks"](_api({}), "o/r") == []


def test_immutability_is_read_from_its_dedicated_endpoint(
    protections: dict[str, Any],
) -> None:
    # The repository response has no immutable_releases field, so a check
    # against it would fail even once immutability is enabled. Operator runs
    # must therefore use the dedicated endpoint, never the repository object.
    requested: list[str] = []

    def call(path: str) -> Any:
        requested.append(path)
        return _api({})(path)

    protections["run_checks"](call, "o/r", include_admin_reads=True)
    assert "repos/o/r/immutable-releases" in requested
    assert "repos/o/r" not in requested


@pytest.mark.parametrize(
    "overrides",
    [
        {"repos/o/r/immutable-releases": {"enabled": False}},
        {"repos/o/r/immutable-releases": {}},
    ],
)
def test_disabled_immutability_is_reported_for_operator_runs(
    protections: dict[str, Any], overrides: dict[str, Any]
) -> None:
    failures = protections["run_checks"](
        _api(overrides), "o/r", include_admin_reads=True
    )
    assert any("immutable releases" in failure.detail for failure in failures)


def test_immutability_endpoint_is_never_read_by_default(
    protections: dict[str, Any],
) -> None:
    # GITHUB_TOKEN gets 403 on this endpoint and cannot be granted the scope,
    # so the workflow must never call it. Immutability is proved instead from
    # the published release object, which `contents` can read.
    requested: list[str] = []

    def call(path: str) -> Any:
        requested.append(path)
        return _api({})(path)

    protections["run_checks"](call, "o/r")
    assert not any("immutable-releases" in path for path in requested)


def test_operator_runs_can_still_opt_into_the_admin_read(
    protections: dict[str, Any],
) -> None:
    requested: list[str] = []

    def call(path: str) -> Any:
        requested.append(path)
        return _api({})(path)

    assert protections["run_checks"](call, "o/r", include_admin_reads=True) == []
    assert any("immutable-releases" in path for path in requested)


def test_self_reviewable_environment_is_rejected(
    protections: dict[str, Any],
) -> None:
    # A reviewer who can approve their own release is not a second pair of eyes.
    overrides = {
        "repos/o/r/environments/release-signing": {
            "protection_rules": [
                {
                    "type": "required_reviewers",
                    "prevent_self_review": False,
                    "reviewers": [{"type": "User"}],
                }
            ],
            "deployment_branch_policy": {"custom_branch_policies": True},
        }
    }
    failures = protections["run_checks"](_api(overrides), "o/r")
    assert any("permits self-review" in failure.detail for failure in failures)


@pytest.mark.parametrize(
    ("policy", "expected"),
    [
        ({"custom_branch_policies": False}, "does not restrict deployments"),
        (None, "does not restrict deployments"),
    ],
)
def test_unrestricted_deployment_policy_is_rejected(
    protections: dict[str, Any], policy: Any, expected: str
) -> None:
    overrides = {
        "repos/o/r/environments/release-signing": {
            "protection_rules": [
                {"type": "required_reviewers", "prevent_self_review": True}
            ],
            "deployment_branch_policy": policy,
        }
    }
    failures = protections["run_checks"](_api(overrides), "o/r")
    assert any(expected in failure.detail for failure in failures)


@pytest.mark.parametrize(
    ("entries", "expected"),
    [
        ([], "no deployment policy entries"),
        ([{"name": "main", "type": "branch"}], "allows non-tag deployments"),
        ([{"name": "nightly-*", "type": "tag"}], "does not cover version tags"),
    ],
)
def test_deployment_tag_policy_must_cover_version_tags(
    protections: dict[str, Any], entries: list[Any], expected: str
) -> None:
    overrides = {
        "repos/o/r/environments/release-signing/deployment-branch-policies": {
            "branch_policies": entries
        }
    }
    failures = protections["run_checks"](_api(overrides), "o/r")
    assert any(expected in failure.detail for failure in failures)


@pytest.mark.parametrize(
    ("listing", "detail", "expected"),
    [
        ([], None, "no active tag ruleset"),
        (
            [{"id": 1, "target": "branch", "enforcement": "active"}],
            None,
            "no active tag ruleset",
        ),
        (
            [{"id": 1, "target": "tag", "enforcement": "disabled"}],
            None,
            "no active tag ruleset",
        ),
        # An unrelated tag ruleset must not satisfy the check.
        (
            [{"id": 1, "target": "tag", "enforcement": "active"}],
            {
                "conditions": {"ref_name": {"include": ["refs/tags/nightly-*"]}},
                "rules": [{"type": "deletion"}, {"type": "update"}],
            },
            "covers version tags",
        ),
        # Deletion alone still allows a tag to be force-moved.
        (
            [{"id": 1, "target": "tag", "enforcement": "active"}],
            {
                "conditions": {"ref_name": {"include": ["refs/tags/v*"]}},
                "rules": [{"type": "deletion"}],
            },
            "blocks updates",
        ),
    ],
    ids=["none", "branch-only", "inactive", "unrelated-tags", "deletion-only"],
)
def test_tag_ruleset_must_actually_freeze_version_tags(
    protections: dict[str, Any],
    listing: list[Any],
    detail: Any,
    expected: str,
) -> None:
    overrides: dict[str, Any] = {"repos/o/r/rulesets": listing}
    if detail is not None:
        overrides["repos/o/r/rulesets/1"] = detail
    failures = protections["run_checks"](_api(overrides), "o/r")
    assert any(expected in failure.detail for failure in failures)


def test_every_protection_failure_is_reported_in_one_run(
    protections: dict[str, Any],
) -> None:
    failures = protections["run_checks"](
        _api(
            {
                "repos/o/r/immutable-releases": {"enabled": False},
                "repos/o/r/rulesets": [],
            }
        ),
        "o/r",
        include_admin_reads=True,
    )

    assert len(failures) == 2
    assert all(failure.remedy for failure in failures)


def test_release_tag_immutability_is_reconfirmed_before_publication(
    workflow: dict[str, Any],
) -> None:
    steps = _steps(workflow, "publish")
    names = [str(step.get("name", "")) for step in steps]
    equality = names.index("Confirm the signed tag still resolves to the built commit")
    draft = names.index("Create draft release with the complete asset set")

    # Re-checked here because the tag could be re-pointed after preflight.
    assert equality < draft
    assert '--commit "${GITHUB_SHA}"' in str(steps[equality]["run"])


def test_failed_reverification_quarantines_rather_than_deletes(
    workflow: dict[str, Any],
) -> None:
    body = str(_incident_step(workflow)["run"])
    assert "gh release delete" not in body
    assert "Do not delete it and do not reuse the tag" in body
    assert "block any latest or bootstrap promotion" in body
    assert workflow["jobs"]["incident"]["permissions"]["issues"] == "write"


def test_preflight_runs_the_protection_script(workflow: dict[str, Any]) -> None:
    commands = "\n".join(
        str(step.get("run", "")) for step in _steps(workflow, "preflight")
    )

    assert "scripts/check_release_protections.py" in commands


def test_publication_never_confers_latest_on_its_own(
    workflow: dict[str, Any],
) -> None:
    publish = "\n".join(
        str(step.get("run", "")) for step in _steps(workflow, "publish")
    )

    # Undrafting alone can designate a stable release as Latest, which would
    # promote it before public reverification has run.
    assert "--latest=false" in publish
    assert "--latest=true" not in publish


def test_latest_is_granted_only_after_public_reverification(
    workflow: dict[str, Any],
) -> None:
    promote = workflow["jobs"]["promote"]
    body = "\n".join(str(step.get("run", "")) for step in _steps(workflow, "promote"))

    assert promote["needs"] == "reverify"
    assert "--latest=true" in body
    # A prerelease must never become Latest even after a clean reverification.
    assert 'if [ "${version}" != "${version%%-*}" ]' in body
    assert "exit 0" in body


def test_write_capable_jobs_never_handle_downloaded_artifacts(
    workflow: dict[str, Any],
) -> None:
    jobs = workflow["jobs"]

    # The job that parses bytes from a public origin must stay read-only.
    assert jobs["reverify"]["permissions"] == {"contents": "read", "id-token": "none"}
    # Each writable token is isolated to a job with a single, minimal action.
    assert jobs["promote"]["permissions"]["contents"] == "write"
    assert "issues" not in jobs["promote"]["permissions"]
    assert jobs["incident"]["permissions"]["issues"] == "write"
    assert jobs["incident"]["permissions"]["contents"] == "read"

    for job in ("promote", "incident"):
        for step in _steps(workflow, job):
            uses = str(step.get("uses", ""))
            run = str(step.get("run", ""))
            assert "checkout" not in uses
            assert "setup-python" not in uses
            assert "pip install" not in run
            assert "verify_published_release" not in run


def test_incident_does_not_depend_on_a_label_that_may_not_exist(
    workflow: dict[str, Any],
) -> None:
    incident = _incident_step(workflow)

    # `gh issue create --label` 404s when the label is absent, which would
    # silently lose the incident exactly when reverification failed.
    assert "--label" not in str(incident["run"])
    assert "RELEASE INCIDENT" in str(incident["run"])


def test_incident_is_raised_only_for_a_reverification_failure(
    workflow: dict[str, Any],
) -> None:
    condition = str(workflow["jobs"]["incident"]["if"])

    # always() keeps the job reachable after a failure. The job result alone is
    # also set by checkout, setup, or install failures, so the exported step
    # outcome is required too: only a real verification failure may accuse the
    # published artifacts.
    assert "always()" in condition
    assert "needs.reverify.result == 'failure'" in condition
    assert "needs.reverify.outputs.verification_outcome == 'failure'" in condition


def test_setup_failures_cannot_be_reported_as_bad_artifacts(
    workflow: dict[str, Any],
) -> None:
    reverify = workflow["jobs"]["reverify"]
    steps = {str(step.get("name", "")): step for step in _steps(workflow, "reverify")}
    verify = steps["Reverify published assets"]
    record = steps["Record the verification outcome"]

    # The outcome must survive the failing step and be exported for the gate.
    assert verify["id"] == "reverify"
    assert verify["continue-on-error"] is True
    assert record["if"] == "always()"
    assert "steps.reverify.outcome" in str(record["run"])
    assert (
        reverify["outputs"]["verification_outcome"]
        == "${{ steps.outcome.outputs.verification_outcome }}"
    )
    # A verification failure must still fail the run, so nothing is promoted.
    fail = steps["Fail the run when verification failed"]
    assert fail["if"] == "steps.reverify.outcome == 'failure'"
    assert "exit 1" in str(fail["run"])


def _incident_step(workflow: dict[str, Any]) -> dict[str, Any]:
    steps = _steps(workflow, "incident")
    incident = [step for step in steps if "run" in step]
    assert len(incident) == 1
    return incident[0]


@pytest.mark.parametrize(
    "exclude",
    [["refs/tags/v2.*"], ["refs/tags/v*"], ["anything"]],
    ids=["specific", "same-pattern", "unrelated"],
)
def test_tag_ruleset_exclusions_disqualify_the_ruleset(
    protections: dict[str, Any], exclude: list[str]
) -> None:
    # An exclusion can carve the real release tags back out of a broad include.
    overrides = {
        "repos/o/r/rulesets/1": {
            "conditions": {
                "ref_name": {"include": ["refs/tags/v*"], "exclude": exclude}
            },
            "rules": [{"type": "deletion"}, {"type": "update"}],
        }
    }
    failures = protections["run_checks"](_api(overrides), "o/r")
    assert any("covers version tags" in failure.detail for failure in failures)


def test_empty_exclusion_list_still_passes(protections: dict[str, Any]) -> None:
    overrides = {
        "repos/o/r/rulesets/1": {
            "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
            "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}],
        }
    }
    assert protections["run_checks"](_api(overrides), "o/r") == []


TAG = "v2.3.0"
COMMIT = "80fa1e28938c53d44784c8302cae90dae98bd721"


def _tag_api(ref: Any, tag_object: Any) -> Any:
    base = _api({})

    def call(path: str) -> Any:
        if path.endswith(f"git/ref/tags/{TAG}"):
            return ref
        if "git/tags/" in path:
            return tag_object
        return base(path)

    return call


def _annotated(sha: str = "tagobj") -> dict[str, Any]:
    return {"object": {"type": "tag", "sha": sha}}


def test_verified_annotated_tag_on_the_approved_commit_passes(
    protections: dict[str, Any],
) -> None:
    api = _tag_api(
        _annotated(),
        {
            "verification": {"verified": True, "reason": "valid"},
            "object": {"type": "commit", "sha": COMMIT},
        },
    )

    assert protections["run_checks"](api, "o/r", tag=TAG, commit=COMMIT) == []


@pytest.mark.parametrize(
    ("ref", "tag_object", "expected"),
    [
        # A lightweight tag points straight at a commit and carries no signature.
        (
            {"object": {"type": "commit", "sha": COMMIT}},
            None,
            "is not an annotated tag",
        ),
        (
            _annotated(),
            {
                "verification": {"verified": False, "reason": "unsigned"},
                "object": {"type": "commit", "sha": COMMIT},
            },
            "does not carry a verified signature",
        ),
        (
            _annotated(),
            {
                "verification": {"verified": False, "reason": "unknown_key"},
                "object": {"type": "commit", "sha": COMMIT},
            },
            "unknown_key",
        ),
        (
            _annotated(),
            {"object": {"type": "commit", "sha": COMMIT}},
            "does not carry a verified signature",
        ),
        (
            _annotated(),
            {
                "verification": {"verified": True},
                "object": {"type": "commit", "sha": "0" * 40},
            },
            "not the approved",
        ),
    ],
    ids=["lightweight", "unsigned", "unknown-key", "no-verification", "wrong-commit"],
)
def test_unsigned_or_misdirected_tags_fail_closed(
    protections: dict[str, Any], ref: Any, tag_object: Any, expected: str
) -> None:
    failures = protections["run_checks"](
        _tag_api(ref, tag_object), "o/r", tag=TAG, commit=COMMIT
    )
    assert any(expected in failure.detail for failure in failures)


def test_tag_checks_are_skipped_when_no_tag_is_supplied(
    protections: dict[str, Any],
) -> None:
    # Repository protection checks must remain usable outside a release run.
    assert protections["run_checks"](_api({}), "o/r") == []


def test_signed_tag_is_enforced_before_building_and_before_publishing(
    workflow: dict[str, Any],
) -> None:
    for job in ("preflight", "publish"):
        commands = "\n".join(str(step.get("run", "")) for step in _steps(workflow, job))
        assert "check_release_protections.py" in commands
        assert '--tag "${GITHUB_REF_NAME}"' in commands
        assert '--commit "${GITHUB_SHA}"' in commands


def test_publication_proves_immutability_from_the_release_object(
    workflow: dict[str, Any],
) -> None:
    steps = _steps(workflow, "publish")
    names = [str(step.get("name", "")) for step in steps]
    publish = names.index("Publish the verified draft without promoting it")
    proof = names.index("Require the published release to be immutable")

    # The repository setting needs administration scope that GITHUB_TOKEN
    # cannot hold, so the proof reads the release object instead.
    assert publish < proof
    body = str(steps[proof]["run"])
    assert "releases/tags/${GITHUB_REF_NAME}" in body
    assert ".immutable" in body


def test_a_mutable_release_is_deleted_rather_than_left_public(
    workflow: dict[str, Any],
) -> None:
    steps = {str(step.get("name", "")): step for step in _steps(workflow, "publish")}
    proof = steps["Require the published release to be immutable"]
    body = str(proof["run"])

    # Immutability can only be proved after publication, so a mutable release
    # exists briefly. Leaving it would expose rewritable bytes at the URL the
    # bootstrap trusts.
    assert "gh release delete" in body
    # The tag is signed and ruleset-protected; the remedy is a new version.
    assert "--cleanup-tag" not in body
    assert "cleanup=deleted" in body
    assert "cleanup=failed" in body
    # The outcome must survive so the incident job can describe what happened.
    assert proof["continue-on-error"] is True
    assert proof["id"] == "immutability"


def test_publication_fails_when_the_release_was_not_immutable(
    workflow: dict[str, Any],
) -> None:
    steps = {str(step.get("name", "")): step for step in _steps(workflow, "publish")}
    record = steps["Record the publication outcome"]
    fail = steps["Fail when the published release was not immutable"]

    assert record["if"] == "always()"
    assert fail["if"] == "steps.immutability.outcome == 'failure'"
    assert "exit 1" in str(fail["run"])
    outputs = workflow["jobs"]["publish"]["outputs"]
    assert outputs["immutability_outcome"] == (
        "${{ steps.outcome.outputs.immutability_outcome }}"
    )
    assert outputs["cleanup"] == "${{ steps.outcome.outputs.cleanup }}"


def test_incident_covers_a_mutable_release_as_well_as_reverification(
    workflow: dict[str, Any],
) -> None:
    incident = workflow["jobs"]["incident"]
    condition = " ".join(str(incident["if"]).split())
    body = str(_incident_step(workflow)["run"])

    assert incident["needs"] == ["publish", "reverify"]
    assert "needs.publish.outputs.immutability_outcome == 'failure'" in condition
    assert "needs.reverify.outputs.verification_outcome == 'failure'" in condition
    # A failed cleanup means a mutable release may still be public, so it must
    # be the loudest thing in the incident.
    assert "CLEANUP FAILED" in body
    assert "Delete the release manually NOW" in body
    assert "do not reuse the tag" in body


def test_promotion_reproves_immutability_before_granting_latest(
    workflow: dict[str, Any],
) -> None:
    body = "\n".join(str(step.get("run", "")) for step in _steps(workflow, "promote"))
    index_check = body.index(".immutable")
    index_promote = body.index("--latest=true")

    assert index_check < index_promote
    assert "Refusing to promote" in body


def test_the_workflow_never_reads_the_administration_scoped_endpoint(
    workflow: dict[str, Any],
) -> None:
    for job in workflow["jobs"]:
        for step in _steps(workflow, job):
            run = str(step.get("run", ""))
            assert "immutable-releases" not in run
            assert "--with-admin-reads" not in run


def test_the_temporary_diagnostic_workflow_is_gone() -> None:
    # It answered its question: GITHUB_TOKEN gets 403 on /immutable-releases.
    assert not Path(".github/workflows/diagnose-protection-reads.yml").exists()


def _scripts_importing_ori() -> set[str]:
    """Return repository scripts that import the `ori` package directly."""
    importing = set()
    for path in Path("scripts").glob("*.py"):
        text = path.read_text(encoding="utf-8")
        if re.search(r"^\s*(from ori[. ]|import ori\b)", text, re.MULTILINE):
            importing.add(path.as_posix())
    return importing


def _scripts_needing_the_package() -> set[str]:
    """Expand to scripts that invoke an ori-importing script in turn."""
    needing = _scripts_importing_ori()
    for path in Path("scripts").glob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if any(script in text for script in _scripts_importing_ori()):
            needing.add(path.as_posix())
    return needing


def test_every_job_invoking_an_ori_importing_script_installs_the_package(
    workflow: dict[str, Any],
) -> None:
    """Derive the requirement rather than trusting a hand-listed set of jobs.

    `python scripts/x.py` puts `scripts/` on `sys.path[0]`, not the repository
    root, so a job that runs an ori-importing script without installing the
    package fails with ModuleNotFoundError. A hardcoded job list previously
    missed `build`, whose wheelhouse script invokes the bundle builder.
    """
    needing = _scripts_needing_the_package()
    assert needing, "expected to find scripts that import ori"

    for job in workflow["jobs"]:
        commands = "\n".join(str(step.get("run", "")) for step in _steps(workflow, job))
        invoked = sorted(script for script in needing if script in commands)
        if invoked:
            assert "pip install --no-deps -e ." in commands, (
                f"job {job!r} runs {invoked} but never installs the package"
            )


INSTALL_GUIDE = Path("docs/linux-install.md")
_CODE_ROW_RE = re.compile(r"^\| `(?P<code>[a-z_]+)` \|", re.MULTILINE)


def test_documented_failure_codes_all_exist_in_the_code() -> None:
    """A failure-code reference that drifts is worse than none at all.

    An operator matching a real error against this table needs every row to be
    a code the installer can actually raise.
    """
    documented = set(_CODE_ROW_RE.findall(INSTALL_GUIDE.read_text(encoding="utf-8")))
    assert documented, "expected a failure-code table in the install guide"

    sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in [*Path("ori/installer").glob("*.py"), *Path("scripts").glob("*")]
        if path.is_file()
    )
    unknown = sorted(code for code in documented if f'"{code}"' not in sources)
    assert not unknown, f"documented codes that no code path raises: {unknown}"


def test_installer_failure_codes_are_all_documented() -> None:
    """Every code the installer can surface must be explainable by the guide."""
    documented = set(_CODE_ROW_RE.findall(INSTALL_GUIDE.read_text(encoding="utf-8")))
    raised = set()
    for path in Path("ori/installer").glob("*.py"):
        raised.update(
            re.findall(
                r"LinuxInstallError\(\s*\n?\s*\"([a-z_]+)\"",
                path.read_text(encoding="utf-8"),
            )
        )
    assert raised, "expected to find raised installer codes"

    undocumented = sorted(raised - documented)
    assert not undocumented, f"codes the guide does not explain: {undocumented}"


def test_arm_bundles_carry_the_raspberry_pi_wheelhouse(
    workflow: dict[str, Any],
) -> None:
    """Every published aarch64 bundle must ship the Pi hardware wheels.

    The build matrix once pinned `ORI_WHEELHOUSE_TARGET: generic` for all six
    targets, so no released bundle carried `gpiozero` at all and a Pi install
    came up with no actuator. The target is a per-entry decision now, and the
    architecture in the bundle name is what decides it.
    """
    entries = workflow["jobs"]["build"]["strategy"]["matrix"]["include"]
    wheelhouse_targets = {
        entry["target"]: entry["wheelhouse-target"] for entry in entries
    }
    assert wheelhouse_targets, "the build matrix declares no targets"
    for target, wheelhouse_target in wheelhouse_targets.items():
        expected = "pi" if "aarch64" in target else "generic"
        assert wheelhouse_target == expected, (
            f"{target} builds the {wheelhouse_target!r} wheelhouse; "
            f"expected {expected!r}"
        )
