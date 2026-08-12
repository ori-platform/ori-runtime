# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import hashlib
import re
import runpy
import urllib.error
import warnings
import zipfile
from pathlib import Path
from typing import Any

import pytest
import yaml

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


def test_release_runs_only_on_immutable_version_tags(workflow: dict[str, Any]) -> None:
    triggers = workflow[True] if True in workflow else workflow["on"]

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
    assert sign["environment"] == "release-signing"
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
    assert jobs["sign"]["needs"] == "build"
    assert jobs["publish"]["needs"] == "sign"
    assert jobs["reverify"]["needs"] == "publish"


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


@pytest.mark.parametrize("job", ["test", "sign", "publish", "reverify"])
def test_jobs_running_repository_scripts_install_the_package(
    workflow: dict[str, Any], job: str
) -> None:
    commands = "\n".join(str(step.get("run", "")) for step in _steps(workflow, job))

    assert "pip install --no-deps -e ." in commands


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


def test_publication_is_reverified_from_the_public_origin(
    workflow: dict[str, Any],
) -> None:
    reverify = "\n".join(
        str(step.get("run", "")) for step in _steps(workflow, "reverify")
    )

    assert "scripts/verify_published_release.py" in reverify
    for target in (
        "linux-x86_64-python3.11",
        "linux-x86_64-python3.12",
        "linux-aarch64-python3.11",
        "linux-aarch64-python3.12",
    ):
        assert target in reverify


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
    # against it would fail even once immutability is enabled.
    requested: list[str] = []

    def call(path: str) -> Any:
        requested.append(path)
        return _api({})(path)

    protections["run_checks"](call, "o/r")
    assert "repos/o/r/immutable-releases" in requested
    assert "repos/o/r" not in requested


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"repos/o/r/immutable-releases": {"enabled": False}}, "immutable releases"),
        ({"repos/o/r/immutable-releases": {}}, "immutable releases"),
    ],
)
def test_disabled_immutability_blocks_the_release(
    protections: dict[str, Any], overrides: dict[str, Any], expected: str
) -> None:
    failures = protections["run_checks"](_api(overrides), "o/r")
    assert any(expected in failure.detail for failure in failures)


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
