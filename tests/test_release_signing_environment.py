# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The signing environment name must stay literal.

Naming it after the version would create a new environment on every tag.
GitHub creates a referenced environment *without* protection rules, so
required reviewers, self-review prevention, the tag-only deployment policy,
the environment-scoped signer variables and the AWS OIDC subject binding would
all silently stop applying — while the protection preflight, which checks
`release-signing` by name, stayed green.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import check_workflows as guard  # noqa: E402

RELEASE = (
    Path(__file__).resolve().parent.parent / ".github" / "workflows" / "release.yml"
)


@pytest.fixture(scope="module")
def workflow() -> str:
    return RELEASE.read_text(encoding="utf-8")


def _check(text: str) -> list[str]:
    failures: list[str] = []
    guard._check_signing_environment(Path("release.yml"), text, failures)
    return failures


def _check_non_release(text: str) -> list[str]:
    failures: list[str] = []
    guard._check_non_release_permissions(Path("ci.yml"), text, failures)
    return failures


def test_the_shipped_workflow_passes(workflow: str) -> None:
    assert _check(workflow) == []


@pytest.mark.parametrize(
    ("label", "replacement"),
    [
        ("ref_name", "${{ github.ref_name }}"),
        ("interpolated", "release-signing-${{ github.ref_name }}"),
    ],
)
def test_a_dynamic_environment_name_is_rejected(
    workflow: str, label: str, replacement: str
) -> None:
    mutated = workflow.replace(
        "      name: release-signing", f"      name: {replacement}"
    )
    failures = _check(mutated)
    assert failures, f"{label} was accepted"
    assert any("expression" in f for f in failures)


def test_an_inline_dynamic_environment_is_rejected(workflow: str) -> None:
    # Replace the whole block: leaving its `url:` line orphaned would make the
    # workflow unparseable, and the test would pass for the wrong reason.
    mutated = re.sub(
        r"    environment:\n(?:      .*\n)+",
        "    environment: ${{ github.ref_name }}\n",
        workflow,
        count=1,
    )
    assert mutated != workflow, "fixture did not replace the environment block"
    assert any("expression" in f for f in _check(mutated))


def test_a_different_literal_environment_is_rejected(workflow: str) -> None:
    mutated = workflow.replace("      name: release-signing", "      name: other")
    assert any("expected 'release-signing'" in f for f in _check(mutated))


def test_a_duplicate_key_is_refused_rather_than_resolved(workflow: str) -> None:
    """GitHub takes the last occurrence; a checker reading the first would
    approve one environment while the workflow deploys to another."""
    mutated = workflow.replace(
        "      name: release-signing\n",
        "      name: release-signing\n      name: ${{ github.ref_name }}\n",
        1,
    )
    assert any("duplicate key" in f for f in _check(mutated))


def test_an_aliased_sign_job_cannot_leak_the_credential(workflow: str) -> None:
    """GitHub supports reusing whole job configurations through anchors.

    Aliasing the sign job copies its `id-token: write` into another job, which
    a parser that never resolves aliases would not see at all.
    """
    mutated = workflow.replace("  sign:\n", "  sign: &signcfg\n", 1)
    mutated = mutated.replace("  publish:\n", "  leaked: *signcfg\n\n  publish:\n", 1)
    assert mutated != workflow, "fixture did not alias the sign job"
    resolved = yaml.safe_load(mutated)
    assert resolved["jobs"]["leaked"]["permissions"]["id-token"] == "write"
    failures = _check(mutated)
    assert failures, "an aliased sign job leaked the credential unnoticed"
    assert any("confined to the sign job" in f for f in failures)


@pytest.mark.parametrize(
    ("label", "replacement"),
    [
        ("quoted key", '    "permissions":\n      id-token: write\n'),
        ("tagged key", "    !!str permissions:\n      id-token: write\n"),
        ("anchored key", "    &key permissions:\n      id-token: write\n"),
        ("quoted value", '    permissions:\n      id-token: "write"\n'),
        ("tagged value", "    permissions:\n      id-token: !!str write\n"),
        ("anchored value", "    permissions:\n      id-token: &grant write\n"),
        ("folded scalar", "    permissions:\n      id-token: >-\n        write\n"),
        ("literal scalar", "    permissions:\n      id-token: |-\n        write\n"),
        ("flow mapping", "    permissions: {contents: read, id-token: write}\n"),
        ("write-all", "    permissions: write-all\n"),
    ],
)
def test_every_encoding_of_a_grant_is_caught(
    workflow: str, label: str, replacement: str
) -> None:
    """These are all valid YAML resolving to `id-token: write`.

    Seven rounds of a hand-written scanner missed one class after another —
    quoted keys, tags, anchors, aliases, flow mappings, block scalars. A real
    parser resolves them all, so this is coverage of the contract rather than
    of syntax the checker happens to recognise.
    """
    failures = _check(_replace_publish_permissions(workflow, replacement))
    assert failures, f"{label} slipped through"
    assert any("confined to the sign job" in f for f in failures)


def test_a_benign_flow_mapping_still_passes(workflow: str) -> None:
    assert (
        _check(
            _replace_publish_permissions(
                workflow, "    permissions: {contents: write}\n"
            )
        )
        == []
    )


def test_an_inherited_grant_does_not_satisfy_the_sign_job(workflow: str) -> None:
    """The sign job must hold the credential itself."""
    document = yaml.safe_load(workflow)
    document["permissions"] = {"contents": "read", "id-token": "write"}
    document["jobs"]["sign"].pop("permissions", None)
    for name, job in document["jobs"].items():
        if name != "sign":
            job["permissions"] = {"contents": "read", "id-token": "none"}
    failures = _check(yaml.safe_dump(document))
    assert any("declared on the job" in f for f in failures)
    assert any("any job added later would inherit" in f for f in failures)


@pytest.mark.parametrize(
    ("label", "permissions"),
    [
        ("write-all", "write-all"),
        ("contents write", {"contents": "write", "id-token": "write"}),
        ("missing contents", {"id-token": "write"}),
        (
            "additional write scope",
            {"contents": "read", "id-token": "write", "actions": "write"},
        ),
        (
            "additional read scope",
            {"contents": "read", "id-token": "write", "actions": "read"},
        ),
    ],
)
def test_the_sign_job_rejects_broader_or_incomplete_permissions(
    workflow: str, label: str, permissions: object
) -> None:
    document = yaml.safe_load(workflow)
    document["jobs"]["sign"]["permissions"] = permissions
    failures = _check(yaml.safe_dump(document))
    assert failures, f"{label} was accepted"
    assert any("permissions must be exactly" in failure for failure in failures)


def test_the_sign_job_accepts_only_the_least_privilege_mapping(
    workflow: str,
) -> None:
    document = yaml.safe_load(workflow)
    document["jobs"]["sign"]["permissions"] = dict(guard.SIGNING_PERMISSIONS)
    assert _check(yaml.safe_dump(document)) == []


@pytest.mark.parametrize(
    "permissions",
    [
        "write-all",
        {"contents": "read", "id-token": "write"},
    ],
)
def test_non_release_workflows_reject_every_workflow_level_oidc_grant(
    permissions: object,
) -> None:
    document = {
        "permissions": permissions,
        "jobs": {"test": {"runs-on": "ubuntu-latest", "steps": []}},
    }
    failures = _check_non_release(yaml.safe_dump(document))
    assert any("allowed only" in failure for failure in failures)


@pytest.mark.parametrize(
    "permissions_yaml",
    [
        '    permissions: {contents: read, id-token: "write"}\n',
        "    permissions: &oidc\n      contents: read\n      id-token: write\n",
        "    permissions: write-all\n",
    ],
)
def test_non_release_workflows_reject_encoded_job_oidc_grants(
    permissions_yaml: str,
) -> None:
    workflow = (
        "permissions:\n  contents: read\n  id-token: none\n"
        "jobs:\n  test:\n    runs-on: ubuntu-latest\n"
        f"{permissions_yaml}"
        "    steps: []\n"
    )
    failures = _check_non_release(workflow)
    assert any("allowed only" in failure for failure in failures)


def test_non_release_workflow_requires_top_level_permissions() -> None:
    workflow = (
        "jobs:\n  test:\n    runs-on: ubuntu-latest\n"
        "    permissions:\n      contents: read\n"
        "    steps:\n      - run: 'permissions: is only text here'\n"
    )
    assert any(
        "missing explicit" in failure for failure in _check_non_release(workflow)
    )


def test_a_workflow_level_grant_is_a_hazard_even_when_overridden(
    workflow: str,
) -> None:
    document = yaml.safe_load(workflow)
    document["permissions"] = {"contents": "read", "id-token": "write"}
    for name, job in document["jobs"].items():
        if name != "sign":
            job["permissions"] = {"contents": "read", "id-token": "none"}
    assert any(
        "any job added later would inherit" in f
        for f in _check(yaml.safe_dump(document))
    )


def test_a_run_block_body_is_not_read_as_structure(workflow: str) -> None:
    mutated = workflow.replace(
        "      - name: Harden runner",
        "      - name: Explain\n        run: |\n"
        "          permissions:\n            id-token: write\n"
        "      - name: Harden runner",
        1,
    )
    assert mutated != workflow
    assert _check(mutated) == []


def test_unparseable_yaml_is_refused(workflow: str) -> None:
    assert any("not parseable YAML" in f for f in _check(workflow + "\n  : : :\n"))


def _replace_publish_permissions(workflow: str, replacement: str) -> str:
    """Swap publish's existing permissions block.

    Inserting a second `permissions:` key would be a duplicate, which the
    strict loader now refuses — so the mutation would test the wrong thing.
    """
    match = re.search(
        r"(  publish:\n(?:    .*\n)*?)    permissions:\n(?:      .*\n)+", workflow
    )
    assert match, "publish permissions block not found"
    return (
        workflow[: match.start()]
        + match.group(1)
        + replacement
        + workflow[match.end() :]
    )


def test_the_shipped_workflow_grants_it_only_in_sign(workflow: str) -> None:
    document = yaml.safe_load(workflow)
    assert document["permissions"]["id-token"] == "none"
    assert document["jobs"]["sign"]["permissions"]["id-token"] == "write"
    for name, job in document["jobs"].items():
        if name != "sign":
            assert job.get("permissions", {}).get("id-token") != "write", name


def test_the_guard_hook_installs_nothing() -> None:
    """The launcher selects an interpreter; it never downloads a dependency."""
    repo = Path(__file__).resolve().parent.parent
    config = yaml.safe_load((repo / ".pre-commit-config.yaml").read_text())
    guard = next(
        hook
        for entry in config["repos"]
        if entry["repo"] == "local"
        for hook in entry["hooks"]
        if hook["id"] == "supply-chain-guard"
    )
    assert guard["language"] == "system"
    assert "additional_dependencies" not in guard
    launcher = (repo / "scripts" / "run-workflow-guard.sh").read_text()
    assert ".venv/bin/python" in launcher
    # It may *name* an install command in its guidance; it must not run one.
    executable = [
        line
        for line in launcher.splitlines()
        if line.strip() and not line.lstrip().startswith(("#", "echo "))
    ]
    for installer in ("pip install", "pip3 ", "easy_install", "curl ", "wget "):
        assert not any(installer in line for line in executable), (
            f"the launcher must not run {installer}"
        )


@pytest.mark.parametrize("workflow_name", ["ci.yml", "release.yml"])
def test_ci_installs_hash_locked_pyyaml_before_running_the_guard(
    workflow_name: str,
) -> None:
    repo = Path(__file__).resolve().parent.parent
    document = yaml.safe_load(
        (repo / ".github" / "workflows" / workflow_name).read_text(encoding="utf-8")
    )
    test_job = document["jobs"]["test"]
    steps = test_job["steps"]
    install_index = next(
        index
        for index, step in enumerate(steps)
        if "pip install --require-hashes -r requirements/dev.txt"
        in str(step.get("run", ""))
    )
    guard_index = next(
        index
        for index, step in enumerate(steps)
        if "python scripts/check_workflows.py" in str(step.get("run", ""))
    )
    assert install_index < guard_index


def test_the_environment_name_matches_what_preflight_verifies() -> None:
    preflight = (
        Path(__file__).resolve().parent.parent
        / "scripts"
        / "check_release_protections.py"
    ).read_text(encoding="utf-8")
    assert f'ENVIRONMENT = "{guard.SIGNING_ENVIRONMENT}"' in preflight


def test_the_oidc_subject_binding_is_documented_for_this_environment() -> None:
    signing = (
        Path(__file__).resolve().parent.parent / "docs" / "RELEASE_SIGNING.md"
    ).read_text(encoding="utf-8")
    assert f"environment:{guard.SIGNING_ENVIRONMENT}" in signing


def test_the_version_is_visible_without_touching_the_environment(
    workflow: str,
) -> None:
    assert "run-name: Release ${{ github.ref_name }}" in workflow
    assert "name: Sign release bundles (${{ github.ref_name }})" in workflow
    assert "      name: release-signing" in workflow
