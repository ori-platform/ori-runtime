#!/usr/bin/env python3
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Guard CI and hook configuration against supply-chain footguns."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

WORKFLOW_DIR = Path(".github/workflows")
PRE_COMMIT_CONFIG = Path(".pre-commit-config.yaml")
SHA_RE = re.compile(r"uses:\s*[^\s#]+@[0-9a-f]{40}(?:\s*#.*)?$")
MUTABLE_ACTION_RE = re.compile(r"uses:\s*[^\s#]+@(?:v\d+(?:\.\d+\.\d+)?|main|master)\b")
PRE_COMMIT_REV_RE = re.compile(r"^\s+rev:\s*([^#\s]+)")
REMOTE_EXEC_RE = re.compile(
    r"(?:curl|wget)\b[^\n]*(?:\|\s*(?:bash|sh|python\d*)|&&\s*(?:bash|sh|python\d*)\b)",
    re.IGNORECASE,
)


def _workflow_files() -> list[Path]:
    if not WORKFLOW_DIR.exists():
        return []
    return sorted(p for p in WORKFLOW_DIR.rglob("*") if p.suffix in {".yml", ".yaml"})


def _line_number(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


# Naming the signing environment after the version would create a *new*
# environment on every tag. GitHub creates a referenced environment without
# protection rules, so required reviewers, self-review prevention, the
# tag-only deployment policy, the environment-scoped signer variables, and the
# AWS OIDC subject binding would all silently cease to apply — while the
# protection preflight, which checks `release-signing` by name, stayed green.
SIGNING_ENVIRONMENT = "release-signing"
SIGNING_PERMISSIONS = {"contents": "read", "id-token": "write"}


class WorkflowError(Exception):
    """The workflow could not be resolved well enough to check."""


class _StrictLoader(yaml.SafeLoader):
    """A loader that refuses duplicate keys.

    GitHub resolves a duplicate mapping key to the last occurrence. A checker
    that reads the first would approve `environment: release-signing` while the
    workflow actually deploys somewhere else, so ambiguity is rejected outright
    rather than resolved by guesswork.
    """


def _no_duplicate_keys(
    loader: _StrictLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise WorkflowError(f"duplicate key {key!r}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicate_keys
)


def _load_workflow(text: str) -> dict[str, object]:
    """Resolve a workflow the way GitHub does, or refuse to guess.

    PyYAML is used rather than a hand-written scanner. Quoted keys, explicit
    tags, anchors, aliases, block scalars and reused job configurations are all
    supported workflow syntax, and a partial parser cannot prove what any of
    them resolve to — it can only fail to notice them.
    """
    try:
        document = yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - strict subclass
    except WorkflowError:
        raise
    except yaml.YAMLError as exc:
        raise WorkflowError(
            f"is not parseable YAML ({exc.__class__.__name__})"
        ) from exc
    if not isinstance(document, dict):
        raise WorkflowError("is not a YAML mapping")
    return document


def _grants_id_token_write(permissions: object) -> bool:
    """Whether a resolved permissions value grants the credential."""
    if permissions == "write-all":
        return True
    return isinstance(permissions, dict) and permissions.get("id-token") == "write"


def _has_exact_signing_permissions(permissions: object) -> bool:
    """Whether the sign job has only the authority required to sign.

    Merely finding ``id-token: write`` is insufficient: ``write-all``,
    ``contents: write``, or an additional write scope would all broaden the
    short-lived signing job's authority while satisfying that weaker check.
    """
    return permissions == SIGNING_PERMISSIONS


def _environment_name(environment: object) -> str | None:
    """The environment name from either the scalar or mapping form."""
    if isinstance(environment, str):
        return environment
    if isinstance(environment, dict):
        name = environment.get("name")
        return name if isinstance(name, str) else None
    return None


def _check_signing_environment(path: Path, text: str, failures: list[str]) -> None:
    """The sign job must name the protected environment and hold the credential."""
    try:
        document = _load_workflow(text)
    except WorkflowError as exc:
        failures.append(f"{path}: {exc}")
        return

    jobs = document.get("jobs")
    if not isinstance(jobs, dict):
        failures.append(f"{path}: declares no jobs")
        return
    sign = jobs.get("sign")
    if not isinstance(sign, dict):
        failures.append(f"{path}: no sign job found; the signing guard cannot apply")
        return

    name = _environment_name(sign.get("environment"))
    if name is None:
        failures.append(f"{path}: the sign job declares no environment name")
    elif "${{" in name:
        failures.append(
            f"{path}: the sign job environment name is an expression ({name!r}); "
            f"it must be the literal {SIGNING_ENVIRONMENT!r}, or its protection "
            "rules and OIDC subject binding will not apply"
        )
    elif name != SIGNING_ENVIRONMENT:
        failures.append(
            f"{path}: the sign job uses environment {name!r}, "
            f"expected {SIGNING_ENVIRONMENT!r}"
        )

    # Local and inherited authority are computed separately. Resolving the sign
    # job's permissions with a fallback to the workflow's would accept a
    # workflow-level grant as if the job had declared it — the opposite of
    # confining the credential, since every job added later would inherit it.
    if not _has_exact_signing_permissions(sign.get("permissions")):
        failures.append(
            f"{path}: the sign job permissions must be exactly "
            "contents: read and id-token: write, declared on the job; "
            "inherited, missing, or additional authority is forbidden"
        )

    workflow_permissions = document.get("permissions")
    if _grants_id_token_write(workflow_permissions):
        failures.append(
            f"{path}: id-token: write is granted at workflow level; any job "
            "added later would inherit it"
        )

    for job_name, job in sorted(jobs.items(), key=lambda item: str(item[0])):
        if job_name == "sign":
            continue
        if not isinstance(job, dict):
            continue
        effective = job.get("permissions", workflow_permissions)
        if _grants_id_token_write(effective):
            inherited = "permissions" not in job
            failures.append(
                f"{path}: id-token: write must be confined to the sign job, "
                f"found {'inherited by' if inherited else 'in'} {job_name!r}"
            )


def _check_non_release_permissions(path: Path, text: str, failures: list[str]) -> None:
    """Reject OIDC authority in every workflow other than release signing."""
    try:
        document = _load_workflow(text)
    except WorkflowError as exc:
        failures.append(f"{path}: {exc}")
        return

    if "permissions" not in document:
        failures.append(f"{path}: missing explicit workflow permissions")
    workflow_permissions = document.get("permissions")
    if _grants_id_token_write(workflow_permissions):
        failures.append(
            f"{path}: id-token: write is allowed only in release.yml's sign job"
        )

    jobs = document.get("jobs")
    if not isinstance(jobs, dict):
        failures.append(f"{path}: declares no jobs")
        return
    for job_name, job in sorted(jobs.items(), key=lambda item: str(item[0])):
        if not isinstance(job, dict):
            continue
        effective = job.get("permissions", workflow_permissions)
        if _grants_id_token_write(effective):
            failures.append(
                f"{path}: id-token: write is allowed only in release.yml's "
                f"sign job, found in or inherited by {job_name!r}"
            )


def _check_pre_commit_config(failures: list[str]) -> None:
    if not PRE_COMMIT_CONFIG.exists():
        return
    current_repo: str | None = None
    for line_number, line in enumerate(
        PRE_COMMIT_CONFIG.read_text().splitlines(), start=1
    ):
        stripped = line.strip()
        if stripped.startswith("- repo:"):
            current_repo = stripped.removeprefix("- repo:").strip()
            continue
        if current_repo in {None, "local"}:
            continue
        match = PRE_COMMIT_REV_RE.match(line)
        if not match:
            continue
        rev = match.group(1)
        if not re.fullmatch(r"[0-9a-f]{40}", rev):
            failures.append(
                f"{PRE_COMMIT_CONFIG}:{line_number}: remote pre-commit hook "
                f"{current_repo} must pin rev to a full commit SHA"
            )


def main() -> int:
    failures: list[str] = []
    for path in _workflow_files():
        text = path.read_text()
        if "pull_request_target" in text:
            failures.append(f"{path}: contains forbidden trigger pull_request_target")
        for match in MUTABLE_ACTION_RE.finditer(text):
            line = _line_number(text, match.start())
            # A full SHA pin with a version comment is allowed; mutable refs are not.
            source_line = text.splitlines()[line - 1]
            if not SHA_RE.search(source_line):
                failures.append(
                    f"{path}:{line}: mutable GitHub Action ref: {source_line.strip()}"
                )
        for match in REMOTE_EXEC_RE.finditer(text):
            line = _line_number(text, match.start())
            failures.append(
                f"{path}:{line}: remote script download/execution is forbidden"
            )
        if path.name == "release.yml":
            _check_signing_environment(path, text, failures)
        else:
            _check_non_release_permissions(path, text, failures)
    _check_pre_commit_config(failures)
    if failures:
        print("Supply-chain guard failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("Supply-chain guard: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
