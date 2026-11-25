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
ACTION_DIR = Path(".github/actions")
PRE_COMMIT_CONFIG = Path(".pre-commit-config.yaml")
PRE_COMMIT_REV_RE = re.compile(r"^\s+rev:\s*([^#\s]+)")
#: The only references a `uses:` may hold: a full commit SHA, a path in this
#: repository, or a container image pinned by digest. Anything else is refused,
#: whatever it is spelled as.
PINNED_USES_RE = re.compile(
    r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[^@\s]+)?@[0-9a-f]{40}"
    r"|\./[^@\s]*"
    r"|docker://[^@\s]+@sha256:[0-9a-f]{64}"
)
#: A download tool named anywhere in a workflow or action. Refused outright:
#: what a fetched script does is not visible here.
DOWNLOAD_RE = re.compile(r"\b(?:curl|wget|Invoke-WebRequest|iwr)\b", re.IGNORECASE)
DOWNLOAD_LIMIT = (
    "a download tool named in workflow or action YAML is refused outright, "
    "as written or as YAML decodes it, comments included; a tool spelled "
    "through shell quoting or expansion (cu''rl, ${X}) or GitHub's own "
    "substitution (${{ env.T }}rl, format()), and a download made "
    "any other way (an interpreter, an action, a script the workflow runs), "
    "is a review boundary this guard does not cover"
)


def _workflow_files() -> list[Path]:
    if not WORKFLOW_DIR.exists():
        return []
    return sorted(p for p in WORKFLOW_DIR.rglob("*") if p.suffix in {".yml", ".yaml"})


def _action_files() -> list[Path]:
    if not ACTION_DIR.exists():
        return []
    return sorted(
        p for p in ACTION_DIR.rglob("*") if p.name in {"action.yml", "action.yaml"}
    )


AUDIT_JOB = "audit"
AUDIT_COMMAND = "python3 scripts/audit_locks.py"
#: A status function in a job's `if` lets it run after a job it needs failed;
#: without one GitHub applies `success()`, and `|| true` defeats an explicit one.
STATUS_FUNCTION_RE = re.compile(r"\b(?:always|failure|cancelled|success)\s*\(", re.I)
#: The one form a waiting job's `if` may take with a status function: it runs
#: after a failed job only when the audit itself succeeded. The group after it
#: must span the rest, so nothing outside it can widen the condition.
AUDITED_ALWAYS = "always() && needs.audit.result == 'success' && ("
QUOTED_LITERAL_RE = re.compile(r"'(?:[^']|'')*'")
#: GitHub-hosted Ubuntu images: a self-hosted runner brings its own python3,
#: PATH and job hooks, which would decide what the audit runs.
HOSTED_RUNNER_RE = re.compile(r"ubuntu-(?:latest|\d+\.\d+)")
#: Keys that name a container image to run, which no pin rule here covers and
#: nothing in this repository needs.
IMAGE_KEYS = frozenset({"container", "services", "image"})
#: A workflow holding the audit may set only these, since the audit inherits
#: them: no `defaults` (a shell or working directory), and in `env` only the
#: project's own `ORI_` names, which no shell, interpreter or runner reads.
AUDITED_WORKFLOW_KEYS = frozenset(
    {"name", "run-name", "on", "permissions", "concurrency", "env", "jobs"}
)
INHERITED_ENV_RE = re.compile(r"ORI_[A-Z0-9_]+")
#: The audit job's only keys, and its steps in order: what it may hold.
AUDIT_JOB_KEYS = frozenset(
    {"name", "runs-on", "timeout-minutes", "permissions", "steps"}
)
AUDIT_STEPS: tuple[tuple[str, str, set[str]], ...] = (
    ("uses", "step-security/harden-runner@", {"egress-policy"}),
    ("uses", "actions/checkout@", {"persist-credentials"}),
    ("run", AUDIT_COMMAND, set()),
)


def _needs(job: object) -> list[str]:
    needs = job.get("needs") if isinstance(job, dict) else None
    if isinstance(needs, str):
        return [needs]
    return [n for n in needs if isinstance(n, str)] if isinstance(needs, list) else []


def _audited_always(condition: object) -> bool:
    """Whether *condition* is exactly `AUDITED_ALWAYS` and one group to its end."""
    if not isinstance(condition, str):
        return False
    text = " ".join(condition.split())
    # Text beside `${{ }}` makes the whole `if` a format string, which is true.
    if "${{" in text or not text.startswith(AUDITED_ALWAYS):
        return False
    # A quoted literal is text to GitHub, so its parentheses group nothing.
    group = QUOTED_LITERAL_RE.sub("''", text[len(AUDITED_ALWAYS) - 1 :])
    if not group.endswith(")"):
        return False
    depth = 0
    for index, char in enumerate(group):
        depth += {"(": 1, ")": -1}.get(char, 0)
        if depth == 0:
            return index == len(group) - 1
    return False


def _audit_job_problem(audit: object) -> str:
    """Why *audit* is not exactly the lock audit, or "" when it is.

    Anything more could skip it, let it fail quietly, or run a package's code
    before it: a condition, `continue-on-error`, a matrix, another step.
    """
    if not isinstance(audit, dict):
        return "is missing"
    if set(audit) - AUDIT_JOB_KEYS:
        return f"holds {sorted(set(audit) - AUDIT_JOB_KEYS)}; only {sorted(AUDIT_JOB_KEYS)}"
    runner = audit.get("runs-on")
    if not isinstance(runner, str) or not HOSTED_RUNNER_RE.fullmatch(runner):
        return f"runs on {runner!r}; only a GitHub-hosted ubuntu image may run it"
    steps = audit.get("steps")
    if not isinstance(steps, list) or len(steps) != len(AUDIT_STEPS):
        return "must hold exactly the runner hardening, the checkout and the audit"
    for step, (kind, value, options) in zip(steps, AUDIT_STEPS, strict=True):
        if not isinstance(step, dict) or set(step) - {"name", kind, "with"}:
            return f"has a step that is not exactly {kind}: {step!r}"
        held = step.get(kind)
        if not isinstance(held, str) or not (
            held.startswith(value) if kind == "uses" else held == value
        ):
            return f"has a step {kind}: {held!r} where {value!r} belongs"
        given = step.get("with", {})
        if not isinstance(given, dict) or set(given) - options:
            return f"passes {given!r} to {held!r}"
    checkout = steps[1].get("with", {})
    if checkout.get("persist-credentials") is not False:
        return "must check out with persist-credentials: false"
    return ""


def _check_audit_first(
    path: Path, document: dict[str, object], failures: list[str]
) -> None:
    """Refuse a job that may install or build before the lock audit passed."""
    jobs = document.get("jobs")
    if not isinstance(jobs, dict):
        return
    waiting = [name for name in jobs if name != AUDIT_JOB]
    audit = jobs.get(AUDIT_JOB)
    problem = _audit_job_problem(audit)
    if problem:
        failures.append(f"{path}: the `{AUDIT_JOB}` job {problem}")
        return
    # PyYAML reads the bare key `on` as True.
    extra = {str(k) for k in document if k is not True} - AUDITED_WORKFLOW_KEYS
    env = document.get("env", {})
    if extra or not isinstance(env, dict):
        failures.append(
            f"{path}: holds {sorted(extra) or 'a non-mapping env'}, which the "
            f"`{AUDIT_JOB}` job would inherit"
        )
    elif bad := sorted(str(k) for k in env if not INHERITED_ENV_RE.fullmatch(str(k))):
        failures.append(
            f"{path}: workflow env {bad} would reach the `{AUDIT_JOB}` job; only "
            "ORI_ names may be set for the whole workflow"
        )
    for name in waiting:
        seen: set[str] = set()
        pending = _needs(jobs[name])
        while pending:
            current = pending.pop()
            if current not in seen:
                seen.add(current)
                pending += _needs(jobs.get(current))
        if AUDIT_JOB not in seen:
            failures.append(
                f"{path}: job {name!r} does not wait on the `{AUDIT_JOB}` job, so it "
                "may install or build a dependency before the locks are audited"
            )
        elif STATUS_FUNCTION_RE.search(str(jobs[name].get("if", ""))) and not (
            AUDIT_JOB in _needs(jobs[name]) and _audited_always(jobs[name].get("if"))
        ):
            failures.append(
                f"{path}: job {name!r} has a status function in its `if`, so it may "
                f"run when the `{AUDIT_JOB}` job did not succeed; the one form "
                f"allowed is `{AUDITED_ALWAYS} … )` with `{AUDIT_JOB}` in its needs"
            )


def _keys(node: object) -> set[str]:
    """Every mapping key in *node*, at any depth, as a string."""
    found: set[str] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            found.add(str(key))
            found |= _keys(value)
    elif isinstance(node, list):
        for item in node:
            found |= _keys(item)
    return found


def _strings(node: object) -> list[str]:
    """Every string in *node*, keys included, as YAML decoded it."""
    found: list[str] = []
    if isinstance(node, str):
        found.append(node)
    elif isinstance(node, dict):
        for key, value in node.items():
            found += _strings(key) + _strings(value)
    elif isinstance(node, list):
        for item in node:
            found += _strings(item)
    return found


def _uses_values(node: object) -> list[object]:
    """Every value held under a `uses` key, at any depth of *node*."""
    found: list[object] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if str(key).lower() == "uses":
                found.append(value)
            found.extend(_uses_values(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_uses_values(item))
    return found


def _check_references(path: Path, text: str, failures: list[str]) -> None:
    """Refuse any `uses:` not pinned, and any download tool, in *path*."""
    try:
        document = _load_workflow(text)
    except (WorkflowError, TypeError) as exc:
        # TypeError: a key YAML allows and a mapping cannot hold, such as a list.
        failures.append(f"{path}: {exc}")
        return
    for key in _keys(document) & IMAGE_KEYS:
        failures.append(
            f"{path}: `{key}` names a container image no pin rule covers; nothing "
            "here needs one, so it is refused"
        )
    for value in _uses_values(document):
        if not isinstance(value, str) or not PINNED_USES_RE.fullmatch(value):
            failures.append(
                f"{path}: unpinned reference uses: {value!r}; pin a full commit "
                "SHA, a ./ path, or a docker:// image by @sha256: digest"
            )
    # The raw text holds the comments; the decoded strings hold what an escape
    # such as `c\u0075rl` spells.
    for match in DOWNLOAD_RE.finditer(text):
        line = _line_number(text, match.start())
        failures.append(f"{path}:{line}: {match.group(0)}: {DOWNLOAD_LIMIT}")
    for value in _strings(document):
        for match in DOWNLOAD_RE.finditer(value):
            failures.append(f"{path}: {match.group(0)}: {DOWNLOAD_LIMIT}")
    if path.parent == WORKFLOW_DIR:
        _check_audit_first(path, document, failures)


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
    except (WorkflowError, TypeError) as exc:
        # TypeError: a key YAML allows and a mapping cannot hold, such as a list.
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
    except (WorkflowError, TypeError) as exc:
        # TypeError: a key YAML allows and a mapping cannot hold, such as a list.
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
        _check_references(path, text, failures)
        if path.name == "release.yml":
            _check_signing_environment(path, text, failures)
        else:
            _check_non_release_permissions(path, text, failures)
    for path in _action_files():
        _check_references(path, path.read_text(), failures)
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
