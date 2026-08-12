#!/usr/bin/env python3
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Prove the repository protections a signed release depends on are present.

GitHub creates a referenced environment *without* protection rules the first
time a workflow names it, so ``environment:`` in a workflow gates nothing on
its own. Every protection the release pipeline relies on is therefore asserted
here before any credential is issued or any artifact is produced.

Each check proves the specific property rather than the presence of a related
object: an environment with a reviewer who may approve their own release, or a
tag ruleset that protects unrelated tags, would satisfy a shallower test while
leaving the release unprotected.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from typing import Any, Callable, Sequence

ENVIRONMENT = "release-signing"
TAG_PATTERN = "refs/tags/v*"
_WILDCARD_REFS = frozenset({"~ALL", "refs/tags/*", TAG_PATTERN})
_IMMUTABILITY_RULES = frozenset({"update", "non_fast_forward"})

ApiClient = Callable[[str], Any]


class ProtectionError(Exception):
    """A missing release protection, stated so an operator can act on it."""

    def __init__(self, detail: str, remedy: str) -> None:
        super().__init__(f"{detail} — {remedy}")
        self.detail = detail
        self.remedy = remedy


def _gh_api(path: str) -> Any:
    result = subprocess.run(
        ["gh", "api", path],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if result.returncode != 0:
        raise ProtectionError(
            f"GitHub API call failed: {path}",
            "confirm the workflow token can read repository settings",
        )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ProtectionError(
            f"GitHub API returned invalid JSON: {path}",
            "retry; if it persists this is a GitHub-side fault",
        ) from exc


def check_immutable_releases(api: ApiClient, repository: str) -> None:
    """Require repository release immutability.

    ``gh release create --verify-tag`` only confirms a tag exists; it neither
    freezes assets nor protects the tag. Immutability is a separate setting
    exposed by its own endpoint, not a field on the repository response.
    """
    payload = api(f"repos/{repository}/immutable-releases")
    if not isinstance(payload, dict) or payload.get("enabled") is not True:
        raise ProtectionError(
            "repository immutable releases are not enabled",
            "enable immutable releases in repository settings",
        )


def check_signing_environment(api: ApiClient, repository: str) -> None:
    """Require a reviewer-gated, tag-scoped signing environment."""
    try:
        environment = api(f"repos/{repository}/environments/{ENVIRONMENT}")
    except ProtectionError as exc:
        raise ProtectionError(
            f"the {ENVIRONMENT} environment does not exist or is unreadable",
            f"create {ENVIRONMENT} with a required reviewer before releasing",
        ) from exc
    if not isinstance(environment, dict):
        raise ProtectionError(
            f"the {ENVIRONMENT} environment response is malformed",
            "retry; if it persists this is a GitHub-side fault",
        )

    rules = environment.get("protection_rules")
    reviewer_rules = (
        [
            rule
            for rule in rules
            if isinstance(rule, dict) and rule.get("type") == "required_reviewers"
        ]
        if isinstance(rules, list)
        else []
    )
    if not reviewer_rules:
        raise ProtectionError(
            f"{ENVIRONMENT} has no required reviewer",
            "add a required reviewer so signing is never unattended",
        )
    # A reviewer who can approve their own release is not a second pair of eyes.
    if any(rule.get("prevent_self_review") is not True for rule in reviewer_rules):
        raise ProtectionError(
            f"{ENVIRONMENT} permits self-review",
            "enable 'prevent self-review' on the required reviewer rule",
        )

    policy = environment.get("deployment_branch_policy")
    if not isinstance(policy, dict) or policy.get("custom_branch_policies") is not True:
        raise ProtectionError(
            f"{ENVIRONMENT} does not restrict deployments to selected refs",
            "set a custom deployment policy limited to version tags",
        )
    _check_deployment_tag_policy(api, repository)


def _check_deployment_tag_policy(api: ApiClient, repository: str) -> None:
    payload = api(
        f"repos/{repository}/environments/{ENVIRONMENT}/deployment-branch-policies"
    )
    policies = payload.get("branch_policies") if isinstance(payload, dict) else None
    entries = (
        [entry for entry in policies if isinstance(entry, dict)]
        if isinstance(policies, list)
        else []
    )
    if not entries:
        raise ProtectionError(
            f"{ENVIRONMENT} has no deployment policy entries",
            "add a tag policy matching the approved version-tag pattern",
        )
    # A branch entry would let a branch run reach the signing role.
    if any(entry.get("type") != "tag" for entry in entries):
        raise ProtectionError(
            f"{ENVIRONMENT} allows non-tag deployments",
            "remove branch policies so only version tags can sign",
        )
    if not any(_matches_version_tags(str(entry.get("name", ""))) for entry in entries):
        raise ProtectionError(
            f"{ENVIRONMENT} tag policy does not cover version tags",
            "use a tag policy such as 'v*' for the approved pattern",
        )


def _matches_version_tags(pattern: str) -> bool:
    return pattern in {"v*", "v*.*.*", "*"}


def check_tag_ruleset(api: ApiClient, repository: str) -> None:
    """Require an active ruleset that freezes published version tags."""
    listing = api(f"repos/{repository}/rulesets")
    candidates = [
        entry
        for entry in (listing if isinstance(listing, list) else [])
        if isinstance(entry, dict)
        and entry.get("target") == "tag"
        and entry.get("enforcement") == "active"
    ]
    if not candidates:
        raise ProtectionError(
            "no active tag ruleset protects release tags",
            "add an active tag ruleset restricting updates and deletions",
        )
    for candidate in candidates:
        detail = api(f"repos/{repository}/rulesets/{candidate.get('id')}")
        if _ruleset_freezes_version_tags(detail):
            return
    raise ProtectionError(
        "no active tag ruleset both covers version tags and blocks updates",
        "restrict update and deletion for refs/tags/v* in the tag ruleset",
    )


def _ruleset_freezes_version_tags(detail: Any) -> bool:
    if not isinstance(detail, dict):
        return False
    conditions = detail.get("conditions")
    ref_name = conditions.get("ref_name") if isinstance(conditions, dict) else None
    if not isinstance(ref_name, dict):
        return False
    # An exclusion can carve the actual release tags back out of a broad
    # include, so any exclusion disqualifies the ruleset rather than being
    # pattern-matched against.
    exclude = ref_name.get("exclude")
    if exclude:
        return False
    include = ref_name.get("include")
    covered = any(
        str(pattern) in _WILDCARD_REFS
        for pattern in (include if isinstance(include, list) else [])
    )
    rules = detail.get("rules")
    types = {
        rule.get("type")
        for rule in (rules if isinstance(rules, list) else [])
        if isinstance(rule, dict)
    }
    # Deletion alone still allows a tag to be force-moved onto other content.
    return covered and "deletion" in types and bool(types & _IMMUTABILITY_RULES)


def check_signed_tag(
    api: ApiClient, repository: str, tag: str, expected_commit: str
) -> None:
    """Require the release ref to be a verified annotated tag on one commit.

    ``--verify-tag`` only proves a tag exists. A lightweight tag carries no
    signature at all, and an annotated tag can be unsigned or signed by an
    unregistered key, so the approval contract's "signed tag" has to be checked
    against GitHub's own verification result rather than assumed.
    """
    ref = api(f"repos/{repository}/git/ref/tags/{tag}")
    obj = ref.get("object") if isinstance(ref, dict) else None
    if not isinstance(obj, dict) or obj.get("type") != "tag":
        raise ProtectionError(
            f"{tag} is not an annotated tag",
            "create the release tag with `git tag -s` so it can carry a signature",
        )
    tag_object = api(f"repos/{repository}/git/tags/{obj.get('sha')}")
    if not isinstance(tag_object, dict):
        raise ProtectionError(
            f"{tag} tag object is unreadable",
            "retry; if it persists this is a GitHub-side fault",
        )
    verification = tag_object.get("verification")
    if not isinstance(verification, dict) or verification.get("verified") is not True:
        reason = (
            verification.get("reason")
            if isinstance(verification, dict)
            else "unavailable"
        )
        raise ProtectionError(
            f"{tag} does not carry a verified signature (reason: {reason})",
            "sign the tag with a key registered to the tagger's GitHub account",
        )
    target = tag_object.get("object")
    if not isinstance(target, dict) or target.get("type") != "commit":
        raise ProtectionError(
            f"{tag} does not point at a commit",
            "tag the approved release commit directly",
        )
    if target.get("sha") != expected_commit:
        raise ProtectionError(
            f"{tag} resolves to {target.get('sha')}, not the approved {expected_commit}",
            "re-tag the approved commit; approval is bound to an exact SHA",
        )


def run_checks(
    api: ApiClient,
    repository: str,
    *,
    tag: str | None = None,
    commit: str | None = None,
) -> list[ProtectionError]:
    """Run every check and collect failures so one run reports all gaps."""
    failures: list[ProtectionError] = []
    for check in (
        check_immutable_releases,
        check_signing_environment,
        check_tag_ruleset,
    ):
        try:
            check(api, repository)
        except ProtectionError as exc:
            failures.append(exc)
    if tag is not None and commit is not None:
        try:
            check_signed_tag(api, repository, tag, commit)
        except ProtectionError as exc:
            failures.append(exc)
    return failures


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the repository protections a signed release depends on."
    )
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", help="release tag to require a verified signature on")
    parser.add_argument("--commit", help="commit the release tag must resolve to")
    args = parser.parse_args(argv)

    if bool(args.tag) != bool(args.commit):
        parser.error("--tag and --commit must be given together")
    failures = run_checks(_gh_api, args.repository, tag=args.tag, commit=args.commit)
    if failures:
        print("Release protections are not in place:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure.detail}", file=sys.stderr)
            print(f"    fix: {failure.remedy}", file=sys.stderr)
        return 2
    print("Release protections verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
