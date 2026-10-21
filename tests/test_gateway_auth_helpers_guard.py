# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Every test authenticator takes an explicit replay cache, and every test
replay cache an explicit start floor.

One built without one starts its floor at the wall clock, so an envelope the
test signed a moment earlier is refused whenever the two straddle a
millisecond: green locally, red on a slow runner. Read by AST, so a rename or
reformat does not slip past it.
"""

from __future__ import annotations

import ast
from pathlib import Path

TESTS = Path(__file__).resolve().parent

#: (path relative to tests/, enclosing function) -> why the default is sound.
EXEMPT = {
    (
        "test_gateway_payload_bounds.py",
        "test_a_key_is_kept_as_before_and_until_its_envelope_is_stale",
    ): "covers the cache the authenticator builds itself, with now_ms pinned to 0",
    (
        "test_gateway_payload_bounds.py",
        "test_the_persisted_replay_cache_prunes_by_index",
    ): "reads a query plan; verifies no envelope",
    (
        "test_gateway_payload_bounds.py",
        "test_a_loaded_key_with_no_signing_time_keeps_its_stored_expiry",
    ): "reads a loaded row; verifies no envelope",
}


def _unguarded() -> list[str]:
    found: list[str] = []
    for path in sorted(TESTS.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for function in ast.walk(tree):
            if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in ast.walk(function):
                if not isinstance(node, ast.Call):
                    continue
                name = getattr(node.func, "id", getattr(node.func, "attr", None))
                given = {k.arg for k in node.keywords}
                if (
                    name == "GatewayMessageAuthenticator"
                    and "replay_cache" not in given
                ) or (
                    name == "GatewayReplayCache"
                    and "start_ms" not in given
                    and None not in given  # **kwargs from a helper that sets it
                ):
                    key = (str(path.relative_to(TESTS)), function.name)
                    if key not in EXEMPT:
                        found.append(f"{key[0]}::{key[1]}:{node.lineno}")
    return sorted(set(found))


def test_every_test_authenticator_takes_an_explicit_replay_cache() -> None:
    assert _unguarded() == [], (
        "a test GatewayMessageAuthenticator has no replay_cache; pass "
        "tests.gateway_auth_helpers.cache_for(config), or add an EXEMPT entry "
        "with its reason"
    )


def test_every_exemption_still_names_a_real_site() -> None:
    for (relative, function), _reason in EXEMPT.items():
        tree = ast.parse((TESTS / relative).read_text(encoding="utf-8"))
        assert any(
            isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and n.name == function
            for n in ast.walk(tree)
        ), (relative, function)
