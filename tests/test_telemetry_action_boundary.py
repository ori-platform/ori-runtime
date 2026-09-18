# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Telemetry is observational, and these tests are what holds that.

`runtime-telemetry/v2` says it in words: nothing a receiver derives from either
route may become an input to an action, a threshold, or a policy on the device.
A sentence in a contract needs a reader who applies it, and the same estate has
already made the same class of mistake on a second route after writing the rule
down in prose. So the boundary is asserted here.

Two guards, because one spelling of "reaches" is not the rule. The first
forecloses an import. The second is an inventory of every way the runtime
touches the exporter at all, which is what a value *passed as a parameter*
would have to change — `ori/runtime.py` legitimately imports both telemetry and
the whole action surface, so the import guard alone would pass while the hazard
sat inside that module.

Neither guard proves the contract's sentence. What they do is make its most
reachable violations fail the suite, and say in their own failure messages what
they do not cover.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

#: The action path: where physical authority is decided and executed. Nothing
#: here may read telemetry, because a value that reaches these modules can
#: reach a tier, a threshold, or an executor.
ACTION_PATH = ("ori/reasoning", "ori/actions")

#: The telemetry surface, whose values are reports about delivery and never
#: facts about the world a decision may rest on.
TELEMETRY_MODULES = ("ori.telemetry",)

#: Every way the runtime is allowed to touch the telemetry exporter, and why
#: each is observational. The pair is (attribute, enclosing function): a member
#: appearing in a new function is a new use and is refused until classified,
#: because that is where a read of export state would arrive.
CLASSIFIED_EXPORTER_USES: dict[tuple[str, str], str] = {
    ("handle_event", "_start_telemetry_export_if_enabled"): (
        "events flow into the exporter and nothing flows back; the subscription "
        "is a sink"
    ),
    ("serve_until", "_start_telemetry_export_if_enabled"): (
        "lifecycle only: the export loop runs until the shutdown event and "
        "returns nothing the runtime reads"
    ),
    ("status_snapshot", "_telemetry_export_health"): (
        "export state is reported in the health snapshot and is never an input "
        "to a decision"
    ),
}

_LIMIT = (
    "This guard catches one spelling of 'reaches'. It does not catch a value "
    "passed as a parameter, stored on an attribute, or returned by a helper "
    "that both sides call. ori/runtime.py imports telemetry and the whole "
    "action surface, so that module is where such a value would live; "
    "test_every_use_of_the_telemetry_exporter_is_classified is the guard for "
    "it, and it is an inventory rather than a proof."
)


def _python_files(*relative: str) -> list[Path]:
    files = [
        path
        for directory in relative
        for path in sorted((ROOT / directory).rglob("*.py"))
    ]
    assert files, f"no source found under {relative}; the scan would pass vacuously"
    return files


def _imported_modules(tree: ast.AST) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            modules.add(node.module)
            modules.update(f"{node.module}.{alias.name}" for alias in node.names)
    return modules


def test_the_action_path_does_not_import_telemetry() -> None:
    """A tier, a threshold or an executor may not read a delivery report."""
    offenders: list[str] = []
    for path in _python_files(*ACTION_PATH):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for module in sorted(_imported_modules(tree)):
            if any(
                module == telemetry or module.startswith(f"{telemetry}.")
                for telemetry in TELEMETRY_MODULES
            ):
                offenders.append(f"{path.relative_to(ROOT)} imports {module}")

    assert not offenders, (
        "the action path imports telemetry, which runtime-telemetry/v2 forbids "
        f"from becoming an input to an action, a threshold or a policy: {offenders}. "
        + _LIMIT
    )


def _exporter_uses() -> dict[tuple[str, str], str]:
    """Every attribute touched on a telemetry exporter, by enclosing function."""
    tree = ast.parse((ROOT / "ori" / "runtime.py").read_text(encoding="utf-8"))
    enclosing: dict[int, str] = {}
    for function in ast.walk(tree):
        if isinstance(function, ast.FunctionDef | ast.AsyncFunctionDef):
            for node in ast.walk(function):
                enclosing.setdefault(id(node), function.name)

    found: dict[tuple[str, str], str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        target = ast.unparse(node.value).lower()
        if "exporter" not in target or "telemetry" not in target:
            if not target.endswith("exporter"):
                continue
        found[(node.attr, enclosing.get(id(node), "<module>"))] = ast.unparse(node)
    return found


def test_every_use_of_the_telemetry_exporter_is_classified() -> None:
    """A new read of export state must be classified before it can pass.

    This is the guard for the case the import test cannot see: `ori/runtime.py`
    holds both sides, so wiring a delivery count into a decision needs no
    import. It would need a new touch on the exporter, and an unclassified
    touch fails here.
    """
    found = _exporter_uses()
    assert found, (
        "no use of the telemetry exporter was found in ori/runtime.py, so this "
        "inventory would pass while enforcing nothing; the scan is broken or "
        "the exporter moved"
    )

    unclassified = sorted(
        f"{attribute} in {function}()"
        for (attribute, function) in found
        if (attribute, function) not in CLASSIFIED_EXPORTER_USES
    )
    assert not unclassified, (
        "the runtime touches the telemetry exporter in a way nobody has "
        f"classified: {unclassified}. Add it to CLASSIFIED_EXPORTER_USES with "
        "the reason it is observational, or refuse it — export state must not "
        "become an input to an action, a threshold or a policy "
        "(runtime-telemetry/v2). " + _LIMIT
    )


def test_the_classification_table_describes_uses_that_exist() -> None:
    """A classification that outlives its call site hides the next one."""
    found = _exporter_uses()
    stale = sorted(
        f"{attribute} in {function}()"
        for (attribute, function) in CLASSIFIED_EXPORTER_USES
        if (attribute, function) not in found
    )
    assert not stale, (
        f"classified exporter uses that no longer exist: {stale}. Remove them, "
        "or the table stops describing the code and starts excusing it."
    )


@pytest.mark.parametrize(
    "reason",
    sorted(CLASSIFIED_EXPORTER_USES.values()),
    ids=range(len(CLASSIFIED_EXPORTER_USES)),
)
def test_each_classification_states_a_reason(reason: str) -> None:
    """An entry with no argument is an allowlist, not a classification."""
    assert len(reason) > 20, f"classification is too thin to review: {reason!r}"
