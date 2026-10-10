# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""No pattern in the runtime ends in ``$``.

``$`` also matches before a final newline, so ``re.compile(r"^[0-9a-f]{32}$")
.match("…\\n")`` accepts the newline. A validator built that way passed a
nonce or device id with a trailing newline into signed JSON bytes, where it
became a raw control character. ``\\Z`` matches only at the end of the string.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "ori"
_REGEX_CALLS = {
    "compile",
    "match",
    "search",
    "fullmatch",
    "sub",
    "split",
    "findall",
    "finditer",
}


def _pattern_ends_in_dollar(pattern: str) -> bool:
    if not pattern.endswith("$"):
        return False
    backslashes = len(pattern) - len(pattern[:-1].rstrip("\\")) - 1
    return backslashes % 2 == 0


def _multiline(call: ast.Call) -> bool:
    flags = [*call.args[1:], *(k.value for k in call.keywords if k.arg == "flags")]
    return any(
        "MULTILINE" in ast.unparse(flag) or re.search(r"\bM\b", ast.unparse(flag))
        for flag in flags
    )


def _offenders() -> list[str]:
    found = []
    for path in sorted(ROOT.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(), filename=str(path))):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "re"
                and node.func.attr in _REGEX_CALLS
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                continue
            if _pattern_ends_in_dollar(node.args[0].value) and not _multiline(node):
                found.append(f"{path.relative_to(ROOT.parent)}:{node.lineno}")
    return found


def test_no_pattern_ends_in_a_dollar_anchor() -> None:
    offenders = _offenders()
    assert not offenders, (
        "end these patterns with \\Z, not $, which also matches before a final "
        f"newline: {offenders}. This guard reads literal patterns passed to the re "
        "module directly; a pattern built at runtime or held in a variable first "
        "is not seen."
    )


def test_the_rule_is_the_one_that_matters() -> None:
    assert re.compile(r"^[0-9a-f]{2}$").match("ab\n")
    assert not re.compile(r"^[0-9a-f]{2}\Z").match("ab\n")
    assert _pattern_ends_in_dollar(r"^a$")
    assert not _pattern_ends_in_dollar(r"^a\$")
    assert _pattern_ends_in_dollar("^a\\\\$")
    assert not _pattern_ends_in_dollar(r"^a\Z")
