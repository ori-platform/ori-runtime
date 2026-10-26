# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Every manifest field the loader reads admits one YAML type.

Each field is crossed with every wrong YAML type and driven through
`SkillLoader.load_one` and `ori skills validate`: each is a refusal naming the
field and the type received, with no other exception, no traceback and no skill
loaded. A guard ties every key the loader reads to a row of the type tables.
"""

from __future__ import annotations

import ast
import copy
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

from ori.cli import EXIT_FAILED, main
from ori.skills._manifest import (
    ACTION_FIELD_TYPES,
    ACTIONS_FIELD_TYPES,
    SENSOR_FIELD_TYPES,
    TOP_LEVEL_FIELD_TYPES,
    TRIGGER_FIELD_TYPES,
)
from ori.skills.loader import SkillLoader, SkillValidationError
from tests.test_cli_skills_validate import _assert_no_traceback

VALID: dict[str, Any] = {
    "name": "typed-skill",
    "version": "0.1.0",
    "author": "ori",
    "signature": "bundled",
    "sensors_required": [{"type": "current_clamp"}],
    "triggers": [
        {
            "name": "t1",
            "condition": "value > 1",
            "action_tier": "A",
            "cooldown_seconds": 0,
            "escalate_to": "rule",
            "bypass_llm": False,
            "requires_approval": False,
            "reasoning_policy": "",
            "approval_timeout_seconds": 300,
            "safe_default_action": "log_to_dashboard",
        }
    ],
    "actions": {
        "available": [{"name": "log_to_dashboard", "tier": "A"}],
        "defaults": {"t1": ["log_to_dashboard"]},
    },
    "prompts": {"t1": "Load is {value}."},
    "config": {},
}

#: Every YAML type, nested ones included, a field may be given.
VALUES: list[Any] = [
    None,
    True,
    7,
    1.5,
    "text",
    ["x"],
    {"k": "v"},
    [["x"]],
    {"k": {"k": "v"}},
]

Setter = Callable[[dict[str, Any], Any], None]


def _admits(value: Any, expected: type) -> bool:
    if expected is int or expected is bool:
        return type(value) is expected
    return isinstance(value, expected)


def _at(*path: Any) -> Setter:
    def put(doc: dict[str, Any], value: Any) -> None:
        target: Any = doc
        for step in path[:-1]:
            target = target[step]
        target[path[-1]] = value

    return put


def _rows() -> Iterator[tuple[str, Setter, type]]:
    for key, expected in TOP_LEVEL_FIELD_TYPES.items():
        yield key, _at(key), expected
    for key, expected in TRIGGER_FIELD_TYPES.items():
        yield key, _at("triggers", 0, key), expected
    for key, expected in ACTIONS_FIELD_TYPES.items():
        yield key, _at("actions", key), expected
    for key, expected in ACTION_FIELD_TYPES.items():
        yield key, _at("actions", "available", 0, key), expected
    for key, expected in SENSOR_FIELD_TYPES.items():
        yield key, _at("sensors_required", 0, key), expected
    yield "triggers[0]", _at("triggers", 0), dict
    yield "sensors_required[0]", _at("sensors_required", 0), dict
    yield "actions.available[0]", _at("actions", "available", 0), dict
    yield "actions.defaults.t1", _at("actions", "defaults", "t1"), list
    yield "actions.defaults.t1[0]", _at("actions", "defaults", "t1", 0), str
    yield "prompts.t1", _at("prompts", "t1"), str


CASES = [
    pytest.param(field, put, expected, value, id=f"{field}={value!r}")
    for field, put, expected in _rows()
    for value in VALUES
    if not _admits(value, expected)
]


@pytest.fixture
def first_party(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "ori.skills.loader.SkillLoader._is_core_bundled_skill",
        lambda self, skill_dir: True,
    )


def _write(tmp_path: Path, doc: dict[str, Any]) -> Path:
    skill_dir = tmp_path / "typed-skill"
    skill_dir.mkdir()
    (skill_dir / "skill.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    return skill_dir


def test_the_valid_manifest_loads(tmp_path: Path, first_party: None) -> None:
    skill = SkillLoader().load_one(_write(tmp_path, VALID))
    assert skill.name == "typed-skill"


@pytest.mark.parametrize(("field", "put", "expected", "value"), CASES)
def test_a_value_of_the_wrong_type_is_refused_naming_its_field(
    tmp_path: Path,
    first_party: None,
    field: str,
    put: Setter,
    expected: type,
    value: Any,
) -> None:
    doc = copy.deepcopy(VALID)
    put(doc, value)
    with pytest.raises(SkillValidationError) as refusal:
        SkillLoader().load_one(_write(tmp_path, doc))
    message = str(refusal.value)
    assert type(refusal.value) is SkillValidationError
    assert field.rsplit(".", 1)[-1] in message
    assert type(value).__name__ in message


@pytest.mark.parametrize("as_json", [False, True])
@pytest.mark.parametrize(("field", "put", "expected", "value"), CASES)
def test_the_cli_reports_a_wrong_type_without_a_traceback(
    tmp_path: Path,
    first_party: None,
    capsys: pytest.CaptureFixture[str],
    field: str,
    put: Setter,
    expected: type,
    value: Any,
    as_json: bool,
) -> None:
    doc = copy.deepcopy(VALID)
    put(doc, value)
    args = ["skills", "validate", str(_write(tmp_path, doc))]
    rc = main(args + (["--json"] if as_json else []))
    captured = capsys.readouterr()
    assert rc == EXIT_FAILED
    _assert_no_traceback(captured)
    assert field.rsplit(".", 1)[-1] in captured.out + captured.err


def _keys_read() -> dict[str, set[str]]:
    """Every string key the loader modules read with `.get` or a subscript."""
    reads: dict[str, set[str]] = {}
    paths = sorted(
        (Path(__file__).resolve().parents[1] / "ori" / "skills").glob("_*.py")
    )
    assert len(paths) >= 5, "the guard found no loader modules to scan"
    for path in paths:
        if path.name == "_provenance.py":
            continue  # reads installation records, never a manifest
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            key: Any = None
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and node.args
                and isinstance(node.args[0], ast.Constant)
            ):
                key = node.args[0].value
            elif isinstance(node, ast.Subscript) and isinstance(
                node.slice, ast.Constant
            ):
                key = node.slice.value
            if isinstance(key, str):
                reads.setdefault(key, set()).add(path.name)
    return reads


def test_every_manifest_key_the_loader_reads_has_a_type() -> None:
    typed = (
        set(TOP_LEVEL_FIELD_TYPES)
        | set(TRIGGER_FIELD_TYPES)
        | set(ACTIONS_FIELD_TYPES)
        | set(ACTION_FIELD_TYPES)
        | set(SENSOR_FIELD_TYPES)
    )
    untyped = {key: files for key, files in _keys_read().items() if key not in typed}
    assert not untyped, (
        f"the loader reads manifest keys with no row in the type tables: {untyped}"
    )


def _with_trigger(**fields: Any) -> dict[str, Any]:
    doc = copy.deepcopy(VALID)
    doc["triggers"][0].update(fields)
    for key, value in fields.items():
        if value is None:
            del doc["triggers"][0][key]
    return doc


@pytest.mark.parametrize(
    "fields",
    [
        {"action_tier": "D", "bypass_llm": True, "condition": ""},
        {"action_tier": "D", "bypass_llm": True, "condition": "   "},
        {"action_tier": "D", "bypass_llm": True, "condition": None},
        {"action_tier": "D", "bypass_llm": True, "condition": "value >"},
        {"condition": "value > 1 1"},
        {"condition": "open('x')"},
        {"cooldown_seconds": -1},
        {"condition": "   "},
        {"condition": "\n"},
    ],
    ids=[
        "tier-d-empty",
        "tier-d-blank",
        "tier-d-missing",
        "tier-d-unparsable",
        "unparsable",
        "forbidden-call",
        "negative-cooldown",
        "blank",
        "newline",
    ],
)
def test_a_trigger_that_could_never_fire_is_refused(
    tmp_path: Path, first_party: None, fields: dict[str, Any]
) -> None:
    with pytest.raises(SkillValidationError):
        SkillLoader().load_one(_write(tmp_path, _with_trigger(**fields)))


def test_a_trigger_below_tier_d_may_have_no_condition(
    tmp_path: Path, first_party: None
) -> None:
    assert SkillLoader().load_one(_write(tmp_path, _with_trigger(condition="")))


@pytest.mark.parametrize("action", ["log_to_dashboard", "my_note"])
@pytest.mark.parametrize("tier", ["Z", " A", "A ", "\uff21", "x"])
def test_an_action_tier_is_exactly_one_of_the_letters(
    tmp_path: Path, first_party: None, tier: str, action: str
) -> None:
    doc = copy.deepcopy(VALID)
    doc["actions"]["available"][0] = {"name": action, "tier": tier}
    doc["actions"]["defaults"]["t1"] = [action]
    with pytest.raises(SkillValidationError, match="tier"):
        SkillLoader().load_one(_write(tmp_path, doc))


def test_a_lowercase_action_tier_still_loads_as_v2_shipped(
    tmp_path: Path, first_party: None
) -> None:
    doc = copy.deepcopy(VALID)
    doc["actions"]["available"][0]["tier"] = "a"
    assert SkillLoader().load_one(_write(tmp_path, doc))


@pytest.mark.parametrize(
    "where", ["skill-name", "defaults-key", "condition", "trigger-name"]
)
def test_a_refusal_echoes_untrusted_text_bounded(
    tmp_path: Path, first_party: None, where: str
) -> None:
    long = "t" * 50_000
    doc = copy.deepcopy(VALID)
    if where == "skill-name":
        doc["name"] = long
        doc["triggers"][0]["cooldown_seconds"] = "ten"
    elif where == "defaults-key":
        doc["actions"]["defaults"][long] = ["log_to_dashboard"]
    elif where == "condition":
        doc["triggers"][0]["condition"] = "value > " + long + " 1"
    else:
        doc["triggers"][0]["name"] = long
        doc["triggers"][0]["escalate_to"] = "cloud"
    with pytest.raises(SkillValidationError) as refusal:
        SkillLoader().load_one(_write(tmp_path, doc))
    assert len(str(refusal.value)) <= 1000


TIER_D = {
    "name": "trip",
    "condition": "value > 5",
    "action_tier": "D",
    "bypass_llm": True,
    "cooldown_seconds": 0,
}


@pytest.mark.parametrize(
    "condition",
    [
        "history.no_such_helper('s') > 0",
        "history.avg_24h() > 0",
        "history.last_n('s', -1) > 0",
        "history.avg_24h(value) > 0",
        "history.avg_24h(sensor_id='s') > 0",
    ],
)
def test_a_history_call_the_engine_refuses_is_refused_beside_a_tier_d_trigger(
    tmp_path: Path, first_party: None, condition: str
) -> None:
    """The engine checks every condition of a skill before selecting any, so a
    bad one here would suspend the valid Tier D trigger at evaluation."""
    doc = _with_trigger(condition=condition)
    doc["triggers"].append(dict(TIER_D))
    doc["actions"]["defaults"]["trip"] = ["log_to_dashboard"]
    with pytest.raises(SkillValidationError, match="cannot evaluate"):
        SkillLoader().load_one(_write(tmp_path, doc))


@pytest.mark.parametrize(
    "condition",
    [
        "value > 1",
        "value > history.avg_24h('s') * 1.4",
        "history.no_such_helper('s') > 0",
        "history.last_n('s', 0) > 0",
        "value >",
        "open('x')",
        "value[0] > 1",
        "-" * 5000 + "1",
        "value > " + "1 + " * 1100 + "1",
    ],
)
def test_load_refuses_a_condition_exactly_when_the_engine_does(
    tmp_path: Path, first_party: None, condition: str
) -> None:
    from ori.reasoning.rule_engine import RuleEngineSafetyError, validated_history_calls

    try:
        validated_history_calls(condition)
        engine_refuses = False
    except RuleEngineSafetyError:
        engine_refuses = True
    doc = _with_trigger(condition=condition)
    if engine_refuses:
        with pytest.raises(SkillValidationError):
            SkillLoader().load_one(_write(tmp_path, doc))
    else:
        assert SkillLoader().load_one(_write(tmp_path, doc))


def _write_text(tmp_path: Path, doc: dict[str, Any], token: str, raw: str) -> Path:
    skill_dir = tmp_path / "typed-skill"
    skill_dir.mkdir()
    text = yaml.safe_dump(doc).replace(token, raw)
    (skill_dir / "skill.yaml").write_text(text, encoding="utf-8")
    return skill_dir


@pytest.mark.parametrize("tier_d", [False, True])
@pytest.mark.parametrize(
    "raw",
    ['"value > \\ud800"', '"' + "-" * 100_000 + '1"', '"value > ' + "1" * 5000 + '"'],
    ids=["lone-surrogate", "deep-unary", "over-long"],
)
@pytest.mark.parametrize("as_json", [False, True])
def test_a_hostile_condition_is_a_refusal_not_a_traceback(
    tmp_path: Path,
    first_party: None,
    capsys: pytest.CaptureFixture[str],
    raw: str,
    tier_d: bool,
    as_json: bool,
) -> None:
    fields: dict[str, Any] = {"condition": "TOKEN"}
    if tier_d:
        fields.update(action_tier="D", bypass_llm=True)
    skill_dir = _write_text(tmp_path, _with_trigger(**fields), "TOKEN", raw)
    with pytest.raises(SkillValidationError) as refusal:
        SkillLoader().load_one(skill_dir)
    assert len(str(refusal.value)) <= 1000
    rc = main(["skills", "validate", str(skill_dir)] + (["--json"] if as_json else []))
    captured = capsys.readouterr()
    assert rc == EXIT_FAILED
    _assert_no_traceback(captured)


def test_an_explicit_empty_tier_is_refused_and_an_omitted_one_is_not(
    tmp_path: Path, first_party: None
) -> None:
    doc = copy.deepcopy(VALID)
    doc["actions"]["available"][0] = {"name": "my_note", "tier": ""}
    doc["actions"]["defaults"]["t1"] = ["my_note"]
    with pytest.raises(SkillValidationError, match="tier"):
        SkillLoader().load_one(_write(tmp_path, doc))
    doc["actions"]["available"][0] = {"name": "my_note"}
    (tmp_path / "typed-skill" / "skill.yaml").unlink()
    (tmp_path / "typed-skill").rmdir()
    assert SkillLoader().load_one(_write(tmp_path, doc))


def test_the_engine_refuses_a_condition_over_its_bound_however_valid() -> None:
    from ori.reasoning.rule_engine import (
        MAX_CONDITION_CHARS,
        RuleEngineSafetyError,
        validated_history_calls,
    )

    valid = "value > 1" + " and value > 1" * (MAX_CONDITION_CHARS // 14)
    assert len(valid) > MAX_CONDITION_CHARS
    with pytest.raises(RuleEngineSafetyError, match="longer than"):
        validated_history_calls(valid)
    assert (
        validated_history_calls(valid[:MAX_CONDITION_CHARS].rsplit(" and", 1)[0]) == []
    )


@pytest.mark.parametrize("failure", [RecursionError])
def test_a_parser_failure_is_a_refusal(
    monkeypatch: pytest.MonkeyPatch, failure: type[BaseException]
) -> None:
    # MemoryError, caught the same way, cannot be raised in a test: pytest
    # itself treats one escaping as an internal error rather than a failure.
    from ori.reasoning.rule_engine import RuleEngineSafetyError, validated_history_calls

    def fail(*_args: Any, **_kwargs: Any) -> Any:
        raise failure

    monkeypatch.setattr("ori.reasoning.rule_engine._check_safety_ast", fail)
    with pytest.raises(RuleEngineSafetyError, match="cannot be parsed"):
        validated_history_calls("value > 1")
