# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import time
from unittest.mock import patch

import pytest

from ori.network.events import OriEvent, SensorReading
from ori.reasoning.rule_engine import (
    EvalContext,
    RuleEngine,
    RuleEngineSafetyError,
    RuleResult,
    _check_safety_ast,
    _extract_history_calls,
    _validate_sensor_value,
)

# ─── Helpers ──────────────────────────────────────────────────────────────────


def _ms() -> int:
    return int(time.time() * 1000)


def _reading(
    value: float = 5.0,
    sensor_id: str = "load-current",
    sensor_type: str = "current_clamp",
) -> SensorReading:
    return SensorReading(
        sensor_id=sensor_id,
        sensor_type=sensor_type,
        value=value,
        unit="ampere",
        timestamp=_ms(),
        quality=1.0,
    )


def _event(value: float = 5.0, sensor_type: str = "current_clamp") -> OriEvent:
    return OriEvent.from_reading(
        _reading(value=value, sensor_type=sensor_type), "dev-01"
    )


def _rule(
    name: str = "overcurrent",
    condition: str = "value > 10.0",
    action_tier: str = "A",
    bypass_llm: bool = False,
    action: str | None = "alert_whatsapp",
    escalate_to: str | None = None,
    cooldown_seconds: int = 0,
) -> dict:
    r: dict = {
        "name": name,
        "condition": condition,
        "action_tier": action_tier,
        "bypass_llm": bypass_llm,
        "cooldown_seconds": cooldown_seconds,
    }
    if action is not None:
        r["action"] = action
    if escalate_to is not None:
        r["escalate_to"] = escalate_to
    return r


# ─── RuleResult defaults ──────────────────────────────────────────────────────


class TestRuleResult:
    def test_defaults(self):
        result = RuleResult(matched=True, action_tier="A")
        assert result.rule_name is None
        assert result.escalate_to is None
        assert result.bypass_llm is False
        assert result.action is None
        assert result.confidence == 1.0

    def test_unmatched_result(self):
        result = RuleResult(matched=False, action_tier="A")
        assert result.matched is False


# ─── Basic evaluation ─────────────────────────────────────────────────────────


class TestEvaluate:
    @pytest.mark.asyncio
    async def test_condition_true_returns_match(self):
        engine = RuleEngine()
        result = await engine.evaluate(
            _event(value=15.0), [_rule(condition="value > 10.0")]
        )
        assert result.matched is True
        assert result.rule_name == "overcurrent"

    @pytest.mark.asyncio
    async def test_condition_false_returns_no_match(self):
        engine = RuleEngine()
        result = await engine.evaluate(
            _event(value=5.0), [_rule(condition="value > 10.0")]
        )
        assert result.matched is False

    @pytest.mark.asyncio
    async def test_first_matching_rule_wins(self):
        engine = RuleEngine()
        rules = [
            _rule(name="low", condition="value > 3.0", action_tier="A"),
            _rule(name="high", condition="value > 8.0", action_tier="B"),
        ]
        result = await engine.evaluate(_event(value=10.0), rules)
        assert result.rule_name == "low"

    @pytest.mark.asyncio
    async def test_second_rule_matches_when_first_does_not(self):
        engine = RuleEngine()
        rules = [
            _rule(name="high", condition="value > 20.0", action_tier="C"),
            _rule(name="medium", condition="value > 8.0", action_tier="B"),
        ]
        result = await engine.evaluate(_event(value=10.0), rules)
        assert result.rule_name == "medium"
        assert result.action_tier == "B"

    @pytest.mark.asyncio
    async def test_no_rules_returns_no_match(self):
        engine = RuleEngine()
        res = await engine.evaluate(_event(), [])
        assert res.matched is False

    @pytest.mark.asyncio
    async def test_empty_condition_skipped(self):
        engine = RuleEngine()
        rules = [{"name": "empty", "condition": "", "action_tier": "A"}]
        res = await engine.evaluate(_event(), rules)
        assert res.matched is False

    @pytest.mark.asyncio
    async def test_result_carries_action_tier(self):
        engine = RuleEngine()
        result = await engine.evaluate(
            _event(value=15.0),
            [_rule(condition="value > 10.0", action_tier="B")],
        )
        assert result.action_tier == "B"

    @pytest.mark.asyncio
    async def test_result_carries_action(self):
        engine = RuleEngine()
        result = await engine.evaluate(
            _event(value=15.0),
            [_rule(condition="value > 10.0", action="trip_breaker")],
        )
        assert result.action == "trip_breaker"

    @pytest.mark.asyncio
    async def test_result_carries_escalate_to(self):
        engine = RuleEngine()
        result = await engine.evaluate(
            _event(value=15.0),
            [_rule(condition="value > 10.0", escalate_to="local_slm")],
        )
        assert result.escalate_to == "local_slm"

    @pytest.mark.asyncio
    async def test_confidence_is_1_for_rule_match(self):
        engine = RuleEngine()
        result = await engine.evaluate(
            _event(value=15.0), [_rule(condition="value > 10.0")]
        )
        assert result.confidence == 1.0

    @pytest.mark.asyncio
    async def test_sensor_context_injected_from_reading(self):
        """sensor_id, sensor_type, unit, quality are available in conditions."""
        engine = RuleEngine()
        rules = [
            _rule(name="r", condition="sensor_type == 'current_clamp'", action_tier="A")
        ]
        res = await engine.evaluate(_event(), rules)
        assert res.matched is True

    @pytest.mark.asyncio
    async def test_extra_context_available_in_condition(self):
        engine = RuleEngine()
        rules = [_rule(condition="value > rated_capacity * 0.8", action_tier="A")]
        result = await engine.evaluate(
            _event(value=9.0), rules, context={"rated_capacity": 10.0}
        )
        assert result.matched is True

    @pytest.mark.asyncio
    async def test_broken_condition_is_skipped(self):
        """Conditions that raise at eval time are logged and skipped, not raised."""
        engine = RuleEngine()
        rules = [
            _rule(name="broken", condition="undefined_var > 5", action_tier="A"),
            _rule(name="ok", condition="value > 0", action_tier="A"),
        ]
        result = await engine.evaluate(_event(value=1.0), rules)
        assert result.matched is True
        assert result.rule_name == "ok"


# ─── Action tiers ─────────────────────────────────────────────────────────────


class TestActionTiers:
    @pytest.mark.asyncio
    async def test_tier_a_rule(self):
        engine = RuleEngine()
        result = await engine.evaluate(
            _event(value=15.0), [_rule(condition="value > 10.0", action_tier="A")]
        )
        assert result.action_tier == "A"

    @pytest.mark.asyncio
    async def test_tier_b_rule(self):
        engine = RuleEngine()
        result = await engine.evaluate(
            _event(value=15.0), [_rule(condition="value > 10.0", action_tier="B")]
        )
        assert result.action_tier == "B"

    @pytest.mark.asyncio
    async def test_tier_c_rule(self):
        engine = RuleEngine()
        result = await engine.evaluate(
            _event(value=15.0), [_rule(condition="value > 10.0", action_tier="C")]
        )
        assert result.action_tier == "C"
        assert result.matched is True

    @pytest.mark.asyncio
    async def test_tier_d_bypass_llm_returns_immediately(self):
        """Tier D with bypass_llm=True fires before other rules are evaluated."""
        engine = RuleEngine()
        rules = [
            _rule(
                name="dangerous_overcurrent",
                condition="value > 5.0",
                action_tier="D",
                bypass_llm=True,
            ),
            _rule(name="should_not_reach", condition="value > 5.0", action_tier="A"),
        ]
        result = await engine.evaluate(_event(value=10.0), rules)
        assert result.matched is True
        assert result.action_tier == "D"
        assert result.bypass_llm is True
        assert result.rule_name == "dangerous_overcurrent"

    @pytest.mark.asyncio
    async def test_tier_d_not_matched_continues_to_next_rule(self):
        """If the Tier D condition is false, evaluation continues normally."""
        engine = RuleEngine()
        rules = [
            _rule(
                name="extreme",
                condition="value > 50.0",
                action_tier="D",
                bypass_llm=True,
            ),
            _rule(name="medium", condition="value > 5.0", action_tier="B"),
        ]
        result = await engine.evaluate(_event(value=10.0), rules)
        assert result.action_tier == "B"
        assert result.rule_name == "medium"

    @pytest.mark.asyncio
    async def test_bypass_llm_propagated_in_result(self):
        engine = RuleEngine()
        result = await engine.evaluate(
            _event(value=15.0),
            [_rule(condition="value > 10.0", bypass_llm=True, action_tier="D")],
        )
        assert result.bypass_llm is True


# ─── Safety checks ────────────────────────────────────────────────────────────


class TestSafetyChecks:
    @pytest.mark.parametrize(
        "condition",
        [
            "import os; os.system('rm -rf /')",
            "__import__('os')",
            "exec('print(1)')",
            "eval('1+1')",
            "open('/etc/passwd')",
            "os.path.exists('/')",
            "sys.exit()",
            "subprocess.run(['ls'])",
        ],
    )
    @pytest.mark.asyncio
    async def test_unsafe_condition_raises(self, condition: str):
        engine = RuleEngine()
        with pytest.raises(RuleEngineSafetyError):
            await engine.evaluate(_event(), [_rule(condition=condition)])

    @pytest.mark.asyncio
    async def test_safe_condition_does_not_raise(self):
        engine = RuleEngine()
        await engine.evaluate(_event(value=15.0), [_rule(condition="value > 10.0")])

    @pytest.mark.asyncio
    async def test_safety_check_runs_before_any_evaluation(self):
        """Even if the first rule is safe, an unsafe later rule still raises."""
        engine = RuleEngine()
        rules = [
            _rule(name="safe", condition="value > 10.0", action_tier="A"),
            _rule(name="unsafe", condition="__import__('os')", action_tier="A"),
        ]
        with pytest.raises(RuleEngineSafetyError):
            await engine.evaluate(_event(value=15.0), rules)

    @pytest.mark.asyncio
    async def test_builtins_not_available_in_condition(self):
        """Built-in functions like len() are rejected by AST validation."""
        engine = RuleEngine()
        rules = [_rule(name="r", condition="len([1,2,3]) > 0", action_tier="A")]
        with pytest.raises(RuleEngineSafetyError):
            await engine.evaluate(_event(), rules)


# ─── Cooldown ─────────────────────────────────────────────────────────────────


class TestCooldown:
    @pytest.mark.asyncio
    async def test_rule_fires_on_first_match(self):
        engine = RuleEngine()
        result = await engine.evaluate(
            _event(value=15.0),
            [_rule(condition="value > 10.0", cooldown_seconds=60)],
        )
        assert result.matched is True

    @pytest.mark.asyncio
    async def test_rule_suppressed_within_cooldown(self):
        engine = RuleEngine()
        rules = [_rule(condition="value > 10.0", cooldown_seconds=60)]
        await engine.evaluate(_event(value=15.0), rules)
        result = await engine.evaluate(_event(value=15.0), rules)
        assert result.matched is False

    @pytest.mark.asyncio
    async def test_rule_fires_again_after_cooldown_expires(self):
        engine = RuleEngine()
        rules = [_rule(name="r", condition="value > 10.0", cooldown_seconds=5)]
        now = _ms()

        with patch("ori.reasoning.rule_engine._now_ms", return_value=now):
            await engine.evaluate(_event(value=15.0), rules)

        # 6 seconds later — cooldown expired
        with patch("ori.reasoning.rule_engine._now_ms", return_value=now + 6_000):
            result = await engine.evaluate(_event(value=15.0), rules)

        assert result.matched is True

    @pytest.mark.asyncio
    async def test_zero_cooldown_always_fires(self):
        engine = RuleEngine()
        rules = [_rule(condition="value > 10.0", cooldown_seconds=0)]
        await engine.evaluate(_event(value=15.0), rules)
        result = await engine.evaluate(_event(value=15.0), rules)
        assert result.matched is True

    @pytest.mark.asyncio
    async def test_cooldown_is_per_rule_name(self):
        """Two rules with different names have independent cooldowns."""
        engine = RuleEngine()
        rules = [
            _rule(
                name="r1",
                condition="value > 10.0",
                cooldown_seconds=60,
                action_tier="A",
            ),
            _rule(
                name="r2",
                condition="value > 10.0",
                cooldown_seconds=60,
                action_tier="B",
            ),
        ]
        await engine.evaluate(_event(value=15.0), rules)
        # r1 is on cooldown → falls through to r2
        result = await engine.evaluate(_event(value=15.0), rules)
        assert result.matched is True
        assert result.rule_name == "r2"


# ─── EvalContext ──────────────────────────────────────────────────────────────


class TestEvalContext:
    def test_values_available_in_namespace(self):
        ctx = EvalContext({"value": 5.0, "rated_capacity": 10.0})
        ns = ctx.as_dict()
        assert ns["value"] == 5.0
        assert ns["rated_capacity"] == 10.0

    def test_history_accessible_in_namespace(self):
        ctx = EvalContext({})
        ns = ctx.as_dict()
        assert ns["history"] is ctx

    def test_avg_24h_returns_zero_without_store(self):
        ctx = EvalContext({})
        assert ctx.avg_24h("any_sensor") == 0.0

    def test_last_n_returns_empty_without_store(self):
        ctx = EvalContext({})
        assert ctx.last_n("any_sensor", 5) == []

    @pytest.mark.asyncio
    async def test_event_without_reading(self):
        """Events with no reading still evaluate correctly with provided context."""
        engine = RuleEngine()
        event = OriEvent(
            event_id="hb-001",
            event_type="device.heartbeat",
            device_id="dev-01",
            sensor_id="",
            timestamp=_ms(),
            reading=None,
        )
        rules = [_rule(name="r", condition="uptime_seconds > 3600", action_tier="A")]
        result = await engine.evaluate(event, rules, context={"uptime_seconds": 7200})
        assert result.matched is True


# ─── _validate_sensor_value ───────────────────────────────────────────────────


class TestValidateSensorValue:
    def test_nan_raises(self):
        with pytest.raises(RuleEngineSafetyError, match="NaN"):
            _validate_sensor_value(float("nan"), "overcurrent")

    def test_positive_inf_raises(self):
        with pytest.raises(RuleEngineSafetyError, match="Inf"):
            _validate_sensor_value(float("inf"), "overcurrent")

    def test_negative_inf_raises(self):
        with pytest.raises(RuleEngineSafetyError, match="-Inf"):
            _validate_sensor_value(float("-inf"), "overcurrent")

    def test_none_raises(self):
        with pytest.raises(RuleEngineSafetyError, match="not numeric"):
            _validate_sensor_value(None, "overcurrent")

    def test_string_raises(self):
        with pytest.raises(RuleEngineSafetyError, match="not numeric"):
            _validate_sensor_value("8.2", "overcurrent")

    def test_valid_float_passes(self):
        # Must not raise for any finite float, including zero and negatives
        _validate_sensor_value(8.2, "overcurrent")
        _validate_sensor_value(0.0, "overcurrent")
        _validate_sensor_value(-1.5, "overcurrent")

    def test_valid_int_passes(self):
        # int is a subtype of numeric — must be accepted
        _validate_sensor_value(10, "overcurrent")


class TestEvaluateRejectsInvalidSensorValue:
    """evaluate() must raise RuleEngineSafetyError before touching rule expressions."""

    def _event_with_value(self, value) -> OriEvent:
        reading = SensorReading(
            sensor_id="load-current",
            sensor_type="current_clamp",
            value=value,
            unit="ampere",
            timestamp=_ms(),
            quality=1.0,
        )
        return OriEvent.from_reading(reading, "dev-01")

    @pytest.mark.asyncio
    async def test_nan_value_raises_before_eval(self):
        engine = RuleEngine()
        rules = [_rule(name="r", condition="value > 5.0")]
        with pytest.raises(RuleEngineSafetyError, match="NaN"):
            await engine.evaluate(self._event_with_value(float("nan")), rules)

    @pytest.mark.asyncio
    async def test_inf_value_raises_before_eval(self):
        engine = RuleEngine()
        rules = [_rule(name="r", condition="value > 5.0")]
        with pytest.raises(RuleEngineSafetyError, match="Inf"):
            await engine.evaluate(self._event_with_value(float("inf")), rules)


# ─── AST safety validation — direct unit tests ────────────────────────────────


class TestCheckSafetyAstHappyPath:
    """Conditions that MUST pass AST validation.

    Every expression pattern used in bundled skills, CLAUDE.md examples,
    and the ori.yaml.example blueprint is covered here.
    """

    @pytest.mark.parametrize(
        "condition",
        [
            # Simple comparisons
            "value > 10.0",
            "value < 180",
            "value >= 0",
            "value <= 100",
            "value == 0",
            "value != 0",
            # Boolean operators
            "cpu_temp > 90 and cpu_temp_quality > 0",
            "grid_voltage < 180 and inverter_battery > 0.4",
            "value > 10 or value < -10",
            "not (value > 10)",
            "gas_concentration > 200 and gas_concentration <= 400",
            # Arithmetic
            "load_current > rated_capacity * 3.0",
            "load_current > rated_capacity * 5.0",
            "value > (rated_capacity * 0.8 + 2.0)",
            "value * 2 + 1 > threshold",
            "value - offset > 0",
            "value / scale_factor < 1.0",
            "value // 10 > 5",
            "value % 2 == 0",
            "value ** 2 > 100",
            # Unary operators
            "-value < -10",
            "+value > 0",
            # String comparison
            "sensor_type == 'current_clamp'",
            # Parenthesised groups
            "(value > 5) and (value < 100)",
            "(value + offset) > (threshold * 1.1)",
            # History calls (energy-anomaly-detector patterns)
            "load_current > (history.avg_24h('load_current') * 1.4)",
            # History calls with multiple arguments
            "history.last_n('load_current', 6) > 0",
            # pc-system-health skill conditions
            "cpu_percent > 90",
            "memory_percent > 85",
            "disk_percent > 90",
            "write_rate_mb_per_min > 50",
            "battery_drain_rate > 5.0",
            "sleep_blocking_processes > 0",
            # Bare constants and names (edge cases)
            "True",
            "False",
            "value",
            "42",
        ],
    )
    def test_valid_condition_passes(self, condition: str):
        _check_safety_ast(condition)  # must not raise


class TestCheckSafetyAstRejections:
    """Conditions that MUST be rejected by AST validation.

    Covers code injection, sandbox escapes, and every Python construct
    that has no legitimate use in a sensor threshold expression.
    """

    # ── Import-based attacks ──────────────────────────────────────────────

    def test_import_statement(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("import os")

    def test_dunder_import_call(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("__import__('os')")

    # ── Dangerous builtin calls ──────────────────────────────────────────

    def test_exec_call(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("exec('print(1)')")

    def test_eval_call(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("eval('1+1')")

    def test_open_call(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("open('/etc/passwd')")

    def test_print_call(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("print('hello')")

    def test_len_call(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("len('abc') > 0")

    def test_type_call(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("type(value)")

    def test_getattr_call(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("getattr(value, '__class__')")

    def test_bare_function_name_as_call(self):
        """Any non-history function call is forbidden."""
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("abs(value) > 5")

    # ── Attribute-based sandbox escapes ───────────────────────────────────

    def test_os_system(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("os.system('rm -rf /')")

    def test_os_path_exists(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("os.path.exists('/')")

    def test_sys_exit(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("sys.exit()")

    def test_subprocess_run(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("subprocess.run(['ls'])")

    def test_dunder_class_escape(self):
        """Classic sandbox escape: ().__class__.__bases__[0].__subclasses__()"""
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("().__class__")

    def test_string_class_mro_escape(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("''.__class__.__mro__")

    def test_attribute_on_value(self):
        """Attribute access on sensor values is forbidden."""
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("value.bit_length() > 5")

    def test_attribute_on_arbitrary_name(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("config.secret_key == 'leaked'")

    # ── Lambda and function definitions ──────────────────────────────────

    def test_lambda(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("(lambda: 1)()")

    def test_lambda_with_args(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("(lambda x: x * 2)(5) > 5")

    # ── Comprehensions ───────────────────────────────────────────────────

    def test_list_comprehension(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("[x for x in range(10)]")

    def test_set_comprehension(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("{x for x in range(10)}")

    def test_dict_comprehension(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("{x: x for x in range(10)}")

    def test_generator_expression(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("sum(x for x in range(10))")

    # ── Walrus operator (:=) ─────────────────────────────────────────────

    def test_walrus_operator(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("(x := 5) > 3")

    # ── F-strings ────────────────────────────────────────────────────────

    def test_fstring(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("f'{value}'")

    def test_fstring_with_expression(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("f'{value * 2}'")

    # ── Subscript / indexing ─────────────────────────────────────────────

    def test_subscript(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("values[0] > 5")

    def test_subscript_on_string(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("'abc'[0] == 'a'")

    # ── Collection literals ──────────────────────────────────────────────

    def test_list_literal(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("[1, 2, 3]")

    def test_dict_literal(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("{'key': 'value'}")

    def test_set_literal(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("{1, 2, 3}")

    def test_tuple_literal(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("(1, 2, 3)")

    # ── Ternary / conditional expression ─────────────────────────────────

    def test_ternary_expression(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("1 if value > 5 else 0")

    # ── Syntax errors ────────────────────────────────────────────────────

    def test_syntax_error_raises_safety_error(self):
        with pytest.raises(RuleEngineSafetyError, match="not a valid expression"):
            _check_safety_ast("value >>>")

    def test_incomplete_expression(self):
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("value >")

    def test_multiple_statements_via_semicolon(self):
        """Semicolons produce statements — mode='eval' rejects them."""
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("x = 1; x > 0")

    # ── Edge cases ───────────────────────────────────────────────────────

    def test_nested_attribute_on_non_history(self):
        """Even deeply nested attribute chains are rejected."""
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("a.b.c > 0")

    def test_method_call_on_non_history(self):
        """Method calls on arbitrary objects are rejected."""
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("value.to_bytes(2, 'big')")

    def test_chained_history_attribute_rejected(self):
        """history.something.something is NOT a direct attribute."""
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("history.store._conn")

    def test_starred_expression(self):
        """Starred assignments cannot appear in eval mode."""
        with pytest.raises(RuleEngineSafetyError):
            _check_safety_ast("*x, = [1,2]")


class TestAstValidationIntegration:
    """End-to-end tests proving AST validation fires inside RuleEngine.evaluate()."""

    @pytest.mark.asyncio
    async def test_all_existing_unsafe_conditions_still_rejected(self):
        """Regression: the 8 original unsafe patterns from Phase 1 still fail."""
        engine = RuleEngine()
        conditions = [
            "import os; os.system('rm -rf /')",
            "__import__('os')",
            "exec('print(1)')",
            "eval('1+1')",
            "open('/etc/passwd')",
            "os.path.exists('/')",
            "sys.exit()",
            "subprocess.run(['ls'])",
        ]
        for condition in conditions:
            with pytest.raises(RuleEngineSafetyError):
                await engine.evaluate(_event(), [_rule(condition=condition)])

    @pytest.mark.asyncio
    async def test_safe_condition_evaluates_normally(self):
        engine = RuleEngine()
        result = await engine.evaluate(
            _event(value=15.0), [_rule(condition="value > 10.0")]
        )
        assert result.matched is True

    @pytest.mark.asyncio
    async def test_history_call_passes_ast_and_evaluates(self):
        """history.avg_24h() passes AST and evaluates (returns 0.0 without store)."""
        engine = RuleEngine()
        result = await engine.evaluate(
            _event(value=15.0),
            [_rule(condition="value > (history.avg_24h('load_current') * 1.4)")],
        )
        # avg_24h returns 0.0 without store, so 15.0 > 0.0 → matched
        assert result.matched is True

    @pytest.mark.asyncio
    async def test_unsafe_rule_in_batch_rejects_entire_batch(self):
        """Even one unsafe rule in the list rejects everything before eval."""
        engine = RuleEngine()
        rules = [
            _rule(name="safe", condition="value > 10.0"),
            _rule(name="evil", condition="().__class__"),
        ]
        with pytest.raises(RuleEngineSafetyError):
            await engine.evaluate(_event(value=15.0), rules)

    @pytest.mark.asyncio
    async def test_broken_condition_still_skipped_after_ast(self):
        """Conditions with undefined variables pass AST but fail at eval — skipped."""
        engine = RuleEngine()
        rules = [
            _rule(name="broken", condition="undefined_var > 5", action_tier="A"),
            _rule(name="ok", condition="value > 0", action_tier="A"),
        ]
        result = await engine.evaluate(_event(value=1.0), rules)
        assert result.matched is True
        assert result.rule_name == "ok"

    @pytest.mark.asyncio
    async def test_compound_condition_from_pc_skill(self):
        """Real condition from pc-system-health: cpu_temp > 90 and cpu_temp_quality > 0."""
        engine = RuleEngine()
        result = await engine.evaluate(
            _event(value=95.0),
            [_rule(condition="value > 90 and quality > 0")],
        )
        assert result.matched is True

    @pytest.mark.asyncio
    async def test_arithmetic_condition_from_energy_skill(self):
        """Real condition from energy-anomaly-detector: load_current > rated_capacity * 5.0."""
        engine = RuleEngine()
        result = await engine.evaluate(
            _event(value=55.0),
            [_rule(condition="value > rated_capacity * 5.0")],
            context={"rated_capacity": 10.0},
        )
        assert result.matched is True


class TestHistoryHelperValidation:
    def test_extract_history_calls_rejects_unsupported_helper(self):
        with pytest.raises(RuleEngineSafetyError, match="unsupported history helper"):
            _extract_history_calls("value > history.anything('sensor')")

    def test_extract_history_calls_rejects_non_literal_args(self):
        with pytest.raises(RuleEngineSafetyError, match="must be literals"):
            _extract_history_calls("value > history.avg_24h(sensor_id)")

    def test_extract_history_calls_rejects_invalid_last_n_range(self):
        with pytest.raises(RuleEngineSafetyError, match="1..1000"):
            _extract_history_calls("value > history.last_n('sensor', 0)")

    @pytest.mark.asyncio
    async def test_evaluate_rejects_invalid_history_helper_usage(self):
        engine = RuleEngine()
        with pytest.raises(RuleEngineSafetyError, match="unsupported history helper"):
            await engine.evaluate(
                _event(value=10.0),
                [_rule(condition="value > history.invalid('sensor')")],
            )
