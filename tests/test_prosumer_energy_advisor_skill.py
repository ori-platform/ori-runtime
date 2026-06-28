# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from datetime import datetime, timezone
from pathlib import Path

import pytest

from ori.network.events import OriEvent, ReasoningResult, SensorReading
from ori.reasoning.rule_engine import RuleEngine
from ori.skills.hooks_api import HookContext
from ori.skills.loader import SkillLoader


class _Store:
    def __init__(self) -> None:
        self._history: dict[str, list[SensorReading]] = {}
        self._state: dict[tuple[str, str], str] = {}

    def hooks_get_history(self, sensor_id: str, limit: int = 1) -> list[SensorReading]:
        return self._history.get(sensor_id, [])[:limit]

    def hooks_avg_last_hours(self, sensor_id: str, _hours: int) -> float | None:
        rows = self._history.get(sensor_id, [])
        if not rows:
            return None
        return sum(r.value for r in rows) / len(rows)

    def hooks_avg_last_n(self, sensor_id: str, n: int) -> float | None:
        rows = self.hooks_get_history(sensor_id, n)
        if not rows:
            return None
        return sum(r.value for r in rows) / len(rows)

    def hooks_get_skill_state(self, skill_name: str, key: str) -> str | None:
        return self._state.get((skill_name, key))

    def hooks_set_skill_state(self, skill_name: str, key: str, value: str) -> None:
        self._state[(skill_name, key)] = value


def _skill_dir() -> Path:
    return Path(__file__).parent.parent / "skills" / "prosumer-energy-advisor"


def _load_skill():
    return SkillLoader().load_one(_skill_dir())


def _ts_utc(year: int, month: int, day: int, hour: int, minute: int = 0) -> int:
    return int(
        datetime(year, month, day, hour, minute, tzinfo=timezone.utc).timestamp() * 1000
    )


def _event(
    *,
    sensor_id: str,
    sensor_type: str,
    value: float,
    quality: float = 1.0,
    timestamp: int,
) -> OriEvent:
    unit = "percent" if sensor_type.endswith("_soc") else "watt"
    reading = SensorReading(
        sensor_id=sensor_id,
        sensor_type=sensor_type,
        value=value,
        unit=unit,
        timestamp=timestamp,
        quality=quality,
        metadata={},
    )
    return OriEvent.from_reading(reading, "prosumer-site-01")


def _settlement_statement():
    return {
        "statement_id": "ikeja-2026-06",
        "disco": "Ikeja Electric",
        "period_start": "2026-06-01",
        "period_end": "2026-06-30",
        "import_kwh": 120.5,
        "export_kwh": 18.25,
        "import_value": 27112.5,
        "export_credit_value": 730.0,
        "net_value": 26382.5,
        "currency": "NGN",
        "source": {
            "type": "disco_statement",
            "reference": "statement PDF sha256:abc123",
            "retrieved_at": "2026-07-01",
        },
        "notes": "Monthly statement uploaded by operator.",
    }


def _net_billing_compliance():
    return {
        "profile": "ng-net-billing-example",
        "version": "2026-06",
        "status": "operator_provided",
        "country": "NG",
        "disco": "Ikeja Electric",
        "source": {
            "type": "operator_record",
            "reference": "ori-energy policy sha256:abc123",
            "retrieved_at": "2026-06-28",
        },
        "export_cap_watts": 1000.0,
        "export_cap_reference": "approved export cap letter",
        "disco_feasibility": {
            "status": "approved",
            "reference": "feasibility report",
            "submitted_at": "2026-06-01",
            "due_by": "2026-06-11",
            "completed_at": "2026-06-08",
        },
        "nerc_registration": {
            "status": "approved",
            "reference": "NERC certificate PDF",
            "certificate_id": "NERC-NB-001",
            "submitted_at": "2026-06-09",
            "due_by": "2026-06-19",
            "completed_at": "2026-06-15",
        },
        "nemsa_inspection": {
            "status": "passed",
            "reference": "NEMSA certificate PDF",
            "certificate_id": "NEMSA-001",
            "submitted_at": "2026-06-16",
            "due_by": "2026-06-26",
            "completed_at": "2026-06-20",
        },
        "monthly_statement": {
            "status": "reconciled",
            "required": True,
            "expected_statement_id": "ikeja-2026-06",
            "period_start": "2026-06-01",
            "period_end": "2026-06-30",
            "due_by": "2026-07-10",
            "reference": "statement PDF sha256:def456",
        },
        "credit_carry_forward": {
            "value": 0.0,
            "currency": "NGN",
            "kwh": 0.0,
            "as_of": "2026-06-30",
        },
        "site_relocation_planned": False,
        "relocation_effective_date": "",
        "notes": "Operator-provided compliance snapshot.",
    }


def _ctx(skill, event, store):
    hook_ctx = HookContext.build(event, store, skill.name, skill_config=skill.config)
    skill.hooks.pre_trigger_eval(hook_ctx)
    context = dict(skill.config)
    context.update(hook_ctx.derived)
    return hook_ctx, context


async def _matches(skill, event, store, trigger_name: str) -> tuple[bool, dict]:
    _, context = _ctx(skill, event, store)
    trigger = next(t for t in skill.triggers if t.name == trigger_name)
    result = await RuleEngine().evaluate(event, [trigger], context=context)
    return result.matched, context


async def _first_match(skill, event, store):
    _, context = _ctx(skill, event, store)
    result = await RuleEngine().evaluate(event, skill.triggers, context=context)
    return result, context


@pytest.mark.asyncio
async def test_skill_loads_as_tier_a_only():
    skill = _load_skill()

    assert skill.name == "prosumer-energy-advisor"
    assert len(skill.triggers) == 8
    assert {trigger.action_tier for trigger in skill.triggers} == {"A"}
    assert {action["tier"] for action in skill.actions["available"]} == {"A"}
    assert any(t.name == "net_billing_compliance_attention" for t in skill.triggers)


@pytest.mark.asyncio
async def test_self_consume_or_store_surplus_matches_when_export_credit_is_low():
    skill = _load_skill()
    skill.config["timezone"] = "UTC"
    store = _Store()
    ts = _ts_utc(2026, 6, 26, 12)

    _ctx(
        skill,
        _event(
            sensor_id="battery",
            sensor_type="growatt_battery_soc",
            value=55.0,
            timestamp=ts,
        ),
        store,
    )
    _ctx(
        skill,
        _event(
            sensor_id="load",
            sensor_type="growatt_load_power",
            value=1200.0,
            timestamp=ts,
        ),
        store,
    )
    event = _event(
        sensor_id="pv",
        sensor_type="growatt_pv_power",
        value=2600.0,
        timestamp=ts,
    )

    matched, context = await _matches(
        skill, event, store, "self_consume_or_store_surplus"
    )

    assert matched is True
    assert context["surplus_watts"] == 1400.0
    assert context["export_credit_discounted"] == 1
    assert context["tariff_policy_valid"] == 1
    assert context["tariff_profile"] == "ng-operator-provided-example"
    assert context["tariff_profile_status"] == "operator_provided"
    assert context["tariff_profile_source_type"] == "operator_estimate"
    assert "billing truth" in context["tariff_profile_meter_of_record_boundary"]
    assert context["exportable_surplus_watts"] == 1400.0
    assert context["export_cap_blocks_export"] == 0
    assert context["should_consume_or_store"] == 1
    assert context["optimizer_action"] == "consume_or_store"
    assert context["self_consumption_value_naira_per_hour"] == 315.0
    assert context["export_value_naira_per_hour"] == 56.0
    assert context["self_consumption_premium_naira_per_hour"] == 259.0
    assert context["ledger_fast_loop_clock"] == "runtime_operational_estimate"
    assert context["ledger_settlement_clock"] == "disco_monthly_statement"
    assert "settlement and billing truth" in context["ledger_meter_of_record_boundary"]


@pytest.mark.asyncio
async def test_self_consume_or_store_surplus_blocks_when_export_credit_is_not_discounted():
    skill = _load_skill()
    skill.config["tariff_profile"]["export_credit_per_kwh"] = 250.0
    store = _Store()
    ts = _ts_utc(2026, 6, 26, 12)

    _ctx(
        skill,
        _event(
            sensor_id="battery",
            sensor_type="growatt_battery_soc",
            value=55.0,
            timestamp=ts,
        ),
        store,
    )
    _ctx(
        skill,
        _event(
            sensor_id="load",
            sensor_type="growatt_load_power",
            value=1200.0,
            timestamp=ts,
        ),
        store,
    )
    event = _event(
        sensor_id="pv",
        sensor_type="growatt_pv_power",
        value=2600.0,
        timestamp=ts,
    )

    matched, context = await _matches(
        skill, event, store, "self_consume_or_store_surplus"
    )

    assert matched is False
    assert context["export_credit_discounted"] == 0


@pytest.mark.asyncio
async def test_draft_tariff_profile_blocks_tariff_dependent_advice():
    skill = _load_skill()
    skill.config["tariff_profile"]["status"] = "draft"
    store = _Store()
    ts = _ts_utc(2026, 6, 26, 12)

    _ctx(
        skill,
        _event(
            sensor_id="battery",
            sensor_type="growatt_battery_soc",
            value=55.0,
            timestamp=ts,
        ),
        store,
    )
    _ctx(
        skill,
        _event(
            sensor_id="load",
            sensor_type="growatt_load_power",
            value=1200.0,
            timestamp=ts,
        ),
        store,
    )
    event = _event(
        sensor_id="pv",
        sensor_type="growatt_pv_power",
        value=2600.0,
        timestamp=ts,
    )

    matched, context = await _matches(
        skill, event, store, "self_consume_or_store_surplus"
    )

    assert matched is False
    assert context["tariff_policy_valid"] == 0
    assert context["config_valid"] == 0
    assert context["tariff_profile_status"] == "draft"


@pytest.mark.asyncio
async def test_invalid_tariff_profile_blocks_advice_and_records_error():
    skill = _load_skill()
    skill.config["tariff_profile"]["source"]["reference"] = ""
    store = _Store()
    ts = _ts_utc(2026, 6, 26, 12)

    _ctx(
        skill,
        _event(
            sensor_id="battery",
            sensor_type="growatt_battery_soc",
            value=55.0,
            timestamp=ts,
        ),
        store,
    )
    _ctx(
        skill,
        _event(
            sensor_id="load",
            sensor_type="growatt_load_power",
            value=1200.0,
            timestamp=ts,
        ),
        store,
    )
    event = _event(
        sensor_id="pv",
        sensor_type="growatt_pv_power",
        value=2600.0,
        timestamp=ts,
    )

    matched, context = await _matches(
        skill, event, store, "self_consume_or_store_surplus"
    )

    assert matched is False
    assert context["tariff_policy_valid"] == 0
    assert context["config_valid"] == 0
    assert "reference" in context["tariff_policy_error"]


@pytest.mark.asyncio
async def test_missing_tariff_profile_blocks_tariff_dependent_advice():
    skill = _load_skill()
    skill.config.pop("tariff_profile")
    store = _Store()
    ts = _ts_utc(2026, 6, 26, 12)

    _ctx(
        skill,
        _event(
            sensor_id="battery",
            sensor_type="growatt_battery_soc",
            value=55.0,
            timestamp=ts,
        ),
        store,
    )
    _ctx(
        skill,
        _event(
            sensor_id="load",
            sensor_type="growatt_load_power",
            value=1200.0,
            timestamp=ts,
        ),
        store,
    )
    event = _event(
        sensor_id="pv",
        sensor_type="growatt_pv_power",
        value=2600.0,
        timestamp=ts,
    )

    matched, context = await _matches(
        skill, event, store, "self_consume_or_store_surplus"
    )

    assert matched is False
    assert context["tariff_policy_valid"] == 0
    assert context["config_valid"] == 0
    assert context["tariff_profile"] == ""
    assert context["tariff_policy_error"] == "missing tariff_profile"


@pytest.mark.asyncio
async def test_settlement_statement_is_exposed_as_slow_clock_context():
    skill = _load_skill()
    skill.config["settlement_statement"] = _settlement_statement()
    store = _Store()
    event = _event(
        sensor_id="grid",
        sensor_type="deye_grid_power",
        value=500.0,
        timestamp=_ts_utc(2026, 7, 1, 8),
    )

    _, context = _ctx(skill, event, store)

    assert context["settlement_statement_present"] == 1
    assert context["settlement_statement_valid"] == 1
    assert context["settlement_statement_error"] == ""
    assert context["settlement_statement_id"] == "ikeja-2026-06"
    assert context["settlement_statement_disco"] == "Ikeja Electric"
    assert context["settlement_period_start"] == "2026-06-01"
    assert context["settlement_period_end"] == "2026-06-30"
    assert context["settlement_import_kwh"] == 120.5
    assert context["settlement_export_kwh"] == 18.25
    assert context["settlement_net_value_naira"] == 26382.5
    assert context["settlement_source_type"] == "disco_statement"


@pytest.mark.asyncio
async def test_net_billing_compliance_context_is_exposed_without_attention():
    skill = _load_skill()
    skill.config["export_cap_watts"] = 1000.0
    skill.config["settlement_statement"] = _settlement_statement()
    skill.config["net_billing_compliance"] = _net_billing_compliance()
    store = _Store()
    event = _event(
        sensor_id="pv",
        sensor_type="deye_pv1_power",
        value=1200.0,
        timestamp=_ts_utc(2026, 7, 1, 8),
    )

    matched, context = await _matches(
        skill,
        event,
        store,
        "net_billing_compliance_attention",
    )

    assert matched is False
    assert context["net_billing_present"] == 1
    assert context["net_billing_valid"] == 1
    assert context["net_billing_tracking_qualified"] == 1
    assert context["net_billing_profile"] == "ng-net-billing-example"
    assert context["net_billing_disco"] == "Ikeja Electric"
    assert context["net_billing_export_cap_watts"] == 1000.0
    assert context["net_billing_export_cap_matches_runtime"] == 1
    assert context["net_billing_attention_required"] == 0
    assert context["net_billing_attention_codes"] == ""
    assert context["net_billing_nerc_certificate_id"] == "NERC-NB-001"
    assert context["net_billing_nemsa_certificate_id"] == "NEMSA-001"
    assert context["net_billing_monthly_statement_status"] == "reconciled"
    assert "authoritative" in context["net_billing_boundary"]


@pytest.mark.asyncio
async def test_net_billing_compliance_attention_matches_when_records_need_review():
    skill = _load_skill()
    skill.config["export_cap_watts"] = 1000.0
    skill.config["net_billing_compliance"] = _net_billing_compliance()
    skill.config["net_billing_compliance"]["disco_feasibility"]["status"] = "submitted"
    skill.config["net_billing_compliance"]["disco_feasibility"]["due_by"] = "2026-06-20"
    skill.config["net_billing_compliance"]["monthly_statement"]["status"] = "missing"
    skill.config["net_billing_compliance"]["monthly_statement"]["due_by"] = "2026-06-28"
    store = _Store()
    event = _event(
        sensor_id="pv",
        sensor_type="deye_pv1_power",
        value=1200.0,
        timestamp=_ts_utc(2026, 7, 1, 8),
    )

    matched, context = await _matches(
        skill,
        event,
        store,
        "net_billing_compliance_attention",
    )

    assert matched is True
    assert context["net_billing_attention_required"] == 1
    assert "disco_feasibility_pending" in context["net_billing_attention_codes"]
    assert "disco_feasibility_due" in context["net_billing_attention_codes"]
    assert "monthly_statement_missing" in context["net_billing_attention_codes"]
    assert "monthly_statement_due" in context["net_billing_attention_codes"]


@pytest.mark.asyncio
async def test_invalid_net_billing_compliance_records_error_without_blocking_advice():
    skill = _load_skill()
    skill.config["net_billing_compliance"] = _net_billing_compliance()
    skill.config["net_billing_compliance"]["source"]["reference"] = ""
    store = _Store()
    ts = _ts_utc(2026, 7, 1, 8)

    _ctx(
        skill,
        _event(
            sensor_id="battery",
            sensor_type="growatt_battery_soc",
            value=55.0,
            timestamp=ts,
        ),
        store,
    )
    _ctx(
        skill,
        _event(
            sensor_id="load",
            sensor_type="growatt_load_power",
            value=1200.0,
            timestamp=ts,
        ),
        store,
    )
    event = _event(
        sensor_id="pv",
        sensor_type="growatt_pv_power",
        value=2600.0,
        timestamp=ts,
    )

    matched, context = await _matches(
        skill,
        event,
        store,
        "self_consume_or_store_surplus",
    )

    assert matched is True
    assert context["net_billing_present"] == 1
    assert context["net_billing_valid"] == 0
    assert "reference" in context["net_billing_error"]


@pytest.mark.asyncio
async def test_invalid_settlement_statement_records_error_without_blocking_advice():
    skill = _load_skill()
    skill.config["settlement_statement"] = _settlement_statement()
    skill.config["settlement_statement"]["source"]["reference"] = ""
    store = _Store()
    ts = _ts_utc(2026, 7, 1, 8)

    _ctx(
        skill,
        _event(
            sensor_id="battery",
            sensor_type="growatt_battery_soc",
            value=55.0,
            timestamp=ts,
        ),
        store,
    )
    _ctx(
        skill,
        _event(
            sensor_id="load",
            sensor_type="growatt_load_power",
            value=1200.0,
            timestamp=ts,
        ),
        store,
    )
    event = _event(
        sensor_id="pv",
        sensor_type="growatt_pv_power",
        value=2600.0,
        timestamp=ts,
    )

    matched, context = await _matches(
        skill, event, store, "self_consume_or_store_surplus"
    )

    assert matched is True
    assert context["settlement_statement_present"] == 1
    assert context["settlement_statement_valid"] == 0
    assert "reference" in context["settlement_statement_error"]


@pytest.mark.asyncio
async def test_export_cap_approaching_matches_on_signed_export_power():
    skill = _load_skill()
    skill.config["export_cap_watts"] = 1000.0
    skill.config["export_cap_warning_ratio"] = 0.8
    store = _Store()
    event = _event(
        sensor_id="grid",
        sensor_type="deye_grid_power",
        value=-850.0,
        timestamp=_ts_utc(2026, 6, 26, 12),
    )

    matched, context = await _matches(skill, event, store, "export_cap_approaching")

    assert matched is True
    assert context["grid_export_watts"] == 850.0
    assert context["export_cap_warning_watts"] == 800.0
    assert context["export_cap_headroom_watts"] == 150.0
    assert context["export_cap_exceeded"] == 0


@pytest.mark.asyncio
async def test_export_cap_exceeded_matches_and_blocks_approaching_trigger():
    skill = _load_skill()
    skill.config["export_cap_watts"] = 1000.0
    skill.config["export_cap_warning_ratio"] = 0.8
    store = _Store()
    event = _event(
        sensor_id="grid",
        sensor_type="deye_grid_power",
        value=-1100.0,
        timestamp=_ts_utc(2026, 6, 26, 12),
    )

    exceeded, context = await _matches(skill, event, store, "export_cap_exceeded")
    approaching, _ = await _matches(skill, event, store, "export_cap_approaching")

    assert exceeded is True
    assert approaching is False
    assert context["grid_export_watts"] == 1100.0
    assert context["export_cap_headroom_watts"] == 0.0
    assert context["exportable_surplus_watts"] == 0.0
    assert context["local_use_or_store_watts"] == 1100.0
    assert context["export_cap_exceeded"] == 1
    assert context["export_cap_blocks_export"] == 1


@pytest.mark.asyncio
async def test_export_cap_exceeded_routes_optimizer_to_consume_or_store():
    """Regression: the optimizer's cap-exceeded label must match a real trigger.

    _optimizer_action() previously returned "use_or_store_surplus" when the
    export cap was exceeded, but no trigger condition checked for that label.
    The skill only kept alerting in this case because the independent
    export_cap_exceeded trigger bypasses optimizer_action entirely. This test
    pins optimizer_action to a label self_consume_or_store_surplus actually
    routes, so the optimizer's own decision can never go silently unmatched.
    """
    skill = _load_skill()
    skill.config["export_cap_watts"] = 1000.0
    store = _Store()
    event = _event(
        sensor_id="grid",
        sensor_type="deye_grid_power",
        value=-1100.0,
        timestamp=_ts_utc(2026, 6, 26, 12),
    )

    matched, context = await _matches(
        skill, event, store, "self_consume_or_store_surplus"
    )

    assert context["export_cap_exceeded"] == 1
    assert context["optimizer_action"] == "consume_or_store"
    assert matched is True


@pytest.mark.asyncio
async def test_export_cap_limits_exportable_surplus_even_before_exporting():
    skill = _load_skill()
    skill.config["export_cap_watts"] = 1000.0
    store = _Store()
    ts = _ts_utc(2026, 6, 26, 12)

    _ctx(
        skill,
        _event(
            sensor_id="grid",
            sensor_type="deye_grid_power",
            value=-700.0,
            timestamp=ts,
        ),
        store,
    )
    _ctx(
        skill,
        _event(
            sensor_id="load",
            sensor_type="deye_load_power",
            value=1200.0,
            timestamp=ts,
        ),
        store,
    )
    _ctx(
        skill,
        _event(
            sensor_id="battery",
            sensor_type="deye_battery_soc",
            value=55.0,
            timestamp=ts,
        ),
        store,
    )
    event = _event(
        sensor_id="pv",
        sensor_type="deye_pv1_power",
        value=2600.0,
        timestamp=ts,
    )

    matched, context = await _matches(
        skill, event, store, "self_consume_or_store_surplus"
    )

    assert matched is True
    assert context["surplus_watts"] == 1400.0
    assert context["export_cap_headroom_watts"] == 300.0
    assert context["exportable_surplus_watts"] == 300.0
    assert context["local_use_or_store_watts"] == 1100.0
    assert context["export_cap_blocks_export"] == 1


@pytest.mark.asyncio
async def test_export_cap_warning_ratio_is_bounded_to_one():
    skill = _load_skill()
    skill.config["export_cap_watts"] = 1000.0
    skill.config["export_cap_warning_ratio"] = 1.4
    store = _Store()
    event = _event(
        sensor_id="grid",
        sensor_type="deye_grid_power",
        value=-1000.0,
        timestamp=_ts_utc(2026, 6, 26, 12),
    )

    matched, context = await _matches(skill, event, store, "export_cap_approaching")

    assert matched is True
    assert context["export_cap_warning_ratio"] == 1.0
    assert context["export_cap_warning_watts"] == 1000.0


@pytest.mark.asyncio
async def test_export_surplus_with_headroom_matches_when_battery_is_full():
    skill = _load_skill()
    store = _Store()
    ts = _ts_utc(2026, 6, 26, 12)

    _ctx(
        skill,
        _event(
            sensor_id="battery",
            sensor_type="growatt_battery_soc",
            value=95.0,
            timestamp=ts,
        ),
        store,
    )
    _ctx(
        skill,
        _event(
            sensor_id="load",
            sensor_type="growatt_load_power",
            value=1000.0,
            timestamp=ts,
        ),
        store,
    )
    event = _event(
        sensor_id="pv",
        sensor_type="growatt_pv_power",
        value=1800.0,
        timestamp=ts,
    )

    matched, context = await _matches(
        skill, event, store, "export_surplus_with_headroom"
    )

    assert matched is True
    assert context["can_export_now"] == 1
    assert context["optimizer_action"] == "export_now"
    assert context["exportable_surplus_watts"] == 800.0
    assert context["export_value_naira_per_hour"] == 32.0


@pytest.mark.asyncio
async def test_defer_deferrable_load_matches_when_import_high_and_reserve_low():
    skill = _load_skill()
    store = _Store()
    ts = _ts_utc(2026, 6, 26, 19)

    _ctx(
        skill,
        _event(
            sensor_id="pv",
            sensor_type="deye_pv1_power",
            value=120.0,
            timestamp=ts,
        ),
        store,
    )
    _ctx(
        skill,
        _event(
            sensor_id="battery",
            sensor_type="deye_battery_soc",
            value=32.0,
            timestamp=ts,
        ),
        store,
    )
    event = _event(
        sensor_id="grid",
        sensor_type="deye_grid_power",
        value=1500.0,
        timestamp=ts,
    )

    matched, context = await _matches(skill, event, store, "defer_deferrable_load")

    assert matched is True
    assert context["grid_import_watts"] == 1500.0
    assert context["battery_soc_snapshot"] == 32.0
    assert context["pv_watts_snapshot"] == 120.0
    assert context["should_defer_load"] == 1
    assert context["optimizer_action"] == "defer_load_preserve_reserve"
    assert context["defer_load_value_naira_per_hour"] == 337.5


@pytest.mark.asyncio
async def test_preserve_battery_reserve_matches_without_high_import():
    skill = _load_skill()
    store = _Store()
    ts = _ts_utc(2026, 6, 26, 20)

    _ctx(
        skill,
        _event(
            sensor_id="battery",
            sensor_type="deye_battery_soc",
            value=35.0,
            timestamp=ts,
        ),
        store,
    )
    _ctx(
        skill,
        _event(
            sensor_id="pv",
            sensor_type="deye_pv1_power",
            value=100.0,
            timestamp=ts,
        ),
        store,
    )
    event = _event(
        sensor_id="load",
        sensor_type="deye_load_power",
        value=450.0,
        timestamp=ts,
    )

    matched, context = await _matches(skill, event, store, "preserve_battery_reserve")

    assert matched is True
    assert context["battery_preserve_needed"] == 1
    assert context["should_defer_load"] == 0
    assert context["optimizer_action"] == "preserve_battery_reserve"


@pytest.mark.asyncio
async def test_reduce_generator_use_matches_with_available_battery_offset():
    skill = _load_skill()
    skill.config["generator_cost_naira_per_kwh"] = 500.0
    store = _Store()
    ts = _ts_utc(2026, 6, 26, 21)

    _ctx(
        skill,
        _event(
            sensor_id="battery",
            sensor_type="deye_battery_soc",
            value=70.0,
            timestamp=ts,
        ),
        store,
    )
    _ctx(
        skill,
        _event(
            sensor_id="load",
            sensor_type="deye_load_power",
            value=900.0,
            timestamp=ts,
        ),
        store,
    )
    event = _event(
        sensor_id="generator",
        sensor_type="diesel_generator_power",
        value=1200.0,
        timestamp=ts,
    )

    matched, context = await _matches(skill, event, store, "reduce_generator_use")

    assert matched is True
    assert context["generator_watts_snapshot"] == 1200.0
    assert context["battery_ready_for_generator_offset"] == 1
    assert context["can_reduce_generator"] == 1
    assert context["optimizer_action"] == "reduce_generator_use"
    assert context["generator_offset_watts"] == 900.0
    assert context["generator_reduction_value_naira_per_hour"] == 450.0


@pytest.mark.asyncio
async def test_optimizer_action_selects_first_rule_when_raw_context_overlaps():
    skill = _load_skill()
    skill.config["generator_cost_naira_per_kwh"] = 500.0
    store = _Store()
    ts = _ts_utc(2026, 6, 26, 21)

    _ctx(
        skill,
        _event(
            sensor_id="battery",
            sensor_type="deye_battery_soc",
            value=70.0,
            timestamp=ts,
        ),
        store,
    )
    _ctx(
        skill,
        _event(
            sensor_id="load",
            sensor_type="deye_load_power",
            value=900.0,
            timestamp=ts,
        ),
        store,
    )
    _ctx(
        skill,
        _event(
            sensor_id="pv",
            sensor_type="deye_pv1_power",
            value=1800.0,
            timestamp=ts,
        ),
        store,
    )
    event = _event(
        sensor_id="generator",
        sensor_type="diesel_generator_power",
        value=1200.0,
        timestamp=ts,
    )

    result, context = await _first_match(skill, event, store)

    assert context["surplus_watts"] == 900.0
    assert context["should_consume_or_store"] == 1
    assert context["can_reduce_generator"] == 1
    assert context["optimizer_action"] == "reduce_generator_use"
    assert result.matched is True
    assert result.rule_name == "reduce_generator_use"


def test_fast_loop_ledger_accumulates_bounded_operational_estimates():
    skill = _load_skill()
    skill.config["generator_cost_naira_per_kwh"] = 500.0
    store = _Store()
    ts0 = _ts_utc(2026, 6, 26, 12)
    ts1 = _ts_utc(2026, 6, 26, 12, 15)

    _ctx(
        skill,
        _event(
            sensor_id="pv",
            sensor_type="deye_pv1_power",
            value=2000.0,
            timestamp=ts0,
        ),
        store,
    )
    _ctx(
        skill,
        _event(
            sensor_id="load",
            sensor_type="deye_load_power",
            value=1000.0,
            timestamp=ts0,
        ),
        store,
    )
    _ctx(
        skill,
        _event(
            sensor_id="grid",
            sensor_type="deye_grid_power",
            value=-400.0,
            timestamp=ts0,
        ),
        store,
    )
    _ctx(
        skill,
        _event(
            sensor_id="battery",
            sensor_type="deye_battery_power",
            value=-200.0,
            timestamp=ts0,
        ),
        store,
    )
    _ctx(
        skill,
        _event(
            sensor_id="generator",
            sensor_type="diesel_generator_power",
            value=300.0,
            timestamp=ts0,
        ),
        store,
    )
    _, context = _ctx(
        skill,
        _event(
            sensor_id="pv",
            sensor_type="deye_pv1_power",
            value=2000.0,
            timestamp=ts1,
        ),
        store,
    )

    assert context["fast_loop_ledger_confidence"] == "bounded_estimate"
    assert context["fast_loop_interval_hours"] == 0.25
    assert context["fast_loop_grid_import_kwh_delta"] == 0.0
    assert context["fast_loop_grid_export_kwh_delta"] == 0.1
    assert context["fast_loop_solar_generation_kwh_delta"] == 0.5
    assert context["fast_loop_site_consumption_kwh_delta"] == 0.25
    assert context["fast_loop_battery_charge_kwh_delta"] == 0.05
    assert context["fast_loop_battery_discharge_kwh_delta"] == 0.0
    assert context["fast_loop_generator_kwh_delta"] == 0.075
    assert context["fast_loop_backup_supply_hours_delta"] == 0.25
    assert context["fast_loop_grid_unavailable_hours_delta"] == 0.0
    assert context["fast_loop_outage_hours_delta"] == 0.0
    assert context["fast_loop_outage_hours_semantics"] == "not_observed"
    assert context["fast_loop_exported_value_naira_delta"] == 4.0
    assert context["fast_loop_self_consumption_value_naira_delta"] == 56.25
    assert context["fast_loop_diesel_displaced_kwh_delta"] == 0.075
    assert context["fast_loop_diesel_displaced_value_naira_delta"] == 37.5
    assert context["fast_loop_grid_export_kwh_total"] == 0.1
    assert context["fast_loop_solar_generation_kwh_total"] == 0.5
    assert context["fast_loop_backup_supply_hours_total"] == 0.25
    assert context["fast_loop_outage_hours_total"] == 0.0


def test_fast_loop_ledger_tracks_explicit_daytime_grid_outage():
    skill = _load_skill()
    store = _Store()
    ts0 = _ts_utc(2026, 6, 26, 12)
    ts1 = _ts_utc(2026, 6, 26, 12, 15)

    _ctx(
        skill,
        _event(
            sensor_id="grid-status",
            sensor_type="grid_available",
            value=0.0,
            timestamp=ts0,
        ),
        store,
    )
    _ctx(
        skill,
        _event(
            sensor_id="load",
            sensor_type="deye_load_power",
            value=1000.0,
            timestamp=ts0,
        ),
        store,
    )
    _, context = _ctx(
        skill,
        _event(
            sensor_id="pv",
            sensor_type="deye_pv1_power",
            value=1200.0,
            timestamp=ts1,
        ),
        store,
    )

    assert context["grid_availability_observed"] == 1
    assert context["grid_unavailable_snapshot"] == 1
    assert context["grid_availability_source"] == "grid_available"
    assert context["fast_loop_interval_hours"] == 0.25
    assert context["fast_loop_backup_supply_hours_delta"] == 0.0
    assert context["fast_loop_grid_unavailable_hours_delta"] == 0.25
    assert context["fast_loop_outage_hours_delta"] == 0.25
    assert context["fast_loop_outage_hours_semantics"] == "explicit_grid_unavailable"
    assert context["fast_loop_outage_hours_total"] == 0.25


def test_fast_loop_ledger_caps_long_gaps_and_handles_corrupt_timestamp():
    skill = _load_skill()
    store = _Store()
    store.hooks_set_skill_state(skill.name, "ledger_last_timestamp_ms", "bad-clock")
    event = _event(
        sensor_id="pv",
        sensor_type="deye_pv1_power",
        value=1000.0,
        timestamp=_ts_utc(2026, 6, 26, 12),
    )

    _, first_context = _ctx(skill, event, store)

    assert first_context["fast_loop_ledger_confidence"] == (
        "not_accumulated:first_sample"
    )
    assert first_context["fast_loop_solar_generation_kwh_delta"] == 0.0

    later = _event(
        sensor_id="pv",
        sensor_type="deye_pv1_power",
        value=1000.0,
        timestamp=_ts_utc(2026, 6, 26, 13),
    )

    _, capped_context = _ctx(skill, later, store)

    assert capped_context["fast_loop_interval_capped"] == 1
    assert capped_context["fast_loop_interval_hours"] == 0.25
    assert capped_context["fast_loop_solar_generation_kwh_delta"] == 0.25


def test_post_reasoning_is_bounded_tier_a_advisory_text():
    skill = _load_skill()
    skill.config["timezone"] = "UTC"
    store = _Store()
    event = _event(
        sensor_id="grid",
        sensor_type="deye_grid_power",
        value=-850.0,
        timestamp=_ts_utc(2026, 6, 26, 12),
    )
    hook_ctx, _ = _ctx(skill, event, store)
    hook_ctx.trigger_name = "export_cap_approaching"
    result = ReasoningResult(
        text="The threshold anomaly indicates a command should be issued to the inverter.",
        tier="local_slm",
        model="stub",
        tokens_used=0,
        latency_ms=0,
        action_tier="B",
        proposed_action="change_inverter_export_limit",
    )

    updated = skill.hooks.post_reasoning(result, hook_ctx)

    assert updated.action_tier == "A"
    assert updated.proposed_action is None
    assert len(updated.text) <= 160
    assert "Ori changed" not in updated.text
    assert "command" not in updated.text.lower()


def test_post_reasoning_for_blocked_export_never_suggests_more_export():
    skill = _load_skill()
    skill.config["timezone"] = "UTC"
    store = _Store()
    event = _event(
        sensor_id="pv",
        sensor_type="deye_pv1_power",
        value=2600.0,
        timestamp=_ts_utc(2026, 6, 26, 12),
    )
    hook_ctx, _ = _ctx(skill, event, store)
    hook_ctx.derived["export_cap_blocks_export"] = 1
    hook_ctx.trigger_name = "self_consume_or_store_surplus"
    result = ReasoningResult(
        text="Export now because the credit may still help.",
        tier="local_slm",
        model="stub",
        tokens_used=0,
        latency_ms=0,
        action_tier="A",
    )

    updated = skill.hooks.post_reasoning(result, hook_ctx)

    assert "do not add grid export" in updated.text.lower()
    assert "before exporting" not in updated.text.lower()
    assert "command" not in updated.text.lower()


def test_post_reasoning_for_generator_use_remains_advisory():
    skill = _load_skill()
    skill.config["timezone"] = "UTC"
    store = _Store()
    event = _event(
        sensor_id="generator",
        sensor_type="diesel_generator_power",
        value=1200.0,
        timestamp=_ts_utc(2026, 6, 26, 21),
    )
    hook_ctx, _ = _ctx(skill, event, store)
    hook_ctx.trigger_name = "reduce_generator_use"
    result = ReasoningResult(
        text="Command the generator off now.",
        tier="local_slm",
        model="stub",
        tokens_used=0,
        latency_ms=0,
        action_tier="C",
        proposed_action="stop_generator",
    )

    updated = skill.hooks.post_reasoning(result, hook_ctx)

    assert updated.action_tier == "A"
    assert updated.proposed_action is None
    assert "consider using available solar or battery" in updated.text.lower()
    assert "command" not in updated.text.lower()


def test_post_reasoning_for_net_billing_attention_remains_advisory():
    skill = _load_skill()
    skill.config["timezone"] = "UTC"
    store = _Store()
    event = _event(
        sensor_id="pv",
        sensor_type="deye_pv1_power",
        value=1200.0,
        timestamp=_ts_utc(2026, 7, 1, 8),
    )
    hook_ctx, _ = _ctx(skill, event, store)
    hook_ctx.derived["net_billing_attention_summary"] = "monthly_statement_missing"
    hook_ctx.trigger_name = "net_billing_compliance_attention"
    result = ReasoningResult(
        text="Command the inverter and update the regulator record now.",
        tier="local_slm",
        model="stub",
        tokens_used=0,
        latency_ms=0,
        action_tier="B",
        proposed_action="update_export_limit",
    )

    updated = skill.hooks.post_reasoning(result, hook_ctx)

    assert updated.action_tier == "A"
    assert updated.proposed_action is None
    assert "net-billing compliance needs review" in updated.text.lower()
    assert "monthly_statement_missing" in updated.text
    assert "command" not in updated.text.lower()
