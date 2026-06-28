# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Hooks for the bundled prosumer-energy-advisor skill."""

from datetime import datetime, timezone

from ori.policy.nerc_net_billing import (
    NET_BILLING_BOUNDARY,
    NetBillingComplianceError,
    evaluate_net_billing_compliance,
    load_net_billing_compliance_data,
)
from ori.policy.prosumer_ledger import (
    PROSUMER_METER_OF_RECORD_BOUNDARY,
    ProsumerLedgerError,
    bounded_fast_loop_interval,
    kwh_from_watts,
    load_settlement_statement_data,
)
from ori.policy.tariff_profiles import (
    METER_OF_RECORD_BOUNDARY,
    TariffProfileError,
    load_tariff_profile_data,
)
from ori.skills.composer import (
    DEFAULT_JARGON_REPLACEMENTS,
    as_float,
    format_event_time_hhmm,
    one_sentence_diagnosis,
    sms_cap,
)

_SMS_MAX_CHARS = 160
_DIAGNOSIS_MAX_CHARS = 58

_PV_TYPES = {"growatt_pv_power", "victron_pv_power", "deye_pv1_power"}
_GRID_TYPES = {"growatt_grid_power", "victron_grid_power", "deye_grid_power"}
_GRID_AVAILABILITY_TYPES = {"grid_available", "grid_present", "utility_available"}
_GRID_VOLTAGE_TYPES = {"grid_voltage", "utility_voltage", "ac_grid_voltage"}
_LOAD_TYPES = {"usb_power", "power", "growatt_load_power", "deye_load_power"}
_BATTERY_SOC_TYPES = {
    "growatt_battery_soc",
    "victron_battery_soc",
    "deye_battery_soc",
}
_BATTERY_POWER_TYPES = {
    "growatt_battery_power",
    "victron_battery_power",
    "deye_battery_power",
}
_GENERATOR_TYPES = {
    "generator_power",
    "diesel_generator_power",
    "generator_runtime_power",
}
_ADVISORY_REPLACEMENTS = DEFAULT_JARGON_REPLACEMENTS + (
    (r"\bcommands?\b", "suggestion"),
    (r"\bissued?\b", "made"),
    (r"\bcontrol(?:s|led|ling)?\b", "guide"),
    (r"\bactuat(?:e|es|ed|ing|ion)\b", "advise"),
)


def _state_get_float(context, key, default=0.0):
    return as_float(context.state.get(key), default)


def _state_get_int_or_none(context, key):
    value = context.state.get(key)
    if value in (None, ""):
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _state_set(context, key, value):
    context.state.set(key, str(value))


def _grid_direction(value):
    """Return import/export watts using signed grid-power convention."""
    grid_import_watts = max(0.0, value)
    grid_export_watts = max(0.0, -value)
    return grid_import_watts, grid_export_watts


def _battery_direction(value):
    """Return charge/discharge watts using positive-discharge convention."""
    battery_discharge_watts = max(0.0, value)
    battery_charge_watts = max(0.0, -value)
    return battery_charge_watts, battery_discharge_watts


def _grid_unavailable_from_status(value):
    """Return 1 when a binary grid-availability signal says grid is absent."""
    return 0 if as_float(value, 0.0) >= 0.5 else 1


def _grid_unavailable_from_voltage(value, available_threshold):
    """Return 1 when a voltage signal is below the configured grid threshold."""
    return 0 if as_float(value, 0.0) >= max(0.0, available_threshold) else 1


def _bounded_warning_ratio(value):
    ratio = as_float(value, 0.8)
    if ratio <= 0.0:
        return 0.8
    return min(1.0, ratio)


def _kw_value_per_hour(watts, naira_per_kwh):
    watts = max(0.0, as_float(watts, 0.0))
    naira_per_kwh = max(0.0, as_float(naira_per_kwh, 0.0))
    return (watts / 1000.0) * naira_per_kwh


def _optimizer_action(
    *,
    export_cap_exceeded,
    can_reduce_generator,
    battery_preserve_needed,
    should_defer_load,
    should_consume_or_store,
    can_export_now,
):
    """Pick one deterministic advisory label; it never grants action authority."""

    if export_cap_exceeded:
        return "consume_or_store"
    if can_reduce_generator:
        return "reduce_generator_use"
    if battery_preserve_needed and should_defer_load:
        return "defer_load_preserve_reserve"
    if should_consume_or_store:
        return "consume_or_store"
    if can_export_now:
        return "export_now"
    if battery_preserve_needed:
        return "preserve_battery_reserve"
    return "monitor"


def _resolve_tariff_profile(cfg):
    raw_profile = cfg.get("tariff_profile")
    if isinstance(raw_profile, dict) and raw_profile:
        return load_tariff_profile_data(raw_profile), ""
    return None, "missing tariff_profile"


def _resolve_settlement_statement(cfg):
    raw_statement = cfg.get("settlement_statement")
    if isinstance(raw_statement, dict) and raw_statement:
        return load_settlement_statement_data(raw_statement), ""
    return None, "missing settlement_statement"


def _resolve_net_billing_compliance(cfg):
    raw_profile = cfg.get("net_billing_compliance")
    if isinstance(raw_profile, dict) and raw_profile:
        return load_net_billing_compliance_data(raw_profile), ""
    return None, "missing net_billing_compliance"


def _state_add_float(context, key, delta):
    total = _state_get_float(context, key, 0.0) + max(0.0, as_float(delta, 0.0))
    _state_set(context, key, total)
    return total


def _current_date_from_timestamp(timestamp_ms):
    timestamp = max(0, int(timestamp_ms or 0)) / 1000.0
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).date().isoformat()


def _compose_sms(trigger_name, hhmm, diagnosis, derived):
    if trigger_name == "self_consume_or_store_surplus":
        cap_blocks_export = as_float(derived.get("export_cap_blocks_export", 0), 0.0)
        if cap_blocks_export >= 1:
            msg = (
                f"At {hhmm}, solar surplus is available. {diagnosis} "
                "Use or store it on-site; do not add grid export."
            )
        else:
            msg = (
                f"At {hhmm}, solar surplus is available. {diagnosis} "
                "Consider using it now or storing it before exporting."
            )
    elif trigger_name == "export_cap_exceeded":
        msg = (
            f"At {hhmm}, export is above the configured site cap. {diagnosis} "
            "Avoid adding grid export; use or store surplus on-site."
        )
    elif trigger_name == "export_cap_approaching":
        msg = (
            f"At {hhmm}, export is near the configured site cap. {diagnosis} "
            "Please review before adding more export load."
        )
    elif trigger_name == "export_surplus_with_headroom":
        msg = (
            f"At {hhmm}, export headroom is available. {diagnosis} "
            "Export can be considered within the configured cap."
        )
    elif trigger_name == "defer_deferrable_load":
        msg = (
            f"At {hhmm}, grid draw is high while backup reserve is low. {diagnosis} "
            "Consider delaying non-urgent loads."
        )
    elif trigger_name == "preserve_battery_reserve":
        msg = (
            f"At {hhmm}, battery reserve is low. {diagnosis} "
            "Keep backup energy for outages and delay non-urgent loads."
        )
    elif trigger_name == "reduce_generator_use":
        msg = (
            f"At {hhmm}, generator use can be reduced. {diagnosis} "
            "Consider using available solar or battery for non-urgent loads."
        )
    elif trigger_name == "net_billing_compliance_attention":
        summary = str(derived.get("net_billing_attention_summary", "")).strip()
        msg = (
            f"At {hhmm}, net-billing compliance needs review. {diagnosis} "
            f"{summary or 'Please check the site records.'}"
        )
    else:
        msg = (
            f"At {hhmm}, energy use needs review. {diagnosis} "
            "Please check the site dashboard."
        )
    return sms_cap(msg, max_chars=_SMS_MAX_CHARS)


def pre_trigger_eval(context):
    """Compute consume/store/export advisory variables from telemetry snapshots."""
    cfg = getattr(context, "config", {}) or {}
    event = getattr(context, "event", None)
    reading = getattr(event, "reading", None)

    min_quality = as_float(cfg.get("min_quality", 0.8), 0.8)
    tariff_profile = None
    tariff_error = ""
    try:
        tariff_profile, tariff_error = _resolve_tariff_profile(cfg)
    except TariffProfileError as exc:
        tariff_error = str(exc)
    settlement_statement = None
    settlement_error = ""
    settlement_raw_present = isinstance(cfg.get("settlement_statement"), dict) and bool(
        cfg.get("settlement_statement")
    )
    try:
        settlement_statement, settlement_error = _resolve_settlement_statement(cfg)
    except ProsumerLedgerError as exc:
        settlement_error = str(exc)
    net_billing_profile = None
    net_billing_error = ""
    net_billing_raw_present = isinstance(
        cfg.get("net_billing_compliance"), dict
    ) and bool(cfg.get("net_billing_compliance"))
    try:
        net_billing_profile, net_billing_error = _resolve_net_billing_compliance(cfg)
    except NetBillingComplianceError as exc:
        net_billing_error = str(exc)
    import_tariff = (
        tariff_profile.import_tariff_per_kwh if tariff_profile is not None else 0.0
    )
    export_credit = (
        tariff_profile.export_credit_per_kwh if tariff_profile is not None else 0.0
    )
    surplus_threshold = as_float(cfg.get("surplus_threshold_watts", 500.0), 500.0)
    high_import_threshold = as_float(
        cfg.get("high_import_threshold_watts", 1000.0), 1000.0
    )
    low_solar_threshold = as_float(cfg.get("low_solar_threshold_watts", 300.0), 300.0)
    battery_reserve_soc = as_float(cfg.get("battery_reserve_soc", 40.0), 40.0)
    battery_full_soc = as_float(cfg.get("battery_full_soc", 90.0), 90.0)
    export_cap_watts = as_float(cfg.get("export_cap_watts", 0.0), 0.0)
    export_cap_warning_ratio = _bounded_warning_ratio(
        cfg.get("export_cap_warning_ratio", 0.8)
    )
    export_min_headroom = as_float(
        cfg.get("export_min_headroom_watts", surplus_threshold), surplus_threshold
    )
    reserve_margin_soc = as_float(cfg.get("battery_reserve_margin_soc", 10.0), 10.0)
    generator_reduce_threshold = as_float(
        cfg.get("generator_reduce_threshold_watts", 800.0), 800.0
    )
    generator_cost = as_float(cfg.get("generator_cost_naira_per_kwh", 0.0), 0.0)
    grid_voltage_available_threshold = as_float(
        cfg.get("grid_voltage_available_threshold", 160.0), 160.0
    )
    ledger_enabled = bool(cfg.get("ledger_enabled", True))
    ledger_max_interval_seconds = as_float(
        cfg.get("ledger_max_interval_seconds", 900.0), 900.0
    )

    tariff_policy_valid = (
        tariff_profile is not None and tariff_profile.advisory_qualified
    )
    config_valid = 1 if tariff_policy_valid and surplus_threshold > 0 else 0
    export_cap_warning_watts = max(0.0, export_cap_watts * export_cap_warning_ratio)

    context.derived["config_valid"] = config_valid
    context.derived["tariff_policy_valid"] = 1 if tariff_policy_valid else 0
    context.derived["tariff_policy_error"] = tariff_error
    context.derived["min_quality"] = min_quality
    context.derived["import_tariff_naira_per_kwh"] = import_tariff
    context.derived["export_credit_naira_per_kwh"] = export_credit
    context.derived["tariff_profile"] = (
        tariff_profile.profile if tariff_profile is not None else ""
    )
    context.derived["tariff_profile_version"] = (
        tariff_profile.version if tariff_profile is not None else ""
    )
    context.derived["tariff_profile_status"] = (
        tariff_profile.status if tariff_profile is not None else ""
    )
    context.derived["tariff_profile_source_type"] = (
        tariff_profile.source.source_type if tariff_profile is not None else ""
    )
    context.derived["tariff_profile_source_reference"] = (
        tariff_profile.source.reference if tariff_profile is not None else ""
    )
    context.derived["tariff_profile_disco"] = (
        tariff_profile.disco if tariff_profile is not None else ""
    )
    context.derived["tariff_profile_effective_from"] = (
        tariff_profile.effective_from if tariff_profile is not None else ""
    )
    context.derived["tariff_profile_meter_of_record_boundary"] = (
        tariff_profile.meter_of_record_boundary
        if tariff_profile is not None
        else METER_OF_RECORD_BOUNDARY
    )
    context.derived["tariff_profile_fixed_charges_per_month"] = (
        tariff_profile.fixed_charges_per_month if tariff_profile is not None else 0.0
    )
    context.derived["tariff_profile_interconnection_charges_per_kwh"] = (
        tariff_profile.interconnection_charges_per_kwh
        if tariff_profile is not None
        else 0.0
    )
    context.derived["tariff_profile_export_credit_formula"] = (
        tariff_profile.export_credit_formula if tariff_profile is not None else ""
    )
    context.derived["export_credit_discounted"] = (
        1 if export_credit < import_tariff else 0
    )
    context.derived["surplus_threshold_watts"] = surplus_threshold
    context.derived["high_import_threshold_watts"] = high_import_threshold
    context.derived["low_solar_threshold_watts"] = low_solar_threshold
    context.derived["battery_reserve_soc"] = battery_reserve_soc
    context.derived["battery_full_soc"] = battery_full_soc
    context.derived["export_cap_configured"] = 1 if export_cap_watts > 0 else 0
    context.derived["export_cap_watts"] = export_cap_watts
    context.derived["export_cap_warning_watts"] = export_cap_warning_watts
    context.derived["export_cap_warning_ratio"] = export_cap_warning_ratio
    context.derived["export_min_headroom_watts"] = export_min_headroom
    context.derived["battery_reserve_margin_soc"] = reserve_margin_soc
    context.derived["generator_reduce_threshold_watts"] = generator_reduce_threshold
    context.derived["generator_cost_naira_per_kwh"] = generator_cost
    context.derived["grid_voltage_available_threshold"] = (
        grid_voltage_available_threshold
    )
    context.derived["ledger_enabled"] = 1 if ledger_enabled else 0
    context.derived["ledger_max_interval_seconds"] = ledger_max_interval_seconds
    context.derived["ledger_meter_of_record_boundary"] = (
        PROSUMER_METER_OF_RECORD_BOUNDARY
    )
    context.derived["ledger_fast_loop_clock"] = "runtime_operational_estimate"
    context.derived["ledger_settlement_clock"] = "disco_monthly_statement"
    context.derived["settlement_statement_present"] = 1 if settlement_raw_present else 0
    context.derived["settlement_statement_valid"] = (
        1 if settlement_statement is not None else 0
    )
    context.derived["settlement_statement_error"] = settlement_error
    context.derived["settlement_statement_id"] = (
        settlement_statement.statement_id if settlement_statement is not None else ""
    )
    context.derived["settlement_statement_disco"] = (
        settlement_statement.disco if settlement_statement is not None else ""
    )
    context.derived["settlement_period_start"] = (
        settlement_statement.period_start if settlement_statement is not None else ""
    )
    context.derived["settlement_period_end"] = (
        settlement_statement.period_end if settlement_statement is not None else ""
    )
    context.derived["settlement_import_kwh"] = (
        settlement_statement.import_kwh if settlement_statement is not None else 0.0
    )
    context.derived["settlement_export_kwh"] = (
        settlement_statement.export_kwh if settlement_statement is not None else 0.0
    )
    context.derived["settlement_import_value_naira"] = (
        settlement_statement.import_value if settlement_statement is not None else 0.0
    )
    context.derived["settlement_export_credit_value_naira"] = (
        settlement_statement.export_credit_value
        if settlement_statement is not None
        else 0.0
    )
    context.derived["settlement_net_value_naira"] = (
        settlement_statement.net_value if settlement_statement is not None else 0.0
    )
    context.derived["settlement_source_type"] = (
        settlement_statement.source.source_type
        if settlement_statement is not None
        else ""
    )
    context.derived["settlement_source_reference"] = (
        settlement_statement.source.reference
        if settlement_statement is not None
        else ""
    )
    current_date = _current_date_from_timestamp(getattr(context, "timestamp", 0) or 0)
    net_billing_evaluation = None
    if net_billing_profile is not None:
        net_billing_evaluation = evaluate_net_billing_compliance(
            net_billing_profile,
            current_date=current_date,
            configured_export_cap_watts=export_cap_watts,
            settlement_statement_valid=settlement_statement is not None,
            settlement_statement_id=(
                settlement_statement.statement_id
                if settlement_statement is not None
                else ""
            ),
        )
    attention_codes = (
        net_billing_evaluation.attention_codes
        if net_billing_evaluation is not None
        else ()
    )
    context.derived["net_billing_present"] = 1 if net_billing_raw_present else 0
    context.derived["net_billing_valid"] = 1 if net_billing_profile is not None else 0
    context.derived["net_billing_tracking_qualified"] = (
        1
        if net_billing_profile is not None and net_billing_profile.tracking_qualified
        else 0
    )
    context.derived["net_billing_error"] = net_billing_error
    context.derived["net_billing_boundary"] = (
        net_billing_profile.boundary
        if net_billing_profile is not None
        else NET_BILLING_BOUNDARY
    )
    context.derived["net_billing_profile"] = (
        net_billing_profile.profile if net_billing_profile is not None else ""
    )
    context.derived["net_billing_profile_version"] = (
        net_billing_profile.version if net_billing_profile is not None else ""
    )
    context.derived["net_billing_status"] = (
        net_billing_profile.status if net_billing_profile is not None else ""
    )
    context.derived["net_billing_disco"] = (
        net_billing_profile.disco if net_billing_profile is not None else ""
    )
    context.derived["net_billing_source_type"] = (
        net_billing_profile.source.source_type
        if net_billing_profile is not None
        else ""
    )
    context.derived["net_billing_source_reference"] = (
        net_billing_profile.source.reference if net_billing_profile is not None else ""
    )
    context.derived["net_billing_export_cap_watts"] = (
        net_billing_profile.export_cap_watts if net_billing_profile is not None else 0.0
    )
    context.derived["net_billing_export_cap_matches_runtime"] = (
        1
        if net_billing_evaluation is not None
        and net_billing_evaluation.export_cap_matches_runtime
        else 0
    )
    context.derived["net_billing_attention_required"] = (
        1
        if net_billing_evaluation is not None
        and net_billing_evaluation.attention_required
        else 0
    )
    context.derived["net_billing_attention_codes"] = ",".join(attention_codes)
    context.derived["net_billing_attention_count"] = len(attention_codes)
    context.derived["net_billing_attention_summary"] = (
        net_billing_evaluation.attention_summary
        if net_billing_evaluation is not None
        else net_billing_error
    )
    context.derived["net_billing_disco_feasibility_status"] = (
        net_billing_profile.disco_feasibility.status
        if net_billing_profile is not None
        else ""
    )
    context.derived["net_billing_disco_feasibility_due_by"] = (
        net_billing_profile.disco_feasibility.due_by
        if net_billing_profile is not None
        else ""
    )
    context.derived["net_billing_nerc_registration_status"] = (
        net_billing_profile.nerc_registration.status
        if net_billing_profile is not None
        else ""
    )
    context.derived["net_billing_nerc_certificate_id"] = (
        net_billing_profile.nerc_registration.certificate_id
        if net_billing_profile is not None
        else ""
    )
    context.derived["net_billing_nemsa_inspection_status"] = (
        net_billing_profile.nemsa_inspection.status
        if net_billing_profile is not None
        else ""
    )
    context.derived["net_billing_nemsa_certificate_id"] = (
        net_billing_profile.nemsa_inspection.certificate_id
        if net_billing_profile is not None
        else ""
    )
    context.derived["net_billing_monthly_statement_status"] = (
        net_billing_profile.statement_tracking.status
        if net_billing_profile is not None
        else ""
    )
    context.derived["net_billing_monthly_statement_due_by"] = (
        net_billing_profile.statement_tracking.due_by
        if net_billing_profile is not None
        else ""
    )
    context.derived["net_billing_credit_carry_forward_value"] = (
        net_billing_profile.credit_carry_forward.value
        if net_billing_profile is not None
        else 0.0
    )
    context.derived["net_billing_credit_carry_forward_kwh"] = (
        net_billing_profile.credit_carry_forward.kwh
        if net_billing_profile is not None
        else 0.0
    )
    context.derived["net_billing_relocation_planned"] = (
        1
        if net_billing_profile is not None
        and net_billing_profile.site_relocation_planned
        else 0
    )
    context.derived["net_billing_relocation_effective_date"] = (
        net_billing_profile.relocation_effective_date
        if net_billing_profile is not None
        else ""
    )

    pv_watts = _state_get_float(context, "last_pv_watts", 0.0)
    load_watts = _state_get_float(context, "last_load_watts", 0.0)
    grid_import_watts = _state_get_float(context, "last_grid_import_watts", 0.0)
    grid_export_watts = _state_get_float(context, "last_grid_export_watts", 0.0)
    battery_soc = _state_get_float(context, "last_battery_soc", 100.0)
    battery_charge_watts = _state_get_float(context, "last_battery_charge_watts", 0.0)
    battery_discharge_watts = _state_get_float(
        context, "last_battery_discharge_watts", 0.0
    )
    generator_watts = _state_get_float(context, "last_generator_watts", 0.0)
    grid_availability_observed = _state_get_float(
        context, "last_grid_availability_observed", 0.0
    )
    grid_unavailable = _state_get_float(context, "last_grid_unavailable", 0.0)
    grid_availability_source = context.state.get("last_grid_availability_source") or ""

    context.derived["is_prosumer_power_event"] = 0
    context.derived["is_grid_power_event"] = 0

    if reading is not None:
        sensor_type = str(getattr(reading, "sensor_type", "")).strip()
        value = as_float(getattr(reading, "value", 0.0), 0.0)

        if sensor_type in _PV_TYPES:
            pv_watts = max(0.0, value)
            _state_set(context, "last_pv_watts", pv_watts)
            context.derived["is_prosumer_power_event"] = 1
        elif sensor_type in _LOAD_TYPES:
            load_watts = max(0.0, value)
            _state_set(context, "last_load_watts", load_watts)
            context.derived["is_prosumer_power_event"] = 1
        elif sensor_type in _GRID_TYPES:
            grid_import_watts, grid_export_watts = _grid_direction(value)
            _state_set(context, "last_grid_import_watts", grid_import_watts)
            _state_set(context, "last_grid_export_watts", grid_export_watts)
            context.derived["is_prosumer_power_event"] = 1
            context.derived["is_grid_power_event"] = 1
        elif sensor_type in _GRID_AVAILABILITY_TYPES:
            grid_availability_observed = 1.0
            grid_unavailable = float(_grid_unavailable_from_status(value))
            grid_availability_source = sensor_type
            _state_set(context, "last_grid_availability_observed", 1.0)
            _state_set(context, "last_grid_unavailable", grid_unavailable)
            _state_set(
                context, "last_grid_availability_source", grid_availability_source
            )
            context.derived["is_prosumer_power_event"] = 1
        elif sensor_type in _GRID_VOLTAGE_TYPES:
            grid_availability_observed = 1.0
            grid_unavailable = float(
                _grid_unavailable_from_voltage(
                    value,
                    grid_voltage_available_threshold,
                )
            )
            grid_availability_source = sensor_type
            _state_set(context, "last_grid_availability_observed", 1.0)
            _state_set(context, "last_grid_unavailable", grid_unavailable)
            _state_set(
                context, "last_grid_availability_source", grid_availability_source
            )
            context.derived["is_prosumer_power_event"] = 1
        elif sensor_type in _BATTERY_SOC_TYPES:
            battery_soc = max(0.0, min(100.0, value))
            _state_set(context, "last_battery_soc", battery_soc)
        elif sensor_type in _BATTERY_POWER_TYPES:
            battery_charge_watts, battery_discharge_watts = _battery_direction(value)
            _state_set(context, "last_battery_charge_watts", battery_charge_watts)
            _state_set(context, "last_battery_discharge_watts", battery_discharge_watts)
            context.derived["is_prosumer_power_event"] = 1
        elif sensor_type in _GENERATOR_TYPES:
            generator_watts = max(0.0, value)
            _state_set(context, "last_generator_watts", generator_watts)
            context.derived["is_prosumer_power_event"] = 1

    surplus_watts = max(0.0, grid_export_watts, pv_watts - load_watts)
    if export_cap_watts > 0:
        export_cap_headroom_watts = max(0.0, export_cap_watts - grid_export_watts)
        exportable_surplus_watts = min(surplus_watts, export_cap_headroom_watts)
        export_cap_exceeded = 1 if grid_export_watts > export_cap_watts else 0
        export_cap_blocks_export = (
            1
            if export_cap_exceeded == 1
            or (surplus_watts > 0 and exportable_surplus_watts < surplus_watts)
            else 0
        )
    else:
        export_cap_headroom_watts = surplus_watts
        exportable_surplus_watts = surplus_watts
        export_cap_exceeded = 0
        export_cap_blocks_export = 0
    local_use_or_store_watts = max(0.0, surplus_watts - exportable_surplus_watts)
    battery_preserve_needed = 1 if battery_soc <= battery_reserve_soc else 0
    battery_ready_for_generator_offset = (
        1 if battery_soc >= battery_reserve_soc + max(0.0, reserve_margin_soc) else 0
    )
    should_defer_load = (
        1
        if grid_import_watts >= high_import_threshold
        and pv_watts <= low_solar_threshold
        and battery_preserve_needed == 1
        else 0
    )
    should_consume_or_store = (
        1
        if surplus_watts >= surplus_threshold
        and battery_soc < battery_full_soc
        and (export_credit < import_tariff or export_cap_blocks_export == 1)
        else 0
    )
    can_export_now = (
        1
        if surplus_watts >= surplus_threshold
        and exportable_surplus_watts >= max(0.0, export_min_headroom)
        and battery_soc >= battery_full_soc
        and export_cap_blocks_export == 0
        else 0
    )
    generator_offset_available = (
        1
        if surplus_watts >= surplus_threshold
        or (battery_ready_for_generator_offset == 1 and load_watts > 0)
        else 0
    )
    can_reduce_generator = (
        1
        if generator_watts >= generator_reduce_threshold
        and generator_offset_available == 1
        else 0
    )
    self_consumption_value = _kw_value_per_hour(surplus_watts, import_tariff)
    export_value = _kw_value_per_hour(exportable_surplus_watts, export_credit)
    self_consumption_premium = max(0.0, self_consumption_value - export_value)
    defer_load_value = _kw_value_per_hour(grid_import_watts, import_tariff)
    generator_offset_watts = min(
        generator_watts,
        max(surplus_watts, load_watts if battery_ready_for_generator_offset else 0.0),
    )
    generator_reduction_value = _kw_value_per_hour(
        generator_offset_watts, generator_cost
    )
    optimizer_action = _optimizer_action(
        export_cap_exceeded=export_cap_exceeded,
        can_reduce_generator=can_reduce_generator,
        battery_preserve_needed=battery_preserve_needed,
        should_defer_load=should_defer_load,
        should_consume_or_store=should_consume_or_store,
        can_export_now=can_export_now,
    )
    action_values = {
        "reduce_generator_use": generator_reduction_value,
        "defer_load_preserve_reserve": defer_load_value,
        "consume_or_store": self_consumption_premium,
        "export_now": export_value,
        "preserve_battery_reserve": defer_load_value,
    }
    optimizer_value = action_values.get(optimizer_action, 0.0)
    current_timestamp = int(getattr(context, "timestamp", 0) or 0)
    last_ledger_timestamp = _state_get_int_or_none(context, "ledger_last_timestamp_ms")
    ledger_interval = (
        bounded_fast_loop_interval(
            last_ledger_timestamp,
            current_timestamp,
            max_interval_seconds=ledger_max_interval_seconds,
        )
        if ledger_enabled and context.derived["is_prosumer_power_event"] == 1
        else bounded_fast_loop_interval(
            None,
            current_timestamp,
            max_interval_seconds=ledger_max_interval_seconds,
        )
    )
    if ledger_enabled and context.derived["is_prosumer_power_event"] == 1:
        if ledger_interval.usable or ledger_interval.reason == "first_sample":
            _state_set(context, "ledger_last_timestamp_ms", current_timestamp)

    grid_import_kwh_delta = kwh_from_watts(grid_import_watts, ledger_interval.hours)
    grid_export_kwh_delta = kwh_from_watts(grid_export_watts, ledger_interval.hours)
    solar_generation_kwh_delta = kwh_from_watts(pv_watts, ledger_interval.hours)
    site_consumption_kwh_delta = kwh_from_watts(load_watts, ledger_interval.hours)
    battery_charge_kwh_delta = kwh_from_watts(
        battery_charge_watts, ledger_interval.hours
    )
    battery_discharge_kwh_delta = kwh_from_watts(
        battery_discharge_watts, ledger_interval.hours
    )
    generator_kwh_delta = kwh_from_watts(generator_watts, ledger_interval.hours)
    backup_supply_hours_delta = (
        ledger_interval.hours
        if load_watts > 0
        and grid_import_watts == 0
        and (generator_watts > 0 or battery_discharge_watts > 0)
        else 0.0
    )
    grid_unavailable_hours_delta = (
        ledger_interval.hours
        if grid_availability_observed >= 1.0 and grid_unavailable >= 1.0
        else 0.0
    )
    exported_value_delta = grid_export_kwh_delta * export_credit
    self_consumed_watts = min(pv_watts + battery_discharge_watts, load_watts)
    self_consumption_value_delta = (
        kwh_from_watts(self_consumed_watts, ledger_interval.hours) * import_tariff
    )
    diesel_displaced_kwh_delta = kwh_from_watts(
        generator_offset_watts, ledger_interval.hours
    )
    diesel_displaced_value_delta = diesel_displaced_kwh_delta * generator_cost
    grid_import_kwh_total = _state_add_float(
        context, "ledger_grid_import_kwh_total", grid_import_kwh_delta
    )
    grid_export_kwh_total = _state_add_float(
        context, "ledger_grid_export_kwh_total", grid_export_kwh_delta
    )
    solar_generation_kwh_total = _state_add_float(
        context, "ledger_solar_generation_kwh_total", solar_generation_kwh_delta
    )
    site_consumption_kwh_total = _state_add_float(
        context, "ledger_site_consumption_kwh_total", site_consumption_kwh_delta
    )
    battery_charge_kwh_total = _state_add_float(
        context, "ledger_battery_charge_kwh_total", battery_charge_kwh_delta
    )
    battery_discharge_kwh_total = _state_add_float(
        context, "ledger_battery_discharge_kwh_total", battery_discharge_kwh_delta
    )
    generator_kwh_total = _state_add_float(
        context, "ledger_generator_kwh_total", generator_kwh_delta
    )
    backup_supply_hours_total = _state_add_float(
        context, "ledger_backup_supply_hours_total", backup_supply_hours_delta
    )
    grid_unavailable_hours_total = _state_add_float(
        context, "ledger_grid_unavailable_hours_total", grid_unavailable_hours_delta
    )
    exported_value_total = _state_add_float(
        context, "ledger_exported_value_naira_total", exported_value_delta
    )
    self_consumption_value_total = _state_add_float(
        context,
        "ledger_self_consumption_value_naira_total",
        self_consumption_value_delta,
    )
    diesel_displaced_kwh_total = _state_add_float(
        context, "ledger_diesel_displaced_kwh_total", diesel_displaced_kwh_delta
    )
    diesel_displaced_value_total = _state_add_float(
        context,
        "ledger_diesel_displaced_value_naira_total",
        diesel_displaced_value_delta,
    )
    ledger_confidence = (
        "bounded_estimate"
        if ledger_interval.usable
        else f"not_accumulated:{ledger_interval.reason}"
    )

    context.derived["pv_watts_snapshot"] = pv_watts
    context.derived["load_watts_snapshot"] = load_watts
    context.derived["grid_import_watts"] = grid_import_watts
    context.derived["grid_export_watts"] = grid_export_watts
    context.derived["battery_soc_snapshot"] = battery_soc
    context.derived["battery_charge_watts_snapshot"] = battery_charge_watts
    context.derived["battery_discharge_watts_snapshot"] = battery_discharge_watts
    context.derived["generator_watts_snapshot"] = generator_watts
    context.derived["grid_availability_observed"] = (
        1 if grid_availability_observed >= 1.0 else 0
    )
    context.derived["grid_unavailable_snapshot"] = 1 if grid_unavailable >= 1.0 else 0
    context.derived["grid_availability_source"] = grid_availability_source
    context.derived["surplus_watts"] = surplus_watts
    context.derived["export_cap_headroom_watts"] = export_cap_headroom_watts
    context.derived["exportable_surplus_watts"] = exportable_surplus_watts
    context.derived["local_use_or_store_watts"] = local_use_or_store_watts
    context.derived["export_cap_exceeded"] = export_cap_exceeded
    context.derived["export_cap_blocks_export"] = export_cap_blocks_export
    context.derived["battery_preserve_needed"] = battery_preserve_needed
    context.derived["battery_ready_for_generator_offset"] = (
        battery_ready_for_generator_offset
    )
    context.derived["should_defer_load"] = should_defer_load
    context.derived["should_consume_or_store"] = should_consume_or_store
    context.derived["can_export_now"] = can_export_now
    context.derived["generator_offset_available"] = generator_offset_available
    context.derived["can_reduce_generator"] = can_reduce_generator
    context.derived["generator_offset_watts"] = generator_offset_watts
    context.derived["self_consumption_value_naira_per_hour"] = self_consumption_value
    context.derived["export_value_naira_per_hour"] = export_value
    context.derived["self_consumption_premium_naira_per_hour"] = (
        self_consumption_premium
    )
    context.derived["defer_load_value_naira_per_hour"] = defer_load_value
    context.derived["generator_reduction_value_naira_per_hour"] = (
        generator_reduction_value
    )
    context.derived["optimizer_action"] = optimizer_action
    context.derived["optimizer_value_naira_per_hour"] = optimizer_value
    context.derived["fast_loop_ledger_confidence"] = ledger_confidence
    context.derived["fast_loop_interval_ms"] = ledger_interval.interval_ms
    context.derived["fast_loop_interval_hours"] = ledger_interval.hours
    context.derived["fast_loop_interval_capped"] = 1 if ledger_interval.capped else 0
    context.derived["fast_loop_grid_import_kwh_delta"] = grid_import_kwh_delta
    context.derived["fast_loop_grid_export_kwh_delta"] = grid_export_kwh_delta
    context.derived["fast_loop_solar_generation_kwh_delta"] = solar_generation_kwh_delta
    context.derived["fast_loop_site_consumption_kwh_delta"] = site_consumption_kwh_delta
    context.derived["fast_loop_battery_charge_kwh_delta"] = battery_charge_kwh_delta
    context.derived["fast_loop_battery_discharge_kwh_delta"] = (
        battery_discharge_kwh_delta
    )
    context.derived["fast_loop_generator_kwh_delta"] = generator_kwh_delta
    context.derived["fast_loop_backup_supply_hours_delta"] = backup_supply_hours_delta
    context.derived["fast_loop_grid_unavailable_hours_delta"] = (
        grid_unavailable_hours_delta
    )
    context.derived["fast_loop_outage_hours_delta"] = grid_unavailable_hours_delta
    context.derived["fast_loop_outage_hours_semantics"] = (
        "explicit_grid_unavailable"
        if grid_availability_observed >= 1.0
        else "not_observed"
    )
    context.derived["fast_loop_exported_value_naira_delta"] = exported_value_delta
    context.derived["fast_loop_self_consumption_value_naira_delta"] = (
        self_consumption_value_delta
    )
    context.derived["fast_loop_diesel_displaced_kwh_delta"] = diesel_displaced_kwh_delta
    context.derived["fast_loop_diesel_displaced_value_naira_delta"] = (
        diesel_displaced_value_delta
    )
    context.derived["fast_loop_grid_import_kwh_total"] = grid_import_kwh_total
    context.derived["fast_loop_grid_export_kwh_total"] = grid_export_kwh_total
    context.derived["fast_loop_solar_generation_kwh_total"] = solar_generation_kwh_total
    context.derived["fast_loop_site_consumption_kwh_total"] = site_consumption_kwh_total
    context.derived["fast_loop_battery_charge_kwh_total"] = battery_charge_kwh_total
    context.derived["fast_loop_battery_discharge_kwh_total"] = (
        battery_discharge_kwh_total
    )
    context.derived["fast_loop_generator_kwh_total"] = generator_kwh_total
    context.derived["fast_loop_backup_supply_hours_total"] = backup_supply_hours_total
    context.derived["fast_loop_grid_unavailable_hours_total"] = (
        grid_unavailable_hours_total
    )
    context.derived["fast_loop_outage_hours_total"] = grid_unavailable_hours_total
    context.derived["fast_loop_exported_value_naira_total"] = exported_value_total
    context.derived["fast_loop_self_consumption_value_naira_total"] = (
        self_consumption_value_total
    )
    context.derived["fast_loop_diesel_displaced_kwh_total"] = diesel_displaced_kwh_total
    context.derived["fast_loop_diesel_displaced_value_naira_total"] = (
        diesel_displaced_value_total
    )

    return context


def post_reasoning(result, context):
    """Compose concise advisory text; never imply physical control."""
    event = getattr(context, "event", None)
    event_ctx = getattr(event, "context", {}) if event is not None else {}
    event_tz = (
        str(event_ctx.get("device_timezone", "")).strip()
        if isinstance(event_ctx, dict)
        else ""
    )
    tz_name = (
        str(getattr(context, "config", {}).get("timezone", "")).strip() or event_tz
    )

    diagnosis = one_sentence_diagnosis(
        result.text,
        jargon_replacements=_ADVISORY_REPLACEMENTS,
        max_chars=_DIAGNOSIS_MAX_CHARS,
        fallback="Ori found a better timing choice for this site.",
    )
    hhmm = format_event_time_hhmm(
        timestamp_ms=int(getattr(context, "timestamp", 0) or 0),
        tz_name=tz_name,
    )
    trigger_name = str(getattr(context, "trigger_name", "") or "")
    result.text = _compose_sms(trigger_name, hhmm, diagnosis, context.derived)
    result.action_tier = "A"
    result.proposed_action = None
    return result
