# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Hooks for the bundled prosumer-energy-advisor skill."""

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
_LOAD_TYPES = {"usb_power", "power", "growatt_load_power", "deye_load_power"}
_BATTERY_SOC_TYPES = {
    "growatt_battery_soc",
    "victron_battery_soc",
    "deye_battery_soc",
}
_ADVISORY_REPLACEMENTS = DEFAULT_JARGON_REPLACEMENTS + (
    (r"\bcommands?\b", "suggestion"),
    (r"\bissued?\b", "made"),
    (r"\bcontrol(?:s|led|ling)?\b", "guide"),
    (r"\bactuat(?:e|es|ed|ing|ion)\b", "advise"),
)


def _state_get_float(context, key, default=0.0):
    return as_float(context.state.get(key), default)


def _state_set(context, key, value):
    context.state.set(key, str(value))


def _grid_direction(value):
    """Return import/export watts using signed grid-power convention."""
    grid_import_watts = max(0.0, value)
    grid_export_watts = max(0.0, -value)
    return grid_import_watts, grid_export_watts


def _compose_sms(trigger_name, hhmm, diagnosis):
    if trigger_name == "self_consume_or_store_surplus":
        msg = (
            f"At {hhmm}, solar surplus is available. {diagnosis} "
            "Consider using it now or storing it before exporting."
        )
    elif trigger_name == "export_cap_approaching":
        msg = (
            f"At {hhmm}, export is near the configured site cap. {diagnosis} "
            "Please review before adding more export load."
        )
    elif trigger_name == "defer_deferrable_load":
        msg = (
            f"At {hhmm}, grid draw is high while backup reserve is low. {diagnosis} "
            "Consider delaying non-urgent loads."
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
    import_tariff = as_float(cfg.get("import_tariff_naira_per_kwh", 0.0), 0.0)
    export_credit = as_float(cfg.get("export_credit_naira_per_kwh", 0.0), 0.0)
    surplus_threshold = as_float(cfg.get("surplus_threshold_watts", 500.0), 500.0)
    high_import_threshold = as_float(
        cfg.get("high_import_threshold_watts", 1000.0), 1000.0
    )
    low_solar_threshold = as_float(cfg.get("low_solar_threshold_watts", 300.0), 300.0)
    battery_reserve_soc = as_float(cfg.get("battery_reserve_soc", 40.0), 40.0)
    battery_full_soc = as_float(cfg.get("battery_full_soc", 90.0), 90.0)
    export_cap_watts = as_float(cfg.get("export_cap_watts", 0.0), 0.0)
    export_cap_warning_ratio = as_float(cfg.get("export_cap_warning_ratio", 0.8), 0.8)

    config_valid = 1 if import_tariff > 0 and surplus_threshold > 0 else 0
    export_cap_warning_watts = max(0.0, export_cap_watts * export_cap_warning_ratio)

    context.derived["config_valid"] = config_valid
    context.derived["min_quality"] = min_quality
    context.derived["import_tariff_naira_per_kwh"] = import_tariff
    context.derived["export_credit_naira_per_kwh"] = export_credit
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

    pv_watts = _state_get_float(context, "last_pv_watts", 0.0)
    load_watts = _state_get_float(context, "last_load_watts", 0.0)
    grid_import_watts = _state_get_float(context, "last_grid_import_watts", 0.0)
    grid_export_watts = _state_get_float(context, "last_grid_export_watts", 0.0)
    battery_soc = _state_get_float(context, "last_battery_soc", 100.0)

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
        elif sensor_type in _BATTERY_SOC_TYPES:
            battery_soc = max(0.0, min(100.0, value))
            _state_set(context, "last_battery_soc", battery_soc)

    surplus_watts = max(0.0, grid_export_watts, pv_watts - load_watts)

    context.derived["pv_watts_snapshot"] = pv_watts
    context.derived["load_watts_snapshot"] = load_watts
    context.derived["grid_import_watts"] = grid_import_watts
    context.derived["grid_export_watts"] = grid_export_watts
    context.derived["battery_soc_snapshot"] = battery_soc
    context.derived["surplus_watts"] = surplus_watts

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
    result.text = _compose_sms(trigger_name, hhmm, diagnosis)
    result.action_tier = "A"
    result.proposed_action = None
    return result
