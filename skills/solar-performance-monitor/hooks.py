# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Hooks for the bundled solar-performance-monitor skill."""

from ori.skills.composer import as_float, as_int, one_sentence_diagnosis, sms_cap

_SMS_MAX_CHARS = 160
_DIAGNOSIS_MAX_CHARS = 66

_PV_TYPES = {"growatt_pv_power", "victron_pv_power"}
_GRID_TYPES = {"growatt_grid_power", "victron_grid_power"}
_BATTERY_SOC_TYPES = {"growatt_battery_soc", "victron_battery_soc"}


def _state_get_float(context, key, default=0.0):
    raw = context.state.get(key)
    return as_float(raw, default)


def _state_set(context, key, value):
    context.state.set(key, str(value))


def _local_hour(context):
    from ori.skills.composer import format_event_time_hhmm

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
    hhmm = format_event_time_hhmm(
        timestamp_ms=as_int(getattr(context, "timestamp", 0), 0),
        tz_name=tz_name,
    )
    try:
        return int(hhmm.split(":", 1)[0])
    except Exception:
        return 12


def _compose_sms_first(trigger_name, hhmm, diagnosis):
    if trigger_name == "solar_underperforming_daytime":
        msg = (
            f"At {hhmm}, solar output is below expected daytime level. {diagnosis} "
            "Please check panel shading, dirt, or inverter status."
        )
    elif trigger_name == "battery_not_charging_when_pv_available":
        msg = (
            f"At {hhmm}, battery was not charging despite good sun. {diagnosis} "
            "Please check charger and battery settings."
        )
    elif trigger_name == "unexpected_grid_draw_with_good_sun":
        msg = (
            f"At {hhmm}, grid draw stayed high despite good sun. {diagnosis} "
            "Please check load scheduling and inverter priority."
        )
    else:
        msg = (
            f"At {hhmm}, solar performance looked unusual. {diagnosis} "
            "Please review system status."
        )
    return sms_cap(msg, max_chars=_SMS_MAX_CHARS)


def pre_trigger_eval(context):
    """Compute solar performance heuristics from current reading + state."""
    cfg = getattr(context, "config", {}) or {}
    event = getattr(context, "event", None)
    reading = getattr(event, "reading", None)

    installed_pv_capacity_watts = as_float(cfg.get("installed_pv_capacity_watts", 0), 0)
    battery_capacity_wh = as_float(cfg.get("battery_capacity_wh", 0), 0)
    min_quality = as_float(cfg.get("min_quality", 0.8), 0.8)
    min_expected_pv_ratio = as_float(cfg.get("min_expected_pv_ratio", 0.25), 0.25)
    strong_sun_ratio = as_float(cfg.get("strong_sun_ratio", 0.5), 0.5)
    grid_draw_threshold_watts = as_float(cfg.get("grid_draw_threshold_watts", 500), 500)
    battery_not_full_soc_threshold = as_float(
        cfg.get("battery_not_full_soc_threshold", 95.0), 95.0
    )
    day_start_hour = as_int(cfg.get("day_start_hour", 10), 10)
    day_end_hour = as_int(cfg.get("day_end_hour", 15), 15)

    config_valid = 1
    if installed_pv_capacity_watts <= 0.0 or battery_capacity_wh <= 0.0:
        config_valid = 0

    context.derived["config_valid"] = config_valid
    context.derived["installed_pv_capacity_watts"] = installed_pv_capacity_watts
    context.derived["battery_capacity_wh"] = battery_capacity_wh
    context.derived["min_quality"] = min_quality
    context.derived["min_expected_pv_ratio"] = min_expected_pv_ratio
    context.derived["strong_sun_ratio"] = strong_sun_ratio
    context.derived["grid_draw_threshold_watts"] = grid_draw_threshold_watts
    context.derived["battery_not_full_soc_threshold"] = battery_not_full_soc_threshold
    context.derived["day_start_hour"] = day_start_hour
    context.derived["day_end_hour"] = day_end_hour

    local_hour = _local_hour(context)
    context.derived["local_hour"] = local_hour
    context.derived["is_daytime"] = (
        1 if day_start_hour <= local_hour <= day_end_hour else 0
    )

    context.derived["pv_power_watts"] = 0.0
    context.derived["pv_capacity_ratio"] = 0.0
    context.derived["pv_ratio_snapshot"] = _state_get_float(
        context, "last_pv_ratio", 0.0
    )
    context.derived["grid_import_watts"] = 0.0
    context.derived["battery_soc_delta"] = 0.0

    if reading is None:
        return context

    sensor_type = str(getattr(reading, "sensor_type", "")).strip()
    current_value = as_float(getattr(reading, "value", 0.0), 0.0)

    if sensor_type in _PV_TYPES:
        pv_watts = max(0.0, current_value)
        ratio = (
            pv_watts / installed_pv_capacity_watts
            if installed_pv_capacity_watts > 0.0
            else 0.0
        )
        context.derived["pv_power_watts"] = pv_watts
        context.derived["pv_capacity_ratio"] = ratio
        context.derived["pv_ratio_snapshot"] = ratio
        _state_set(context, "last_pv_ratio", ratio)

    if sensor_type in _GRID_TYPES:
        # Positive grid power is treated as import for this first-release heuristic.
        grid_import = max(0.0, current_value)
        context.derived["grid_import_watts"] = grid_import
        context.derived["pv_ratio_snapshot"] = _state_get_float(
            context, "last_pv_ratio", 0.0
        )

    if sensor_type in _BATTERY_SOC_TYPES:
        previous_soc = _state_get_float(context, "last_battery_soc", current_value)
        delta = current_value - previous_soc
        context.derived["battery_soc_delta"] = delta
        context.derived["pv_ratio_snapshot"] = _state_get_float(
            context, "last_pv_ratio", 0.0
        )
        _state_set(context, "last_battery_soc", current_value)

    return context


def post_reasoning(result, context):
    """Compose concise operator message from diagnosis-only model output."""
    from ori.skills.composer import format_event_time_hhmm

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
        max_chars=_DIAGNOSIS_MAX_CHARS,
        fallback="Solar behavior changed in a way that needs attention.",
    )
    hhmm = format_event_time_hhmm(
        timestamp_ms=as_int(getattr(context, "timestamp", 0), 0),
        tz_name=tz_name,
    )
    trigger_name = str(getattr(context, "trigger_name", "") or "")
    result.text = _compose_sms_first(trigger_name, hhmm, diagnosis)
    return result
