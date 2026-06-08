# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Hooks for the bundled retail-occupancy-optimizer skill."""

from ori.skills.composer import (
    as_float,
    as_int,
    format_event_time_hhmm,
    one_sentence_diagnosis,
    sms_cap,
)

_OCCUPANCY_TYPES = {"occupancy_count"}
_POWER_TYPES = {
    "total_power_watts",
    "active_power",
    "growatt_grid_power",
    "victron_grid_power",
}
_SMS_MAX_CHARS = 160
_DIAGNOSIS_MAX_CHARS = 68


def _state_get(context, key, default=""):
    value = context.state.get(key)
    return default if value is None else value


def _state_get_float(context, key, default=0.0):
    return as_float(_state_get(context, key, default), default)


def _state_get_int(context, key, default=0):
    return as_int(_state_get(context, key, default), default)


def _state_set(context, key, value):
    context.state.set(key, str(value))


def _event_timezone(context):
    event = getattr(context, "event", None)
    event_ctx = getattr(event, "context", {}) if event is not None else {}
    event_tz = (
        str(event_ctx.get("device_timezone", "")).strip()
        if isinstance(event_ctx, dict)
        else ""
    )
    return str(getattr(context, "config", {}).get("timezone", "")).strip() or event_tz


def _local_hour(context):
    hhmm = format_event_time_hhmm(
        timestamp_ms=as_int(getattr(context, "timestamp", 0), 0),
        tz_name=_event_timezone(context),
    )
    try:
        return int(hhmm.split(":", 1)[0])
    except Exception:
        return 12


def _hour_in_window(hour, start_hour, end_hour):
    if start_hour == end_hour:
        return True
    if start_hour < end_hour:
        return start_hour <= hour < end_hour
    return hour >= start_hour or hour < end_hour


def _resolve_currency(context):
    cfg = getattr(context, "config", {}) or {}
    symbol = str(cfg.get("currency_symbol", "")).strip()
    if symbol:
        return symbol
    code = str(cfg.get("currency_code", "NGN")).strip().upper()
    return code or "NGN"


def _compose_message(trigger_name, hhmm, diagnosis, context):
    currency = _resolve_currency(context)
    daily_cost = as_float(context.derived.get("projected_waste_cost_daily"), 0.0)
    cost_part = (
        f" About {currency}{daily_cost:,.0f}/day may be at risk."
        if daily_cost > 0
        else ""
    )

    if trigger_name == "empty_business_hours_high_power":
        msg = (
            f"At {hhmm}, the facility looked empty while power stayed high. "
            f"{diagnosis}{cost_part} Reply YES to approve eco mode."
        )
    elif trigger_name == "empty_off_hours_load_shed":
        msg = (
            f"At {hhmm}, Ori found the facility empty after hours and shed "
            f"non-critical load. {diagnosis}{cost_part}"
        )
    else:
        msg = (
            f"At {hhmm}, occupancy and power use looked mismatched. "
            f"{diagnosis}{cost_part}"
        )
    return sms_cap(msg, max_chars=_SMS_MAX_CHARS)


def pre_trigger_eval(context):
    cfg = getattr(context, "config", {}) or {}
    event = getattr(context, "event", None)
    reading = getattr(event, "reading", None)
    now = as_int(getattr(context, "timestamp", 0), 0)

    min_quality = as_float(cfg.get("min_quality", 0.8), 0.8)
    occupancy_empty_threshold = as_float(cfg.get("occupancy_empty_threshold", 0.0), 0.0)
    empty_duration_threshold_minutes = max(
        1, as_int(cfg.get("empty_duration_threshold_minutes", 45), 45)
    )
    power_snapshot_staleness_minutes = max(
        1, as_int(cfg.get("power_snapshot_staleness_minutes", 15), 15)
    )
    baseline_hours = max(1, as_int(cfg.get("baseline_hours", 24), 24))
    high_power_threshold_watts = as_float(
        cfg.get("high_power_threshold_watts", 3500), 3500
    )
    high_power_baseline_multiplier = max(
        1.0, as_float(cfg.get("high_power_baseline_multiplier", 1.25), 1.25)
    )
    business_start_hour = as_int(cfg.get("business_start_hour", 8), 8) % 24
    business_end_hour = as_int(cfg.get("business_end_hour", 18), 18) % 24
    off_hours_start_hour = as_int(cfg.get("off_hours_start_hour", 22), 22) % 24
    tariff_per_kwh = max(0.0, as_float(cfg.get("tariff_per_kwh", 0.0), 0.0))

    context.derived["min_quality"] = min_quality
    context.derived["occupancy_empty_threshold"] = occupancy_empty_threshold
    context.derived["empty_duration_threshold_minutes"] = (
        empty_duration_threshold_minutes
    )
    context.derived["power_snapshot_staleness_minutes"] = (
        power_snapshot_staleness_minutes
    )
    context.derived["baseline_hours"] = baseline_hours
    context.derived["high_power_threshold_watts"] = high_power_threshold_watts
    context.derived["high_power_baseline_multiplier"] = high_power_baseline_multiplier
    context.derived["business_start_hour"] = business_start_hour
    context.derived["business_end_hour"] = business_end_hour
    context.derived["off_hours_start_hour"] = off_hours_start_hour

    context.derived["config_valid"] = 1 if high_power_threshold_watts > 0 else 0
    context.derived["is_optimizer_event"] = 0
    context.derived["facility_empty"] = 0
    context.derived["occupancy_count"] = 0.0
    context.derived["empty_duration_minutes"] = 0.0
    context.derived["power_watts"] = 0.0
    context.derived["power_snapshot_fresh"] = 0
    context.derived["power_baseline_watts"] = 0.0
    context.derived["power_baseline_valid"] = 0
    context.derived["power_ratio_to_baseline"] = 0.0
    context.derived["power_waste_detected"] = 0
    context.derived["estimated_waste_watts"] = 0.0
    context.derived["projected_waste_cost_daily"] = 0.0

    local_hour = _local_hour(context)
    context.derived["local_hour"] = local_hour
    context.derived["business_hours"] = (
        1 if _hour_in_window(local_hour, business_start_hour, business_end_hour) else 0
    )
    context.derived["off_hours"] = (
        1
        if local_hour >= off_hours_start_hour or local_hour < business_start_hour
        else 0
    )

    if reading is None:
        return context

    sensor_id = str(getattr(reading, "sensor_id", "")).strip()
    sensor_type = str(getattr(reading, "sensor_type", "")).strip()
    current_value = as_float(getattr(reading, "value", 0.0), 0.0)

    if sensor_type not in _OCCUPANCY_TYPES and sensor_type not in _POWER_TYPES:
        return context
    context.derived["is_optimizer_event"] = 1

    if sensor_type in _OCCUPANCY_TYPES:
        occupancy_count = max(0.0, current_value)
        _state_set(context, "last_occupancy_count", occupancy_count)
        _state_set(context, "last_occupancy_ts", now)
        if occupancy_count <= occupancy_empty_threshold:
            empty_since_ms = _state_get_int(context, "occupancy_empty_since_ms", 0)
            if empty_since_ms <= 0:
                empty_since_ms = now
                _state_set(context, "occupancy_empty_since_ms", empty_since_ms)
        else:
            _state_set(context, "occupancy_empty_since_ms", 0)
    else:
        power_watts = max(0.0, current_value)
        _state_set(context, "last_power_watts", power_watts)
        _state_set(context, "last_power_ts", now)
        _state_set(context, "last_power_sensor_id", sensor_id)

    occupancy_count = _state_get_float(context, "last_occupancy_count", 0.0)
    empty_since_ms = _state_get_int(context, "occupancy_empty_since_ms", 0)
    facility_empty = occupancy_count <= occupancy_empty_threshold and empty_since_ms > 0
    empty_duration_minutes = (
        max(now - empty_since_ms, 0) / 60000.0 if facility_empty else 0.0
    )

    power_watts = _state_get_float(context, "last_power_watts", 0.0)
    power_ts = _state_get_int(context, "last_power_ts", 0)
    power_sensor_id = str(
        _state_get(context, "last_power_sensor_id", sensor_id)
    ).strip()
    power_age_minutes = max(now - power_ts, 0) / 60000.0 if power_ts > 0 else 1e9
    power_snapshot_fresh = power_age_minutes <= power_snapshot_staleness_minutes

    context.derived["occupancy_count"] = occupancy_count
    context.derived["facility_empty"] = 1 if facility_empty else 0
    context.derived["empty_duration_minutes"] = empty_duration_minutes
    context.derived["power_watts"] = power_watts
    context.derived["power_snapshot_fresh"] = 1 if power_snapshot_fresh else 0

    baseline = context.history.avg_hours(power_sensor_id, baseline_hours)
    baseline_watts = as_float(baseline, 0.0) if baseline is not None else 0.0
    baseline_valid = baseline_watts > 0.0
    context.derived["power_baseline_watts"] = baseline_watts
    context.derived["power_baseline_valid"] = 1 if baseline_valid else 0

    if baseline_valid:
        ratio = power_watts / baseline_watts if baseline_watts > 0 else 0.0
        estimated_waste_watts = max(0.0, power_watts - baseline_watts)
        context.derived["power_ratio_to_baseline"] = ratio
        context.derived["estimated_waste_watts"] = estimated_waste_watts
        context.derived["projected_waste_cost_daily"] = (
            (estimated_waste_watts / 1000.0) * 24.0 * tariff_per_kwh
        )
        if (
            power_snapshot_fresh
            and power_watts >= high_power_threshold_watts
            and ratio >= high_power_baseline_multiplier
        ):
            context.derived["power_waste_detected"] = 1

    return context


def post_reasoning(result, context):
    hhmm = format_event_time_hhmm(
        timestamp_ms=as_int(getattr(context, "timestamp", 0), 0),
        tz_name=_event_timezone(context),
    )
    trigger_name = str(getattr(context, "trigger_name", "") or "")
    diagnosis = one_sentence_diagnosis(
        result.text,
        max_chars=_DIAGNOSIS_MAX_CHARS,
        fallback="The building appears empty while energy use remains high.",
    )
    result.text = _compose_message(trigger_name, hhmm, diagnosis, context)
    return result
