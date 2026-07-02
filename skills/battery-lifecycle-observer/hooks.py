# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Hooks for the bundled battery-lifecycle-observer skill."""

from ori.skills.composer import (
    as_float,
    as_int,
    format_event_time_hhmm,
    one_sentence_diagnosis,
    sms_cap,
)

_SOC_TYPES = {"growatt_battery_soc", "victron_battery_soc", "battery_percent"}
_GRID_POWER_TYPES = {"growatt_grid_power", "victron_grid_power", "active_power"}
_SMS_MAX_CHARS = 160
_DIAGNOSIS_MAX_CHARS = 66
_EFC_WINDOW_MS = 7 * 24 * 60 * 60 * 1000


def _state_get_float(context, key, default=0.0):
    return as_float(context.state.get(key), default)


def _state_get_int(context, key, default=0):
    return as_int(context.state.get(key), default)


def _state_set(context, key, value):
    context.state.set(key, str(value))


def _sensor_id_list(cfg, key):
    raw = cfg.get(key, [])
    if not isinstance(raw, list):
        return set()
    return {str(item).strip() for item in raw if str(item).strip()}


def _compose_sms(trigger_name, hhmm, diagnosis):
    if trigger_name == "battery_deep_discharge_risk":
        msg = (
            f"At {hhmm}, backup battery stayed too low for too long. {diagnosis} "
            "Please reduce deep discharge and recharge sooner."
        )
    elif trigger_name == "battery_cycle_stress":
        msg = (
            f"At {hhmm}, battery cycle stress stayed high this week. {diagnosis} "
            "Please review load profile to reduce wear."
        )
    elif trigger_name == "olax_voltage_decay_degraded":
        msg = (
            f"At {hhmm}, backup battery voltage dropped too fast during outage. {diagnosis} "
            "Please inspect UPS battery health."
        )
    else:
        msg = (
            f"At {hhmm}, battery lifecycle behavior needs attention. {diagnosis} "
            "Please review backup system health."
        )
    return sms_cap(msg, max_chars=_SMS_MAX_CHARS)


def pre_trigger_eval(context):
    cfg = getattr(context, "config", {}) or {}
    event = getattr(context, "event", None)
    reading = getattr(event, "reading", None)
    now = as_int(getattr(context, "timestamp", 0), 0)

    min_quality = as_float(cfg.get("min_quality", 0.8), 0.8)
    low_soc_threshold = as_float(cfg.get("low_soc_threshold", 20.0), 20.0)
    low_soc_persist_minutes = max(
        1, as_int(cfg.get("low_soc_persistence_minutes", 30), 30)
    )
    efc_warning_threshold_weekly = as_float(
        cfg.get("efc_warning_threshold_weekly", 7.0), 7.0
    )
    grid_outage_voltage_threshold = as_float(
        cfg.get("grid_outage_voltage_threshold", 180.0), 180.0
    )
    olax_min_outage_minutes = max(1, as_int(cfg.get("olax_min_outage_minutes", 10), 10))
    olax_decay_threshold_v_per_hour = as_float(
        cfg.get("olax_decay_threshold_v_per_hour", 1.2), 1.2
    )
    battery_voltage_sensor_ids = _sensor_id_list(cfg, "battery_voltage_sensor_ids")
    grid_voltage_sensor_ids = _sensor_id_list(cfg, "grid_voltage_sensor_ids")

    context.derived["min_quality"] = min_quality
    context.derived["low_soc_threshold"] = low_soc_threshold
    context.derived["low_soc_persistence_minutes"] = low_soc_persist_minutes
    context.derived["efc_warning_threshold_weekly"] = efc_warning_threshold_weekly
    context.derived["grid_outage_voltage_threshold"] = grid_outage_voltage_threshold
    context.derived["olax_min_outage_minutes"] = olax_min_outage_minutes
    context.derived["olax_decay_threshold_v_per_hour"] = olax_decay_threshold_v_per_hour

    context.derived["is_soc_sensor"] = 0
    context.derived["soc_value"] = 0.0
    context.derived["low_soc_persist_minutes"] = 0.0
    context.derived["weekly_efc"] = 0.0

    context.derived["is_voltage_mode"] = 0
    context.derived["is_battery_voltage_sensor"] = 0
    context.derived["outage_active"] = 0
    context.derived["outage_duration_minutes"] = 0.0
    context.derived["voltage_decay_v_per_hour"] = 0.0

    if reading is None:
        return context

    sensor_id = str(getattr(reading, "sensor_id", "")).strip()
    sensor_type = str(getattr(reading, "sensor_type", "")).strip()
    value = as_float(getattr(reading, "value", 0.0), 0.0)

    # Outage state updates from explicit grid-voltage sensors.
    if sensor_id in grid_voltage_sensor_ids:
        if value <= grid_outage_voltage_threshold:
            if _state_get_int(context, "outage_active", 0) == 0:
                _state_set(context, "outage_start_ms", now)
            _state_set(context, "outage_active", 1)
        else:
            _state_set(context, "outage_active", 0)
            _state_set(context, "outage_start_ms", 0)
            _state_set(context, "outage_start_voltage", 0.0)

    # Optional fallback outage updates from inverter-reported grid power.
    # This fallback is authoritative only when explicit grid-voltage sensors
    # are not configured.
    if sensor_type in _GRID_POWER_TYPES:
        if value <= 0.0:
            if _state_get_int(context, "outage_active", 0) == 0:
                _state_set(context, "outage_start_ms", now)
            _state_set(context, "outage_active", 1)
        elif not grid_voltage_sensor_ids:
            _state_set(context, "outage_active", 0)
            _state_set(context, "outage_start_ms", 0)
            _state_set(context, "outage_start_voltage", 0.0)

    outage_active = _state_get_int(context, "outage_active", 0)
    outage_start_ms = _state_get_int(context, "outage_start_ms", 0)
    if outage_active == 1 and outage_start_ms > 0 and now > outage_start_ms:
        context.derived["outage_active"] = 1
        context.derived["outage_duration_minutes"] = (now - outage_start_ms) / 60000.0

    # SOC mode: equivalent full cycle estimate and deep-discharge persistence.
    if sensor_type in _SOC_TYPES:
        soc = max(0.0, min(100.0, value))
        context.derived["is_soc_sensor"] = 1
        context.derived["soc_value"] = soc

        low_soc_start_ms = _state_get_int(context, "low_soc_start_ms", 0)
        if soc <= low_soc_threshold:
            if low_soc_start_ms <= 0:
                low_soc_start_ms = now
                _state_set(context, "low_soc_start_ms", low_soc_start_ms)
            context.derived["low_soc_persist_minutes"] = (
                max(now - low_soc_start_ms, 0) / 60000.0
            )
        else:
            _state_set(context, "low_soc_start_ms", 0)

        efc_window_start_ms = _state_get_int(context, "efc_window_start_ms", now)
        efc_accum_pct = _state_get_float(context, "efc_accum_pct", 0.0)
        last_soc = _state_get_float(context, "last_soc_value", soc)
        last_soc_ts = _state_get_int(context, "last_soc_ts", now)

        if now <= efc_window_start_ms or (now - efc_window_start_ms) > _EFC_WINDOW_MS:
            efc_window_start_ms = now
            efc_accum_pct = 0.0

        if now > last_soc_ts:
            efc_accum_pct += abs(soc - last_soc)

        weekly_efc = efc_accum_pct / 100.0
        context.derived["weekly_efc"] = weekly_efc

        _state_set(context, "efc_window_start_ms", efc_window_start_ms)
        _state_set(context, "efc_accum_pct", efc_accum_pct)
        _state_set(context, "last_soc_value", soc)
        _state_set(context, "last_soc_ts", now)

    # Voltage-proxy mode (OLAX PoC): decay slope during active outage.
    if sensor_id in battery_voltage_sensor_ids:
        context.derived["is_voltage_mode"] = 1
        context.derived["is_battery_voltage_sensor"] = 1

        if outage_active == 1:
            start_voltage = _state_get_float(context, "outage_start_voltage", 0.0)
            if start_voltage <= 0.0:
                start_voltage = value
                _state_set(context, "outage_start_voltage", start_voltage)

            duration_ms = max(now - max(outage_start_ms, 0), 0)
            if duration_ms > 0:
                hours = duration_ms / 3600000.0
                decay_v_per_hour = max(0.0, (start_voltage - value) / hours)
                context.derived["voltage_decay_v_per_hour"] = decay_v_per_hour
                context.derived["outage_active"] = 1
                context.derived["outage_duration_minutes"] = duration_ms / 60000.0
        else:
            _state_set(context, "outage_start_voltage", 0.0)

    return context


def post_reasoning(result, context):
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
        fallback="Battery behavior changed in a way that needs attention.",
    )
    hhmm = format_event_time_hhmm(
        timestamp_ms=as_int(getattr(context, "timestamp", 0), 0),
        tz_name=tz_name,
    )
    trigger_name = str(getattr(context, "trigger_name", "") or "")
    result.text = _compose_sms(trigger_name, hhmm, diagnosis)
    return result
