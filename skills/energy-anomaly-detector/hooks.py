# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Hooks for the bundled energy-anomaly-detector skill."""

from ori.skills.composer import (
    DEFAULT_JARGON_REPLACEMENTS,
    as_float,
    as_int,
    one_sentence_diagnosis,
    resolve_timezone,
    sms_cap,
)


def _mean(values):
    if not values:
        return 0.0
    return sum(values) / len(values)


def _stddev(values):
    if len(values) < 2:
        return 0.0
    avg = _mean(values)
    variance = sum((v - avg) ** 2 for v in values) / len(values)
    return variance**0.5


_SMS_MAX_CHARS = 160
_DIAGNOSIS_MAX_CHARS = 66
_DEFAULT_POWER_FACTOR = 0.9
_FALLBACK_LINE_VOLTAGE = 230.0

_COUNTRY_TO_CURRENCY_CODE = {
    "NG": "NGN",
    "KE": "KES",
    "US": "USD",
    "CA": "CAD",
    "GB": "GBP",
    "GH": "GHS",
    "ZA": "ZAR",
    "EU": "EUR",
}

_CURRENCY_CODE_TO_SYMBOL = {
    "NGN": "₦",
    "KES": "KSh",
    "USD": "$",
    "CAD": "C$",
    "GBP": "£",
    "GHS": "GH₵",
    "ZAR": "R",
    "EUR": "€",
}

_COUNTRY_TO_LINE_VOLTAGE = {
    "NG": 230.0,
    "KE": 230.0,
    "GB": 230.0,
    "GH": 230.0,
    "ZA": 230.0,
    "US": 120.0,
    "CA": 120.0,
}


def _resolve_timezone(tz_name):
    return resolve_timezone(tz_name)


def _format_event_time(context):
    ts_ms = as_int(getattr(context, "timestamp", 0), 0)
    ts_sec = max(0, ts_ms) / 1000.0
    tz_name = getattr(context, "config", {}).get("timezone")
    from datetime import datetime

    dt = datetime.fromtimestamp(ts_sec, tz=_resolve_timezone(tz_name))
    return dt.strftime("%H:%M")


def _one_sentence(text):
    return one_sentence_diagnosis(
        text,
        jargon_replacements=DEFAULT_JARGON_REPLACEMENTS,
        max_chars=_DIAGNOSIS_MAX_CHARS,
        fallback="Power use changed in a way that needs quick attention.",
    )


def _compose_sms_first(trigger_name, hhmm, diagnosis, anchor=""):
    prefix = f"{anchor}. " if anchor else ""
    if trigger_name == "sustained_overdraw":
        msg = (
            f"{prefix}At {hhmm}, I noticed power stayed high for too long. {diagnosis} "
            "I flagged it early so you can prevent extra cost."
        )
    elif trigger_name == "sudden_load_spike":
        msg = (
            f"{prefix}At {hhmm}, power jumped suddenly. {diagnosis} "
            "I flagged it now so you can check affected equipment."
        )
    elif trigger_name == "unstable_power_draw":
        msg = (
            f"{prefix}At {hhmm}, power became unstable. {diagnosis} "
            "I flagged it now so you can prevent a failure."
        )
    elif trigger_name == "dangerous_overcurrent":
        msg = (
            f"{prefix}At {hhmm}, I detected a dangerous power surge. {diagnosis} "
            "Please isolate non-essential load now."
        )
    else:
        msg = (
            f"{prefix}At {hhmm}, I noticed unusual power behavior. {diagnosis} "
            "I flagged it now so you can act early."
        )
    return sms_cap(msg, max_chars=_SMS_MAX_CHARS)


def _country_code(context):
    cfg = getattr(context, "config", {}) or {}
    explicit = str(cfg.get("country_code", "")).strip().upper()
    if len(explicit) == 2 and explicit.isalpha():
        return explicit
    event = getattr(context, "event", None)
    event_ctx = getattr(event, "context", {}) if event is not None else {}
    if isinstance(event_ctx, dict):
        from_event = str(event_ctx.get("device_country_code", "")).strip().upper()
        if len(from_event) == 2 and from_event.isalpha():
            return from_event
    return ""


def _resolve_currency(context):
    cfg = getattr(context, "config", {}) or {}
    explicit_symbol = str(cfg.get("currency_symbol", "")).strip()
    if explicit_symbol:
        return explicit_symbol

    explicit_code = str(cfg.get("currency_code", "")).strip().upper()
    if explicit_code:
        return _CURRENCY_CODE_TO_SYMBOL.get(explicit_code, explicit_code)

    cc = _country_code(context)
    inferred_code = _COUNTRY_TO_CURRENCY_CODE.get(cc, "USD")
    return _CURRENCY_CODE_TO_SYMBOL.get(inferred_code, inferred_code)


def _resolve_line_voltage(context):
    cfg = getattr(context, "config", {}) or {}
    raw_voltage = cfg.get("line_voltage", None)
    try:
        if raw_voltage is not None:
            voltage = float(raw_voltage)
            if voltage > 0.0:
                return voltage, "exact"
    except (TypeError, ValueError):
        pass

    cc = _country_code(context)
    if cc in _COUNTRY_TO_LINE_VOLTAGE:
        return _COUNTRY_TO_LINE_VOLTAGE[cc], "estimated"
    return _FALLBACK_LINE_VOLTAGE, "estimated"


def _resolve_power_factor(context):
    cfg = getattr(context, "config", {}) or {}
    raw_pf = cfg.get("power_factor", _DEFAULT_POWER_FACTOR)
    if raw_pf is None:
        raw_pf = _DEFAULT_POWER_FACTOR
    try:
        pf = float(raw_pf)
    except (TypeError, ValueError):
        pf = _DEFAULT_POWER_FACTOR
    return min(1.0, max(0.1, pf))


def _resolve_tariff(context):
    cfg = getattr(context, "config", {}) or {}
    raw = cfg.get("tariff_per_kwh", None)
    if raw is None:
        return 0.0, False
    try:
        tariff = float(raw)
    except (TypeError, ValueError):
        return 0.0, False
    return (tariff, tariff > 0.0)


def _round_money(amount):
    if amount < 1.0:
        return round(amount, 2)
    if amount < 100.0:
        return round(amount, 1)
    return int(round(amount))


def _cost_anchor(context):
    projected = as_float(context.derived.get("projected_extra_cost_daily", 0.0), 0.0)
    if projected <= 0.0:
        return ""
    symbol = str(context.derived.get("cost_currency_symbol", "")).strip() or "$"
    amount = _round_money(projected)
    confidence = str(context.derived.get("cost_confidence", "estimated"))
    estimate_suffix = " (estimate)" if confidence != "exact" else ""
    return f"{symbol}{amount}/day projected extra cost risk{estimate_suffix}"


def pre_trigger_eval(context):
    """Compute baseline-aware anomaly features for trigger expressions."""
    cfg = getattr(context, "config", {}) or {}
    event = getattr(context, "event", None)
    reading = getattr(event, "reading", None)

    context.derived["min_quality"] = as_float(cfg.get("min_quality", 0.8), 0.8)
    context.derived["overdraw_threshold_percent"] = as_float(
        cfg.get("overdraw_threshold_percent", 30.0),
        30.0,
    )
    context.derived["spike_ratio_threshold"] = as_float(
        cfg.get("spike_ratio_threshold", 1.5),
        1.5,
    )
    context.derived["sustained_ratio_threshold"] = as_float(
        cfg.get("sustained_ratio_threshold", 0.7),
        0.7,
    )
    context.derived["volatility_threshold_percent"] = as_float(
        cfg.get("volatility_threshold_percent", 20.0),
        20.0,
    )
    context.derived["history_window"] = max(
        3,
        as_int(cfg.get("history_window", 10), 10),
    )
    context.derived["persistence_window"] = max(
        3,
        as_int(cfg.get("persistence_window", 6), 6),
    )
    context.derived["dangerous_overcurrent_threshold"] = as_float(
        cfg.get("dangerous_overcurrent_threshold", 20.0),
        20.0,
    )

    context.derived["baseline_24h"] = 0.0
    context.derived["baseline_valid"] = 0
    context.derived["time_of_week_baseline"] = 0.0
    context.derived["time_of_week_baseline_usable"] = 0
    context.derived["time_of_week_covered_weeks"] = 0
    context.derived["time_of_week_deviation_percent"] = 0.0
    context.derived["context_aware_suppression"] = 0
    context.derived["deviation_percent"] = 0.0
    context.derived["spike_ratio"] = 0.0
    context.derived["sustained_high_ratio"] = 0.0
    context.derived["sustained_high_count"] = 0
    context.derived["recent_volatility_percent"] = 0.0
    context.derived["delta_amps"] = 0.0
    context.derived["line_voltage_used"] = 0.0
    context.derived["power_factor_used"] = 0.0
    context.derived["estimated_kw_delta"] = 0.0
    context.derived["observed_window_hours"] = 0.0
    context.derived["observed_extra_cost_window"] = 0.0
    context.derived["projected_extra_cost_daily"] = 0.0
    context.derived["cost_currency_symbol"] = _resolve_currency(context)
    context.derived["cost_confidence"] = "estimated"

    if reading is None:
        return context

    sensor_id = str(getattr(reading, "sensor_id", "")).strip()
    current_value = as_float(getattr(reading, "value", 0.0), 0.0)
    history_window = context.derived["history_window"]
    persistence_window = context.derived["persistence_window"]

    baseline = context.history.avg_hours(sensor_id, 24)
    baseline_24h = as_float(baseline, 0.0) if baseline is not None else 0.0
    baseline_valid = 1 if baseline_24h > 0.0 else 0

    context.derived["baseline_24h"] = baseline_24h
    context.derived["baseline_valid"] = baseline_valid

    tow_baseline = context.history.same_weekday_hour_baseline(
        sensor_id,
        lookback_weeks=as_int(cfg.get("time_of_week_lookback_weeks", 8), 8),
        min_weeks=as_int(cfg.get("time_of_week_min_weeks", 3), 3),
    )
    if isinstance(tow_baseline, dict) and tow_baseline.get("usable"):
        tow_avg = as_float(tow_baseline.get("avg_value"), 0.0)
        context.derived["time_of_week_baseline"] = tow_avg
        context.derived["time_of_week_baseline_usable"] = 1
        context.derived["time_of_week_covered_weeks"] = as_int(
            tow_baseline.get("covered_weeks", 0),
            0,
        )
        if tow_avg > 0.0:
            tow_deviation = ((current_value - tow_avg) / tow_avg) * 100.0
            context.derived["time_of_week_deviation_percent"] = tow_deviation
            tolerance_percent = as_float(
                cfg.get("time_of_week_suppression_tolerance_percent", 10.0),
                10.0,
            )
            if tow_deviation <= tolerance_percent:
                context.derived["context_aware_suppression"] = 1

    if baseline_valid == 1:
        context.derived["deviation_percent"] = (
            (current_value - baseline_24h) / baseline_24h
        ) * 100.0

    history_rows = context.history.fetch_history(sensor_id, limit=history_window)
    values = [
        as_float(item.get("value", 0.0), 0.0)
        for item in history_rows
        if isinstance(item, dict)
    ]

    if values:
        last_value = values[0]
        if last_value > 0.0:
            context.derived["spike_ratio"] = current_value / last_value

        if baseline_valid == 1:
            volatility = _stddev(values)
            context.derived["recent_volatility_percent"] = (
                volatility / baseline_24h
            ) * 100.0

            sustained_threshold = baseline_24h * (
                1.0 + (context.derived["overdraw_threshold_percent"] / 100.0)
            )
            recent_values = values[:persistence_window]
            if recent_values:
                sustained_count = sum(
                    1 for v in recent_values if v >= sustained_threshold
                )
                context.derived["sustained_high_count"] = sustained_count
                context.derived["sustained_high_ratio"] = sustained_count / len(
                    recent_values
                )

    # Deterministic cost estimator (P3-R6):
    # keep both observed window and projected /day run-rate values.
    delta_amps = 0.0
    if baseline_valid == 1 and current_value > baseline_24h:
        delta_amps = current_value - baseline_24h
    context.derived["delta_amps"] = delta_amps

    tariff_per_kwh, tariff_is_explicit = _resolve_tariff(context)
    line_voltage, voltage_confidence = _resolve_line_voltage(context)
    power_factor = _resolve_power_factor(context)

    context.derived["line_voltage_used"] = line_voltage
    context.derived["power_factor_used"] = power_factor

    confidence = (
        "exact" if tariff_is_explicit and voltage_confidence == "exact" else "estimated"
    )
    context.derived["cost_confidence"] = confidence

    if delta_amps <= 0.0 or tariff_per_kwh <= 0.0:
        return context

    kw_delta = (delta_amps * line_voltage * power_factor) / 1000.0
    context.derived["estimated_kw_delta"] = kw_delta

    observed_hours = 0.0
    history_rows = context.history.fetch_history(
        sensor_id,
        limit=max(2, persistence_window),
    )
    timestamps = [
        as_int(item.get("timestamp", 0), 0)
        for item in history_rows
        if isinstance(item, dict)
    ]
    if len(timestamps) >= 2:
        span_ms = max(timestamps) - min(timestamps)
        if span_ms > 0:
            observed_hours = span_ms / 3_600_000.0
    if observed_hours <= 0.0:
        observed_minutes = max(5, as_int(cfg.get("observed_window_minutes", 10), 10))
        observed_hours = observed_minutes / 60.0
    context.derived["observed_window_hours"] = observed_hours

    observed_kwh = kw_delta * observed_hours
    observed_cost = observed_kwh * tariff_per_kwh
    context.derived["observed_extra_cost_window"] = observed_cost

    projected_daily = kw_delta * 24.0 * tariff_per_kwh
    context.derived["projected_extra_cost_daily"] = projected_daily

    return context


def post_reasoning(result, context):
    """Compose SMS-first operator message with deterministic local timestamp."""
    diagnosis = _one_sentence(result.text)
    trigger_name = str(getattr(context, "trigger_name", "") or "")
    hhmm = _format_event_time(context)
    # Per approved scope, hook uses risk framing only.
    anchor = _cost_anchor(context)
    result.text = _compose_sms_first(trigger_name, hhmm, diagnosis, anchor=anchor)
    return result
