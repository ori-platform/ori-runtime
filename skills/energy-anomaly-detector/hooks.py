# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Hooks for the bundled energy-anomaly-detector skill."""


def _as_float(value, default):
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _as_int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


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


def pre_trigger_eval(context):
    """Compute baseline-aware anomaly features for trigger expressions."""
    cfg = getattr(context, "config", {}) or {}
    event = getattr(context, "event", None)
    reading = getattr(event, "reading", None)

    context.derived["min_quality"] = _as_float(cfg.get("min_quality", 0.8), 0.8)
    context.derived["overdraw_threshold_percent"] = _as_float(
        cfg.get("overdraw_threshold_percent", 30.0),
        30.0,
    )
    context.derived["spike_ratio_threshold"] = _as_float(
        cfg.get("spike_ratio_threshold", 1.5),
        1.5,
    )
    context.derived["sustained_ratio_threshold"] = _as_float(
        cfg.get("sustained_ratio_threshold", 0.7),
        0.7,
    )
    context.derived["volatility_threshold_percent"] = _as_float(
        cfg.get("volatility_threshold_percent", 20.0),
        20.0,
    )
    context.derived["history_window"] = max(
        3,
        _as_int(cfg.get("history_window", 10), 10),
    )
    context.derived["persistence_window"] = max(
        3,
        _as_int(cfg.get("persistence_window", 6), 6),
    )
    context.derived["dangerous_overcurrent_threshold"] = _as_float(
        cfg.get("dangerous_overcurrent_threshold", 20.0),
        20.0,
    )

    context.derived["baseline_24h"] = 0.0
    context.derived["baseline_valid"] = 0
    context.derived["deviation_percent"] = 0.0
    context.derived["spike_ratio"] = 0.0
    context.derived["sustained_high_ratio"] = 0.0
    context.derived["sustained_high_count"] = 0
    context.derived["recent_volatility_percent"] = 0.0

    if reading is None:
        return context

    sensor_id = str(getattr(reading, "sensor_id", "")).strip()
    current_value = _as_float(getattr(reading, "value", 0.0), 0.0)
    history_window = context.derived["history_window"]
    persistence_window = context.derived["persistence_window"]

    baseline = context.history.avg_hours(sensor_id, 24)
    baseline_24h = _as_float(baseline, 0.0) if baseline is not None else 0.0
    baseline_valid = 1 if baseline_24h > 0.0 else 0

    context.derived["baseline_24h"] = baseline_24h
    context.derived["baseline_valid"] = baseline_valid

    if baseline_valid == 1:
        context.derived["deviation_percent"] = (
            (current_value - baseline_24h) / baseline_24h
        ) * 100.0

    history_rows = context.history.fetch_history(sensor_id, limit=history_window)
    values = [
        _as_float(item.get("value", 0.0), 0.0)
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

    return context


def post_reasoning(result, context):
    """Append concise baseline context to operator-facing explanation."""
    baseline = _as_float(context.derived.get("baseline_24h", 0.0), 0.0)
    deviation = _as_float(context.derived.get("deviation_percent", 0.0), 0.0)
    if baseline > 0.0:
        result.text = (
            f"{result.text}\n"
            f"Baseline(24h): {baseline:.2f}A | Deviation: {deviation:.1f}%"
        )
    return result
