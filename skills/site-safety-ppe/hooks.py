# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Hooks for site-safety-ppe skill."""


def _as_float(value, default):
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def pre_trigger_eval(context):
    """Expose sensor-specific score names and threshold config to rule context."""
    event = getattr(context, "event", None)
    reading = getattr(event, "reading", None)
    if reading is None:
        return

    sensor_type = str(getattr(reading, "sensor_type", "")).strip()
    if sensor_type in {"ppe_hardhat_violation_score", "ppe_vest_violation_score"}:
        context.derived[sensor_type] = _as_float(getattr(reading, "value", 0.0), 0.0)

    cfg = getattr(context, "config", {}) or {}
    context.derived["violation_score_threshold"] = _as_float(
        cfg.get("violation_score_threshold", 0.7), 0.7
    )
    context.derived["min_detection_quality"] = _as_float(
        cfg.get("min_detection_quality", 0.6), 0.6
    )


def post_reasoning(result, ctx):
    """Enrich alert text with zone and camera context from perception metadata."""
    if ctx.event and ctx.event.reading:
        meta = ctx.event.reading.metadata
        parts = []
        if meta.get("zone_id"):
            parts.append(f"Zone: {meta['zone_id']}")
        if meta.get("camera_id"):
            parts.append(f"Camera: {meta['camera_id']}")
        if meta.get("subject_id"):
            parts.append(f"Worker ref: {meta['subject_id']}")

        cfg = getattr(ctx, "config", {}) or {}
        score_t = _as_float(cfg.get("violation_score_threshold", 0.7), 0.7)
        quality_t = _as_float(cfg.get("min_detection_quality", 0.6), 0.6)
        parts.append(f"Gate: score>{score_t:.2f}, quality>{quality_t:.2f}")

        if parts:
            result.text = result.text + "\n" + "  |  ".join(parts)
    return result
