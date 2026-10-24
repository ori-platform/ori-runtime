# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Alert and notification text, alert identity, and the keys alert policy counts by."""

import datetime as dt
import hashlib
import json
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ori.actions.alert_delivery import AlertSendReceipt, OutboundAlert
from ori.config import Config
from ori.reasoning.elevator import SkillContext
from ori.utils.time_utils import now_ms

SETUP_NOTIFICATION_MAX_CHARS = 320


# ── Helpers ───────────────────────────────────────────────────────────────────


def _cap_sms_message(message: str, limit: int = 160) -> str:
    compact = " ".join(message.split())
    if len(compact) <= limit:
        return compact
    return compact[: max(limit - 3, 0)].rstrip() + "..."


def message_from_context(
    ctx: SkillContext,
    fallback: str,
    channel: str = "sms",
) -> str:
    """Build a channel-aware alert message string from a SkillContext."""
    event_ctx = (
        ctx.event.context if ctx.event and isinstance(ctx.event.context, dict) else {}
    )
    channel_key = str(channel or "").strip().lower()

    msg = ""
    channel_messages = event_ctx.get("channel_messages")
    if isinstance(channel_messages, dict):
        raw_channel = channel_messages.get(channel_key) or channel_messages.get(
            "default"
        )
        if isinstance(raw_channel, str) and raw_channel.strip():
            msg = raw_channel.strip()
    if not msg:
        raw_operator = event_ctx.get("operator_message")
        if isinstance(raw_operator, str) and raw_operator.strip():
            msg = raw_operator.strip()

    # Fallback for raw sensor alerts that did not pass through a skill composer.
    if not msg and ctx.event and ctx.event.reading:
        r = ctx.event.reading
        if channel_key == "whatsapp":
            msg = (
                f"[{ctx.event.device_id}] {r.sensor_id} ({r.sensor_type})\n"
                f"Value: {r.value} {r.unit}"
            )
        else:
            msg = f"[{ctx.event.device_id}] {r.sensor_id} ({r.sensor_type}): {r.value} {r.unit}"

    if not msg:
        msg = str(fallback)

    if channel_key == "sms":
        return _cap_sms_message(msg)
    return msg


def resolve_setup_notification_channels(
    raw_channels: Any,
    primary_alert_channel: str,
) -> list[str]:
    if isinstance(raw_channels, str):
        candidates = [raw_channels]
    elif isinstance(raw_channels, list):
        candidates = raw_channels
    else:
        candidates = ["primary"]

    primary = str(primary_alert_channel or "sms").strip().lower()
    if primary not in {"sms", "whatsapp"}:
        primary = "sms"

    resolved: list[str] = []
    for raw in candidates:
        channel = str(raw).strip().lower()
        if channel == "primary":
            channel = primary
        if channel in {"sms", "whatsapp"} and channel not in resolved:
            resolved.append(channel)
    return resolved


def setup_success_message(
    *,
    config: Config,
    connected_sensor_count: int,
    active_trigger_count: int,
) -> str:
    """Describe only the notification posture established at startup.

    The safety disclaimer is fixed text and must never be removed by a generic
    tail truncation.  ``device.location`` is operator-controlled and unbounded
    by the config schema, so only that field is compacted and shortened to fit.
    """
    location = " ".join(str(config.device.location or "").split()) or "site"
    sensor_label = "sensor" if connected_sensor_count == 1 else "sensors"
    rule_label = "rule" if active_trigger_count == 1 else "rules"
    prefix = "Ori is online at "
    suffix = (
        f": {connected_sensor_count} {sensor_label} connected and "
        f"{active_trigger_count} {rule_label} active. "
        "Ori will notify you when it detects a configured risk. "
        "No safety cutoff is commissioned, so Ori can warn but cannot intervene."
    )
    location_budget = max(
        SETUP_NOTIFICATION_MAX_CHARS - len(prefix) - len(suffix),
        0,
    )
    if len(location) > location_budget:
        if location_budget <= 3:
            location = "." * location_budget
        else:
            location = location[: location_budget - 3].rstrip() + "..."
    return prefix + location + suffix


def count_active_triggers(
    *,
    configured_sensors: list[Any],
    connected_sensor_ids: set[str],
    loaded_skills: list[Any],
) -> int:
    """Count registered rules with at least one connected declared input.

    A skill's triggers are registered for every type in ``sensors_required``.
    Matching more than one connected type therefore makes a trigger reachable
    through more than one subscription, but it remains one rule and is counted
    once.  Skills without a declared type are excluded conservatively: a
    wildcard subscription is not a declared operator-facing input contract.
    """
    connected_types: set[str] = set()
    for sensor in configured_sensors:
        sensor_id = str(getattr(sensor, "id", ""))
        sensor_type = getattr(sensor, "type", "")
        if (
            sensor_id in connected_sensor_ids
            and isinstance(sensor_type, str)
            and sensor_type
        ):
            connected_types.add(sensor_type)

    active_count = 0
    for skill in loaded_skills:
        required = getattr(skill, "sensors_required", [])
        if not isinstance(required, list):
            continue
        declared_types: set[str] = set()
        for item in required:
            if not isinstance(item, dict):
                continue
            sensor_type = item.get("type")
            if isinstance(sensor_type, str) and sensor_type:
                declared_types.add(sensor_type)
        if not connected_types.intersection(declared_types):
            continue
        triggers = getattr(skill, "triggers", [])
        if isinstance(triggers, list):
            active_count += len(triggers)
    return active_count


def resolve_skill_identity(ctx: SkillContext) -> tuple[str, bool]:
    """The skill's name and whether the loader marked it first-party.

    `first_party` is set by the loader from the packaged roots and never read
    from `skill.yaml`, so a skill cannot claim it. Anything that cannot be
    resolved reads as community, which resolves to no class.
    """
    skill = getattr(ctx, "skill", None) if ctx else None
    name = getattr(skill, "name", "") if skill is not None else ""
    first_party = bool(getattr(skill, "first_party", False))
    return (str(name or "").strip(), first_party)


def resolve_trigger_name(ctx: SkillContext) -> str:
    if ctx and isinstance(getattr(ctx, "trigger_name", ""), str):
        trigger_name = ctx.trigger_name.strip()
        if trigger_name:
            return trigger_name
    if ctx and ctx.event and isinstance(getattr(ctx.event, "sensor_id", ""), str):
        return ctx.event.sensor_id
    return ""


def resolve_original_ts(ctx: SkillContext) -> int:
    if ctx and ctx.event:
        try:
            return int(ctx.event.timestamp)
        except Exception:
            pass  # an unreadable timestamp falls back to now
    return now_ms()


def resolve_action_declared_tier(ctx: SkillContext, action_name: str) -> str:
    """Resolve declared tier for an action from skill capability metadata."""
    if ctx and hasattr(ctx, "skill") and hasattr(ctx.skill, "actions"):
        available = None
        if isinstance(ctx.skill.actions, dict):
            available = ctx.skill.actions.get("available")
        if isinstance(available, list):
            for item in available:
                if not isinstance(item, dict):
                    continue
                if str(item.get("name", "")) != action_name:
                    continue
                tier = str(item.get("tier", "")).upper().strip()
                if tier in {"A", "B", "C", "D"}:
                    return tier
    return "A"


def build_alert_id(
    *,
    channel: str,
    recipient: str,
    alert: OutboundAlert,
    action_tier: str,
    trigger_name: str,
    original_ts: int,
) -> str:
    variables = json.dumps(
        list(alert.template_variables), separators=(",", ":"), ensure_ascii=False
    )
    raw = (
        f"{channel}|{recipient}|{action_tier}|{trigger_name}|{original_ts}|"
        f"{alert.intent.value}|{variables}|{alert.sms_body}"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def format_alert_timestamp(timestamp_ms: int, timezone_name: str) -> str:
    try:
        timezone: dt.tzinfo = ZoneInfo(str(timezone_name or "UTC"))
    except ZoneInfoNotFoundError:
        timezone = dt.UTC
    return dt.datetime.fromtimestamp(
        max(0, int(timestamp_ms)) / 1000,
        tz=timezone,
    ).strftime("%Y-%m-%d %H:%M %Z")


def coerce_alert_send_receipt(
    value: object,
    *,
    fallback_channel: str,
) -> AlertSendReceipt:
    """Keep legacy test doubles safe while production senders use receipts."""

    if isinstance(value, AlertSendReceipt):
        return value
    if value is True:
        return AlertSendReceipt.accepted_without_provider_receipt(
            channel=fallback_channel
        )
    return AlertSendReceipt.refused(channel=fallback_channel, error="sender_refused")


def preference_disabled_key(
    channel: str, alert_class: str | None, timestamp_ms: int
) -> str:
    month = dt.datetime.fromtimestamp(
        max(0, int(timestamp_ms)) / 1000,
        tz=dt.UTC,
    ).strftime("%Y-%m")
    normalized = str(channel or "").strip().lower() or "unknown"
    return f"disabled:{normalized}:{alert_class or 'unclassified'}:{month}"


def alert_policy_count_key(channel: str, timestamp_ms: int) -> str:
    month = dt.datetime.fromtimestamp(
        max(0, int(timestamp_ms)) / 1000,
        tz=dt.UTC,
    ).strftime("%Y-%m")
    normalized = str(channel or "").strip().lower() or "unknown"
    return f"external_alert_count:{normalized}:{month}"
