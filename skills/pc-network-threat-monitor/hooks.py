# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Hooks for pc-network-threat-monitor skill."""


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


def _as_int_set(values):
    if not isinstance(values, list):
        return set()
    output = set()
    for value in values:
        try:
            output.add(int(value))
        except (TypeError, ValueError):
            continue
    return output


def _as_lower_str_set(values):
    if not isinstance(values, list):
        return set()
    output = set()
    for value in values:
        text = str(value).strip().lower()
        if text:
            output.add(text)
    return output


def _state_get_float(context, key, default=0.0):
    return _as_float(context.state.get(key), default)


def _state_get_int(context, key, default=0):
    return _as_int(context.state.get(key), default)


def _state_set(context, key, value):
    context.state.set(key, str(value))


def pre_trigger_eval(context):
    """Compute derived cyber anomaly metrics from current reading + state."""
    cfg = getattr(context, "config", {}) or {}
    min_quality = _as_float(cfg.get("min_quality", 0.8), 0.8)
    warmup_polls = max(0, _as_int(cfg.get("baseline_warmup_polls", 5), 5))
    correlation_window_ms = (
        max(1, _as_int(cfg.get("correlation_window_seconds", 600), 600)) * 1000
    )
    listener_delta_threshold = _as_float(cfg.get("listener_delta_threshold", 1), 1)
    established_delta_threshold = _as_float(
        cfg.get("established_delta_threshold", 20),
        20,
    )
    user_delta_threshold = _as_float(cfg.get("user_delta_threshold", 1), 1)

    known_ports = _as_int_set(cfg.get("known_listener_ports", []))
    known_users = _as_lower_str_set(cfg.get("known_terminal_users", []))

    context.derived["min_quality"] = min_quality
    context.derived["listener_delta_threshold"] = listener_delta_threshold
    context.derived["established_delta_threshold"] = established_delta_threshold
    context.derived["established_ratio_threshold"] = _as_float(
        cfg.get("established_ratio_threshold", 2.5),
        2.5,
    )
    context.derived["user_delta_threshold"] = user_delta_threshold
    context.derived["tier_c_established_ratio"] = _as_float(
        cfg.get("tier_c_established_ratio", 4.0),
        4.0,
    )
    context.derived["tier_c_user_delta"] = _as_float(cfg.get("tier_c_user_delta", 1), 1)

    context.derived["listener_delta"] = 0.0
    context.derived["established_delta"] = 0.0
    context.derived["established_ratio_24h"] = 0.0
    context.derived["user_delta"] = 0.0

    event = getattr(context, "event", None)
    reading = getattr(event, "reading", None)
    if reading is None:
        context.derived["warmup_complete"] = 0
        context.derived["recent_listener_spike"] = 0
        context.derived["recent_user_spike"] = 0
        return

    now_ts = _as_int(getattr(context, "timestamp", 0), 0)
    poll_count = _state_get_int(context, "poll_count", 0) + 1
    _state_set(context, "poll_count", poll_count)
    warmup_complete = 1 if poll_count > warmup_polls else 0
    context.derived["warmup_complete"] = warmup_complete

    sensor_type = str(getattr(reading, "sensor_type", "")).strip()
    current_value = _as_float(getattr(reading, "value", 0.0), 0.0)
    quality = _as_float(getattr(reading, "quality", 0.0), 0.0)

    if sensor_type == "net_listening_sockets":
        ports = []
        metadata = getattr(reading, "metadata", {}) or {}
        for port in metadata.get("listener_ports", []):
            try:
                ports.append(int(port))
            except (TypeError, ValueError):
                continue

        adjusted_listeners = current_value
        if ports:
            adjusted_listeners = float(sum(1 for p in ports if p not in known_ports))

        prev = _state_get_float(
            context,
            "last_net_listening_sockets",
            adjusted_listeners,
        )
        delta = max(0.0, adjusted_listeners - prev) if warmup_complete else 0.0

        context.derived["net_listening_sockets"] = adjusted_listeners
        context.derived["listener_delta"] = delta
        _state_set(context, "last_net_listening_sockets", adjusted_listeners)

        if (
            warmup_complete
            and quality >= min_quality
            and delta >= listener_delta_threshold
        ):
            _state_set(context, "last_listener_spike_ts", now_ts)

    elif sensor_type == "net_established_connections":
        prev = _state_get_float(
            context, "last_net_established_connections", current_value
        )
        delta = max(0.0, current_value - prev) if warmup_complete else 0.0

        baseline = context.history.avg_hours(reading.sensor_id, 24)
        baseline_value = _as_float(baseline, 0.0)
        ratio = (
            current_value / baseline_value
            if baseline_value > 0.0
            else (current_value if current_value > 0 else 0.0)
        )

        context.derived["net_established_connections"] = current_value
        context.derived["established_delta"] = delta
        context.derived["established_ratio_24h"] = ratio
        _state_set(context, "last_net_established_connections", current_value)

        if (
            warmup_complete
            and quality >= min_quality
            and delta >= established_delta_threshold
        ):
            _state_set(context, "last_established_spike_ts", now_ts)

    elif sensor_type == "active_terminal_users":
        sessions = []
        metadata = getattr(reading, "metadata", {}) or {}
        if isinstance(metadata.get("sessions"), list):
            sessions = metadata["sessions"]

        adjusted_users = current_value
        if sessions:
            filtered = []
            for session in sessions:
                name = str(session.get("name", "")).strip().lower()
                if name and name not in known_users:
                    filtered.append(session)
            adjusted_users = float(len(filtered))

        prev = _state_get_float(context, "last_active_terminal_users", adjusted_users)
        delta = max(0.0, adjusted_users - prev) if warmup_complete else 0.0

        context.derived["active_terminal_users"] = adjusted_users
        context.derived["user_delta"] = delta
        _state_set(context, "last_active_terminal_users", adjusted_users)

        if warmup_complete and quality >= min_quality and delta >= user_delta_threshold:
            _state_set(context, "last_user_spike_ts", now_ts)

    listener_ts = _state_get_int(context, "last_listener_spike_ts", 0)
    user_ts = _state_get_int(context, "last_user_spike_ts", 0)
    context.derived["recent_listener_spike"] = (
        1 if listener_ts > 0 and (now_ts - listener_ts) <= correlation_window_ms else 0
    )
    context.derived["recent_user_spike"] = (
        1 if user_ts > 0 and (now_ts - user_ts) <= correlation_window_ms else 0
    )


def post_reasoning(result, ctx):
    """Add compact host context to operator-facing text."""
    event = getattr(ctx, "event", None)
    reading = getattr(event, "reading", None)
    if reading is None:
        return result

    metadata = getattr(reading, "metadata", {}) or {}
    parts = []
    if reading.sensor_type == "net_listening_sockets":
        ports = metadata.get("listener_ports", [])
        if isinstance(ports, list) and ports:
            parts.append(f"Listener ports: {', '.join(str(p) for p in ports[:6])}")

    if reading.sensor_type == "active_terminal_users":
        usernames = metadata.get("usernames", [])
        if isinstance(usernames, list) and usernames:
            parts.append(f"Active users: {', '.join(str(u) for u in usernames[:6])}")

    if parts:
        result.text = result.text + "\n" + "  |  ".join(parts)
    return result
