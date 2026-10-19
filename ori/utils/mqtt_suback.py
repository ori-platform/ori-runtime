# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Reading a broker's SUBACK, shared by every MQTT client that subscribes."""

from __future__ import annotations

from typing import Any

# The SUBACK codes that grant a subscription; every other code refuses it.
MQTT_GRANTED_QOS = (0, 1, 2)


def subscription_refusal(granted: Any) -> str | None:
    """Why the broker's answer to one SUBSCRIBE is not a subscription, or None.

    aiomqtt returns the SUBACK codes and raises on none of them: 0 to 2 is the
    QoS the broker granted, and 0x80 and above is a refusal. An answer that
    carries no code, or one that cannot be read, grants nothing.

    A grant is the broker's word and no more: one that grants the subscription
    and withholds delivery, as mosquitto's `acl_file` does, is not seen here.
    """
    codes = list(granted) if isinstance(granted, (list, tuple)) else [granted]
    if not codes:
        return "the SUBACK carried no code"
    for code in codes:
        value = getattr(code, "value", code)
        if isinstance(value, bool) or not isinstance(value, int):
            return f"unreadable SUBACK code {code!r}"
        if value not in MQTT_GRANTED_QOS:
            name = "" if code is value else f" {code}"
            return f"SUBACK {value:#04x}{name}"
    return None
