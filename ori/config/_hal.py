# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The ``hal`` section."""

import logging
from dataclasses import dataclass, field
from typing import Any

from ori.config._actions import _VALID_BCM_PINS
from ori.config._fields import ConfigValidationError

logger = logging.getLogger("ori.config")


@dataclass
class HalConfig:
    circuit_breaker: dict = field(default_factory=dict)
    external_watchdog: dict = field(default_factory=dict)
    status_signaling: dict = field(default_factory=dict)


def parse_hal(data: Any) -> HalConfig:
    """Parse the HAL block gracefully, enforcing safe defaults on failure."""
    default_cb = {
        "failure_threshold": 5,
        "recovery_timeout_s": 300,
        "success_threshold": 2,
    }
    default_external_watchdog = {
        "enabled": False,
        "gpio_pin": 17,
        "ping_interval_s": 30,
    }
    default_status_signaling = {
        "enabled": False,
        "power_led_pin": 17,
        "relay_led_pin": 27,
        "network_led_pin": 22,
        "health_led_pin": 23,
        "buzzer_pin": 24,
        "tick_ms": 100,
    }

    if not isinstance(data, dict):
        if data is not None:
            logger.warning(
                "[config] 'hal' config missing or not a dict. Falling back to default circuit breaker."
            )
        return HalConfig(
            circuit_breaker=default_cb,
            external_watchdog=default_external_watchdog,
            status_signaling=default_status_signaling,
        )

    cb_data = data.get("circuit_breaker")
    if not isinstance(cb_data, dict):
        if cb_data is not None:
            logger.warning(
                "[config] 'hal.circuit_breaker' missing or not a dict. Falling back to default circuit breaker."
            )
        cb_out = default_cb
    else:
        try:
            cb_out = {
                "failure_threshold": int(cb_data.get("failure_threshold", 5)),
                "recovery_timeout_s": int(cb_data.get("recovery_timeout_s", 300)),
                "success_threshold": int(cb_data.get("success_threshold", 2)),
            }
        except (ValueError, TypeError):
            logger.warning(
                "[config] 'hal.circuit_breaker' has invalid types. Falling back to default circuit breaker."
            )
            cb_out = default_cb
        else:
            if cb_out["failure_threshold"] < 1:
                raise ConfigValidationError(
                    "hal.circuit_breaker.failure_threshold must be >= 1."
                )
            if cb_out["recovery_timeout_s"] < 1:
                raise ConfigValidationError(
                    "hal.circuit_breaker.recovery_timeout_s must be >= 1."
                )
            if cb_out["success_threshold"] < 1:
                raise ConfigValidationError(
                    "hal.circuit_breaker.success_threshold must be >= 1."
                )

    ew_data = data.get("external_watchdog")
    if ew_data is None:
        ew_out = default_external_watchdog
    elif not isinstance(ew_data, dict):
        logger.warning(
            "[config] 'hal.external_watchdog' is not a mapping. Falling back to defaults."
        )
        ew_out = default_external_watchdog
    else:
        try:
            ew_out = {
                "enabled": bool(ew_data.get("enabled", False)),
                "gpio_pin": int(ew_data.get("gpio_pin", 17)),
                "ping_interval_s": int(ew_data.get("ping_interval_s", 30)),
            }
        except (TypeError, ValueError):
            logger.warning(
                "[config] 'hal.external_watchdog' has invalid types. Falling back to defaults."
            )
            ew_out = default_external_watchdog

    if ew_out["gpio_pin"] not in _VALID_BCM_PINS:
        raise ConfigValidationError(
            f"hal.external_watchdog.gpio_pin={ew_out['gpio_pin']} is outside the "
            "valid BCM range (2-27) for Raspberry Pi 4."
        )
    if ew_out["ping_interval_s"] < 1:
        raise ConfigValidationError(
            "hal.external_watchdog.ping_interval_s must be >= 1."
        )

    ss_data = data.get("status_signaling")
    if ss_data is None:
        ss_out = default_status_signaling
    elif not isinstance(ss_data, dict):
        logger.warning(
            "[config] 'hal.status_signaling' is not a mapping. Falling back to defaults."
        )
        ss_out = default_status_signaling
    else:
        try:
            ss_out = {
                "enabled": bool(ss_data.get("enabled", False)),
                "power_led_pin": int(ss_data.get("power_led_pin", 17)),
                "relay_led_pin": int(ss_data.get("relay_led_pin", 27)),
                "network_led_pin": int(ss_data.get("network_led_pin", 22)),
                "health_led_pin": int(ss_data.get("health_led_pin", 23)),
                "buzzer_pin": int(ss_data.get("buzzer_pin", 24)),
                "tick_ms": int(ss_data.get("tick_ms", 100)),
            }
        except (TypeError, ValueError):
            logger.warning(
                "[config] 'hal.status_signaling' has invalid types. Falling back to defaults."
            )
            ss_out = default_status_signaling

    for key in (
        "power_led_pin",
        "relay_led_pin",
        "network_led_pin",
        "health_led_pin",
        "buzzer_pin",
    ):
        pin = int(ss_out[key])
        if pin not in _VALID_BCM_PINS:
            raise ConfigValidationError(
                f"hal.status_signaling.{key}={pin} is outside the valid BCM range (2-27) for Raspberry Pi 4."
            )

    ss_pins = [
        int(ss_out["power_led_pin"]),
        int(ss_out["relay_led_pin"]),
        int(ss_out["network_led_pin"]),
        int(ss_out["health_led_pin"]),
        int(ss_out["buzzer_pin"]),
    ]
    if len(set(ss_pins)) != len(ss_pins):
        raise ConfigValidationError(
            "hal.status_signaling pins must be unique (no duplicate BCM pin assignments)."
        )
    if int(ss_out["tick_ms"]) < 50:
        raise ConfigValidationError("hal.status_signaling.tick_ms must be >= 50.")

    if bool(ss_out.get("enabled")) and bool(ew_out.get("enabled")):
        ew_pin = int(ew_out["gpio_pin"])
        for key in (
            "power_led_pin",
            "relay_led_pin",
            "network_led_pin",
            "health_led_pin",
            "buzzer_pin",
        ):
            if int(ss_out[key]) == ew_pin:
                raise ConfigValidationError(
                    f"hal.status_signaling.{key} conflicts with hal.external_watchdog.gpio_pin."
                )

    return HalConfig(
        circuit_breaker=cb_out,
        external_watchdog=ew_out,
        status_signaling=ss_out,
    )
