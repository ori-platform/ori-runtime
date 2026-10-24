# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Intervals, timeouts and limits the runtime's loops and services read."""

WATCHDOG_DEVICE = "/dev/watchdog"


WATCHDOG_PING_INTERVAL = 10  # seconds — kernel expects a ping at least this often


WATCHDOG_TIMEOUT = 60  # seconds — kernel reboots if no ping within this window


EXTERNAL_WATCHDOG_GPIO = 17  # BCM pin for optional external watchdog heartbeat


EXTERNAL_WATCHDOG_PING_S = 30  # heartbeat interval for external watchdog devices


TIER_D_DRAIN_TIMEOUT = 5.0  # seconds — wait for in-flight Tier D tasks on shutdown


# An action record waiting this long means the store is not answering; health
# degrades rather than report a stalled record queue as healthy.
RECORD_STALL_MS = 30_000


EVIDENCE_SHUTDOWN_FLUSH_TIMEOUT_S = 5.0


ALERT_OUTBOX_RETRY_INTERVAL_S = 30.0


ALERT_OUTBOX_BATCH_SIZE = 50


ALERT_OUTBOX_MAX_ATTEMPTS_NON_TIER_D = 10


ALERT_OUTBOX_TIER_D_CRITICAL_THRESHOLD = 3


CAPABILITY_POSTURE_UPDATE_INTERVAL_S = 30.0


DEVICE_POLICY_REFRESH_DEFAULT_S = 21600.0


DEVICE_POLICY_TRANSIENT_AUDIT_SUPPRESS_MS = 900_000


STALE_SENSOR_MIN_CHECK_INTERVAL_S = 1.0


# A sensor failing every poll logs one WARNING per this interval, the rest DEBUG.
READ_FAILURE_LOG_INTERVAL_S = 60.0


STALE_SENSOR_MAX_CHECK_INTERVAL_S = 30.0


HEALTH_SOCKET_DEFAULT_PATH = "/run/ori/health.sock"
