# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Ori Runtime — main entry point.

Wires every component built into a running system:

    runtime = OriRuntime(config_path="ori.yaml")
    asyncio.run(runtime.start())

Or via the CLI entry point::

    ori-runtime --config /path/to/ori.yaml

``OriRuntime`` is composed from one class per domain, each in a private module
under ``ori/runtime/``, over ``RuntimeCore``, which holds every attribute; the
module-level helpers live in private modules by concern. This module is the
runtime's interface: ``OriRuntime``, ``main``, and the functions and constants
other code reads from it. Everything else is private to the module that
defines it; ``tests/test_runtime_public_surface.py`` holds the set.
"""

from ori.runtime._constants import EVIDENCE_SHUTDOWN_FLUSH_TIMEOUT_S
from ori.runtime._device_io import adapter_connect_config
from ori.runtime._evidence_wiring import (
    EVIDENCE_POSTURE_AUTHORITY_KEYS_INCOMPLETE,
    EVIDENCE_POSTURE_AUTHORITY_KEYS_MISSING,
    EVIDENCE_POSTURE_AUTHORITY_KEYS_REFUSED,
    EVIDENCE_POSTURE_CUSTODY_UNCONFIGURED,
    EVIDENCE_POSTURE_SIGNING_UNAVAILABLE,
)
from ori.runtime._main import main
from ori.runtime._measurement_policy import (
    MEASUREMENT_REFUSALS_BEFORE_DEGRADED,
    MEASUREMENT_WINDOWS_TO_RECOVER,
    measurement_notice_stage_due,
)
from ori.runtime._runtime import OriRuntime

__all__ = [
    "EVIDENCE_POSTURE_AUTHORITY_KEYS_INCOMPLETE",
    "EVIDENCE_POSTURE_AUTHORITY_KEYS_MISSING",
    "EVIDENCE_POSTURE_AUTHORITY_KEYS_REFUSED",
    "EVIDENCE_POSTURE_CUSTODY_UNCONFIGURED",
    "EVIDENCE_POSTURE_SIGNING_UNAVAILABLE",
    "EVIDENCE_SHUTDOWN_FLUSH_TIMEOUT_S",
    "MEASUREMENT_REFUSALS_BEFORE_DEGRADED",
    "MEASUREMENT_WINDOWS_TO_RECOVER",
    "OriRuntime",
    "adapter_connect_config",
    "main",
    "measurement_notice_stage_due",
]
