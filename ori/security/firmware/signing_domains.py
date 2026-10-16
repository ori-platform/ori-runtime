# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The signing domains of the runtime command key, firmware-commands/v2.

Every signature the runtime command key makes covers ``domain || NUL ||
object bytes``; nothing is signed over the object bytes alone. The runtime
signs for a device only while its accepted manifest declares, by
``runtime_key_domains``, that it verifies in these domains
(firmware-telemetry/v2, Runtime Key Domains).
"""

from __future__ import annotations

from typing import Any

COMMAND_DOMAIN = b"ori.firmware_command.v2"
LIVENESS_DOMAIN = b"ori.firmware_liveness.v2"
RUNTIME_KEY_DOMAINS_FIELD = "runtime_key_domains"
RUNTIME_KEY_DOMAINS_VALUE = "firmware-commands/v2"


def command_preimage(command: bytes) -> bytes:
    """The bytes a command signature covers."""
    return COMMAND_DOMAIN + b"\x00" + command


def liveness_preimage(liveness: bytes) -> bytes:
    """The bytes a liveness signature covers, at ``v`` 1 and ``v`` 2 alike."""
    return LIVENESS_DOMAIN + b"\x00" + liveness


def declares_signing_domains(manifest: Any) -> bool:
    """The manifest declares the domains: the exact string, compared whole."""
    if not isinstance(manifest, dict):
        return False
    value = manifest.get(RUNTIME_KEY_DOMAINS_FIELD)
    return type(value) is str and value == RUNTIME_KEY_DOMAINS_VALUE
