# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Shared parsing for `termux-usb` output.

Termux is a supported development path — it is how someone runs the runtime on
their own phone — so its diagnostics have to be as truthful as any other.
"""

from __future__ import annotations

import json

# `termux-usb -l` names raw USB devices by path. Anything that is not a device
# path is prose: a permission error, a Termux:API prompt, a "none found" line.
_DEVICE_PATH_PREFIX = "/dev/"


def parse_termux_usb_output(output: str) -> list[str]:
    """Return the USB device paths in `termux-usb -l` output, and nothing else.

    The command usually emits a JSON array and older builds emit plain lines,
    so both are read. Neither form is trusted to contain only devices: it exits
    zero while printing a human message often enough that treating every line
    as a device path is how "termux-usb sees USB device(s)" came to be reported
    for output that said the opposite.

    Entries are therefore kept only when they look like a device path. An entry
    that does not is not a device, and reporting it as one sends an installer
    after a USB-serial bridge for a problem that is not there.
    """
    cleaned = output.strip()
    if not cleaned:
        return []

    if cleaned.startswith("[") and cleaned.endswith("]"):
        try:
            parsed = json.loads(cleaned)
        except json.JSONDecodeError:
            return []
        if not isinstance(parsed, list):
            return []
        candidates = [str(item).strip() for item in parsed]
    else:
        candidates = [line.strip() for line in cleaned.splitlines()]

    return [item for item in candidates if item.startswith(_DEVICE_PATH_PREFIX)]
