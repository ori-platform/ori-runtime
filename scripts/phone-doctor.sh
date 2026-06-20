#!/data/data/com.termux/files/usr/bin/bash
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

# Phone Starter readiness check wrapper for Android/Termux installs.
set -euo pipefail

CONFIG_PATH="${1:-ori.yaml}"

if command -v ori-phone-doctor >/dev/null 2>&1; then
  exec ori-phone-doctor --config "${CONFIG_PATH}"
fi

exec python -m ori.phone_doctor --config "${CONFIG_PATH}"
