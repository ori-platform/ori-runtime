#!/usr/bin/env bash
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if command -v mypy >/dev/null 2>&1; then
  MYPY=(mypy)
elif [[ -x ".venv/bin/mypy" ]]; then
  MYPY=(.venv/bin/mypy)
else
  MYPY=(python -m mypy)
fi

"${MYPY[@]}" \
  ori/network/events.py \
  ori/security/gateway_messages.py \
  ori/security/remote_commands.py \
  ori/policy/device_policy.py \
  ori/policy/remote_fetch.py \
  ori/reasoning/escalation_policy.py \
  ori/reasoning/capability_posture.py \
  ori/gateway/mqtt_security.py \
  ori/gateway/reasoning.py \
  ori/gateway/export.py \
  ori/gateway/heartbeat.py \
  ori/gateway/node_heartbeat.py
