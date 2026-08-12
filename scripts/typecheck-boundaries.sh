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
  ori/reasoning/rule_engine.py \
  ori/skills/hooks_api.py \
  ori/skills/loader.py \
  ori/integration/rule_evaluation.py \
  ori/security/gateway_messages.py \
  ori/security/webhook_signatures.py \
  ori/security/remote_commands.py \
  ori/security/release_bundles.py \
  ori/security/aws_kms_release_signer.py \
  ori/installer/linux.py \
  ori/installer/cli.py \
  ori/network/sms_webhook.py \
  ori/actions/sms.py \
  ori/policy/device_policy.py \
  ori/policy/remote_fetch.py \
  ori/reasoning/escalation_policy.py \
  ori/reasoning/capability_posture.py \
  ori/gateway/mqtt_security.py \
  ori/gateway/reasoning.py \
  ori/gateway/export.py \
  ori/gateway/heartbeat.py \
  ori/gateway/node_heartbeat.py \
  ori/firmware_mqtt_operator.py
