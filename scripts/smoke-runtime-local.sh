#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CONFIG_FILE="${1:-ori.local.yaml}"
RUN_SECONDS="${2:-8}"
LOG_FILE="${3:-ori-local.log}"
DB_FILE="${4:-ori_local_smoke.db}"

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "❌ Config file not found: $CONFIG_FILE"
  exit 1
fi

if [[ ! -d ".venv" ]]; then
  echo "❌ .venv not found. Create/activate your virtual env first."
  exit 1
fi

# shellcheck disable=SC1091
source .venv/bin/activate
export ORI_AUTOLOAD_DOTENV="${ORI_AUTOLOAD_DOTENV:-true}"

rm -f "$LOG_FILE" "$DB_FILE"

echo "▶ Running runtime smoke test"
echo "  config:   $CONFIG_FILE"
echo "  duration: ${RUN_SECONDS}s"
echo "  log:      $LOG_FILE"

python -m ori.runtime --config "$CONFIG_FILE" >"$LOG_FILE" 2>&1 &
RUNTIME_PID=$!

sleep "$RUN_SECONDS"
kill -INT "$RUNTIME_PID" 2>/dev/null || true
wait "$RUNTIME_PID" || true

echo
echo "▶ Key runtime lines"
grep -E "config loaded|local SLM enabled|event loop ready|shutdown initiated|shutdown complete|reasoning pipeline failed" "$LOG_FILE" || true

if grep -q "reasoning pipeline failed" "$LOG_FILE"; then
  echo
  echo "❌ Smoke test failed: reasoning pipeline error detected"
  exit 2
fi

required=(
  "config loaded"
  "local SLM enabled"
  "event loop ready"
  "shutdown initiated"
)

missing=0
for line in "${required[@]}"; do
  if ! grep -q "$line" "$LOG_FILE"; then
    echo "❌ Missing expected log line: $line"
    missing=1
  fi
done

if [[ "$missing" -ne 0 ]]; then
  echo
  echo "❌ Smoke test failed: missing required startup/shutdown markers"
  exit 3
fi

if ! grep -q "shutdown complete" "$LOG_FILE"; then
  echo "⚠️  shutdown complete marker not seen (short run). This is non-fatal for smoke."
fi

echo
echo "✅ Smoke test passed"
