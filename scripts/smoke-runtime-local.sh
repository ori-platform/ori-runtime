#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CONFIG_FILE="${1:-ori.local.yaml}"
RUN_SECONDS="${2:-8}"
LOG_FILE="${3:-ori-local.log}"
DB_FILE="${4:-ori_local_smoke.db}"
PRETTY_MODE="${ORI_PRETTY_LOGS:-auto}"

use_pretty=0
case "${PRETTY_MODE}" in
  1|true|TRUE|yes|YES|on|ON)
    use_pretty=1
    ;;
  auto|AUTO|"")
    if [[ -t 1 ]]; then
      use_pretty=1
    fi
    ;;
esac

if [[ "$use_pretty" -eq 1 ]]; then
  C_RESET=$'\033[0m'
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
  C_CYAN=$'\033[36m'
else
  C_RESET=""
  C_RED=""
  C_GREEN=""
  C_YELLOW=""
  C_BLUE=""
  C_CYAN=""
fi

print_color() {
  local color="$1"
  shift
  printf "%s%s%s\n" "$color" "$*" "$C_RESET"
}

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

print_color "$C_BLUE" "▶ Running runtime smoke test"
echo "  config:   $CONFIG_FILE"
echo "  duration: ${RUN_SECONDS}s"
echo "  log:      $LOG_FILE"
echo "  pretty:   ${PRETTY_MODE}"

python -m ori.runtime --config "$CONFIG_FILE" >"$LOG_FILE" 2>&1 &
RUNTIME_PID=$!

sleep "$RUN_SECONDS"
kill -INT "$RUNTIME_PID" 2>/dev/null || true
wait "$RUNTIME_PID" || true

echo
print_color "$C_BLUE" "▶ Key runtime lines"
key_lines="$(grep -E "config loaded|local SLM enabled|event loop ready|shutdown initiated|shutdown complete|reasoning pipeline failed| ERROR | WARNING " "$LOG_FILE" || true)"
if [[ -n "$key_lines" ]]; then
  while IFS= read -r line; do
    case "$line" in
      *"reasoning pipeline failed"*|*" ERROR "*)
        print_color "$C_RED" "$line"
        ;;
      *" WARNING "*)
        print_color "$C_YELLOW" "$line"
        ;;
      *"shutdown complete"*|*"event loop ready"*)
        print_color "$C_GREEN" "$line"
        ;;
      *"config loaded"*|*"local SLM enabled"*)
        print_color "$C_CYAN" "$line"
        ;;
      *)
        echo "$line"
        ;;
    esac
  done <<< "$key_lines"
else
  print_color "$C_YELLOW" "No key lines matched."
fi

if grep -q "reasoning pipeline failed" "$LOG_FILE"; then
  echo
  print_color "$C_RED" "❌ Smoke test failed: reasoning pipeline error detected"
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
    print_color "$C_RED" "❌ Missing expected log line: $line"
    missing=1
  fi
done

if [[ "$missing" -ne 0 ]]; then
  echo
  print_color "$C_RED" "❌ Smoke test failed: missing required startup/shutdown markers"
  exit 3
fi

if ! grep -q "shutdown complete" "$LOG_FILE"; then
  print_color "$C_YELLOW" "⚠️  shutdown complete marker not seen (short run). This is non-fatal for smoke."
fi

echo
print_color "$C_GREEN" "✅ Smoke test passed"
