#!/usr/bin/env bash
# HoneyTrace emergency-off: stop responses FIRST, then roll back ONLY the
# changes HoneyTrace itself applied. Idempotent - safe to run twice.
# It never deletes evidence, incidents or operator configuration.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HT="$PROJECT_DIR/.venv/bin/honeytrace"
[[ -x "$HT" ]] || HT="$(command -v honeytrace || echo "python3 -m honeytrace")"

echo "==> HoneyTrace EMERGENCY OFF"
"$HT" emergency-off

# Stop the daemon last (it keeps collecting evidence unless told otherwise).
if command -v systemctl &>/dev/null && systemctl list-unit-files | grep -q '^honeytrace.service'; then
  systemctl stop honeytrace.service || true
else
  "$HT" stop || true
fi

echo "==> Emergency off complete."
echo "    - responses disabled, arming state = disarmed"
echo "    - HoneyTrace firewall rules rolled back (only honeytrace-tagged)"
echo "    - evidence preserved in the configured data directory"
