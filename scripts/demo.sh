#!/usr/bin/env bash
# HoneyTrace one-click demo: isolated scenario, controlled attacks, reports.
# Everything below is synthetic and offline-safe. Run on the lab machine.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HT="$PROJECT_DIR/.venv/bin/honeytrace"
[[ -x "$HT" ]] || HT="$(command -v honeytrace || echo "python3 -m honeytrace")"

echo "=============================================="
echo " HoneyTrace demo (offline, synthetic only)"
echo "=============================================="

# 0. Validate config first - never demo with a broken config.
"$HT" test-config || { echo "config invalid; fix config/ first"; exit 1; }

# 1. Generate decoys into the configured lab paths.
"$HT" decoys generate
"$HT" decoys list

# 2. Self-test the pipeline.
"$HT" test

# 3. Run the bundled demo scenario (replayable, deterministic).
"$HT" demo || true

# 4. Verify the evidence written so far.
"$HT" verify || true

# 5. Render reports and start the dashboard briefly.
"$HT" report || true
echo ""
echo "Demo complete."
echo "  - Incident centre : $HT serve   (then open http://127.0.0.1:8443)"
echo "  - Case export     : $HT export --out demo-case.zip"
echo "  - Cleanup         : $HT decoys clean && $HT clean --yes"
