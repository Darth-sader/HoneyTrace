#!/usr/bin/env bash
# HoneyTrace lab installer - prepares a DEDICATED Linux lab machine or VM.
#
# This script is for a disposable lab environment. It:
#   1. creates the 'honeytrace' service account and the 'labuser' lab account
#   2. installs system dependencies (Debian/Ubuntu/Kali package names)
#   3. creates a venv and installs HoneyTrace
#   4. installs audit rules that tag lab file/exec events with 'honeytrace'
#   5. installs systemd units
#
# Run it ON the lab machine (sudo bash scripts/install_lab.sh).
# It never touches hosts outside this machine.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_USER="honeytrace"
LAB_USER="labuser"

echo "==> HoneyTrace lab installer"
echo "    project : $PROJECT_DIR"
echo "    user    : $SERVICE_USER   lab account: $LAB_USER"

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: run with sudo" >&2
  exit 1
fi

# ---- 1. accounts ---------------------------------------------------------- #
id -u "$SERVICE_USER" &>/dev/null || useradd --system --shell /usr/sbin/nologin --home-dir /var/lib/honeytrace "$SERVICE_USER"
id -u "$LAB_USER" &>/dev/null || useradd -m -s /bin/bash "$LAB_USER"

# ---- 2. packages ----------------------------------------------------------- #
if command -v apt-get &>/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq \
    python3 python3-venv python3-pip \
    auditd audispd-plugins \
    tcpdump \
    iptables \
    tlog \
    libnotify-bin \
    rsyslog || true
fi

# ---- 3. directories & python ----------------------------------------------- #
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 /var/lib/honeytrace
cd "$PROJECT_DIR"
python3 -m venv .venv
./.venv/bin/pip install --upgrade pip >/dev/null
./.venv/bin/pip install -e ".[decoys,gui,dev]" >/dev/null
chown -R "$SERVICE_USER":"$SERVICE_USER" "$PROJECT_DIR/data" 2>/dev/null || true

# ---- 4. audit rules ---------------------------------------------------------- #
# Tag everything the lab user executes and all access to lab paths, so the
# audit collector can attribute file events to processes.
cat >/etc/audit/rules.d/honeytrace.rules <<EOF
-a always,exit -F arch=b64 -S execve -F auid=${LAB_USER} -k honeytrace
-a always,exit -F arch=b32 -S execve -F auid=${LAB_USER} -k honeytrace
-w /home/${LAB_USER}/Documents -p rwa -k honeytrace
-w /home/${LAB_USER}/Projects -p rwa -k honeytrace
EOF
augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/honeytrace.rules 2>/dev/null || true
systemctl try-restart auditd 2>/dev/null || true

# Give the service account read access to the audit log (Debian uses 'adm').
usermod -aG adm "$SERVICE_USER" 2>/dev/null || true

# ---- 5. systemd units --------------------------------------------------------- #
install -m 0644 systemd/honeytrace.service /etc/systemd/system/
install -m 0644 systemd/honeytrace-health.service /etc/systemd/system/
install -m 0644 systemd/honeytrace-health.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable honeytrace.service honeytrace-health.timer 2>/dev/null || true

# ---- 6. sanity ------------------------------------------------------------------ #
./.venv/bin/honeytrace test-config || {
  echo "WARNING: config validation failed - edit config/ before starting the service"
}
echo "==> Install complete."
echo "    Next steps:"
echo "      1. honeytrace decoys generate      (creates synthetic decoys)"
echo "      2. honeytrace arm --mode observe"
echo "      3. systemctl start honeytrace"
echo "      4. scripts/demo.sh for the one-click demo"
