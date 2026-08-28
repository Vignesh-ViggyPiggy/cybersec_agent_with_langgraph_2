#!/usr/bin/env bash
# install.sh — sets up this hierarchy_system checkout (the vault machine)
# on Rocky Linux 8: Python 3.11 (Rocky 8's bare python3/pip3 resolve to
# 3.6/3.7, so this installs and uses python3.11/pip3.11 explicitly), and a
# systemd service for mcp_server.py so it survives reboots.
#
# Run as root from inside the extracted hierarchy_system/ directory:
#   sudo ./install.sh
#
# Does NOT touch real IPs: copies .env.example to .env if missing, but you
# still need to edit .env yourself afterward (ANALYSIS_SERVER_URL -> the
# analysis machine's real address).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

if [ "$EUID" -ne 0 ]; then
  echo "Run as root (sudo ./install.sh) — installs system packages and a systemd unit." >&2
  exit 1
fi

RUN_USER="$(logname 2>/dev/null || echo root)"

echo "== [1/3] Installing Python 3.11 =="
if ! dnf install -y python3.11 python3.11-pip 2>/dev/null; then
  dnf module enable -y python3.11
  dnf install -y python3.11 python3.11-pip
fi

echo "== [2/3] Creating venv and installing Python dependencies =="
python3.11 -m venv venv
venv/bin/pip install --upgrade pip
venv/bin/pip install -r requirements.txt

echo "== [3/3] Installing systemd service for mcp_server.py =="
cat > /etc/systemd/system/hierarchy-mcp-server.service <<EOF
[Unit]
Description=Vault file server (hierarchy_system/mcp_server.py)
After=network.target

[Service]
Type=simple
WorkingDirectory=$HERE
ExecStart=$HERE/venv/bin/python mcp_server.py
Restart=on-failure
User=$RUN_USER

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now hierarchy-mcp-server

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Wrote .env from .env.example — edit ANALYSIS_SERVER_URL before triggering analysis."
fi

echo
echo "mcp_server.py is running via systemd (hierarchy-mcp-server.service)."
echo "Trigger an analysis manually with: venv/bin/python trigger_mcp_client.py <hierarchy>"
