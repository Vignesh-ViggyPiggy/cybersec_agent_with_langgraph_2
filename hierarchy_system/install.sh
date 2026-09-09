#!/usr/bin/env bash
# install.sh — sets up this hierarchy_system_v2 checkout (the vault machine).
# Detects the platform and installs Python 3.11 accordingly:
#   - Rocky Linux 8 (or another RHEL-like): dnf-installs python3.11/pip3.11
#     (Rocky 8's bare python3/pip3 resolve to 3.6/3.7, so this is explicit
#     throughout).
#   - Windows, run under Git Bash: uses winget for Python 3.11 if it isn't
#     already present.
# Either way it then creates a venv and installs requirements.txt.
#
# There's only one long-running process here (mcp_server.py), so there's
# no separate starter script — just run it directly once .env is set:
#   venv/bin/python mcp_server.py        (Linux)
#   venv/Scripts/python.exe mcp_server.py (Windows)
#
# Does NOT touch real IPs: copies .env.example to .env if missing, but you
# still need to edit .env yourself afterward (ANALYSIS_SERVER_URL -> the
# analysis machine's real address) — the attack-checking configuration
# (ATTACK_ORDER, ATTACK_PRIMARY_*, etc.) already ships fully populated in
# .env.example's companion, the real .env in this same directory; edit that
# if you need to change which attack types are checked or where.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

OS_KIND="unknown"
case "$(uname -s)" in
  Linux*)
    if [ -f /etc/os-release ] && grep -qiE '^(ID|ID_LIKE)=.*(rocky|rhel|centos)' /etc/os-release; then
      OS_KIND="rocky"
    else
      OS_KIND="linux-other"
    fi
    ;;
  MINGW*|MSYS*|CYGWIN*) OS_KIND="windows" ;;
esac
echo "Detected platform: $OS_KIND"

echo "== [1/2] Installing Python 3.11 =="
case "$OS_KIND" in
  rocky|linux-other)
    if [ "$EUID" -ne 0 ]; then
      echo "Run as root (sudo ./install.sh) — installs system packages via dnf." >&2
      exit 1
    fi
    if ! dnf install -y python3.11 python3.11-pip 2>/dev/null; then
      dnf module enable -y python3.11
      dnf install -y python3.11 python3.11-pip
    fi
    PY311=python3.11
    ;;
  windows)
    if command -v py >/dev/null 2>&1 && py -3.11 --version >/dev/null 2>&1; then
      PY311="py -3.11"
    elif command -v python3.11 >/dev/null 2>&1; then
      PY311=python3.11
    elif command -v winget >/dev/null 2>&1; then
      echo "Python 3.11 not found — installing via winget."
      winget install --id Python.Python.3.11 -e --accept-source-agreements --accept-package-agreements
      PY311="py -3.11"
    else
      echo "Python 3.11 not found and winget isn't available — install it from https://www.python.org/downloads/ (check 'Add to PATH'), then re-run this script." >&2
      exit 1
    fi
    ;;
  *)
    echo "Unsupported platform ($(uname -s)) — this installer targets Rocky Linux 8 and Windows (via Git Bash)." >&2
    exit 1
    ;;
esac

echo "== [2/2] Creating venv and installing Python dependencies =="
$PY311 -m venv venv
if [ -x venv/Scripts/python.exe ]; then PY="venv/Scripts/python.exe"; else PY="venv/bin/python"; fi
"$PY" -m pip install --upgrade pip
"$PY" -m pip install -r requirements.txt

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Wrote .env from .env.example — edit ANALYSIS_SERVER_URL before running mcp_server.py."
fi

echo
echo "Install complete. Edit .env to point at your analysis machine, then run:"
echo "  $PY mcp_server.py"
