#!/usr/bin/env bash
# install.sh — sets up this analysis_system checkout. Detects the
# platform and installs accordingly:
#   - Rocky Linux 8 (or another RHEL-like): dnf-installs Python 3.11/pip3.11
#     (Rocky 8's bare python3/pip3 resolve to 3.6/3.7, so this is explicit
#     throughout) and Ollama via its official installer.
#   - Windows, run under Git Bash: uses winget for Python 3.11 and Ollama
#     if either isn't already present.
# Either way it then creates a venv, installs requirements.txt, and builds
# the bundled cybersecqwen model (model/Modelfile + model/cybersecqwen.gguf,
# produced by ../analysis_system/scripts/export_model.sh on the build
# machine). No corpus to ingest — this package has no local corpus/database
# of any kind; the attack checklist comes from hierarchy_system over MCP.
#
# There's only one long-running process here (trigger_mcp_server.py).
# Bring it up afterward with ./start.sh (backgrounds it, writes
# trigger_mcp_server.pid); stop it again with ./stop.sh.
#
# Does NOT touch real IPs: copies .env.example to .env if missing, but you
# still need to edit .env yourself afterward (MCP_SERVER_URL -> the vault
# machine's real address, running hierarchy_system/mcp_server.py).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

wait_for_port() {
  local url="$1" tries="${2:-30}" code
  for _ in $(seq 1 "$tries"); do
    if curl -s -o /dev/null "$url"; then code=0; else code=$?; fi
    if [ "$code" -ne 7 ]; then return 0; fi
    sleep 1
  done
  echo "Warning: timed out waiting for $url" >&2
  return 1
}

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

echo "== [1/5] Installing Python 3.11 =="
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

echo "== [2/5] Creating venv and installing Python dependencies =="
$PY311 -m venv venv
if [ -x venv/Scripts/python.exe ]; then PY="venv/Scripts/python.exe"; else PY="venv/bin/python"; fi
"$PY" -m pip install --upgrade pip
"$PY" -m pip install -r requirements.txt

echo "== [3/5] Installing Ollama =="
if ! command -v ollama >/dev/null 2>&1; then
  case "$OS_KIND" in
    rocky|linux-other)
      curl -fsSL https://ollama.com/install.sh | sh
      ;;
    windows)
      if command -v winget >/dev/null 2>&1; then
        winget install --id Ollama.Ollama -e --accept-source-agreements --accept-package-agreements
      else
        echo "winget isn't available — install Ollama from https://ollama.com/download/windows, then re-run this script." >&2
        exit 1
      fi
      ;;
  esac
fi

if ! wait_for_port "http://127.0.0.1:11434/" 5; then
  if [ "$OS_KIND" = "windows" ]; then
    echo "Ollama not responding yet — starting 'ollama serve' in the background."
    nohup ollama serve > ollama.log 2>&1 &
  fi
  wait_for_port "http://127.0.0.1:11434/" 30
fi

echo "== [4/5] Building cybersecqwen =="
if [ ! -f model/Modelfile ] || [ ! -f model/cybersecqwen.gguf ]; then
  echo "Missing model/Modelfile or model/cybersecqwen.gguf in this package — cannot build the model." >&2
  echo "Copy them from ../analysis_system/model/ or rebuild via ../analysis_system/scripts/export_model.sh." >&2
  exit 1
fi
ollama create cybersecqwen -f model/Modelfile

echo "== [5/5] Preparing .env =="
if [ ! -f .env ]; then
  cp .env.example .env
  echo "Wrote .env from .env.example — edit MCP_SERVER_URL before running ./start.sh."
fi

echo
echo "Install complete. Edit .env to point at your vault machine, then run:"
echo "  ./start.sh"
