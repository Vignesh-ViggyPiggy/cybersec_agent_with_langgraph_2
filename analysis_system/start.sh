#!/usr/bin/env bash
# start.sh — starts corpus_server.py then trigger_mcp_server.py in the
# background (plain nohup + PID files, no service manager). Works
# unchanged on Rocky Linux 8 or under Git Bash on Windows — it just picks
# the right venv layout for whichever platform ran install.sh.
#
# Run this after install.sh has finished and .env points at your vault
# machine.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

if [ -x venv/Scripts/python.exe ]; then
  PY="venv/Scripts/python.exe"
else
  PY="venv/bin/python"
fi

nohup "$PY" corpus_server.py > corpus_server.log 2>&1 &
echo $! > corpus_server.pid
echo "corpus_server.py started (pid $(cat corpus_server.pid), log: corpus_server.log)"

sleep 2

nohup "$PY" trigger_mcp_server.py > trigger_mcp_server.log 2>&1 &
echo $! > trigger_mcp_server.pid
echo "trigger_mcp_server.py started (pid $(cat trigger_mcp_server.pid), log: trigger_mcp_server.log)"

echo
echo "Stop both with:"
echo "  kill \$(cat corpus_server.pid) \$(cat trigger_mcp_server.pid)"
