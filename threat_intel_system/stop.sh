#!/usr/bin/env bash
# stop.sh — stops the mcp_server.py process started by start.sh.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

if [ -f mcp_server.pid ] && kill -0 "$(cat mcp_server.pid)" 2>/dev/null; then
  kill "$(cat mcp_server.pid)"
  rm -f mcp_server.pid
  echo "mcp_server.py stopped."
else
  echo "mcp_server.py is not running."
  rm -f mcp_server.pid
fi
