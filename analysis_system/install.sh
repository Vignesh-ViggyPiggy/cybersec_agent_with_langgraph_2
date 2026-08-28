#!/usr/bin/env bash
# install.sh — sets up this analysis_system checkout on a Rocky Linux 8
# machine: Python 3.11 (Rocky 8's bare python3/pip3 resolve to 3.6/3.7, so
# this installs and uses python3.11/pip3.11 explicitly), Ollama plus the
# bundled cybersecqwen model (model/Modelfile + model/cybersecqwen.gguf,
# produced by scripts/export_model.sh on the build machine), the corpus
# vector DB (corpus_server.py + ingest_corpus.py), and systemd services for
# corpus_server.py and trigger_mcp_server.py so they survive reboots.
#
# Run as root from inside the extracted analysis_system/ directory:
#   sudo ./install.sh
#
# Does NOT touch real IPs: copies .env.example to .env if missing, but you
# still need to edit .env yourself afterward (MCP_SERVER_URL -> the vault
# machine's real address).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

if [ "$EUID" -ne 0 ]; then
  echo "Run as root (sudo ./install.sh) — installs system packages and systemd units." >&2
  exit 1
fi

RUN_USER="$(logname 2>/dev/null || echo root)"

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

echo "== [1/7] Installing Python 3.11 =="
if ! dnf install -y python3.11 python3.11-pip 2>/dev/null; then
  dnf module enable -y python3.11
  dnf install -y python3.11 python3.11-pip
fi

echo "== [2/7] Creating venv and installing Python dependencies =="
python3.11 -m venv venv
venv/bin/pip install --upgrade pip
venv/bin/pip install -r requirements.txt

echo "== [3/7] Installing Ollama =="
if ! command -v ollama >/dev/null 2>&1; then
  curl -fsSL https://ollama.com/install.sh | sh
fi
systemctl enable --now ollama
wait_for_port "http://127.0.0.1:11434/" 30

echo "== [4/7] Pulling embedding model and building cybersecqwen =="
ollama pull nomic-embed-text
if [ ! -f model/Modelfile ] || [ ! -f model/cybersecqwen.gguf ]; then
  echo "Missing model/Modelfile or model/cybersecqwen.gguf in this package — cannot build the model." >&2
  echo "Rebuild the tarball with scripts/package_release.sh on a machine that has the model." >&2
  exit 1
fi
ollama create cybersecqwen -f model/Modelfile

echo "== [5/7] Installing systemd services =="
cat > /etc/systemd/system/analysis-corpus.service <<EOF
[Unit]
Description=Attack corpus vector store (analysis_system/corpus_server.py)
After=network.target ollama.service
Requires=ollama.service

[Service]
Type=simple
WorkingDirectory=$HERE
ExecStart=$HERE/venv/bin/python corpus_server.py
Restart=on-failure
User=$RUN_USER

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/analysis-trigger.service <<EOF
[Unit]
Description=Analysis trigger MCP server (analysis_system/trigger_mcp_server.py)
After=network.target analysis-corpus.service
Requires=analysis-corpus.service

[Service]
Type=simple
WorkingDirectory=$HERE
ExecStart=$HERE/venv/bin/python trigger_mcp_server.py
Restart=on-failure
User=$RUN_USER

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now analysis-corpus.service

echo "== [6/7] Ingesting corpus documents into the vector store =="
wait_for_port "http://127.0.0.1:8003/mcp" 30
venv/bin/python ingest_corpus.py

echo "== [7/7] Preparing .env =="
if [ ! -f .env ]; then
  cp .env.example .env
  echo "Wrote .env from .env.example — edit MCP_SERVER_URL before starting analysis-trigger."
fi

echo
echo "Corpus service is running (analysis-corpus.service)."
echo "Once .env points MCP_SERVER_URL at your vault machine, start the trigger server with:"
echo "  systemctl enable --now analysis-trigger"
