# Cybersecurity Log Analysis Agent with LangGraph

A LangGraph-based cybersecurity analyst that pulls a customer's log
hierarchy from a vault machine, independently checks it against 23 known
attack types plus a secure/messages/audit.log catch-all, and writes one
combined markdown report — pushed back to the vault when done.

For architecture diagrams, the full per-attack-type reference, the
library/model breakdown, and code-level detail, see
**[DOCUMENTATION.md](DOCUMENTATION.md)**. This file covers setup and usage.

---

## Two systems, two machines

```
├── hierarchy_system/     # the VAULT machine — hosts rationalVault/data
│   ├── mcp_server.py           # FastMCP server (:8002): fetch_directory_files, upload_file
│   ├── trigger_mcp_client.py   # manually ask the analysis machine to run analysis
│   ├── install.sh, requirements.txt, .env.example
│
└── analysis_system/      # the ANALYSIS machine — runs the LangGraph pipeline
    ├── attack_status_workflow.py   # per-attack-type checks + triggers log analysis
    ├── trigger_mcp_server.py       # FastMCP server (:8001): accepts "analyze this hierarchy"
    ├── corpus_server.py            # vector store (:8003) backing the attack-type taxonomy
    ├── ingest_corpus.py            # one-shot: load corpus_documents/*.json into it
    ├── corpus_documents/           # per-attack-type + evidence-file knowledge (source of truth)
    ├── model/                      # Modelfile (+ your own cybersecqwen.gguf, not committed)
    ├── lib/                        # shared helpers, log_analysis_workflow.py, mcp/corpus clients
    ├── hierarchies/                 # local working dir (git-ignored — pulled data + reports)
    ├── install.sh, start.sh, requirements.txt, .env.example
```

Neither package touches the other's dependencies — `hierarchy_system`
never imports LangChain/LangGraph/Ollama, and `analysis_system` never runs
on the vault machine.

If everything runs on one machine for local testing, point both `.env`
files at `localhost`.

---

## Setup

### Vault machine (`hierarchy_system/`)

```bash
cd hierarchy_system
python -m venv venv && source venv/bin/activate   # venv\Scripts\Activate.ps1 on Windows
pip install -r requirements.txt
cp .env.example .env    # set ANALYSIS_SERVER_URL to the analysis machine's trigger_mcp_server.py
python mcp_server.py    # binds 0.0.0.0:8002 — no auth/TLS, trusted-network only
```

### Analysis machine (`analysis_system/`)

```bash
cd analysis_system
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

ollama pull nomic-embed-text                    # embedding model for corpus_server.py
ollama create cybersecqwen -f model/Modelfile   # needs model/cybersecqwen.gguf — see model/Modelfile

cp .env.example .env    # set MCP_SERVER_URL to the vault machine's mcp_server.py

python corpus_server.py &     # binds 8003
python ingest_corpus.py       # one-shot: loads corpus_documents/*.json into the vector store
python trigger_mcp_server.py  # binds 0.0.0.0:8001, exposes analyze_hierarchy(hierarchy, vault_root)
```

For a packaged Rocky Linux 8 / Windows install instead of the manual steps
above, see **Packaging and installing** below.

---

## Usage

**From the vault machine** — the simplest path, trigger one hierarchy:
```bash
cd hierarchy_system
python trigger_mcp_client.py 5/101/1/4/1
```

**Directly on the analysis machine** — full pipeline, one report:
```bash
cd analysis_system
python attack_status_workflow.py 5/101/1/4/1
python attack_status_workflow.py 5/101/1/4/1 --vault-root /rationalVault/data --no-sync   # local testing, no MCP pull/push
```

**Log analysis alone**, against an already-pulled hierarchy:
```bash
python -m lib.log_analysis_workflow 5/101/1/4/1
```

Output, per hierarchy: `hierarchies/<hierarchy>/reports/attack_status_report_<timestamp>.md`
— attack-status sections, then the log-analysis section, then a summary
block. `hierarchies/` is entirely git-ignored (local working data).

---

## Troubleshooting

- **`trigger_mcp_client.py` hangs or errors** — confirm `trigger_mcp_server.py` is running on the analysis machine and `ANALYSIS_SERVER_URL` in the vault's `.env` points at it correctly.
- **"No files returned" / attack types read as `not_configured`** — confirm `mcp_server.py` is running on the vault machine, `MCP_SERVER_URL` in the analysis machine's `.env` points at it, and the hierarchy path actually exists under `rationalVault/data/` there.
- **`attack_status_workflow.py` / `corpus_server.py` errors about a missing corpus entry** — `corpus_server.py` must already be running, and `ingest_corpus.py` must have been run against it at least once (see Setup above).
- **Empty or weak analysis output** — verify the `cybersecqwen` model exists in Ollama and internet access is available for search enrichment.

---

## Packaging and installing

Each package ships its own `install.sh`, which **detects the platform
it's running on** (Rocky Linux 8/RHEL-like vs Windows under Git Bash) and
installs accordingly. On Rocky 8, bare `python`/`pip` resolve to system
Python 3.6/3.7, so both installers explicitly install and use
**Python 3.11**/**pip3.11**; on Windows they use `winget` for the same
purpose if Python 3.11 isn't already present. No service manager is
involved — `install.sh` only installs dependencies and ingests the corpus
once; you bring the long-running processes up yourself afterward with a
plain starter script.

**Build the tarballs:**
```bash
scripts/package_release.sh
```
Needs `analysis_system/model/cybersecqwen.gguf` to exist first — either
place it there yourself (next to the already-committed `Modelfile`, no
Ollama needed on the packaging machine), or run this on a machine that
already has the model built in Ollama and let it export automatically via
`scripts/export_model.sh`. Produces `dist/analysis_system.tar.gz` and
`dist/hierarchy_system.tar.gz` — neither the `.gguf` nor `dist/` are
committed to git.

**Install on the target machine:**
```bash
tar -xzf analysis_system.tar.gz   # or hierarchy_system.tar.gz
cd analysis_system                # or hierarchy_system
./install.sh                      # sudo ./install.sh on Rocky 8
```
`hierarchy_system/install.sh` sets up Python + `requirements.txt` only —
run `mcp_server.py` directly afterward (no starter script needed, it's the
only long-running process). `analysis_system/install.sh` also installs
Ollama, builds `cybersecqwen`, and ingests the corpus; once `.env` is set,
bring the real services up with `./start.sh` (starts `corpus_server.py`
then `trigger_mcp_server.py` in the background, PID files for both).

Neither installer touches real IPs — each copies its own `.env.example` to
`.env` if one isn't already present, but you still need to edit `.env`
yourself afterward.

## Last Updated

August 29, 2026
