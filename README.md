# Cybersecurity Log Analysis Agent with LangGraph

A LangGraph-based cybersecurity analyst that pulls per-customer log hierarchies from a vault machine, runs a two-pass rule-based anomaly detector over them, classifies incidents against local datasets, enriches context with web search, and generates a markdown report plus an IOC XML file — pushed back to the vault when done.

---

## 1. Two systems, two machines

The repo is split into two independent packages, each with its own dependencies, meant to run on two different machines (they can also run on one machine for local testing):

```
cybersec_agent_with_langgraph/
├── hierarchy_system/     # the VAULT machine — hosts rationalVault/data
│   ├── mcp_server.py           # FastMCP server: fetch_directory_files, upload_file
│   ├── trigger_mcp_client.py   # manually ask the analysis machine to run analysis
│   ├── requirements.txt
│   └── .env.example
│
└── analysis_system/      # the ANALYSIS machine — runs the LangGraph pipeline
    ├── test.py                 # the LangGraph workflow itself
    ├── anomaly_workflow.py     # Pass 1 + Pass 2 rule-based anomaly detection
    ├── mcp_client.py           # client helpers (pull/push files via MCP)
    ├── populate_hierarchies.py # standalone manual-pull script
    ├── trigger_mcp_server.py   # FastMCP server: accepts "analyze this hierarchy"
    ├── datasets_files/         # merged incident datasets used for classification
    ├── hierarchies/            # local working dir (git-ignored — pulled data + reports)
    ├── requirements.txt
    └── .env.example
```

Neither package touches the other's dependencies — `hierarchy_system` never imports LangChain/LangGraph/Ollama, and `analysis_system` never needs to run standalone on the vault.

---

## 2. How a run actually happens

```
 Vault machine (hierarchy_system)                    Analysis machine (analysis_system)
 ┌────────────────────────────────┐                  ┌──────────────────────────────────────┐
 │ rationalVault/data/...          │                  │ trigger_mcp_server.py (:8001)         │
 │ mcp_server.py (:8000)           │◄─────pull/push───│   exposes analyze_hierarchy tool      │
 │                                 │     over MCP      │                                       │
 │ trigger_mcp_client.py ──────────┼──trigger call────►│   → anomaly_workflow.py               │
 │   (or a chatbot/UI calling      │                  │      Pass 1: known-verdict extraction  │
 │    the same tool)                │                  │      Pass 2: independent surfacing     │
 └────────────────────────────────┘                  │   → test.py's LangGraph pipeline       │
                                                       │      classify → search → explain →     │
                                                       │      IOC vectors → markdown report     │
                                                       │   → pushes report + IOC XML back to     │
                                                       │      the vault via mcp_client.send_files│
                                                       └──────────────────────────────────────┘
```

Both machines act as **both** an MCP client and an MCP server at different points: the vault serves file reads/writes (`mcp_server.py`) but also initiates the trigger (`trigger_mcp_client.py`); the analysis machine accepts trigger requests (`trigger_mcp_server.py`) but also pulls/pushes files as a client of the vault's server (`mcp_client.py`, used internally by `anomaly_workflow.py` and `test.py`).

If everything runs on one machine for local testing, point both `.env` files at `localhost`.

---

## 3. Setup

### 3.1 Vault machine (`hierarchy_system/`)

```bash
cd hierarchy_system
python -m venv venv
```
```bash
# bash/WSL
source venv/bin/activate
pip install -r requirements.txt
```
```powershell
# PowerShell
venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and set `ANALYSIS_SERVER_URL` to wherever the analysis machine's `trigger_mcp_server.py` listens (default port 8001).

Start the file server:
```bash
python mcp_server.py
```
Binds `0.0.0.0:8000` by default. **No authentication or TLS** — `fetch_directory_files` reads any path the caller requests, `upload_file` writes anywhere under the server's own directory. Fine on a trusted private network (LAN, VPN mesh, Tailscale); do not expose to an untrusted network without adding auth/TLS in front of it.

### 3.2 Analysis machine (`analysis_system/`)

```bash
cd analysis_system
python -m venv venv
pip install -r requirements.txt
```

Also needs:
- Ollama running locally with the model referenced in `test.py` (`cybersec-qwen25-3b-q4`)
- Internet access for DuckDuckGo enrichment (optional but recommended)

Copy `.env.example` to `.env` and set `MCP_SERVER_URL` to the vault machine's `mcp_server.py` address.

Start the trigger server:
```bash
python trigger_mcp_server.py
```
Binds `0.0.0.0:8001`, exposes one tool: `analyze_hierarchy(hierarchy, vault_root)`.

---

## 4. Running an analysis

**From the vault machine**, the simplest path — manually trigger one hierarchy:
```bash
cd hierarchy_system
python trigger_mcp_client.py 5/101/1/4/1
```
This calls the analysis machine's `analyze_hierarchy` tool, which pulls that hierarchy's files, runs detection + the full pipeline, and pushes the report + IOC XML back to the vault under the same hierarchy path.

**Directly on the analysis machine**, for local testing without a live trigger call:
```bash
cd analysis_system
python anomaly_workflow.py 5/101/1/4/1
```
Pulls the hierarchy, runs Pass 1 + Pass 2 detection, writes `hierarchies/5/101/1/4/1/anomaly_findings.txt` — this alone doesn't run the LLM pipeline, just the rule-based detection layer. To also run the full LangGraph analysis against an existing `anomaly_findings.txt`, use `test.py`'s `_run_workflow_for_logs_file` (see `test.py` for the exact call, or trigger the whole thing end-to-end via `trigger_mcp_server.py`'s `analyze_hierarchy`).

For manually staging/debugging a pull without running detection at all:
```bash
python populate_hierarchies.py rationalVault/data --hierarchy 5/101/1/4/1
```

---

## 5. What `anomaly_workflow.py` actually does

Two passes over the pulled hierarchy, feeding into a single `anomaly_findings.txt`:

- **Pass 1 — known findings.** Reads verdicts the vault's own `/athinio/bin` scripts already computed (`alertlog.xml` flags, `suspicious_authentication.xml`, `rootkitscan.txt`, raw detection-script output files like `binmodify.txt`/`rcheckOutput`) and tags each with a deterministic category.
- **Pass 2 — independent anomaly surfacing.** Diff-against-cache, frequency analysis, and structure-aware pattern matching over files that have no upstream verdict of their own (`secure`, `audit.log`, `config_dift.xml`) — catches things the vault's own rule-based scripts might miss.

The header written into `anomaly_findings.txt` includes a **primary** suggested `incident_type` plus any **secondary** incident types also detected in the same pull, and a list of **verification-script suggestions** — categories a finding suggests that `alertlog.xml`'s own flags haven't confirmed, each pointing at the specific `/athinio/bin` script that would check for it directly.

`test.py`'s pipeline reads all of this: the primary/secondary hints strongly steer classification (treated as deterministic ground truth, not a guess — see the code comments in `InitialSearchFromLogsToDatasetNode` and `ExplainerOutputNode` for exactly how much latitude the model has to override them), and the verification-script suggestions become concrete recommended actions in the final report.

If Pass 1 + Pass 2 find nothing, `test.py` short-circuits before invoking the LLM at all and writes a minimal "clean" report directly — this avoids the model inventing a plausible-sounding but fabricated incident from empty input.

---

## 6. Outputs

For each analyzed hierarchy, written back into the same folder (and pushed to the vault when triggered via `trigger_mcp_server.py`):

- `anomaly_findings.txt` — Pass 1 + Pass 2 output
- `analysis_report_YYYY-MM-DD_HH-MM-SS.md` — full markdown report
- `vector_group_output.xml` — IOC vector group, ready to append to `rv_ioc_lin.xml`

`hierarchies/` (under `analysis_system/`) is entirely git-ignored — it's local working data (pulled hierarchy files, generated reports), not something to commit. Same treatment as `rationalVault/`, which is vault-machine-only source data.

---

## 7. Troubleshooting

- **`trigger_mcp_client.py` hangs or errors** — confirm `trigger_mcp_server.py` is actually running on the analysis machine and `ANALYSIS_SERVER_URL` in the vault's `.env` points at it correctly.
- **`populate_hierarchies.py` / `anomaly_workflow.py` report "No files returned"** — confirm `mcp_server.py` is running on the vault machine, `MCP_SERVER_URL` in the analysis machine's `.env` points at it, and the hierarchy path actually exists under `rationalVault/data/` there.
- **Empty or weak analysis output** — verify Ollama model availability on the analysis machine and internet access for search enrichment.
- **Dataset routing seems off** — check `datasets_files/*.json` contains valid `incident_type` fields matching what `anomaly_workflow.py`'s category tagging produces.
- **Report threat_level always high/critical** — should be fixed by the calibration rubric in `ExplainerOutputNode`'s prompt; if you still see this, check the model is actually reaching that code path rather than falling back to the strict-JSON retry path.

## 8. Packaging and installing

Each package ships its own `install.sh`, which **detects the platform it's
running on** (Rocky Linux 8/RHEL-like vs Windows under Git Bash) and
installs accordingly — no separate script per OS. On Rocky 8, bare
`python`/`pip` resolve to system Python 3.6/3.7, so both installers
explicitly install and use **Python 3.11**/**pip3.11** rather than relying
on the bare commands; on Windows they use `winget` for the same purpose if
Python 3.11 isn't already present.

There's no service manager involved (no systemd units, no Windows
services) — install.sh only installs dependencies and ingests the corpus
once; you bring the actual long-running processes up yourself afterward
with a plain starter script.

### 8.1 Build the tarballs (on a machine that already has the model)

```bash
scripts/package_release.sh
```

This exports the real weights of the local Ollama `cybersecqwen` model (via
`scripts/export_model.sh`) into `analysis_system/model/cybersecqwen.gguf`
alongside a self-contained `model/Modelfile`, then produces:

- `dist/analysis_system.tar.gz`
- `dist/hierarchy_system.tar.gz`

Neither the exported `.gguf` nor `dist/` are committed to git (see
`.gitignore`) — they're multi-gigabyte build output, regenerated on demand.

### 8.2 Install on the target machine

Copy the relevant tarball to its target machine, extract, and run the
bundled installer (root/sudo only needed on the Rocky 8 branch, for `dnf`):

```bash
tar -xzf analysis_system.tar.gz   # or hierarchy_system.tar.gz
cd analysis_system                # or hierarchy_system
./install.sh                      # sudo ./install.sh on Rocky 8
```

- **`hierarchy_system/install.sh`** — installs Python 3.11 + a venv and
  `requirements.txt`. Only one long-running process here, so there's no
  starter script — once `.env` is set, just run `mcp_server.py` directly
  (the installer prints the exact command for the venv it created).
- **`analysis_system/install.sh`** — installs Python 3.11 + a venv and
  `requirements.txt`, installs Ollama, builds `cybersecqwen` from the
  bundled `model/Modelfile`, and ingests `corpus_documents/*.json` into the
  vector store via a temporarily-started `corpus_server.py`. Once `.env` is
  set, bring the real services up with:
  ```bash
  ./start.sh
  ```
  which starts `corpus_server.py` then `trigger_mcp_server.py` in the
  background (`nohup` + PID files in `corpus_server.pid` /
  `trigger_mcp_server.pid`; stop with `kill $(cat corpus_server.pid)
  $(cat trigger_mcp_server.pid)`).

Neither installer touches real IPs — each copies its own `.env.example` to
`.env` if one isn't already present, but you still need to **edit `.env`
yourself** afterward (`MCP_SERVER_URL` on the analysis machine,
`ANALYSIS_SERVER_URL` on the vault machine) to point at your actual
environment before running `start.sh` / `mcp_server.py`.

## Last Updated

August 28, 2026
