# Cybersecurity Log Analysis Agent with LangGraph

A LangGraph-based cybersecurity analyst that pulls a customer's log
hierarchy from a vault machine, independently checks it against every
attack type configured on that vault plus a catch-all log-analysis pass,
and writes one combined markdown report — pushed back to the vault when
done.

No local corpus, database, or embedding/RAG lookup of any kind — the
fine-tuned model judges every piece of evidence directly, and the attack
checklist (which attack types, in what order, against which files/tags)
is entirely hierarchy-side configuration, fetched fresh over MCP once per
run.

For architecture, per-attack-type reference, and code-level detail, see
**[DOCUMENTATION.md](DOCUMENTATION.md)**. This file covers setup and usage.

---

## Two systems, two machines

```
├── hierarchy_system/     # the VAULT machine — hosts rationalVault/data
│   ├── mcp_server.py           # FastMCP server (:8002): fetch_directory_files,
│   │                            # upload_file, get_attack_checklist
│   ├── trigger_mcp_client.py   # manually ask the analysis machine to run analysis
│   ├── .env                     # ATTACK_ORDER, ATTACK_PRIMARY_<type>,
│   │                            # ATTACK_VERIFY_<type>, LOG_FILE_PATHS, etc. —
│   │                            # the single source of truth for what gets checked
│   ├── install.sh, start.sh, stop.sh, requirements.txt, .env.example
│
└── analysis_system/      # the ANALYSIS machine — runs the LangGraph pipeline
    ├── analysis.py                 # the whole pipeline: MCP transport, the
    │                                # per-attack evidence engine, catch-all log analysis
    ├── trigger_mcp_server.py       # FastMCP server (:8001): accepts "analyze this hierarchy"
    ├── model/                      # Modelfile (+ your own cybersecqwen.gguf, not committed)
    ├── lib/                        # llm_client.py — the shared Ollama client
    ├── hierarchies/                 # local working dir (git-ignored — pulled data + reports)
    ├── install.sh, start.sh, stop.sh, requirements.txt, .env.example
```

Neither package touches the other's dependencies — `hierarchy_system`
never imports LangChain/LangGraph/Ollama, and `analysis_system` never runs
on the vault machine.

If everything runs on one machine for local testing, point both `.env`
files at `localhost`.

---

## Required directory structure per hierarchy

For full checking coverage, this is what should exist under
`rationalVault/data/<hierarchy>/` (e.g. `rationalVault/data/5/101/1/4/1/`)
on the vault machine — derived from the current `hierarchy_system/.env`:

```
rationalVault/data/<hierarchy>/
├── Alert.xml                       # read by ~20 attack types (one tag each)
├── athinio/
│   ├── security/
│   │   ├── dataprotection.xml       # dlp_data_exposure
│   │   └── malwarefiles.xml         # clam_malware
│   ├── system/
│   │   ├── alertlog.xml             # verify tier for ~10 attack types
│   │   ├── nouser_noowner.xml       # orphaned_files
│   │   ├── secOpsOutput_91          # rootkit_malware
│   │   ├── secOpsOutput_94          # config_drift
│   │   ├── secOpsOutput_96          # immutable_attribute_drift
│   │   ├── secOpsOutput_112         # unknown_binary_detection
│   │   ├── secOpsOutput_128         # special_folder_monitoring
│   │   ├── user_emptypass_list.xml  # weak_password_accounts
│   │   └── zero_uid.xml             # unauthorized_uid0_account
│   └── tmp/
│       └── imm_changes              # immutable_attribute_drift (verify)
├── home/athinio/data/1cloudFiler/log/
│   └── gateway.log*                 # gateway_unauthorized_breakin (verify)
├── rationalVault/log/
│   └── rationalclient.log*          # config_drift, unknown_binary_detection, user_breach
└── var/
    ├── log/
    │   ├── audit.log                # catch-all log analysis only
    │   ├── messages                 # catch-all log analysis only
    │   ├── osstatus.log*             # config_drift, unknown_binary_detection
    │   └── secure                    # user_breach (verify) + catch-all log analysis
    └── neridio/
        └── banned_ip.xml             # banned_ip_bruteforce
```

`*` marks files that rotate on the real system (`gateway.log_230`,
`rationalclient.log_237`, ...) — every plain-text path is matched as a
prefix, so both the bare name and any rotated copies are picked up
automatically.

**Nothing here is a hard requirement** — a missing primary file just
resolves that attack type as `not_configured` rather than erroring, and a
missing verify file is treated as clean by default (same as a genuinely
clean read). This table is a snapshot for reference; `hierarchy_system/.env`'s
`ATTACK_PRIMARY_<type>`/`ATTACK_VERIFY_<type>`/`LOG_FILE_PATHS` are the actual, authoritative
source and will drift from this list as attack types are added or
changed — see [DOCUMENTATION.md § 3](DOCUMENTATION.md#3-hierarchy_systemenv-schema)
for the full per-path breakdown.

---

## Setup

### Vault machine (`hierarchy_system/`)

```bash
cd hierarchy_system
python -m venv venv && source venv/bin/activate   # venv\Scripts\Activate.ps1 on Windows
pip install -r requirements.txt
cp .env.example .env    # set ANALYSIS_SERVER_URL to the analysis machine's trigger_mcp_server.py
```

Before starting the server, edit `.env`'s `ATTACK_ORDER`/`ATTACK_PRIMARY_<type>`/
etc. to reflect this vault's real attack-checking configuration — see
`.env.example`'s schema comments, or copy the worked examples from a
sibling vault's `.env`. Then:

```bash
./start.sh    # backgrounds mcp_server.py, binds 0.0.0.0:8002 — no auth/TLS, trusted-network only
```
Stop it with `./stop.sh`. It's the only long-running process on this
machine.

### Analysis machine (`analysis_system/`)

```bash
cd analysis_system
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

ollama create cybersecqwen -f model/Modelfile   # needs model/cybersecqwen.gguf — see model/Modelfile

cp .env.example .env    # set MCP_SERVER_URL to the vault machine's mcp_server.py

./start.sh  # backgrounds trigger_mcp_server.py, binds 0.0.0.0:8001, exposes analyze_hierarchy(hierarchy, vault_root)
```
Stop it with `./stop.sh`. It's the only long-running process on this
machine.

No embedding model, no vector store, no corpus-ingestion step — this
package has no local knowledge base of any kind. Every attack type it
checks, and every file/tag it reads for each one, comes from the vault
machine's `hierarchy_system/.env` over MCP, fetched once per run.

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
python analysis.py 5/101/1/4/1
python analysis.py 5/101/1/4/1 --vault-root hierarchies --no-sync   # local testing, no MCP pull/push
```

Output, per hierarchy: `hierarchies/<hierarchy>/reports/attack_status_report_<timestamp>.md`
— attack-status sections (one per configured attack type), then the
log-analysis section (only if something was actually found), then a
summary block. `hierarchies/` is entirely git-ignored (local working data,
including anything pulled from a real vault — never commit it).

---

## Troubleshooting

- **`trigger_mcp_client.py` hangs or errors** — confirm `trigger_mcp_server.py` is running on the analysis machine and `ANALYSIS_SERVER_URL` in the vault's `.env` points at it correctly.
- **Attack types read as `not_configured`** — confirm `mcp_server.py` is running on the vault machine, `MCP_SERVER_URL` in the analysis machine's `.env` points at it, and the hierarchy path actually exists under `rationalVault/data/` there.
- **An attack type isn't being checked at all** — it must be listed in the vault's `hierarchy_system/.env`'s `ATTACK_ORDER`; removing a type from that list disables it without deleting its configuration.
- **Empty or weak analysis output** — verify the `cybersecqwen` model exists in Ollama (`ollama list`) and internet access is available for the log-analysis search enrichment step.

---

## Packaging and installing

Each package ships its own `install.sh`, which **detects the platform
it's running on** (Rocky Linux 8/RHEL-like vs Windows under Git Bash) and
installs accordingly. On Rocky 8, bare `python`/`pip` resolve to system
Python 3.6/3.7, so both installers explicitly install and use
**Python 3.11**/**pip3.11**; on Windows they use `winget` for the same
purpose if Python 3.11 isn't already present. No service manager is
involved — `install.sh` only installs dependencies and builds the bundled
model; you bring the long-running process up yourself afterward.

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
bring `mcp_server.py` up afterward with `./start.sh` (stop with
`./stop.sh`; it's the only long-running process). `analysis_system/install.sh`
also installs Ollama and builds `cybersecqwen`; once `.env` is set, bring
`trigger_mcp_server.py` up the same way, with `./start.sh`/`./stop.sh`.

Neither installer touches real IPs — each copies its own `.env.example` to
`.env` if one isn't already present, but you still need to edit `.env`
yourself afterward (and, on the vault side, populate the real attack
checklist).

## Last Updated

September 9, 2026
