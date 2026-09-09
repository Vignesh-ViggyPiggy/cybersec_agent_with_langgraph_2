# Design: A No-RAG, .env-Driven Evidence Engine for Attack-Status Checks

**Status: implemented (2026-09-09).** This document describes the current
design of `analysis_system/analysis.py`'s per-attack evidence engine — a
from-scratch redesign that replaced an earlier corpus/ChromaDB-based
workflow (`attack_status_workflow.py` + `corpus_documents/*.json` +
`corpus_server.py`, since removed from this repo; git history from before
2026-09-09 has it if ever needed). See [DOCUMENTATION.md](DOCUMENTATION.md)
for the as-built architecture in full; this document is the design
record — why it looks like this, not just what it does.

---

## 1. Motivation: what was wrong with the corpus-based approach

The earlier design resolved each attack type's evidence sources by
querying `corpus_server.py`, a FastMCP service fronting a Chroma vector
store built from `corpus_documents/attack_*.json`. Each entry's
`evidence_sources` carried a `known_patterns` list — deterministic
matchers (`{"value": "1", "detected": true}`, `{"pattern": "...", ...}`
with regex/backreference support) tried first, falling back to an LLM
judgment call only when nothing matched.

Three problems drove the redesign:

1. **The deterministic matchers were themselves a maintenance burden with
   a ceiling.** Every new evidence shape (a new log-correlation pattern, a
   new count threshold convention) needed either a new matcher kind or a
   bespoke Python function, and no matcher set could anticipate every
   real-world log format in advance. The corpus was hand-maintained data,
   but the *matching logic* was still code.
2. **The corpus was redundant with what the model already knew.** A
   fine-tuned model (`cybersecqwen`) trained specifically on
   `content -> "Status: DETECTED|CLEAN. <explanation>"` pairs derived from
   this exact corpus doesn't need retrieved context re-injected into its
   prompt to interpret a tag or log line it was trained on — the
   embedding/vector-store machinery was doing work the fine-tune already
   did.
3. **Config and code were tangled.** Which attack types get checked, in
   what order, and against which files/tags lived in `corpus_documents/*.json`
   on the *analysis* machine — despite that being entirely a fact about the
   *vault* machine's data layout, which the analysis machine has no
   independent way to verify.

## 2. The redesign, in three moves

**No RAG.** The whole corpus/embedding/database stack is gone. Instead,
`hierarchy_system/mcp_server.py`'s `get_attack_checklist` tool reads a
single flat `.env` **on the vault machine** (`ATTACK_ORDER`,
`ATTACK_PRIMARY_<type>`, `ATTACK_VERIFY_<type>`, `LOG_FILE_PATHS`, etc. —
see `hierarchy_system/.env.example`) and returns the whole check order
plus every evidence file/tag path, for every attack type, as one dict.
`analysis_system/analysis.py` fetches this **once per run** (see
`fetch_attack_checklist()`), not once per attack type — every subsequent
`resolve_attack_node` call is then a plain in-memory dict lookup, not a
network call. `analysis_system/.env` only holds things genuinely local to
the analysis machine (model name, MCP server URL, timeouts) — nothing
about which hierarchy-side files get checked.

This also fixes problem 3 directly: the vault machine, which actually
owns the data, now owns the config that describes it. The analysis
machine is fully generic — pointed at a different vault with a
completely different `.env`, it checks a completely different set of
attack types without a single code change.

**The model judges every evidence source directly — no
`known_patterns` matching at all.** `cybersecqwen` was fine-tuned
specifically on `content -> "Status: DETECTED|CLEAN. <explanation>"` pairs
derived from this exact corpus (see `cybersecqwen_finetune/`) — it already
"knows" what a given tag or log line's content means, so no retrieved
context needs to be injected to ground it, and no separate deterministic
matcher is needed either. See `_judge_content_with_model` in
`analysis.py`. The one case that's still resolved for free (no model
call): a missing file, or a present-but-empty value — nothing to judge
either way.

**Everything else — the primary-then-verification tier structure and the
markdown report shape — is unchanged in spirit from the original
design; the output vocabulary itself was later simplified to exactly
three `final_status` outcomes: `detected`, `not_detected`,
`not_configured`.** A primary source reading "detected" is a `detected`
result, immediately. A clean primary gets cross-checked against a
verification tier (only reached once every primary source reads clean);
if verification disagrees and reads `detected`, that's simply `detected`
too — the LAST source actually evaluated is always the final word,
whether that's a lone primary with nothing else configured to check it,
or the end of a verification tier. There's no separate "unverifiable" or
"discrepancy" status: a single unverified primary source is exactly as
final as one corroborated by three, and a verification tier disagreeing
with a clean primary isn't flagged specially — it's just the detection
that tier actually surfaced. `ATTACK_RELIABLE_<type>=false` and a
genuinely missing primary file both resolve as `not_configured`,
distinguished only by an internal flag for rendering (the caveat text
vs. the missing file's path).

## 3. Evidence source shapes

Every source is one entry in `ATTACK_PRIMARY_<type>` or
`ATTACK_VERIFY_<type>`, parsed by `_parse_source_spec`:

- `"<path>"` — a bare path. Read as whole-file text; the model judges the
  raw content directly (no wrapper).
- `"<path>#<tag>"` — reads one XML element's text from that path (e.g.
  `Alert.xml#Ransom`). Wrapped as `"<ALERT>\n  <Tag>value</Tag>\n</ALERT>"`
  before being sent to the model — this exact wrapper is how `cybersecqwen`
  was trained on every tag reading, real or synthetic (confirmed: a bare
  extracted value with no tag context is out-of-distribution and makes the
  model guess "detected" almost regardless of the actual value).
- `"<pathA>;<pathB>"` — multiple files combined into **one** reading, for
  cases where a file is ambiguous alone but clear in combination with a
  sibling (e.g. `var/log/secure;rationalVault/log/rationalclient.log` for
  `user_breach`'s two-stage correlation). Rendered with a `--- path ---`
  header per file.
- A comma inside `ATTACK_PRIMARY_<type>`/`ATTACK_VERIFY_<type>` separates
  multiple **co-equal** sources — any one reading `detected` makes the
  whole tier `detected`. This is how a multi-tag attack type (`ransomware`:
  5 tags) is expressed: 5 primary sources, not 1 primary plus 4
  special-cased siblings.

Every plain-text path (not an XML tag read) is glob-matched as a PREFIX
(`path*`), which transparently handles rotating logs (confirmed:
`rationalclient.log`/`gateway.log` never exist under their bare name on
the real vault, always `..._NNN`) while still matching the bare filename
itself when a file doesn't rotate.

## 4. The one deliberate exception: literal-phrase sources

A handful of log-based evidence sources have a real writer script whose
*entire* detection logic is a grep for one fixed literal phrase — not a
judgment call at all. `gateway_unauthorized_breakin`'s `gateway.log` is
the confirmed example: `break_alert.sh` greps for the exact string
`"Possible Break-in Attempt"` and nothing else.

Routing this through the model was tried — repeatedly. Across 5
consecutive fine-tune retrains (each adding more clean-log training
examples for this one case, 2 rows growing to 7), the model consistently
misjudged a routine `SIGKILL`/restart-cycle log as `DETECTED`, reasoning
from surface vocabulary (`ALERT-SIGNAL`, `signal 9`) that sounds alarming
but isn't the actual ground truth. An exhaustive sweep of every other tag
across every other attack type in the whole `.env` config, at both
DETECTED and CLEAN values (130 cases), passed at 99.2% — this one case
was a genuine, isolated outlier, not a sign of a broader model weakness.

Since the real ground truth here is deterministic, checking it directly
is more reliable than continuing to fight the model's prior with more
training data. `analysis.py`'s `LITERAL_PHRASE_SOURCES` registry maps
`(attack_type, file)` pairs to their exact literal phrase; `_evaluate_source`
checks it before ever calling the model, resolving instantly (no model
call, no latency) for the sources in that registry. This is scoped
narrowly — every other evidence source, for this and every other attack
type, is still model-judged. It's not a reversion to `known_patterns`
matching generally; it's a targeted carve-out for the specific case where
the "judgment" is provably not a judgment at all, confirmed against the
real writer script's own source.

## 5. What this buys, concretely

- Adding a new attack type is a pure `.env` edit on the vault machine —
  zero code changes on the analysis machine, zero retraining needed
  *unless* the new evidence source's content shape is genuinely novel
  (a new log format cybersecqwen has never seen). See
  [ADDING_ATTACK_TYPES.md](ADDING_ATTACK_TYPES.md).
- The analysis machine has no local state describing the vault's data —
  pointing it at a different vault with a different `.env` just works.
- No embedding model, no vector database, no ingestion step to keep in
  sync with a JSON corpus.
- The failure mode when the model is wrong is narrow and knowable: a
  content shape it wasn't trained on well enough, fixable by adding
  training examples (see `cybersecqwen_finetune/generate_new_attack_examples.py`)
  — or, in the rare case that turns out to be a deterministic check in
  disguise, the `LITERAL_PHRASE_SOURCES` carve-out above.
