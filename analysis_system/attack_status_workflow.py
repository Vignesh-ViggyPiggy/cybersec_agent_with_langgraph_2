"""
attack_status_workflow.py — per-attack detection workflow, generic evidence engine.

For each attack type known to corpus_server.py (see lib/attack_status_data.py
and corpus_documents/attack_*.json), independently:
  1. Resolve this attack type's ordered `evidence_sources` list from its
     corpus entry (see EVIDENCE_ENGINE_DESIGN.md for the full design).
  2. Walk the PRIMARY-tier sources (the live status tag(s)/file(s) — e.g.
     Alert.xml's tag, or a text-pattern scan of an output file). Any one of
     them reading as "detected" -> detected, explain, done. (Multiple
     primary sources are co-equal — this is how a multi-tag attack type
     like ransomware's Ransom/bin/lib/honeypot/Process, "any one of five",
     is expressed: 5 primary-tier sources, not 1 primary + 4 verification.)
  3. If every primary source reads clean, walk the VERIFICATION-tier
     sources in order (if any) — each interpreted the SAME way a primary
     source is (known deterministic patterns first, then an LLM judgment
     call if the source allows one and no pattern matched). Any one
     reading "detected" -> discrepancy, script re-run suggested, explained
     anyway. All reading clean -> not_detected (verified). No verification
     tier configured at all -> not_detected_unverifiable.
  4. Render this attack's conclusion as one markdown section, append it to
     the running report file, and DISCARD everything else about this attack
     before moving to the next one. This is deliberate — context stays flat
     regardless of how many attack types get processed, instead of growing
     with every iteration.

This collapses what used to be two separate hardcoded verification paths
(readable_report's LLM-only check, check_raw_logs's per-attack-type Python
matcher functions) into one generic mechanism: every evidence source —
whether an XML tag, a text/log pattern scan, or a rotating log file — is
interpreted the same way, driven entirely by each source's own
`known_patterns`/`default_verdict`/`judgment_allowed` corpus fields. Adding
a new attack type of any evidence shape (see ADDING_ATTACK_TYPES.md) now
never requires a Python change, including the shapes that used to need a
RAW_LOG_CHECKERS function.

Before any of that: this hierarchy's vault data (/rationalVault/data/<hierarchy>
on the actual vault machine) is pulled down via MCP into a local working copy
under hierarchies/<hierarchy>/, using the same populate_hierarchies.py
mechanism the rest of this codebase already uses — every file read above
happens against that local copy, never against the remote vault directly.
This is what lets the workflow run from the analysis machine instead of
requiring it to run co-located with the vault's real filesystem.

After every attack type has been processed:
  - lib/log_analysis_workflow.py's context-flat per-incident pipeline runs
    as the catch-all for whatever these fixed per-attack checks structurally
    can't catch (secure/messages/audit.log), appending its own sections
    directly into this same report. Always runs — not opt-in.
  - the final summary is a plain string/regex parse of the accumulated
    markdown's status lines, not another LLM call — cheap and reliable for
    something that's just counting.
  - the finished report is pushed back up to the vault (alongside the source
    files it was generated from) via the same upload_file/send_files
    mechanism trigger_mcp_server.py already uses for the log-analysis
    pipeline's own reports.

Requires corpus_server.py already running (python corpus_server.py from this
directory) — every attack type's evidence_sources now comes from that
vector store, not a local flat file. No local fallback if it's down. Also
requires MCP_SERVER_URL (.env) pointing at the vault machine's running
mcp_server.py, for the pull/push steps.

Usage:
    python attack_status_workflow.py 5/101/1/4/1
    python attack_status_workflow.py 5/101/1/4/1 --vault-root /rationalVault/data
"""

from typing import TypedDict, Literal, NotRequired
from pathlib import Path
from datetime import datetime
import argparse
import re
import xml.etree.ElementTree as ET

from langchain_core.prompts import ChatPromptTemplate
from langgraph.graph import StateGraph, END
from pydantic import BaseModel, Field
from ddgs import DDGS

from lib.attack_status_data import get_known_attack_types, get_enabled_attack_types, get_attack_entry
from lib.populate_hierarchies import populate_hierarchies
from lib.mcp_client import send_files

# Reused, not reimplemented — DEFAULT_VAULT_ROOT's canonical definition lives here.
from lib.anomaly_workflow import DEFAULT_VAULT_ROOT

# The single shared Ollama client instance — same model, same timeout, same
# env-var overrides used by lib/log_analysis_workflow.py.
from lib.llm_client import model

STATUS_MARKER = "STATUS_MARKER"  # used to make the markdown machine-parsable


# ── State ──────────────────────────────────────────────────────────────────

class EvidenceSourceResult(TypedDict):
    file: str
    tag: NotRequired[str | None]       # the XML tag name, for xml_tag sources -- more specific than `file` alone
    tier: str                          # "primary" | "verification"
    existed: bool                      # False if the file (or every rotated/listed file) was missing
    verdict: str                       # "detected" | "not_detected" | "inconclusive"
    meaning: str
    content: NotRequired[str | None]   # raw value/text read, for display
    matched: NotRequired[str | None]   # which known_pattern matched, if any


class AttackState(TypedDict):
    attack_type: str
    hierarchy: str
    vault_root: str

    meaning: str
    writer_script: str
    ui_feature_name: NotRequired[str | None]
    confidence: str
    evidence_sources: list[dict]
    caveat: NotRequired[str]
    data_source_reliable: NotRequired[bool]

    primary_results: NotRequired[list[EvidenceSourceResult]]
    verification_results: NotRequired[list[EvidenceSourceResult]]
    triggering_results: NotRequired[list[EvidenceSourceResult]]
    final_status: NotRequired[str]     # detected | not_detected | not_detected_unverifiable | discrepancy | not_configured | cannot_determine
    explainer_text: NotRequired[str]
    corroborating_evidence_text: NotRequired[str]
    markdown_section: NotRequired[str]


class SourceJudgmentResult(BaseModel):
    verdict: Literal["detected", "not_detected", "inconclusive"] = Field(
        description="detected if this evidence clearly shows the attack occurred; not_detected if it "
                    "clearly supports a clean result; inconclusive if the evidence doesn't clearly "
                    "support either."
    )
    reasoning: str = Field(description="1-3 sentence justification citing what was found in the evidence.")


# ── Helpers ────────────────────────────────────────────────────────────────

def _read_xml_tags(file_path: Path, tag_names: list[str]) -> tuple[dict[str, str | None], bool]:
    """Flat-tag XML read — return value distinguishes "file doesn't exist
    here" from "file exists but is malformed or lacks the tag". On the real
    system, only a configured subset of a client's files ever get copied up
    to rationalVault/data/<hierarchy>/, so a missing file usually means
    "never configured to sync from that client", not "clean"."""
    if not file_path.exists():
        return {}, False
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        values = {}
        for tag_name in tag_names:
            element = root.find(tag_name)
            values[tag_name] = element.text if element is not None else None
        return values, True
    except Exception:
        return {}, True


def _read_text_file(file_path: Path, max_chars: int = 4000) -> tuple[str | None, bool]:
    """Same missing-vs-unreadable distinction as _read_xml_tags."""
    if not file_path.exists():
        return None, False
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
        return content[:max_chars], True
    except Exception:
        return None, True


def _hierarchy_path(vault_root: str, hierarchy: str) -> Path:
    return Path(vault_root) / hierarchy.strip("/\\")


def _read_evidence_source(vault_root: str, hierarchy: str, source: dict) -> tuple[str | None, bool]:
    """Reads one evidence source per its read_as/rotates config. `file` may
    be a single path or a list of paths — e.g. user_breach's sshd signal
    spans both var/log/secure and rationalclient.log, and a multi-file
    readable_report verification (e.g. immutable_attribute_drift's
    secOpsOutput_96 + imm_changes) needs every file combined into ONE
    blob, not judged file-by-file — a file that's ambiguous read alone
    (e.g. an expected-empty detail file with no findings) can be entirely
    clear in combination with its sibling file, exactly how the old
    verify_against_raw_evidence_node always combined every raw_evidence_files
    entry into one LLM call rather than one call per file. rotates=True
    glob-matches each path as a prefix (`path*`), since these logs rotate
    on the real system (confirmed: rationalclient.log/gateway.log never
    exist under their bare name, always `..._NNN`). Returns (content,
    existed) — existed=False means nothing was found at all."""
    hierarchy_root = _hierarchy_path(vault_root, hierarchy)
    files = source["file"] if isinstance(source["file"], list) else [source["file"]]

    if source.get("read_as") == "xml_tag":
        # xml_tag reads exactly one file/tag -- never a list.
        file_path = hierarchy_root / files[0]
        values, existed = _read_xml_tags(file_path, [source["tag"]])
        return (values.get(source["tag"]) if existed else None), existed

    parts: list[str] = []
    any_existed = False
    multi = len(files) > 1 or source.get("rotates")
    for f in files:
        paths = sorted(hierarchy_root.glob(f + "*")) if source.get("rotates") else [hierarchy_root / f]
        for p in paths:
            content, existed = _read_text_file(p, max_chars=20000 if source.get("rotates") else 8000)
            if existed:
                any_existed = True
            if existed and content:
                parts.append(f"--- {p.relative_to(hierarchy_root)} ---\n{content}" if multi else content)
    return ("\n\n".join(parts) if parts else ""), any_existed


def _match_known_patterns(value: str | None, known_patterns: list[dict]) -> tuple[str, str, str | None] | None:
    """Tries each known_patterns entry in declared order; returns
    (verdict, meaning, matched_repr) for the first match, or None if
    nothing matched. Three matcher kinds:
      - "value": exact string equality (tag reads == this literal)
      - "min_value": int(value) >= this threshold (count-style checks)
      - "non_empty": value has any non-whitespace content at all
      - "pattern": regex search (supports named groups + backreferences,
        e.g. correlating the same captured IP across two lines — see
        EVIDENCE_ENGINE_DESIGN.md §1 for why this replaces bespoke
        per-attack-type Python matcher functions)
    """
    if value is None:
        return None
    for kp in known_patterns:
        if "value" in kp:
            if value == kp["value"]:
                return ("detected" if kp["detected"] else "not_detected", kp.get("meaning", ""), kp["value"])
        elif "min_value" in kp:
            try:
                if int(value) >= kp["min_value"]:
                    return ("detected" if kp["detected"] else "not_detected", kp.get("meaning", ""),
                            f">= {kp['min_value']}")
            except (TypeError, ValueError):
                continue
        elif "non_empty" in kp:
            if bool(value.strip()) == bool(kp["non_empty"]):
                return ("detected" if kp["detected"] else "not_detected", kp.get("meaning", ""), "non_empty")
        elif "pattern" in kp:
            flags = 0
            for flag_name in kp.get("flags", []):
                flags |= getattr(re, flag_name)
            if re.search(kp["pattern"], value, flags):
                return ("detected" if kp["detected"] else "not_detected", kp.get("meaning", ""), kp["pattern"])
    return None


def _judge_source_with_llm(attack_type: str, meaning: str, content: str, examples: list[dict]) -> tuple[str, str]:
    """LLM fallback for a source with judgment_allowed=true whose
    known_patterns didn't match anything — same role today's
    verify_against_raw_evidence_node played, generalized to any evidence
    source instead of only readable_report types. Grounded by this
    source's own labeled examples, same as before."""
    example_lines = "\n".join(
        f"  [{ex.get('label', '?')}] {ex.get('content', '')}\n    ({ex.get('note', '')})"
        for ex in (examples or [])
    ) or "(none provided)"

    template = ChatPromptTemplate.from_messages([
        ("system",
         "You are a cybersecurity analyst judging one piece of evidence for one specific attack type. "
         "Decide whether this evidence clearly shows the attack occurred (detected), clearly supports a "
         "clean result (not_detected), or is genuinely inconclusive either way. Labeled examples below are "
         "illustrative reference only, not real findings — base your judgment ONLY on the actual live "
         "content given. A shared multi-purpose file may contain unrelated indicators for other attack "
         "types — only judge evidence SPECIFIC to this attack type; unrelated indicators elsewhere in the "
         "same file are not evidence against or for this one. A restated pass/fail verdict line with no "
         "further checkable detail is weak corroboration, not independent evidence — weigh specific, "
         "checkable detail (file paths, counts, timestamps) more heavily."),
        ("user",
         "Attack type: {attack_type}\nWhat this status normally means: {meaning}\n\n"
         "Illustrative examples (not real findings):\n{examples}\n\n"
         "ACTUAL LIVE CONTENT:\n{content}\n\n"
         "detected, not_detected, or inconclusive?")
    ])
    try:
        structured_model = model.with_structured_output(SourceJudgmentResult)
        result = (template | structured_model).invoke({
            "attack_type": attack_type, "meaning": meaning, "examples": example_lines, "content": content,
        })
        return result.verdict, result.reasoning
    except Exception as e:
        return "inconclusive", f"Judgment pass failed ({e}); treated as inconclusive."


def _evaluate_source(state: AttackState, source: dict, tier: str) -> EvidenceSourceResult:
    """Reads one evidence source and resolves it to a verdict: pattern
    match first (free, deterministic) -> default_verdict if the source
    declares one and nothing matched (this is what makes a plain
    text-pattern scan like rootkit_malware's "no Warning: line = clean"
    resolve definitively instead of falling through to inconclusive) ->
    an LLM judgment if judgment_allowed and still nothing resolved ->
    inconclusive as the final fallback."""
    value, existed = _read_evidence_source(state["vault_root"], state["hierarchy"], source)
    file_display = ", ".join(source["file"]) if isinstance(source["file"], list) else source["file"]
    base: EvidenceSourceResult = {"file": file_display, "tag": source.get("tag"), "tier": tier, "existed": existed}

    if not existed:
        # A source can declare default_verdict for exactly this case too --
        # e.g. readable_report verification sources default to not_detected
        # when their evidence file(s) are missing, matching the old
        # verify_against_raw_evidence_node's explicit "expected evidence not
        # found -- fall back to the tag's own 'not detected' status" behavior,
        # rather than treating a merely-unsynced file as a red flag.
        if "default_verdict" in source:
            return {**base, "verdict": source["default_verdict"],
                    "meaning": source.get("default_meaning", "") +
                               " (Evidence file not found -- not configured to sync from the client system.)",
                    "content": None}
        return {**base, "verdict": "inconclusive",
                "meaning": "File not found — not configured to sync from the client system.", "content": None}

    matched = _match_known_patterns(value, source.get("known_patterns", []))
    if matched:
        verdict, meaning, matched_repr = matched
        return {**base, "verdict": verdict, "meaning": meaning, "content": value, "matched": matched_repr}

    if source.get("judgment_allowed") and value:
        verdict, meaning = _judge_source_with_llm(state["attack_type"], state["meaning"], value, source.get("examples", []))
        return {**base, "verdict": verdict, "meaning": meaning, "content": value}

    if "default_verdict" in source:
        return {**base, "verdict": source["default_verdict"], "meaning": source.get("default_meaning", ""), "content": value}

    return {**base, "verdict": "inconclusive",
            "meaning": "No known pattern matched; no default or judgment configured.", "content": value}


def _format_provenance_chain(writer_script: str, files_checked: str) -> str:
    """Renders writer_script as a step-by-step chain from the root source
    down to the file(s) this workflow actually reads. writer_script is an
    arrow-delimited chain (" -> ") wherever a real multi-hop provenance was
    confirmed from source; entries with no confirmed chain render as a
    single step."""
    hops = [h.strip() for h in writer_script.split(" -> ") if h.strip()] or [writer_script]
    lines = [f"{i}. {hop}" for i, hop in enumerate(hops, start=1)]
    lines.append(f"{len(hops) + 1}. **`{files_checked}`** *(this workflow reads here)*")
    return "\n".join(lines)


# ── Nodes ──────────────────────────────────────────────────────────────────

def resolve_attack_node(state: AttackState) -> AttackState:
    """Corpus lookup by exact id — attack_type is a fixed known key at this
    point (resolved from get_enabled_attack_types()), not a free-text query."""
    entry = get_attack_entry(state["attack_type"])
    metadata = entry["metadata"]

    updated = dict(state)
    updated.update({
        "meaning": entry["explanation"],
        "writer_script": metadata.get("writer_script", "unknown"),
        "ui_feature_name": metadata.get("ui_feature_name"),
        "confidence": metadata.get("confidence", "unknown"),
        "evidence_sources": metadata.get("evidence_sources", []),
    })
    if "caveat" in metadata:
        updated["caveat"] = metadata["caveat"]
    updated["data_source_reliable"] = metadata.get("data_source_reliable", True)
    return updated


def route_after_resolve(state: AttackState) -> str:
    """A known-unreliable data source is checked before anything else."""
    return "cannot_determine" if not state.get("data_source_reliable", True) else "run_chain"


def cannot_determine_node(state: AttackState) -> AttackState:
    return {**state, "final_status": "cannot_determine"}


def run_evidence_chain_node(state: AttackState) -> AttackState:
    """The generic evidence engine (see module docstring +
    EVIDENCE_ENGINE_DESIGN.md). Two tiers, walked in order:

    PRIMARY tier — the live status read(s). All primary sources are
    evaluated (not stopped at the first), because a multi-tag attack type
    (e.g. ransomware's 5 co-equal tags) needs every triggered one reported,
    not just the first. Any primary source detected -> final_status
    "detected", explained, done.

    VERIFICATION tier — only reached if every primary source read clean.
    Walked in order; the first one to read "detected" makes this a
    "discrepancy" (the tag said clean, independent evidence disagreed).
    If none are configured, or none are checkable, the clean primary
    result is reported as "not_detected_unverifiable" — unverified, but
    not treated as suspicious. If every configured verification source
    reads clean, "not_detected" (verified across N independent sources).
    """
    sources = state.get("evidence_sources") or []
    primary_sources = [s for s in sources if s.get("tier", "primary") == "primary"]
    verification_sources = [s for s in sources if s.get("tier") == "verification"]

    primary_results: list[EvidenceSourceResult] = []
    for i, source in enumerate(primary_sources):
        result = _evaluate_source(state, source, "primary")
        if not result["existed"] and i == 0:
            # The FIRST primary source's file is genuinely missing -- this
            # attack type's status can't be determined at all for this
            # hierarchy (most likely never configured to sync), distinct
            # from every other source-missing case below.
            return {**state, "primary_results": primary_results + [result], "final_status": "not_configured"}
        primary_results.append(result)

    detected_primaries = [r for r in primary_results if r["verdict"] == "detected"]
    if detected_primaries:
        return {**state, "primary_results": primary_results, "triggering_results": detected_primaries,
                "final_status": "detected"}

    verification_results: list[EvidenceSourceResult] = []
    for source in verification_sources:
        result = _evaluate_source(state, source, "verification")
        verification_results.append(result)
        if result["verdict"] == "detected":
            return {**state, "primary_results": primary_results, "verification_results": verification_results,
                    "triggering_results": [result], "final_status": "discrepancy"}

    verified_clean_count = sum(1 for r in verification_results if r["verdict"] == "not_detected")
    final_status = "not_detected" if verified_clean_count >= 1 and verification_results and \
        all(r["verdict"] == "not_detected" for r in verification_results) else "not_detected_unverifiable"

    return {**state, "primary_results": primary_results, "verification_results": verification_results,
            "final_status": final_status}


def route_after_chain(state: AttackState) -> str:
    return "attack_info" if state["final_status"] in ("detected", "discrepancy") else "render"


def _read_corroborating_evidence(state: AttackState) -> str:
    """Reads every evidence source that WASN'T already read as part of
    reaching this result (or re-displays what was), for display in the
    rendered report — matches the old behavior of always showing every
    declared evidence file's content on a detected/discrepancy result,
    not just whichever one specifically triggered it."""
    pieces = []
    for tier_results in (state.get("primary_results") or [], state.get("verification_results") or []):
        for r in tier_results:
            if r.get("content"):
                content = r["content"]
                display = content if len(content) <= 1500 else content[:1500]
                pieces.append(f"--- {r['file']} ---\n{display}")
    return "\n\n".join(pieces)


def attack_info_node(state: AttackState) -> AttackState:
    """Explain the attack + recommended actions, using the same
    search-then-synthesize approach as lib/log_analysis_workflow.py's own
    per-incident search/explain steps."""
    attack_type = state["attack_type"]
    corroborating_evidence_text = _read_corroborating_evidence(state)

    queries = [
        f"what is a {attack_type.replace('_', ' ')} cyberattack",
        f"how to respond to and remediate a {attack_type.replace('_', ' ')} attack",
    ]

    snippets = []
    for query in queries:
        try:
            with DDGS() as ddgs:
                for r in list(ddgs.text(query, max_results=3)):
                    snippets.append(f"- {r.get('title', '')}: {r.get('body', '')}")
        except Exception as e:
            snippets.append(f"- (search failed for '{query}': {e})")

    template = ChatPromptTemplate.from_messages([
        ("system",
         "You are a cybersecurity analyst writing a short, plain-language "
         "explanation for a customer dashboard. Given search snippets about an "
         "attack type, write: (1) a 2-3 sentence explanation of what this "
         "attack is, and (2) 3-5 concrete recommended actions, as a bullet list."),
        ("user", "Attack type: {attack_type}\n\nSearch results:\n{snippets}")
    ])

    try:
        response = (template | model).invoke({
            "attack_type": attack_type,
            "snippets": "\n".join(snippets) if snippets else "No search results available.",
        })
        explainer_text = getattr(response, "content", str(response))
    except Exception as e:
        explainer_text = f"(Explanation generation failed: {e})"

    return {**state, "explainer_text": str(explainer_text), "corroborating_evidence_text": corroborating_evidence_text}


def render_markdown_section_node(state: AttackState) -> AttackState:
    attack_label = state["attack_type"].replace("_", " ").title()
    final_status = state["final_status"]

    # STATUS_MARKER (the HTML comment) always carries the real, precise
    # status for accurate summary counts — but not_detected_unverifiable is
    # displayed to the reader as plain "NOT DETECTED", since the
    # unverified/verified distinction is now conveyed by whether a
    # verification tier was actually checked, not by a separate status word.
    display_status = "not_detected" if final_status == "not_detected_unverifiable" else final_status

    def _label(r: EvidenceSourceResult) -> str:
        """The tag name is more specific than the file when the source is
        an xml_tag read (e.g. ransomware's 5 tags all live in Alert.xml --
        naming the file alone can't distinguish which one triggered)."""
        return r["tag"] if r.get("tag") else r["file"]

    sources = state.get("evidence_sources") or []
    all_results = (state.get("primary_results") or []) + (state.get("verification_results") or [])
    files_checked = ", ".join(dict.fromkeys(r["file"] for r in all_results)) or "(none read)"
    labels_checked = ", ".join(dict.fromkeys(_label(r) for r in all_results)) or "(none read)"

    lines = [f"## {attack_label}", "", f"<!-- {STATUS_MARKER}: {final_status} -->"]
    lines.append(f"**Status:** {display_status.replace('_', ' ').upper()}")
    lines.append(f"\n**Source chain:**\n{_format_provenance_chain(state['writer_script'], files_checked)}")

    if final_status == "detected":
        triggering = state.get("triggering_results") or []
        if len(triggering) > 1 or (state.get("primary_results") and len(state["primary_results"]) > 1):
            triggered_labels = ", ".join(_label(r) for r in triggering)
            lines.append(f"\n**Triggering evidence:** `{triggered_labels}` (out of `{labels_checked}` checked)")
        elif triggering:
            lines.append(f"\n**Triggering evidence:** `{_label(triggering[0])}` — {triggering[0]['meaning']}")
        lines.append(f"\n{state['meaning']}")
        if state.get("corroborating_evidence_text"):
            lines.append(f"\n### Corroborating raw evidence\n\n```\n{state['corroborating_evidence_text']}\n```")
        lines.append(f"\n### What this attack is / recommended actions\n\n{state.get('explainer_text', '')}")

    elif final_status == "discrepancy":
        triggering = (state.get("triggering_results") or [{}])[0]
        lines.append(
            f"\n⚠ The status tag says 'not detected', but independent review of `{_label(triggering) if triggering else '?'}` "
            f"disagreed: {triggering.get('meaning', '')}"
        )
        feature_ref = state.get("ui_feature_name") or f"the feature that manages `{state['writer_script']}`"
        lines.append(
            f"\n**Recommended:** re-run **{feature_ref}** from the dashboard "
            f"for an authoritative fresh determination."
        )
        if state.get("corroborating_evidence_text"):
            lines.append(f"\n### Corroborating raw evidence\n\n```\n{state['corroborating_evidence_text']}\n```")
        lines.append(f"\n### What this attack is / recommended actions\n\n{state.get('explainer_text', '')}")

    elif final_status == "not_detected":
        lines.append(f"\n✅ Not detected. Verified clean across {len(all_results)} evidence source(s): {files_checked}.")

    elif final_status == "not_detected_unverifiable":
        primary_results = state.get("primary_results") or []
        live_value_display = primary_results[0].get("content") if primary_results else None
        if live_value_display and "\n" in str(live_value_display):
            value_line = f"currently reads:\n\n```\n{live_value_display}\n```"
        else:
            value_line = f"currently reads `{live_value_display}`."
        lines.append(
            f"\n✅ Not detected -- `{files_checked}` {value_line}\n\n"
            f"No further evidence source was conclusive, so this reading could not be "
            f"cross-checked against anything else — it reflects only what the primary source reports."
        )
        lines.append(f"\n**What determines this status:**\n\n{state.get('meaning', '')}")

    elif final_status == "not_configured":
        first_file = sources[0]["file"] if sources else "?"
        first_file_display = ", ".join(first_file) if isinstance(first_file, list) else first_file
        vault_display = f"rationalVault/data/{state['hierarchy']}/{first_file_display}"
        lines.append(
            f"\n❓ **File not configured for this system.** `{first_file_display}` was not "
            f"found at `{vault_display}`. This file was not configured to be copied to the "
            f"RV server from the client system for this hierarchy, so this attack type's "
            f"status could not be checked — this is not the same as a clean result."
        )

    else:  # cannot_determine
        lines.append(
            "\n⛔ **Cannot determine.** The data source for this attack type is known "
            "to be unreliable independent of its current value — see the known-issue "
            "note above. Do not treat this as either detected or clean."
        )

    return {**state, "markdown_section": "\n".join(lines) + "\n"}


# ── Graph assembly ─────────────────────────────────────────────────────────

def build_attack_graph():
    workflow = StateGraph(AttackState)

    workflow.add_node("resolve", resolve_attack_node)
    workflow.add_node("cannot_determine", cannot_determine_node)
    workflow.add_node("run_chain", run_evidence_chain_node)
    workflow.add_node("attack_info", attack_info_node)
    workflow.add_node("render", render_markdown_section_node)

    workflow.set_entry_point("resolve")

    workflow.add_conditional_edges("resolve", route_after_resolve, {
        "cannot_determine": "cannot_determine",
        "run_chain": "run_chain",
    })

    workflow.add_conditional_edges("run_chain", route_after_chain, {
        "attack_info": "attack_info",
        "render": "render",
    })

    workflow.add_edge("attack_info", "render")
    workflow.add_edge("cannot_determine", "render")
    workflow.add_edge("render", END)

    return workflow.compile()


_attack_graph = None


def _get_attack_graph():
    global _attack_graph
    if _attack_graph is None:
        _attack_graph = build_attack_graph()
    return _attack_graph


# ── Outer driver ───────────────────────────────────────────────────────────

def run_attack_status_loop(hierarchy: str, vault_root: str, report_path: Path) -> None:
    """Runs every ENABLED attack type (see get_enabled_attack_types) as an
    isolated invocation of the compiled graph, appending each conclusion to
    report_path and discarding the rest of that attack's state before moving
    to the next."""
    graph = _get_attack_graph()
    enabled = get_enabled_attack_types()
    known_count = len(get_known_attack_types())

    with open(report_path, "a", encoding="utf-8") as f:
        f.write(
            f"# Attack Status Report\n\n**Hierarchy:** `{hierarchy}`  \n"
            f"**Generated:** {datetime.now().isoformat()}  \n"
            f"**Attack types checked:** {len(enabled)} of {known_count} known\n\n"
        )

    for attack_type in enabled:
        initial_state: AttackState = {
            "attack_type": attack_type,
            "hierarchy": hierarchy,
            "vault_root": vault_root,
        }
        result = graph.invoke(initial_state)
        with open(report_path, "a", encoding="utf-8") as f:
            f.write(result["markdown_section"] + "\n")
        # `result` (and everything it references — evidence text, search
        # snippets) goes out of scope here. Nothing from this attack carries
        # into the next iteration except what's already been written to disk.


def parse_deterministic_summary(report_path: Path) -> dict:
    """Plain regex count of the status markers written by
    render_markdown_section_node — no LLM call for something that's just
    counting."""
    try:
        content = report_path.read_text(encoding="utf-8")
    except Exception:
        return {}

    counts: dict[str, int] = {}
    for match in re.finditer(rf"<!-- {STATUS_MARKER}: (\w+) -->", content):
        status = match.group(1)
        counts[status] = counts.get(status, 0) + 1
    return counts


def render_summary_block(counts: dict) -> str:
    total = sum(counts.values())
    lines = ["## Summary", "", f"**{total} attack types checked.**", ""]
    for status in ("detected", "discrepancy", "not_detected", "not_detected_unverifiable", "cannot_determine", "not_configured"):
        if status in counts:
            lines.append(f"- {status.replace('_', ' ')}: {counts[status]}")
    return "\n".join(lines) + "\n"


# ── Top-level entry point ─────────────────────────────────────────────────

# Matches trigger_mcp_server.py's HIERARCHIES_DIR convention (Path(__file__).parent
# / "hierarchies") and the log-analysis pipeline's report location
# (hierarchies/<hierarchy>/analysis_report_*.md) — reports from this workflow
# now live alongside those, under their own reports/ subfolder rather than in
# whatever directory happened to be the current working directory.
DEFAULT_HIERARCHIES_DIR = Path(__file__).parent / "hierarchies"


def run_full_workflow(
    hierarchy: str,
    vault_root: str = DEFAULT_VAULT_ROOT,
    hierarchies_dir: Path = DEFAULT_HIERARCHIES_DIR,
    sync_with_vault: bool = True,
) -> dict:
    hierarchy_clean = hierarchy.strip("/\\")

    # Pull this hierarchy's vault data down to a local working copy via MCP,
    # same mechanism populate_hierarchies.py already uses for the log-analysis
    # pipeline — every read in this workflow happens against that local copy,
    # never against vault_root directly, since vault_root is a path on the
    # REMOTE vault machine, not necessarily accessible from wherever this
    # process runs. sync_with_vault=False skips this (and the push-back at
    # the end) for local testing against a filesystem path that's already
    # local, e.g. a scratch directory with hand-built test fixtures.
    if sync_with_vault:
        print(f"Pulling {vault_root}/{hierarchy_clean} -> {hierarchies_dir / hierarchy_clean} ...")
        populate_hierarchies(vault_root, hierarchies_dir, hierarchy_clean)

    reports_dir = hierarchies_dir / hierarchy_clean / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / f"attack_status_report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.md"

    # Reads resolve against the local pulled copy (hierarchies_dir), not the
    # remote vault_root — _hierarchy_path()'s existing Path(x)/hierarchy join
    # is reused unchanged, just fed hierarchies_dir in vault_root's place.
    local_root = str(hierarchies_dir) if sync_with_vault else vault_root
    run_attack_status_loop(hierarchy, local_root, report_path)

    summary_counts = parse_deterministic_summary(report_path)
    with open(report_path, "a", encoding="utf-8") as f:
        f.write(render_summary_block(summary_counts))

    # Catch-all: secure/messages/audit.log analysis for whatever the fixed
    # per-attack checks above structurally can't catch. Uses
    # lib/log_analysis_workflow.py's context-flat restructure (classify once,
    # then an isolated invoke-append-discard pass per incident — the same
    # convention run_attack_status_loop already uses above) instead of the
    # old single-linear-graph pipeline, which re-sent the full raw log text
    # to the LLM at multiple nodes and grew every step of one run. Appends
    # directly into THIS SAME report_path rather than a separate file. Always
    # runs, after the attack checks — not opt-in.
    from lib.log_analysis_workflow import run_log_analysis_loop
    # Reads from local_root (the SAME already-pulled local copy the attack
    # checks above just read from), not vault_root — this module does no
    # pulling of its own. See its module docstring.
    log_analysis_result = run_log_analysis_loop(hierarchy, Path(local_root), report_path)

    # Push the finished report back up to the vault, alongside the source
    # files it was generated from — same upload_file/send_files mechanism
    # trigger_mcp_server.py already uses for the log-analysis pipeline's reports.
    vault_upload_result = None
    if sync_with_vault:
        vault_upload_result = send_files(
            str(report_path), "upload_file",
            relative_path=f"{hierarchy_clean}/reports/{report_path.name}",
        )
        print(f"Uploaded report to vault: {vault_upload_result}")

    return {
        "hierarchy": hierarchy,
        "report_path": str(report_path),
        "summary_counts": summary_counts,
        "log_analysis": log_analysis_result,
        "vault_upload_result": vault_upload_result,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the per-attack status workflow for one hierarchy, followed by "
                    "secure/messages/audit.log analysis as a catch-all — always both, one report."
    )
    parser.add_argument("hierarchy", help="e.g. 5/101/1/4/1")
    parser.add_argument("--vault-root", default=DEFAULT_VAULT_ROOT)
    parser.add_argument("--hierarchies-dir", default=str(DEFAULT_HIERARCHIES_DIR),
                         help="Reports are written under <hierarchies-dir>/<hierarchy>/reports/.")
    parser.add_argument("--no-sync", action="store_true",
                         help="Skip the MCP pull/push to the vault — read/write hierarchies-dir directly "
                              "as if it were already the vault data (for local testing with hand-built "
                              "fixtures, not for real use).")
    args = parser.parse_args()

    result = run_full_workflow(
        args.hierarchy, args.vault_root, Path(args.hierarchies_dir),
        sync_with_vault=not args.no_sync,
    )
    print(f"\nReport written to: {result['report_path']}")
    print(f"Summary: {result['summary_counts']}")
    if result.get("vault_upload_result"):
        print(f"Vault upload: {result['vault_upload_result']}")


if __name__ == "__main__":
    main()
