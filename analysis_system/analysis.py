"""
analysis.py — the whole analysis pipeline in one file: MCP transport to the
vault machine, the per-attack evidence engine, and the catch-all log
analysis pass. Companion to lib/llm_client.py (the shared Ollama client) —
the only other module in this package, and the only one never run directly.

This is a from-scratch redesign of the old analysis_system/ package's
attack_status_workflow.py + lib/*, with three deliberate differences:

1. NO RAG. The old package resolved each attack type's evidence sources by
   querying corpus_server.py, a FastMCP service fronting a Chroma vector
   store (corpus_documents/*.json). That whole corpus/embedding/database
   stack is gone. Instead, hierarchy_system/mcp_server.py's
   get_attack_checklist tool reads a single flat .env on the VAULT machine
   (ATTACK_ORDER, ATTACK_PRIMARY_<type>, ATTACK_VERIFY_<type>, LOG_FILE_PATHS,
   etc. — see that package's .env.example) and returns the whole check order +
   evidence file/tag paths for every attack type, plus which log files the
   catch-all log-analysis pass reads, as one dict. This process fetches it
   ONCE per run (see fetch_attack_checklist below), not once per attack type.
   This package's own .env only holds things that are genuinely local to the
   analysis machine (model name/timeout, MCP_SERVER_URL) — nothing about
   which hierarchy-side files get checked.

2. The fine-tuned cybersecqwen model judges EVERY evidence source directly —
   no known_patterns regex matching at all. cybersecqwen was fine-tuned
   specifically on content -> "Status: DETECTED|CLEAN. <1-3 sentence
   grounded explanation>" pairs derived from this exact corpus (see
   cybersecqwen_finetune/SESSION_SUMMARY.md) — it already "knows" what a
   given tag/file's content means, so no retrieved context needs to be
   injected into the prompt to ground it, and no separate deterministic
   matcher is needed either. See _judge_content_with_model. The one
   deterministic case that's still free (no LLM call): a missing file, or a
   present-but-empty value — nothing to judge either way.

3. Every non-metric tag in the real Alert.xml (40 tags) and
   athinio/system/alertlog.xml (25 tags) has a configured checking path in
   hierarchy_system/.env — 38 attack types total (23 ported from the old
   corpus, 15 added for full coverage; see that .env's comments for exactly
   which tag maps to which attack type, and which few tags were left out as
   pure metrics/timestamps rather than attack indicators).

Everything else — the six final_status outcomes (detected / discrepancy /
not_detected / not_detected_unverifiable / not_configured / cannot_determine),
the primary-then-verification tier structure, the markdown report shape, and
the always-run catch-all log analysis pass — is unchanged in spirit from the
old package.

Usage:
    python analysis.py 5/101/1/4/1
    python analysis.py 5/101/1/4/1 --vault-root /rationalVault/data
    python analysis.py 5/101/1/4/1 --vault-root hierarchies --no-sync   (local testing)
"""

from typing import TypedDict, Literal, List, NotRequired
from pathlib import Path
from datetime import datetime
from collections import Counter
import argparse
import asyncio
import base64
import json
import os
import re
import sys
import time
import xml.etree.ElementTree as ET

from dotenv import load_dotenv

# Must run BEFORE importing lib.llm_client — that module reads MODEL_NAME
# (and the other MODEL_* knobs) from the environment at import time, so
# loading .env any later would silently leave it on the "cybersecqwen"
# default instead of whatever MODEL_NAME is actually set to.
load_dotenv()

from fastmcp import Client
from langchain_core.prompts import ChatPromptTemplate
from langgraph.graph import StateGraph, END
from pydantic import BaseModel, Field
from ddgs import DDGS

from lib.llm_client import model, CYBERSECQWEN_JUDGE_SYSTEM_PROMPT

# Windows consoles sometimes default to a non-UTF-8 codepage.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8")
        except Exception:
            pass

MCP_SERVER_URL = os.getenv("MCP_SERVER_URL") or "http://100.90.44.5:8000/mcp"
DEFAULT_VAULT_ROOT = "/rationalVault/data"
STATUS_MARKER = "STATUS_MARKER"


def _fmt_elapsed(seconds: float) -> str:
    if seconds >= 60:
        m, s = divmod(seconds, 60)
        return f"{int(m)}m{s:.1f}s"
    return f"{seconds:.1f}s"


def _append_report(report_path: Path, text: str) -> None:
    """Every piece of markdown that gets appended to the running report goes
    through here, so the console output is always a live mirror of exactly
    what's being written to the file — not a separate summary, the same
    text, in both places, as it's produced."""
    with open(report_path, "a", encoding="utf-8") as f:
        f.write(text)
    print(text)


# ═════════════════════════════════════════════════════════════════════════
# MCP transport — talk to hierarchy_system/mcp_server.py on the vault
# machine (file pull/push, and the attack checklist).
# ═════════════════════════════════════════════════════════════════════════

def _to_plain(obj):
    """Recursively convert fastmcp/pydantic result objects into plain dict/list/scalar values."""
    if isinstance(obj, dict):
        return {k: _to_plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_plain(v) for v in obj]

    model_dump = getattr(obj, "model_dump", None)
    if callable(model_dump):
        return _to_plain(model_dump())

    # fastmcp wraps bare `dict`/`list` return annotations in a pydantic
    # RootModel client-side; unwrap it via its `.root` attribute.
    if hasattr(obj, "root"):
        return _to_plain(obj.root)

    return obj


def _unwrap_result_envelope(value):
    """
    Some fastmcp versions wrap a bare list/scalar return value in a
    {"result": <value>} envelope in the wire-format JSON (observed: a tool
    annotated to return List[dict] came back as {'result': []} instead of
    a bare list). A real fetch_directory_files/upload_file/get_attack_checklist
    result is never itself shaped like {"result": ...}, so unwrapping this
    is unambiguous.
    """
    if isinstance(value, dict) and set(value.keys()) == {"result"}:
        return value["result"]
    return value


def _extract_tool_result(result):
    """
    Pull the plain Python value out of a fastmcp CallToolResult.

    Prefer the raw JSON text blocks in `result.content` over `result.data` /
    `result.structured_content`: those attributes can come back as
    fastmcp-internal pydantic wrapper objects whose shape varies by fastmcp
    version, whereas the wire-format JSON always decodes to plain
    dict/list/scalar values via json.loads.
    """
    content = getattr(result, "content", None)
    if content:
        for block in content:
            text = getattr(block, "text", None)
            if text:
                try:
                    return _unwrap_result_envelope(json.loads(text))
                except json.JSONDecodeError:
                    continue

    structured = getattr(result, "structured_content", None)
    if structured:
        return _unwrap_result_envelope(_to_plain(structured))

    data = getattr(result, "data", None)
    if data is not None:
        return _unwrap_result_envelope(_to_plain(data))

    return _unwrap_result_envelope(_to_plain(result))


async def _call_mcp_tool_async(toolname: str, args: dict):
    client = Client(MCP_SERVER_URL)
    async with client:
        result = await client.call_tool(toolname, args)
        return _extract_tool_result(result)


def _call_mcp_tool(toolname: str, args: dict):
    return asyncio.run(_call_mcp_tool_async(toolname, args))


def fetch_directory_files(root_path: str) -> list[dict]:
    """Ask the vault's MCP server to recursively read every file under
    root_path and return each file's relative path, content, and encoding
    ("utf-8" or "base64" for binary files)."""
    return _call_mcp_tool("fetch_directory_files", {"root_path": root_path})


def decode_file_content(entry: dict) -> bytes:
    """Turn a fetch_directory_files() entry back into raw bytes."""
    content = entry.get("content", "")
    if entry.get("encoding") == "base64":
        return base64.b64decode(content)
    return content.encode("utf-8")


def send_files(file, toolname, relative_path=None):
    """Upload a local file to the vault's upload_file tool. relative_path
    controls where it lands on the vault (e.g.
    "5/101/1/4/1/analysis_report_....md"); defaults to the local file path
    if omitted."""
    with open(file, "r", encoding="utf-8") as f:
        content = f.read()
    return _call_mcp_tool(toolname, {"relative_path": relative_path or file, "content": content})


def fetch_attack_checklist() -> dict:
    """Fetch the whole attack-checking configuration (order + per-attack
    primary/verification evidence specs + writer/ui_feature/reliable/caveat
    metadata) from hierarchy_system/mcp_server.py's get_attack_checklist
    tool. Called ONCE per run (see run_full_workflow) — every attack type's
    resolve_attack_node below is then a plain in-memory dict lookup, not a
    network call. This is the ONLY configuration source for which attack
    types get checked, in what order, and against which files/tags — there
    is no local corpus file or database of any kind in this package."""
    return _call_mcp_tool("get_attack_checklist", {})


def populate_hierarchies(root_path: str, dest_dir: Path, hierarchy: str | None = None) -> None:
    """Pulls a vault subtree via MCP and writes it under dest_dir/<hierarchy>,
    mirroring the server-side {company}/{customer}/{branch}/{product}/{system}
    layout."""
    prefix = Path()
    server_path = root_path

    if hierarchy:
        hierarchy_clean = hierarchy.strip("/\\").replace("\\", "/")
        server_path = f"{root_path.rstrip('/')}/{hierarchy_clean}"
        prefix = Path(hierarchy_clean)

    print(f"Fetching files from server path: {server_path}")
    entries = fetch_directory_files(server_path)

    if not entries:
        print("No files returned. Check that the path exists on the server.")
        return

    print(f"Received {len(entries)} file(s) from server.")

    copied = 0
    skipped = 0

    for entry in entries:
        relative_path = entry.get("relative_path")
        if not relative_path:
            continue

        local_relative_path = prefix / relative_path
        target = dest_dir / local_relative_path
        new_bytes = decode_file_content(entry)

        if target.exists() and target.is_file() and target.read_bytes() == new_bytes:
            skipped += 1
            continue

        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(new_bytes)
        copied += 1
        print(f"  + {local_relative_path.as_posix()}")

    print("\nDone.")
    print(f"Copied:  {copied}")
    print(f"Skipped (unchanged): {skipped}")
    print(f"Destination: {dest_dir}")


# ═════════════════════════════════════════════════════════════════════════
# Evidence engine — read one source, judge it with the fine-tuned model.
# ═════════════════════════════════════════════════════════════════════════

class EvidenceSourceResult(TypedDict):
    file: str
    tag: NotRequired[str | None]       # the XML tag name, for "path#tag" sources
    tier: str                          # "primary" | "verification"
    existed: bool                      # False if the file (or every glob-matched file) was missing
    verdict: str                       # "detected" | "not_detected" | "inconclusive"
    meaning: str
    content: NotRequired[str | None]   # raw value/text read, for display


class AttackState(TypedDict):
    attack_type: str
    hierarchy: str
    vault_root: str
    checklist: dict                    # the {order, attacks} structure fetched once per run

    writer_script: NotRequired[str]
    ui_feature_name: NotRequired[str | None]
    caveat: NotRequired[str | None]
    primary_specs: NotRequired[list[str]]
    verify_specs: NotRequired[list[str]]
    data_source_reliable: NotRequired[bool]

    primary_results: NotRequired[list[EvidenceSourceResult]]
    verification_results: NotRequired[list[EvidenceSourceResult]]
    triggering_results: NotRequired[list[EvidenceSourceResult]]
    final_status: NotRequired[str]     # detected | not_detected | not_detected_unverifiable | discrepancy | not_configured | cannot_determine
    explainer_text: NotRequired[str]
    corroborating_evidence_text: NotRequired[str]
    markdown_section: NotRequired[str]


def _hierarchy_path(vault_root: str, hierarchy: str) -> Path:
    return Path(vault_root) / hierarchy.strip("/\\")


def _parse_source_spec(spec: str) -> tuple[list[str], str | None]:
    """"<path>#<tag>" -> ([path], tag) — xml_tag reads exactly one file,
    never a list. "<pathA>;<pathB>" -> ([pathA, pathB], None) — files
    combined into one reading. A bare "<path>" -> ([path], None)."""
    if "#" in spec:
        file_part, tag = spec.split("#", 1)
        return [file_part.strip()], tag.strip()
    return [f.strip() for f in spec.split(";") if f.strip()], None


def _read_xml_tag(file_path: Path, tag_name: str) -> tuple[str | None, bool]:
    """Return value distinguishes "file doesn't exist here" from "file
    exists but is malformed or lacks the tag". On the real system, only a
    configured subset of a client's files ever get copied up to
    rationalVault/data/<hierarchy>/, so a missing file usually means "never
    configured to sync from that client", not "clean"."""
    if not file_path.exists():
        return None, False
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        element = root.find(tag_name)
        return (element.text if element is not None else None), True
    except Exception:
        return None, True


def _read_text_file(file_path: Path, max_chars: int) -> tuple[str | None, bool]:
    """Same missing-vs-unreadable distinction as _read_xml_tag."""
    if not file_path.exists():
        return None, False
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
        return content[:max_chars], True
    except Exception:
        return None, True


def _read_evidence_source(hierarchy_root: Path, spec: str) -> tuple[str | None, bool]:
    """Reads one evidence source per its spec. Every plain-text path is
    glob-matched as a PREFIX (path*), which transparently handles rotating
    logs (confirmed: rationalclient.log/gateway.log never exist under their
    bare name, always ..._NNN) while still matching the bare filename itself
    when a file doesn't rotate — so no separate "rotates" flag is needed.
    Multiple files (";"-joined) are combined into ONE blob, not judged
    file-by-file — a file that's ambiguous read alone (e.g. an
    expected-empty detail file with no findings) can be entirely clear in
    combination with its sibling file. Returns (content, existed) —
    existed=False means nothing was found at all."""
    files, tag = _parse_source_spec(spec)

    if tag:
        value, existed = _read_xml_tag(hierarchy_root / files[0], tag)
        return value, existed

    parts: list[str] = []
    any_existed = False
    all_matches: list[Path] = []
    for f in files:
        all_matches.extend(sorted(hierarchy_root.glob(f + "*")))
    multi = len(all_matches) > 1
    for p in all_matches:
        content, existed = _read_text_file(p, max_chars=20000 if multi else 8000)
        if existed:
            any_existed = True
        if existed and content:
            parts.append(f"--- {p.relative_to(hierarchy_root)} ---\n{content}" if multi else content)
    return ("\n\n".join(parts) if parts else ""), any_existed


def _judge_content_with_model(attack_type: str, content: str) -> tuple[str, str]:
    """The ONE judgment call every evidence source goes through — no
    known_patterns regex matching at all. Reuses cybersecqwen's exact
    fine-tuning format (system prompt + "Source: {attack_type}\\n\\nContent:
    \\n{content}" user message, expecting "Status: DETECTED|CLEAN. <1-3
    sentence explanation>" back) verbatim, since the model was trained
    specifically on this content -> explanation mapping and needs no
    retrieved/injected context to interpret it. Known limitation (see
    cybersecqwen_finetune/SESSION_SUMMARY.md): unlike a deterministic
    matcher, this can occasionally misjudge even a simple flag value — that
    is the accepted cost of removing regex matching entirely."""
    template = ChatPromptTemplate.from_messages([
        ("system", CYBERSECQWEN_JUDGE_SYSTEM_PROMPT),
        ("user", "Source: {attack_type}\n\nContent:\n{content}"),
    ])
    try:
        response = (template | model).invoke({"attack_type": attack_type, "content": content})
        text = str(getattr(response, "content", response)).strip()
    except Exception as e:
        return "inconclusive", f"Judgment call failed ({e}); treated as inconclusive."

    # The model was trained on a literal "Status: DETECTED|CLEAN. <explanation>"
    # prefix, but real inference doesn't always reproduce that exact framing —
    # confirmed in practice: "DETECTED\n\n...", "The content is CLEAN....",
    # "Classification: CLEAN\nExplanation: ...", and a "Status:" label landing
    # mid-response after some preamble have all been observed. Searching for
    # the verdict word anywhere (first occurrence) instead of anchoring on an
    # exact leading "Status:" label is what actually classifies these
    # correctly — anchoring there was silently forcing nearly every real
    # DETECTED/CLEAN answer into "inconclusive".
    verdict_match = re.search(r"\b(DETECTED|CLEAN)\b", text, re.IGNORECASE)
    if not verdict_match:
        return "inconclusive", f"Model response didn't state DETECTED or CLEAN; treated as inconclusive. Raw: {text[:300]}"

    verdict = "detected" if verdict_match.group(1).upper() == "DETECTED" else "not_detected"
    # Strip a clean leading "Status:"/"Classification:" label when the
    # response actually starts with one, so the displayed meaning isn't
    # front-loaded with a redundant restatement of the verdict already shown
    # in the "Status:" line above it in the report — otherwise show the full
    # response as-is (still perfectly readable, just not trimmed).
    meaning = re.sub(r"^\s*(?:status|classification)\s*:?\s*(?:detected|clean)\.?\s*", "",
                      text, flags=re.IGNORECASE).strip() or text
    return verdict, meaning


def _log_source_result(attack_type: str, result: "EvidenceSourceResult", elapsed: float) -> None:
    """Console mirror of every evidence source as soon as it's evaluated —
    real-time, one line per source, before the attack's markdown section
    even exists yet. Separate from _append_report's file<->console mirror
    below (which shows the same information again, but assembled into the
    final per-attack narrative) -- this one exists so progress is visible
    live while a run is in flight, not just once each attack finishes.
    elapsed covers the file read + (if reached) the model judgment call for
    this one source -- near-zero for a missing file or empty value (no
    model call made), real generation+network latency otherwise, which is
    what actually dominates a run's wall-clock time."""
    label = result.get("tag") or result["file"]
    content_preview = (result.get("content") or "")[:200]
    print(f"  [{attack_type}] {result['tier']} {label} "
          f"({'missing' if not result['existed'] else 'read'}) -> {result['verdict'].upper()} "
          f"[{_fmt_elapsed(elapsed)}]")
    if result.get("content") is not None:
        print(f"      content: {content_preview!r}")
    print(f"      meaning: {result['meaning']}")


# A handful of log-based evidence sources have a real writer script whose
# ENTIRE detection logic is a grep for one fixed literal phrase -- not a
# judgment call at all. gateway_unauthorized_breakin's gateway.log is
# confirmed here: break_alert.sh greps for "Possible Break-in Attempt" and
# nothing else. Routing this through the model was tested across 5
# consecutive retrains (each adding more clean-log training examples,
# 2 -> 7 rows) and consistently misjudged a routine SIGKILL/restart-cycle
# log as DETECTED regardless -- the model's prior that "signal 9 sounds
# like an attack" outweighed every added counter-example. Since the real
# ground truth is deterministic, checking it directly is more reliable
# than continuing to fight that prior with more training data. Scoped
# narrowly to this one (attack_type, file) pair -- every other source for
# this and every other attack type is still model-judged.
LITERAL_PHRASE_SOURCES: dict[tuple[str, str], str] = {
    ("gateway_unauthorized_breakin", "home/athinio/data/1cloudFiler/log/gateway.log"): "Possible Break-in Attempt",
}


def _evaluate_source(hierarchy_root: Path, attack_type: str, spec: str, tier: str) -> EvidenceSourceResult:
    """Reads one evidence source and resolves it: a missing file, or a
    present-but-empty value, resolves for free (nothing to judge either
    way); a source in LITERAL_PHRASE_SOURCES resolves via a direct substring
    check (nothing to judge either way, just for a different reason) —
    everything else goes to the fine-tuned model."""
    source_start = time.perf_counter()
    files, tag = _parse_source_spec(spec)
    file_display = ";".join(files) if len(files) > 1 else files[0]
    value, existed = _read_evidence_source(hierarchy_root, spec)
    base: EvidenceSourceResult = {"file": file_display, "tag": tag, "tier": tier, "existed": existed}

    literal_phrase = LITERAL_PHRASE_SOURCES.get((attack_type, file_display))

    if not existed:
        result: EvidenceSourceResult = {
            **base, "verdict": "not_detected",
            "meaning": "Evidence file not found -- not configured to sync from the client system "
                       "(treated as clean by default).",
            "content": None,
        }
    elif not value or not str(value).strip():
        result = {**base, "verdict": "not_detected", "meaning": "No content to judge -- treated as clean.",
                  "content": value}
    elif literal_phrase:
        detected = literal_phrase in str(value)
        meaning = (f"The literal phrase '{literal_phrase}' -- the exact string this source's real writer "
                   f"script greps for -- appears in this content."
                   if detected else
                   f"The literal phrase '{literal_phrase}', the exact string this source's real writer script "
                   f"greps for, does not appear anywhere in this content.")
        result = {**base, "verdict": "detected" if detected else "not_detected", "meaning": meaning,
                  "content": value}
    else:
        # cybersecqwen's training data wraps every XML-tag reading as
        # "<ALERT>\n  <Tag>value</Tag>\n</ALERT>" regardless of the tag's real
        # source file/root element (confirmed against
        # cybersecqwen_finetune/finetune_dataset/train.jsonl) — a bare extracted
        # value with no tag context is out-of-distribution and was confirmed, in
        # practice, to make the model guess "detected" almost regardless of the
        # actual value. Plain-text sources are sent as-is (that's how they were
        # trained too — see e.g. a raw rationalclient.log line in the same
        # dataset, with no wrapper). `content` (for display/logging) is set to
        # this SAME judged_content, not the bare value -- the console log and
        # the report's "Corroborating raw evidence" block should show exactly
        # what the model was actually shown, not a trimmed-down version of it.
        judged_content = f"<ALERT>\n  <{tag}>{value}</{tag}>\n</ALERT>" if tag else value
        verdict, meaning = _judge_content_with_model(attack_type, judged_content)
        result = {**base, "verdict": verdict, "meaning": meaning, "content": judged_content}

    _log_source_result(attack_type, result, time.perf_counter() - source_start)
    return result


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


# ═════════════════════════════════════════════════════════════════════════
# Graph nodes
# ═════════════════════════════════════════════════════════════════════════

def resolve_attack_node(state: AttackState) -> AttackState:
    """Plain in-memory dict lookup against the checklist fetched once per
    run — no network call per attack type."""
    entry = state["checklist"].get("attacks", {}).get(state["attack_type"], {})
    updated = dict(state)
    updated.update({
        "writer_script": entry.get("writer") or "unknown",
        "ui_feature_name": entry.get("ui_feature"),
        "caveat": entry.get("caveat"),
        "primary_specs": entry.get("primary") or [],
        "verify_specs": entry.get("verify") or [],
        "data_source_reliable": entry.get("reliable", True),
    })
    return updated


def route_after_resolve(state: AttackState) -> str:
    """A known-unreliable data source is checked before anything else."""
    return "cannot_determine" if not state.get("data_source_reliable", True) else "run_chain"


def cannot_determine_node(state: AttackState) -> AttackState:
    return {**state, "final_status": "cannot_determine"}


def run_evidence_chain_node(state: AttackState) -> AttackState:
    """Two tiers, walked in order:

    PRIMARY tier — the live status read(s). All primary sources are
    evaluated (not stopped at the first), because a multi-tag attack type
    (e.g. ransomware's 5 co-equal tags) needs every triggered one reported.
    Any primary source detected -> final_status "detected". The FIRST
    primary source's file being missing means this attack type's status
    can't be determined at all for this hierarchy -> "not_configured".

    VERIFICATION tier — only reached if every primary source read clean.
    Walked in order; the first one to read "detected" makes this a
    "discrepancy". If every configured verification source reads clean,
    "not_detected". No verification tier, or none conclusive ->
    "not_detected_unverifiable"."""
    hierarchy_root = _hierarchy_path(state["vault_root"], state["hierarchy"])
    primary_specs = state.get("primary_specs") or []
    verify_specs = state.get("verify_specs") or []

    primary_results: list[EvidenceSourceResult] = []
    for i, spec in enumerate(primary_specs):
        result = _evaluate_source(hierarchy_root, state["attack_type"], spec, "primary")
        if not result["existed"] and i == 0:
            return {**state, "primary_results": primary_results + [result], "final_status": "not_configured"}
        primary_results.append(result)

    detected_primaries = [r for r in primary_results if r["verdict"] == "detected"]
    if detected_primaries:
        return {**state, "primary_results": primary_results, "triggering_results": detected_primaries,
                "final_status": "detected"}

    verification_results: list[EvidenceSourceResult] = []
    for spec in verify_specs:
        result = _evaluate_source(hierarchy_root, state["attack_type"], spec, "verification")
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
    """Displays every evidence source actually read on a detected/discrepancy
    result, not just whichever one specifically triggered it."""
    pieces = []
    for tier_results in (state.get("primary_results") or [], state.get("verification_results") or []):
        for r in tier_results:
            if r.get("content"):
                content = r["content"]
                display = content if len(content) <= 1500 else content[:1500]
                pieces.append(f"--- {r['file']} ---\n{display}")
    return "\n\n".join(pieces)


def attack_info_node(state: AttackState) -> AttackState:
    """Explain the attack + recommended actions via web search + synthesis —
    unrelated to the per-source judgment above, uses the same model's
    general instruction-following ability."""
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

    # not_detected_unverifiable is displayed as plain "NOT DETECTED" — the
    # unverified/verified distinction is conveyed by whether a verification
    # tier was actually checked, not by a separate status word.
    display_status = "not_detected" if final_status == "not_detected_unverifiable" else final_status

    def _label(r: EvidenceSourceResult) -> str:
        """The tag name is more specific than the file when the source is
        an xml_tag read (e.g. ransomware's 5 tags all live in Alert.xml)."""
        return r["tag"] if r.get("tag") else r["file"]

    all_results = (state.get("primary_results") or []) + (state.get("verification_results") or [])
    files_checked = ", ".join(dict.fromkeys(r["file"] for r in all_results)) or "(none read)"
    labels_checked = ", ".join(dict.fromkeys(_label(r) for r in all_results)) or "(none read)"

    lines = [f"## {attack_label}", "", f"<!-- {STATUS_MARKER}: {final_status} -->"]
    lines.append(f"**Status:** {display_status.replace('_', ' ').upper()}")
    lines.append(f"\n**Source chain:**\n{_format_provenance_chain(state.get('writer_script', 'unknown'), files_checked)}")

    if final_status == "detected":
        triggering = state.get("triggering_results") or []
        if len(triggering) > 1 or (state.get("primary_results") and len(state["primary_results"]) > 1):
            triggered_labels = ", ".join(_label(r) for r in triggering)
            lines.append(f"\n**Triggering evidence:** `{triggered_labels}` (out of `{labels_checked}` checked)")
        elif triggering:
            lines.append(f"\n**Triggering evidence:** `{_label(triggering[0])}` — {triggering[0]['meaning']}")
        if state.get("corroborating_evidence_text"):
            lines.append(f"\n### Corroborating raw evidence\n\n```\n{state['corroborating_evidence_text']}\n```")
        lines.append(f"\n### What this attack is / recommended actions\n\n{state.get('explainer_text', '')}")

    elif final_status == "discrepancy":
        triggering = (state.get("triggering_results") or [{}])[0]
        lines.append(
            f"\n⚠ The status tag says 'not detected', but independent review of `{_label(triggering) if triggering else '?'}` "
            f"disagreed: {triggering.get('meaning', '')}"
        )
        feature_ref = state.get("ui_feature_name") or f"the feature that manages `{state.get('writer_script', 'unknown')}`"
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
        primary_meaning = primary_results[0].get("meaning", "") if primary_results else ""
        if live_value_display and "\n" in str(live_value_display):
            value_line = f"currently reads:\n\n```\n{live_value_display}\n```"
        else:
            value_line = f"currently reads `{live_value_display}`."
        lines.append(
            f"\n✅ Not detected -- `{files_checked}` {value_line}\n\n"
            f"No further evidence source was conclusive, so this reading could not be "
            f"cross-checked against anything else — it reflects only what the primary source reports."
        )
        lines.append(f"\n**What determines this status:**\n\n{primary_meaning}")

    elif final_status == "not_configured":
        primary_results = state.get("primary_results") or []
        first_file_display = primary_results[0]["file"] if primary_results else "?"
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
            "to be unreliable independent of its current value — see the note below. "
            "Do not treat this as either detected or clean."
        )
        if state.get("caveat"):
            lines.append(f"\n{state['caveat']}")

    return {**state, "markdown_section": "\n".join(lines) + "\n"}


# ═════════════════════════════════════════════════════════════════════════
# Graph assembly
# ═════════════════════════════════════════════════════════════════════════

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


# ═════════════════════════════════════════════════════════════════════════
# Attack-status outer driver
# ═════════════════════════════════════════════════════════════════════════

def run_attack_status_loop(hierarchy: str, vault_root: str, report_path: Path, checklist: dict) -> float:
    """Runs every attack type in checklist["order"] as an isolated invocation
    of the compiled graph, appending each conclusion to report_path and
    discarding the rest of that attack's state before moving to the next.
    Returns total elapsed seconds for this whole phase, and prints a
    per-attack timing breakdown (slowest first) at the end so it's obvious
    which attack types actually dominate a run's wall-clock time."""
    graph = _get_attack_graph()
    order = checklist.get("order") or []

    _append_report(report_path,
        f"# Attack Status Report\n\n**Hierarchy:** `{hierarchy}`  \n"
        f"**Generated:** {datetime.now().isoformat()}  \n"
        f"**Attack types checked:** {len(order)}\n\n"
    )

    phase_start = time.perf_counter()
    attack_timings: list[tuple[str, float]] = []

    for attack_type in order:
        print(f"\n{'=' * 78}\nChecking: {attack_type}\n{'=' * 78}")
        attack_start = time.perf_counter()
        initial_state: AttackState = {
            "attack_type": attack_type,
            "hierarchy": hierarchy,
            "vault_root": vault_root,
            "checklist": checklist,
        }
        result = graph.invoke(initial_state)
        attack_elapsed = time.perf_counter() - attack_start
        attack_timings.append((attack_type, attack_elapsed))
        print(f"  -- {attack_type} took {_fmt_elapsed(attack_elapsed)} --")
        _append_report(report_path, result["markdown_section"] + "\n")
        # `result` (and everything it references) goes out of scope here.

    phase_elapsed = time.perf_counter() - phase_start
    print(f"\n{'#' * 78}\n# ATTACK-STATUS PHASE: {len(order)} types in {_fmt_elapsed(phase_elapsed)} "
          f"(avg {_fmt_elapsed(phase_elapsed / max(1, len(order)))}/type)\n{'#' * 78}")
    for attack_type, elapsed in sorted(attack_timings, key=lambda t: -t[1])[:10]:
        print(f"  {_fmt_elapsed(elapsed):>10}  {attack_type}")

    return phase_elapsed


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


# ═════════════════════════════════════════════════════════════════════════
# Log analysis — catch-all for secure/messages/audit.log, context-flat like
# the attack-status loop above: classify once, then an isolated
# invoke-append-discard pass per incident.
# ═════════════════════════════════════════════════════════════════════════

LOG_STATUS_MARKER = "LOG_INCIDENT_MARKER"
CLEAN_RUN_MARKER = "No log files found in this pull."

DEFAULT_LOG_FILE_PATHS = ["var/log/messages", "var/log/secure", "var/log/audit.log"]

# Restricted to only the incident types actually detectable from the three
# canonical logs this workflow reads (secure/messages/audit.log) — a
# category not reachable from any of them is excluded from the enum
# entirely, since prompt-level discouragement alone was confirmed (in the
# original package) to just redirect wrong answers toward OTHER wrong
# categories rather than the correct one.
ALLOWED_INCIDENT_TYPES = {
    "user_breach",
    "privilege_escalation",
    "ssh_key_injection",
    "suspicious_command_execution",
    "assets_permission_tamper",
    "file_integrity_tamper",
    "unknown_binary_execution",
    "log_tampering",
    "banned_ip",
    "disk_full",
    "memory_leak",
    "network_anomaly",
}

INCIDENT_TYPES = sorted(ALLOWED_INCIDENT_TYPES)
INCIDENT_TYPES_SET = set(INCIDENT_TYPES)
INCIDENT_TYPES_HINT = ", ".join(INCIDENT_TYPES)


def _load_log_file_paths(log_file_paths: list[str] | None) -> list[str]:
    """log_file_paths comes from hierarchy_system's get_attack_checklist
    tool (LOG_FILE_PATHS in that package's .env) -- which files this
    workflow reads for the log-analysis catch-all is hierarchy-side config,
    fetched once per run alongside the attack checklist, same as every
    other check. Falls back to the three canonical security logs if unset
    or the checklist didn't carry one."""
    return log_file_paths or DEFAULT_LOG_FILE_PATHS


def _load_log_tail_lines() -> int:
    raw = os.getenv("LOG_TAIL_LINES", "").strip()
    try:
        return int(raw) if raw else 300
    except ValueError:
        return 300


def _read_as_text_or_placeholder(path: Path, tail_lines: int) -> str:
    """Non-UTF-8 (binary) files are included as a placeholder line rather
    than raw bytes. Text files are capped to their last tail_lines lines —
    these logs grow unbounded on the client, and re-sending the same
    already-seen history every run wastes tokens for no new signal."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        size = path.stat().st_size
        return f"[binary file, {size} bytes, not included]"
    total = len(lines)
    if total > tail_lines:
        lines = lines[-tail_lines:]
        return f"[showing last {tail_lines} of {total} lines]\n" + "\n".join(lines)
    return "\n".join(lines)


class MessageState(TypedDict):
    logs: str
    result: dict
    logs_path: NotRequired[str]
    output_dir: NotRequired[str]
    customer_ids: NotRequired[List[str]]


def _carry_context(state: MessageState) -> dict:
    return {
        "logs_path": str(state.get("logs_path", "") or ""),
        "output_dir": str(state.get("output_dir", "") or ""),
        "customer_ids": list(state.get("customer_ids", []) or []),
    }


class InitialAnalysisTemplate(BaseModel):
    title: str = Field(description="An appropriate title of the attack or potential attack after analyzing the logs")
    content: str = Field(description="A 100-200 word initial analysis of the attack or potential attack after analyzing the logs")


class LogClassificationTemplate(BaseModel):
    attack_detected: bool = Field(
        description="True only if the logs show a genuine attack/incident pattern -- not just "
                    "unusual-looking but benign activity. False means the logs reflect healthy, "
                    "routine, or merely erroneous (non-attack) behavior."
    )
    incident_type: Literal[tuple(INCIDENT_TYPES)] | None = Field(
        default=None,
        description=f"Required when attack_detected is true -- the single incident type that best "
                    f"matches, one of: {INCIDENT_TYPES_HINT}. Must be null/omitted when "
                    f"attack_detected is false."
    )


class QuestionFormerOutputTemplate(BaseModel):
    search_query_1: str = Field(description="A search query describing the incident/technique itself in plain, general terms — what happened and how it's typically carried out")
    search_query_2: str = Field(description="Another search query describing the incident/technique itself, from a different angle (e.g. the attacker's likely objective or method)")
    search_query_3: str = Field(description="A search query targeted at a named threat-intelligence source (MITRE ATT&CK, CISA advisories, or NVD/CVE) — use a site: operator for that source's domain when there's a specific technique/CVE angle to search for")
    search_query_4: str = Field(description="Another threat-intelligence-source-targeted search query, aimed at a different named source than search_query_3")
    search_query_5: str = Field(description="Another threat-intelligence-source-targeted search query, aimed at a different named source than search_query_3 and search_query_4")


class ExplainerOutputTemplate(BaseModel):
    threat_level: Literal["low", "medium", "high", "critical"] = Field(description="The threat level of the detected attack based on the search results")
    detailed_analysis: str = Field(description="A more detailed analysis of the detected attack based on the search results", min_length=500)
    search_results: List[dict] = Field(description="The search results used to derive the detailed analysis")
    recommended_actions: List[str] = Field(description="Recommended actions to mitigate the attack based on the detailed analysis", min_length=5)


def _extract_first_json_object(text: str):
    if not text:
        return None
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                candidate = text[start:i + 1]
                try:
                    return json.loads(candidate)
                except Exception:
                    return None
    return None


def _dedupe_multiline_text(text: str) -> str:
    raw_lines = [line.rstrip() for line in str(text).splitlines()]
    deduped_lines = []
    seen = set()
    for line in raw_lines:
        normalized = re.sub(r"\s+", " ", line.strip()).casefold()
        if not normalized:
            if deduped_lines and deduped_lines[-1] != "":
                deduped_lines.append("")
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        deduped_lines.append(line.strip())
    while deduped_lines and deduped_lines[-1] == "":
        deduped_lines.pop()
    return "\n".join(deduped_lines).strip()


def _normalize_initial_analysis_payload(payload: dict) -> dict:
    out = dict(payload or {})
    title = str(out.get("title", "Potential Security Incident")).strip()
    if not title:
        title = "Potential Security Incident"
    out["title"] = title
    content = str(out.get("content", "")).strip()
    content = _dedupe_multiline_text(content)
    if len(content) < 120:
        content = (
            "Observed logs indicate potentially suspicious activity that warrants further investigation. "
            "Multiple indicators suggest authentication anomalies, service-level errors, or behavior that "
            "could be associated with attack reconnaissance or exploitation attempts. Initial containment "
            "and targeted triage are recommended while validating source legitimacy and affected assets."
        )
    out["content"] = content
    return out


def _normalize_log_classification_payload(payload: dict) -> dict:
    out = dict(payload or {})
    attack_detected = bool(out.get("attack_detected", False))
    incident_type = str(out.get("incident_type") or "").strip() or None
    if not attack_detected or incident_type not in INCIDENT_TYPES_SET:
        incident_type = None
    return {"attack_detected": attack_detected and incident_type is not None, "incident_type": incident_type}


def _format_step_label(step: int, message: str, total_steps: int | None = None) -> str:
    if total_steps is None:
        return f"[STEP {step}] {message}"
    return f"[STEP {step}/{total_steps}] {message}"


def InitialAnalysisNode(state: MessageState) -> MessageState:
    """Generates a title + 100-200 word initial analysis from the raw logs.
    The FIRST of two places raw log text reaches the LLM (the only two,
    total, in this whole log-analysis section)."""
    print("\n" + "=" * 70)
    print(_format_step_label(1, "Generating initial title and analysis from logs..."))
    print("=" * 70)

    structured_model = model.with_structured_output(InitialAnalysisTemplate)
    template = ChatPromptTemplate.from_messages([
        ("system", "You are a cybersecurity analyst. Analyze the logs and provide an appropriate title and a 100-200 word initial analysis. Ignore file-not-found style noise and focus on true security indicators. "
                   "Be literal and precise about what the logs actually say. Do not paraphrase or substitute the name of a system, service, or component with a different one just because other lines nearby mention something similar-sounding — e.g. if the logs say 'logging service is disabled', report that literally; do not describe it as an 'SSH service' outage just because SSH-related lines also happen to appear elsewhere in the same input. If the logs contain multiple distinct findings (e.g. a log-tampering alert and a separate SSH auth-failure count), describe them as separate observations rather than merging them into one narrative that conflates unrelated systems."),
        ("user", "{logs}")
    ])
    input_payload = {"logs": state["logs"]}
    chain = template | structured_model

    try:
        result = chain.invoke(input_payload)
    except Exception as e:
        print(f"  ⚠ Initial analysis parsing failed: {e}")
        print("  ↻ Retrying initial analysis with strict JSON fallback...")
        fallback_prompt = ChatPromptTemplate.from_messages([
            ("system", """Return ONLY valid JSON with these exact keys:
- title: string
- content: string (100-200 words)

Be literal and precise about what the logs actually say — do not paraphrase or substitute the name of a system/service with a different one just because something similar-sounding appears nearby.

Do not include markdown, HTML, comments, or extra text before/after JSON."""),
            ("user", """Analyze the following logs and return strict JSON now:
{logs}""")
        ])
        try:
            raw_response = (fallback_prompt | model).invoke(input_payload)
            raw_text = getattr(raw_response, "content", "")
            if isinstance(raw_text, list):
                raw_text = "\n".join(str(x) for x in raw_text)
            raw_text = str(raw_text)
            parsed = _extract_first_json_object(raw_text)
        except Exception as fallback_exc:
            print(f"  ⚠ Fallback also failed/timed out: {fallback_exc}")
            print("  ↻ Using safe defaults instead.")
            parsed = None
        normalized = _normalize_initial_analysis_payload(parsed or {})
        result = InitialAnalysisTemplate.model_validate(normalized)

    print(f"✓ Initial title: {result.title}")
    return {
        **_carry_context(state),
        "logs": state["logs"],
        "result": result.model_dump(),
    }


def InitialSearchFromLogsToDatasetNode(state: MessageState) -> MessageState:
    """Classifies whether the logs show a genuine attack pattern at all
    (attack_detected), and if so, which single incident_type best matches.
    The SECOND and last place raw log text reaches the LLM. No secondary
    incidents, no separate "none_applicable" enum value to fall back to and
    accidentally promote a lesser finding into the primary slot — just one
    yes/no decision plus, when yes, one label. Self-consistency voting (N
    passes, majority vote) guards against a real observed instability
    (different answers to byte-identical input on a single pass)."""
    print("\n" + "=" * 70)
    print(_format_step_label(2, "Classifying incident type from initial analysis + logs..."))
    print("=" * 70)

    incident_type_model = model.with_structured_output(LogClassificationTemplate)
    prior_result = dict(state.get("result", {}))
    title = str(prior_result.get("title", "Potential Security Incident"))
    content = str(prior_result.get("content", ""))

    incident_type_template = ChatPromptTemplate.from_messages([
        ("system", f"""You are a cybersecurity analyst.
Using the existing initial analysis and logs, decide:
- attack_detected (true/false) — true ONLY if the logs show a genuine attack/incident pattern,
  not merely unusual-looking, erroneous, or otherwise noteworthy but non-attack activity
  (e.g. a service crash-looping and failing to restart is an operational issue, not an attack,
  unless the logs also show something actually attack-shaped causing it).
- incident_type (string, required only if attack_detected is true) — the single type that best
  matches: {INCIDENT_TYPES_HINT}

Ignore file-not-found style noise and focus on true security indicators.

Base your choice strictly on the LITERAL actions, commands, filenames, and alert
messages that actually appear in the logs below — not on a type's name merely
sounding thematically related or "safe" to pick when uncertain. Pick the type
whose own definition most literally matches what these specific logs show,
not the most generic-sounding "something is wrong" option. If nothing in the
logs literally matches any listed type's own definition, attack_detected must
be false — do not force-fit the closest-sounding label.

One pattern worth being precise about: auth/sshd-style logs showing a cluster
of "Failed password" entries (for one or more usernames) from the same source
address, followed by an "Accepted password" (not "Accepted publickey") success
from that SAME address shortly after, is user_breach — that specific
failed-then-succeeded-by-password sequence from one source IP is the
compromise, regardless of any other routine publickey sessions, sudo
commands, or cron jobs also present in the same log window; those surrounding
lines are normal activity and shouldn't pull the classification toward a
different category instead."""),
        ("user", """Logs:
{logs}

Initial Analysis:
Title: {title}
Content: {content}""")
    ])

    input_payload = {"logs": state["logs"], "title": title, "content": content}
    incident_type_chain = incident_type_template | incident_type_model

    def _classify_once_vote() -> LogClassificationTemplate:
        try:
            result = incident_type_chain.invoke(input_payload)
            normalized = _normalize_log_classification_payload(result.model_dump())
            return LogClassificationTemplate.model_validate(normalized)
        except Exception as e:
            print(f"  ⚠ Structured output parsing failed: {e}")
            print("  ↻ Retrying incident type classification with strict JSON fallback...")
            fallback_prompt = ChatPromptTemplate.from_messages([
                ("system", f"""Return ONLY valid JSON with these exact keys:
- attack_detected: boolean
- incident_type: string or null (required, one of: {INCIDENT_TYPES_HINT}, if attack_detected is true; null otherwise)

Do not include markdown, HTML, comments, or extra text before/after JSON."""),
                    ("user", """Analyze the following logs and initial analysis and return strict JSON now:

        Logs:
        {logs}

        Initial Analysis:
        Title: {title}
        Content: {content}""")
            ])
            try:
                raw_response = (fallback_prompt | model).invoke(input_payload)
                raw_text = getattr(raw_response, "content", "")
                if isinstance(raw_text, list):
                    raw_text = "\n".join(str(x) for x in raw_text)
                raw_text = str(raw_text)
                parsed = _extract_first_json_object(raw_text)
            except Exception as fallback_exc:
                print(f"  ⚠ Fallback also failed/timed out: {fallback_exc}")
                print("  ↻ Using safe defaults instead.")
                parsed = None
            normalized = _normalize_log_classification_payload(parsed or {})
            return LogClassificationTemplate.model_validate(normalized)

    vote_count = max(1, int(os.getenv("CLASSIFICATION_VOTE_COUNT", "1")))
    votes = [_classify_once_vote() for _ in range(vote_count)]
    detected_counts = Counter(v.attack_detected for v in votes)
    winning_detected, _ = detected_counts.most_common(1)[0]
    print(f"  Self-consistency vote ({vote_count} passes) on attack_detected: "
          f"{dict(detected_counts)} -> chose {winning_detected}")

    if winning_detected:
        agreeing_votes = [v for v in votes if v.attack_detected and v.incident_type]
        type_counts = Counter(v.incident_type for v in agreeing_votes)
        winning_type = type_counts.most_common(1)[0][0] if type_counts else None
        classification_result = LogClassificationTemplate(attack_detected=winning_type is not None,
                                                            incident_type=winning_type)
    else:
        classification_result = LogClassificationTemplate(attack_detected=False, incident_type=None)

    print(f"✓ attack_detected: {classification_result.attack_detected}"
          + (f", incident_type: {classification_result.incident_type}" if classification_result.attack_detected else ""))

    return {
        **_carry_context(state),
        "logs": state["logs"],
        "result": {**prior_result, **classification_result.model_dump()},
    }


def _classify_once(logs_content: str, logs_file: Path, output_dir: Path, customer_ids: list[str]) -> dict:
    state: MessageState = {
        "logs": logs_content,
        "result": {},
        "logs_path": str(logs_file),
        "output_dir": str(output_dir),
        "customer_ids": customer_ids,
    }
    state = InitialAnalysisNode(state)
    state = InitialSearchFromLogsToDatasetNode(state)
    return state["result"]


def _form_search_queries(title: str, content: str, incident_type: str) -> list[str]:
    structured_model = model.with_structured_output(QuestionFormerOutputTemplate)
    incident_type_hint = (
        f" The incident has already been classified as '{incident_type}' — let that guide which "
        f"general concept each query targets."
        if incident_type else ""
    )
    template = ChatPromptTemplate.from_messages([
        ("system", "You are a cybersecurity analyst. Based on the incident title and analysis below, "
                   "generate 5 search queries to find more information about this attack or potential attack.\n\n"
                   "The first two queries should simply describe the incident/technique itself in plain, "
                   "general terms — what happened and how it's typically carried out. The other three should "
                   "each be targeted at a specific named threat-intelligence source — MITRE ATT&CK, CISA "
                   "advisories, NVD/CVE — phrased to surface pages from that source specifically (e.g. using "
                   "a site: operator such as site:attack.mitre.org, site:cisa.gov, or site:nvd.nist.gov) when "
                   "there's a concrete technique/CVE angle to search for.\n\n"
                   "IMPORTANT: Do not use internal or proprietary system field names, product names, or file "
                   "paths specific to this environment in any query — those won't return useful public "
                   "results. Every query must be traceable to something the title or analysis actually says."
                   + incident_type_hint),
        ("user", "Title: {title}\n\nAnalysis: {content}")
    ])
    try:
        result = (template | structured_model).invoke({"title": title, "content": content})
        return [q for q in [result.search_query_1, result.search_query_2, result.search_query_3,
                             result.search_query_4, result.search_query_5] if q]
    except Exception as e:
        print(f"  ⚠ Search-query generation failed ({e}); proceeding with no search queries.")
        return []


def _run_ddg_search(queries: list[str]) -> list[dict]:
    all_results = []
    for i, query in enumerate(queries, 1):
        print(f"  [{i}/{len(queries)}] Searching: {query}")
        try:
            with DDGS() as ddgs:
                for r in list(ddgs.text(query, max_results=5)):
                    url = r.get("href", "")
                    all_results.append({
                        "query_number": i,
                        "query": query,
                        "title": r.get("title", "No title"),
                        "url": url,
                        "snippet": r.get("body", "No description available"),
                    })
                    # Live console mirror of each result as it's found, same
                    # convention as _log_source_result/_append_report -- the
                    # report's own "Search results" section already showed
                    # these as markdown links ([title](url)), but that's
                    # invisible during a live run and the raw url is hidden
                    # behind the title text even once rendered.
                    print(f"       - {r.get('title', 'No title')}")
                    if url:
                        print(f"         {url}")
        except Exception as e:
            print(f"       ✗ Search error: {e}")
    return all_results


def _explain_incident(title: str, content: str, incident_type: str,
                       search_results: list[dict]) -> ExplainerOutputTemplate | None:
    structured_model = model.with_structured_output(ExplainerOutputTemplate)
    search_context = "\n\n".join([
        f"Query {sr.get('query_number')}: {sr.get('query')}\n"
        f"Title: {sr.get('title', 'N/A')}\nURL: {sr.get('url', 'N/A')}\nSnippet: {sr.get('snippet', 'N/A')}"
        for sr in search_results if "error" not in sr
    ]) or "No search results available."

    template = ChatPromptTemplate.from_messages([
        ("system", """You are a senior cybersecurity analyst.

Explain this one incident in a clear analyst narrative style, grounded in the title/analysis and search intelligence given — do not invent details not supported by them.

The search results are general background intelligence about how an attack technique of this kind typically works — they are NOT a report of what was observed on this specific system. Never phrase something from a search result as if it was directly observed.

Calibrate threat_level against these criteria — do not default to High/Critical just because the topic is security-related:
- LOW: a single low-confidence or easily-explained indicator with no evidence of actual compromise.
- MEDIUM: suspicious activity with real supporting evidence, but not confirmed compromise.
- HIGH: multiple corroborating findings, or strong evidence of actual unauthorized access/tampering, contained in scope.
- CRITICAL: confirmed active compromise with severe or business-critical impact. Reserve for cases the evidence clearly supports.

Provide: threat_level, a detailed analysis (300-500 words) of what happened / likely progression / implications, the search results used, and recommended actions.

Write detailed_analysis as plain paragraphs — do NOT use markdown headers (#, ##, ###) inside it. This text gets inserted into a larger report that already has its own heading structure; headers inside your answer would break that structure. Use bold text (**like this**) for emphasis instead, if needed."""),
        ("user", """Title: {title}
Content: {content}
Incident type: {incident_type}

Threat Intelligence from Search Results:
{search_context}

Provide your detailed security analysis for this one incident.""")
    ])
    try:
        return (template | structured_model).invoke({
            "title": title, "content": content, "incident_type": incident_type,
            "search_context": search_context,
        })
    except Exception as e:
        print(f"  ⚠ Explanation generation failed for '{incident_type}': {e}")
        return None


def _demote_embedded_headers(text: str) -> str:
    """Defensive backstop: any leading #-header line found is demoted to
    bold text instead of a header, so a model emitting one doesn't render as
    a peer heading to this incident's own section, breaking the report's
    heading hierarchy."""
    lines = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            heading_text = stripped.lstrip("#").strip()
            lines.append(f"**{heading_text}**" if heading_text else "")
        else:
            lines.append(line)
    return "\n".join(lines)


def _render_search_results_section(search_results: list[dict]) -> str:
    if not search_results:
        return "\n**Search results:** none returned for this incident's queries.\n"

    by_query: dict[int, list[dict]] = {}
    query_text: dict[int, str] = {}
    for r in search_results:
        qn = r.get("query_number")
        by_query.setdefault(qn, []).append(r)
        query_text[qn] = r.get("query", "")

    lines = ["\n**Search results:**"]
    for qn in sorted(by_query, key=lambda x: (x is None, x)):
        lines.append(f"\n_Query: {query_text[qn]}_")
        for r in by_query[qn]:
            title = r.get("title") or "No title"
            url = r.get("url", "")
            snippet = r.get("snippet", "")
            entry = f"[{title}]({url})" if url else title
            lines.append(f"- {entry} — {snippet}")
            # The url above is only visible if this markdown actually gets
            # rendered (it's just hidden link-target text otherwise, e.g. in
            # a plain-text viewer or the console) -- show it explicitly too.
            if url:
                lines.append(f"  {url}")
    return "\n".join(lines) + "\n"


def _render_incident_section(incident_type: str,
                              explainer: ExplainerOutputTemplate | None,
                              search_results: list[dict]) -> str:
    """Renders the one attack this run found -- there's never more than
    one, so no primary/secondary role label is needed."""
    label = incident_type.replace("_", " ").title()
    lines = [f"## {label}", "", f"<!-- {LOG_STATUS_MARKER}: {incident_type} -->"]

    if explainer is None:
        lines.append("\n⚠ Detailed explanation could not be generated for this incident (see logs).")
    else:
        lines.append(f"\n**Threat level:** {explainer.threat_level.upper()}")
        lines.append(f"\n{_demote_embedded_headers(explainer.detailed_analysis)}")
        if explainer.recommended_actions:
            lines.append("\n**Recommended actions:**")
            for action in explainer.recommended_actions:
                lines.append(f"- {action}")

    lines.append(_render_search_results_section(search_results))
    return "\n".join(lines) + "\n"


def _consolidate_local_log_files(hierarchy_dir: Path, log_file_paths: list[str] | None) -> str:
    """Reads the configured log paths directly from the ALREADY-LOCAL
    hierarchy directory (run_full_workflow already pulled the whole tree,
    including var/log/*, before this runs) — no separate pull here."""
    tail_lines = _load_log_tail_lines()
    sections = []
    for configured_path in _load_log_file_paths(log_file_paths):
        path = hierarchy_dir / configured_path.strip("/")
        if not path.is_file():
            print(f"  - Not found locally: {path} (not present in this hierarchy's pulled copy)")
            continue
        content = _read_as_text_or_placeholder(path, tail_lines)
        sections.append(f"===== {configured_path} =====\n{content}")
        print(f"  + Found: {path}")

    if not sections:
        return CLEAN_RUN_MARKER + "\n"
    return "\n\n".join(sections) + "\n"


def run_log_analysis_loop(hierarchy: str, hierarchies_dir: Path, report_path: Path,
                           log_file_paths: list[str] | None = None) -> dict:
    """Classifies the aggregated log content ONCE, then processes each
    resulting incident as an isolated unit — appending its section to
    report_path and discarding everything about it before moving to the
    next, the same convention run_attack_status_loop already uses. Timed
    end-to-end plus per-phase (classification vs. each incident), returned
    in the result dict's "elapsed" key so run_full_workflow can report a
    combined attack-status-vs-log-analysis breakdown. log_file_paths comes
    from hierarchy_system's get_attack_checklist (fetched once per run,
    same call that fetches the attack order/sources) -- this package no
    longer carries its own LOG_FILE_PATHS default."""
    phase_start = time.perf_counter()
    hierarchy_clean = hierarchy.strip("/\\")
    hierarchy_dir = hierarchies_dir / Path(hierarchy_clean)

    print("\n" + "=" * 70)
    print(f"READING CONFIGURED LOG FILES FROM LOCAL PULLED COPY "
          f"({len(_load_log_file_paths(log_file_paths))} path(s) from hierarchy_system's LOG_FILE_PATHS)")
    print("=" * 70)
    logs_content = _consolidate_local_log_files(hierarchy_dir, log_file_paths)

    logs_file = hierarchy_dir / "logs_aggregated.txt"
    logs_file.write_text(logs_content, encoding="utf-8")

    _append_report(report_path,
        f"\n# Log Analysis (secure / messages / audit.log)\n\n**Read from:** `{hierarchy_dir}` "
        f"(var/log/messages, var/log/secure, var/log/audit.log)\n\n")

    if CLEAN_RUN_MARKER in logs_content:
        _append_report(report_path,
            "✅ Clean run — none of the configured log files were present in this hierarchy's local pulled copy.\n")
        return {"incident_count": 0, "logs_file": str(logs_file), "elapsed": time.perf_counter() - phase_start}

    print("\n" + "#" * 70)
    print("# LOG ANALYSIS — classify once, then isolated per-incident processing")
    print("#" * 70)

    output_dir = hierarchy_dir
    customer_ids = hierarchy_clean.split("/")
    classify_start = time.perf_counter()
    classification = _classify_once(logs_content, logs_file, output_dir, customer_ids)
    classify_elapsed = time.perf_counter() - classify_start
    print(f"  -- classification (InitialAnalysisNode + InitialSearchFromLogsToDatasetNode) "
          f"took {_fmt_elapsed(classify_elapsed)} --")
    # Raw log text is never referenced again past this line.

    title = classification.get("title", "Potential Security Incident")
    content = classification.get("content", "")
    attack_detected = bool(classification.get("attack_detected"))
    incident_type = classification.get("incident_type")

    _append_report(report_path, f"**Initial analysis — {title}:**\n\n{content}\n")

    if not attack_detected or not incident_type:
        _append_report(report_path,
            "\n✅ Not an attack — no incident pattern detected in these logs; see the initial "
            "analysis above for what they actually show.\n")
        phase_elapsed = time.perf_counter() - phase_start
        print(f"\n{'#' * 78}\n# LOG-ANALYSIS PHASE: {_fmt_elapsed(phase_elapsed)} total "
              f"(classification {_fmt_elapsed(classify_elapsed)}, no attack detected)\n{'#' * 78}")
        return {"incident_count": 0, "logs_file": str(logs_file), "elapsed": phase_elapsed}

    print(f"\n{'='*70}\nProcessing incident: {incident_type}\n{'='*70}")
    incident_start = time.perf_counter()

    queries = _form_search_queries(title, content, incident_type)
    search_results = _run_ddg_search(queries) if queries else []
    explainer = _explain_incident(title, content, incident_type, search_results)
    section = _render_incident_section(incident_type, explainer, search_results)

    incident_elapsed = time.perf_counter() - incident_start
    print(f"  -- {incident_type} took {_fmt_elapsed(incident_elapsed)} --")

    _append_report(report_path, section + "\n")

    phase_elapsed = time.perf_counter() - phase_start
    print(f"\n{'#' * 78}\n# LOG-ANALYSIS PHASE: {_fmt_elapsed(phase_elapsed)} total "
          f"(classification {_fmt_elapsed(classify_elapsed)}, incident {_fmt_elapsed(incident_elapsed)})"
          f"\n{'#' * 78}")

    return {"incident_count": 1, "logs_file": str(logs_file), "elapsed": phase_elapsed}


# ═════════════════════════════════════════════════════════════════════════
# Top-level entry point
# ═════════════════════════════════════════════════════════════════════════

DEFAULT_HIERARCHIES_DIR = Path(__file__).parent / "hierarchies"


def run_full_workflow(
    hierarchy: str,
    vault_root: str = DEFAULT_VAULT_ROOT,
    hierarchies_dir: Path = DEFAULT_HIERARCHIES_DIR,
    sync_with_vault: bool = True,
) -> dict:
    hierarchy_clean = hierarchy.strip("/\\")

    if sync_with_vault:
        print(f"Pulling {vault_root}/{hierarchy_clean} -> {hierarchies_dir / hierarchy_clean} ...")
        populate_hierarchies(vault_root, hierarchies_dir, hierarchy_clean)

    print("Fetching attack checklist from hierarchy_system's mcp_server.py ...")
    checklist = fetch_attack_checklist()
    print(f"  {len(checklist.get('order') or [])} attack types configured.")

    reports_dir = hierarchies_dir / hierarchy_clean / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / f"attack_status_report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.md"

    # Reads resolve against the local pulled copy (hierarchies_dir), not the
    # remote vault_root.
    local_root = str(hierarchies_dir) if sync_with_vault else vault_root
    attack_status_elapsed = run_attack_status_loop(hierarchy, local_root, report_path, checklist)

    summary_counts = parse_deterministic_summary(report_path)
    _append_report(report_path, render_summary_block(summary_counts))

    # Catch-all: secure/messages/audit.log analysis for whatever the fixed
    # per-attack checks above structurally can't catch. Always runs.
    log_analysis_result = run_log_analysis_loop(hierarchy, Path(local_root), report_path,
                                                 checklist.get("log_file_paths"))
    log_analysis_elapsed = log_analysis_result.get("elapsed", 0.0)

    vault_upload_result = None
    if sync_with_vault:
        vault_upload_result = send_files(
            str(report_path), "upload_file",
            relative_path=f"{hierarchy_clean}/reports/{report_path.name}",
        )
        print(f"Uploaded report to vault: {vault_upload_result}")

    total_elapsed = attack_status_elapsed + log_analysis_elapsed
    print(f"\n{'#' * 78}\n# RUN TOTAL: {_fmt_elapsed(total_elapsed)} "
          f"(attack-status phase: {_fmt_elapsed(attack_status_elapsed)}, "
          f"log-analysis phase: {_fmt_elapsed(log_analysis_elapsed)})\n{'#' * 78}")

    return {
        "hierarchy": hierarchy,
        "report_path": str(report_path),
        "summary_counts": summary_counts,
        "log_analysis": log_analysis_result,
        "vault_upload_result": vault_upload_result,
        "timing": {
            "attack_status_seconds": attack_status_elapsed,
            "log_analysis_seconds": log_analysis_elapsed,
            "total_seconds": total_elapsed,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the per-attack status workflow for one hierarchy, followed by "
                    "secure/messages/audit.log analysis as a catch-all — always both, one report. "
                    "No RAG, no local corpus: the attack checklist is fetched from "
                    "hierarchy_system's mcp_server.py, and the fine-tuned cybersecqwen model "
                    "judges every evidence source directly."
    )
    parser.add_argument("hierarchy", help="e.g. 5/101/1/4/1")
    parser.add_argument("--vault-root", default=DEFAULT_VAULT_ROOT)
    parser.add_argument("--hierarchies-dir", default=str(DEFAULT_HIERARCHIES_DIR),
                         help="Reports are written under <hierarchies-dir>/<hierarchy>/reports/.")
    parser.add_argument("--no-sync", action="store_true",
                         help="Skip the MCP pull/push to the vault — read/write hierarchies-dir directly "
                              "as if it were already the vault data (for local testing with hand-built "
                              "fixtures, not for real use). The attack checklist is still fetched over MCP "
                              "either way.")
    args = parser.parse_args()

    result = run_full_workflow(
        args.hierarchy, args.vault_root, Path(args.hierarchies_dir),
        sync_with_vault=not args.no_sync,
    )
    print(f"\nReport written to: {result['report_path']}")
    print(f"Summary: {result['summary_counts']}")
    timing = result.get("timing") or {}
    print(f"Timing: attack-status {_fmt_elapsed(timing.get('attack_status_seconds', 0.0))}, "
          f"log-analysis {_fmt_elapsed(timing.get('log_analysis_seconds', 0.0))}, "
          f"total {_fmt_elapsed(timing.get('total_seconds', 0.0))}")
    if result.get("vault_upload_result"):
        print(f"Vault upload: {result['vault_upload_result']}")


if __name__ == "__main__":
    main()
