"""
attack_status_workflow.py — per-attack detection workflow.

For each attack type known to corpus_server.py (see lib/attack_status_data.py
and corpus_documents/attack_*.json), independently:
  1. Read the live status tag for this hierarchy (deterministic XML read).
  2. If detected -> explain the attack + recommended actions, done.
  3. If not detected -> branch on whether raw evidence exists to verify against:
       - real evidence exists (readable_report / diffable_snapshot_files):
         an LLM independently checks that evidence against the "clean" tag.
         Agrees -> clean. Disagrees -> flagged as a discrepancy, script
         re-run suggested, explanation given anyway.
       - no evidence exists (opaque_binary_only / requires_live_recompute):
         report the tag's status as-is. No verification is attempted.
  4. Render this attack's conclusion as one markdown section, append it to
     the running report file, and DISCARD everything else about this attack
     before moving to the next one. This is deliberate — context stays flat
     regardless of how many attack types get processed, instead of growing
     with every iteration.

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
directory) — every attack type's file/tag/evidence info now comes from that
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

from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langgraph.graph import StateGraph, END
from pydantic import BaseModel, Field
from ddgs import DDGS

from lib.attack_status_data import get_known_attack_types, get_enabled_attack_types, get_attack_entry
from lib.corpus_client import get_corpus_entry
from lib.populate_hierarchies import populate_hierarchies
from lib.mcp_client import send_files

# Reused, not reimplemented — these are the exact confirmed sshd
# brute-force-then-compromise regexes already established in
# anomaly_workflow.py (and the same pattern lib/log_analysis_workflow.py's
# own classification prompt describes in words), for the check_raw_logs
# verification path below. DEFAULT_VAULT_ROOT's canonical definition also
# lives here.
from lib.anomaly_workflow import SSHD_FAIL_RE, SSHD_ACCEPT_RE, DEFAULT_VAULT_ROOT

# The single shared Ollama client instance — same model, same timeout, same
# env-var overrides used by lib/log_analysis_workflow.py.
from lib.llm_client import model

# Maps a raw_evidence_files relative path to the corpus id documenting that
# specific file's format/expected content, so verify_against_raw_evidence_node
# can hand the model a labeled reference example alongside the live content
# being checked, instead of an unfamiliar format to interpret cold.
_EVIDENCE_FILE_CORPUS_IDS = {
    "athinio/system/aide_report.txt": "aide_report_txt",
    "athinio/system/rootkitscan.txt": "rootkitscan_txt",
}

# Raw log files each check_raw_logs attack type reads, as GLOB patterns (not
# exact filenames) keyed by attack_type — confirmed on a real hierarchy
# (5/101/1/4/1, 2026-08-27) that rationalclient.log is Julian-day rotated at
# rationalVault/log/rationalclient.log_NNN, never a plain
# athinio/system/rationalclient.log as originally assumed here; that wrong
# exact path silently made this check always report "file not found" against
# a real vault pull. Globbing sidesteps needing to track the current rotation
# suffix. Per-attack-type because different checks read entirely different
# logs in entirely different directories (e.g. gateway_unauthorized_breakin's
# gateway.log lives under home/athinio/data/1cloudFiler/log/, confirmed
# rotated the same way). Joined onto the hierarchy root same as every other
# read in this workflow.
RAW_LOG_FILE_PATTERNS: dict[str, list[str]] = {
    "user_breach": ["var/log/secure*", "rationalVault/log/rationalclient.log*"],
    "gateway_unauthorized_breakin": ["home/athinio/data/1cloudFiler/log/gateway.log*"],
}

# Deliberately empty. secOpsOutput_113 was previously treated as a
# supplementary cross-reference for user_breach, but its real source
# (secOpsScript_113, confirmed 2026-08-28) shows it only restates the
# current User_breach tag value as a text line — the exact same
# restated-conclusion problem found and fixed in gateway_breach_activity's
# secOpsOutput_105. Kept as an empty registry (rather than removed outright)
# in case a genuinely independent supplementary source is confirmed for some
# other check_raw_logs attack type in the future.
SUPPLEMENTARY_RAW_LOG_STATUS_FILES: dict[str, str] = {}


def _check_user_breach_raw_logs(log_text: str) -> tuple[bool, str]:
    """Deterministic pattern match, not an LLM judgment call — reuses the
    exact confirmed sshd brute-force-then-compromise regexes already
    established in anomaly_workflow.py, rather than re-describing the same
    pattern in a prompt and asking a model to (imperfectly) re-derive it.
    A cluster of Failed password entries from an address, followed by an
    Accepted password (not Accepted publickey) from that SAME address, is
    the compromise — this is the identical rule
    lib/log_analysis_workflow.py's own classification prompt already
    encodes in words for the log-analysis pipeline."""
    fails = SSHD_FAIL_RE.findall(log_text)
    accepts = SSHD_ACCEPT_RE.findall(log_text)
    fail_ips = {ip for _, ip in fails}
    for user, ip in accepts:
        if ip in fail_ips:
            return True, (
                f"Found failed password attempts from {ip} followed by a successful "
                f"password login for '{user}' from that same address — matches the "
                f"confirmed brute-force-then-compromise pattern."
            )
    return False, "No failed-then-accepted-password sequence from the same source address found in the available logs."


def _check_gateway_breakin_raw_logs(log_text: str) -> tuple[bool, str]:
    """Deterministic phrase match, not an LLM judgment call — confirmed real
    signature per a real product QA test spec (2026-08-27): the
    oneCloudFilerx binary writes a line containing 'Break-in Attempt' to
    gateway.log whenever it detects one (e.g. a root-owned file that a normal
    user's removal attempt was denied on). Originally this attack type was
    routed through the generic LLM-based verify_against_raw_evidence_node
    with alertlog.xml as supplementary evidence — that produced a real,
    confirmed-live bug: the model treated OTHER unrelated active flags in
    that shared multi-tag file as if they contradicted this specific attack
    type's own clean status, and separately treated the (at the time,
    non-globbed) missing gateway.log itself as grounds for suspicion rather
    than neutral absence. A precise phrase match against the real log is
    both more reliable and avoids feeding the model a confusing shared
    status file at all."""
    matches = [line for line in log_text.splitlines() if "Break-in Attempt" in line]
    if matches:
        return True, (
            f"Found {len(matches)} line(s) containing 'Break-in Attempt' in gateway.log, "
            f"e.g.: {matches[0].strip()}"
        )
    return False, "No 'Break-in Attempt' lines found in the available gateway.log content."


# Registry of attack-type-specific raw-log checkers. Deliberately not a
# generic LLM-based check like verify_against_raw_evidence_node — where a
# precise, already-confirmed pattern exists (like this one), a deterministic
# regex match is more reliable than asking a model to re-derive it from a
# text description each time. Only attack types with a genuinely confirmed
# pattern belong here; everything else stays opaque_binary_only rather than
# getting a guessed-at pattern dressed up as a real check.
RAW_LOG_CHECKERS = {
    "user_breach": _check_user_breach_raw_logs,
    "gateway_unauthorized_breakin": _check_gateway_breakin_raw_logs,
}


STATUS_MARKER = "STATUS_MARKER"  # used to make the markdown machine-parsable


# ── State ──────────────────────────────────────────────────────────────────

class AttackState(TypedDict):
    attack_type: str
    hierarchy: str
    vault_root: str

    status_file: str
    status_tag: str
    meaning: str
    writer_script: str
    ui_feature_name: NotRequired[str | None]
    confidence: str
    verification_category: str
    value_schema: NotRequired[dict]
    raw_evidence_files: NotRequired[list[str]]
    caveat: NotRequired[str]
    data_source_reliable: NotRequired[bool]
    status_tags: NotRequired[list[str]]  # when set, overrides status_tag as the set of tags checked in status_file

    live_value: NotRequired[str | None]
    tag_values: NotRequired[dict[str, str | None]]   # set alongside live_value when status_tags has >1 entry
    triggered_tags: NotRequired[list[str]]            # which tag(s) in status_tags actually indicated detection
    status_file_existed: NotRequired[bool]
    verification_outcome: NotRequired[str | None]   # confirmed_clean | contradiction
    verification_reasoning: NotRequired[str]
    final_status: NotRequired[str]                   # detected | not_detected | not_detected_unverifiable | discrepancy
    explainer_text: NotRequired[str]
    corroborating_evidence_text: NotRequired[str]
    markdown_section: NotRequired[str]


class EvidenceVerificationResult(BaseModel):
    outcome: Literal["confirmed_clean", "contradiction"] = Field(
        description="confirmed_clean if the raw evidence supports the 'not detected' "
                    "status; contradiction if the evidence suggests the attack may "
                    "actually have occurred despite the tag saying otherwise."
    )
    reasoning: str = Field(description="1-3 sentence justification citing what was found in the evidence.")


# ── Helpers ────────────────────────────────────────────────────────────────

def _read_xml_tags(file_path: Path, tag_names: list[str]) -> tuple[dict[str, str | None], bool]:
    """Flat-tag XML read, same defensive pattern as attack_processor.py's
    read_all_tags / rv_log_analysis_lincas.py's get_key_values, but the
    return value distinguishes "file doesn't exist here" from "file exists
    but is malformed or lacks the tag" — those aren't the same thing. On the
    real system, only a configured subset of a client's files ever get
    copied up to rationalVault/data/<hierarchy>/, so a missing file usually
    means "never configured to sync from that client", not "clean". Reads
    several sibling tags from one parse instead of one — used for
    attack types genuinely backed by multiple related flags in the same
    status_file (e.g. ransomware's Ransom/bin/lib cluster in Alert.xml, any
    one of which indicates the attack; checking only one silently misses the
    others, as confirmed live on a real hierarchy where Ransom read 0 while
    bin and lib both read 1)."""
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


def _is_detected(live_value: str | None, value_schema: dict | None) -> bool:
    """Interprets a raw tag value according to its declared value_schema.
    Defaults to binary_flag (== "1") only because that's the only encoding
    actually confirmed for most Alert.xml tags — NOT a safe universal
    assumption, which is exactly what made clam_malware's real value
    ("Infected files: N", not "0"/"1") silently never match before this."""
    if live_value is None:
        return False

    schema = value_schema or {"type": "binary_flag"}
    schema_type = schema.get("type", "binary_flag")

    if schema_type == "binary_flag":
        return live_value == "1"
    if schema_type in ("string_pattern", "file_contains_pattern"):
        # Same regex-search mechanics for both — file_contains_pattern only
        # differs in WHERE read_live_status_node sources live_value from
        # (the whole raw file's text, not one XML tag's inner text), for
        # attack types whose real detection output is a plain-text scan
        # rather than an XML tag (e.g. config_drift's secOpsScript_94, which
        # never writes to any Alert.xml/alertlog.xml tag at all — the
        # filename/Tampered-or-None pairs in secOpsOutput_94 ARE the primary
        # evidence, confirmed against real source, not a secondary file to
        # cross-check a tag against).
        pattern = schema.get("detected_regex", "")
        return bool(pattern) and re.search(pattern, live_value) is not None
    if schema_type == "raw_value_needs_baseline_diff":
        # The tag itself (e.g. config_drift's mtime_binary) is a raw
        # timestamp/permission value, not a flag — it can never indicate
        # "detected" on its own. Always false here so the graph proceeds to
        # verify_against_raw_evidence_node, where the actual baseline diff
        # is what determines drift, every time — not as a fallback only
        # checked when this (meaningless) flag says clean.
        return False
    if schema_type == "count_greater_than_zero":
        # Only valid where ANY occurrence is inherently concerning (empty-
        # password accounts, extra UID-0 accounts, orphaned files) — NOT for
        # things like SUID/SGID binaries or open ports, where some nonzero
        # count is normal on every system and this would false-positive
        # constantly. Those need a baseline/whitelist comparison instead,
        # which wasn't confirmed to exist in this bundle, so they're
        # deliberately not modeled this way.
        try:
            return int(live_value) > 0
        except (TypeError, ValueError):
            return False
    if schema_type == "file_non_empty":
        # read_live_status_node sets live_value to "non_empty"/"empty" for
        # this schema type instead of parsing an XML tag — some files (e.g.
        # banned_ip.xml) are checked for content presence, not a tag value.
        return live_value == "non_empty"

    # Unknown schema type — don't silently guess either direction.
    raise ValueError(f"Unknown value_schema type: {schema_type!r}")


# ── Nodes ──────────────────────────────────────────────────────────────────

def resolve_attack_files_node(state: AttackState) -> AttackState:
    """Corpus lookup by exact id — attack_type is a fixed known key at this
    point (resolved from get_enabled_attack_types()), not a free-text query,
    so this is get_corpus_entry (exact match), never query_corpus (semantic
    search). See lib/attack_status_data.py's module docstring."""
    entry = get_attack_entry(state["attack_type"])
    metadata = entry["metadata"]

    updated = dict(state)
    updated.update({
        "status_file": metadata["status_file"],
        "status_tag": metadata["status_tag"],
        "meaning": entry["explanation"],
        "writer_script": metadata.get("writer_script", "unknown"),
        "ui_feature_name": metadata.get("ui_feature_name"),
        "confidence": metadata.get("confidence", "unknown"),
        "verification_category": metadata["verification_category"],
        "value_schema": metadata.get("value_schema", {"type": "binary_flag"}),
    })
    if "raw_evidence_files" in metadata:
        updated["raw_evidence_files"] = metadata["raw_evidence_files"]
    if "caveat" in metadata:
        updated["caveat"] = metadata["caveat"]
    if "status_tags" in metadata:
        updated["status_tags"] = metadata["status_tags"]
    updated["data_source_reliable"] = metadata.get("data_source_reliable", True)
    return updated


def read_live_status_node(state: AttackState) -> AttackState:
    # Always relative to THIS hierarchy's own vault path
    # (rationalVault/data/<company>/<customer>/<branch>/<product>/<system>),
    # never to vault_root directly — every customer/system has its own unique
    # hierarchy, and status_file (e.g. "Alert.xml") is only ever meaningful
    # relative to that specific path, not to the vault root.
    file_path = _hierarchy_path(state["vault_root"], state["hierarchy"]) / state["status_file"]

    value_schema = state.get("value_schema") or {"type": "binary_flag"}
    if value_schema.get("type") == "file_contains_pattern":
        # Some attack types' real detection output is a plain-text scan, not
        # an XML tag — e.g. config_drift's secOpsScript_94 writes alternating
        # filename/"Tampered"-or-"None" line pairs to secOpsOutput_94 and
        # never touches Alert.xml or alertlog.xml at all, confirmed against
        # its real source. status_tag is a documentation label here (e.g.
        # "N/A -- text scan, not a tag read"), not something actually read.
        if not file_path.exists():
            return {**state, "live_value": None, "status_file_existed": False, "triggered_tags": []}
        content = _read_text_file(file_path, max_chars=8000)[0] or ""
        triggered = [state["status_tag"]] if _is_detected(content, value_schema) else []
        return {**state, "live_value": content, "status_file_existed": True, "triggered_tags": triggered}

    if value_schema.get("type") == "file_non_empty":
        # Some files (banned_ip.xml) are checked for content presence, not a
        # specific tag value — confirmed via scanning-lin.py's own
        # is_file_empty_or_non_existent check on this exact file.
        if not file_path.exists():
            return {**state, "live_value": None, "status_file_existed": False, "triggered_tags": []}
        content = _read_text_file(file_path)[0] or ""
        live_value = "non_empty" if content.strip() else "empty"
        triggered = [state["status_tag"]] if _is_detected(live_value, value_schema) else []
        return {**state, "live_value": live_value, "status_file_existed": True, "triggered_tags": triggered}

    # status_tags (plural) overrides status_tag when an attack type is
    # genuinely backed by more than one related flag in the same status_file
    # — detection triggers on ANY of them, computed once here (not
    # re-derived in routing) so there's a single source of truth for what
    # "detected" means for this attack.
    status_tags = state.get("status_tags") or [state["status_tag"]]
    tag_values, file_existed = _read_xml_tags(file_path, status_tags)
    if not file_existed:
        return {**state, "live_value": None, "status_file_existed": False, "triggered_tags": []}

    triggered_tags = [tag for tag, value in tag_values.items() if _is_detected(value, value_schema)]
    live_value = (
        tag_values.get(status_tags[0]) if len(status_tags) == 1
        else ", ".join(f"{tag}={value}" for tag, value in tag_values.items())
    )
    return {
        **state,
        "live_value": live_value,
        "tag_values": tag_values,
        "triggered_tags": triggered_tags,
        "status_file_existed": True,
    }


def route_after_resolve(state: AttackState) -> str:
    """A known-unreliable data source is checked before anything else — if
    the file/tag itself is known to be wrong (not just unverifiable), reading
    its live value would only produce a confidently-wrong answer, so this
    skips read_status entirely rather than trusting a value from it."""
    return "cannot_determine" if not state.get("data_source_reliable", True) else "read_status"


def route_from_status_check(state: AttackState) -> str:
    """Single combined routing decision from read_status: a missing status
    file takes priority over everything else — it means this attack type's
    status genuinely cannot be determined for this hierarchy (most likely
    because that file was never configured to sync from the client system to
    the RV server), not that it's clean. Detected short-circuits straight
    through; not-detected splits further on whether raw evidence exists to
    verify against."""
    if not state.get("status_file_existed", True):
        return "not_configured"
    if state.get("triggered_tags"):
        return "detected"
    if state["verification_category"] in ("readable_report", "diffable_snapshot_files"):
        return "verify"
    if state["verification_category"] == "check_raw_logs" and state["attack_type"] in RAW_LOG_CHECKERS:
        return "verify_raw_logs"
    return "unverifiable"


def route_after_verification(state: AttackState) -> str:
    return "discrepancy" if state.get("verification_outcome") == "contradiction" else "confirmed_clean"


def detected_path_node(state: AttackState) -> AttackState:
    return {**state, "final_status": "detected"}


def unverifiable_path_node(state: AttackState) -> AttackState:
    return {**state, "final_status": "not_detected_unverifiable"}


def cannot_determine_node(state: AttackState) -> AttackState:
    return {**state, "final_status": "cannot_determine"}


def not_configured_node(state: AttackState) -> AttackState:
    return {**state, "final_status": "not_configured"}


def verify_against_raw_evidence_node(state: AttackState) -> AttackState:
    # Always relative to this hierarchy's own vault path, same as
    # read_live_status_node — raw_evidence_files entries (e.g.
    # "athinio/system/aide_report.txt") are only ever meaningful joined onto
    # this specific hierarchy's folder, never onto vault_root directly.
    hierarchy_root = _hierarchy_path(state["vault_root"], state["hierarchy"])
    evidence_texts = []
    missing_files = []
    for rel_path in state.get("raw_evidence_files", []):
        content, existed = _read_text_file(hierarchy_root / rel_path)
        if not existed:
            missing_files.append(rel_path)
            continue
        if not content:
            continue

        # Pull the corpus's explanation of THIS SPECIFIC evidence file
        # (exact id lookup, not semantic search) so the model isn't
        # cold-reading an unfamiliar report format — it gets a labeled
        # reference example alongside the live content being checked.
        corpus_context = ""
        corpus_id = _EVIDENCE_FILE_CORPUS_IDS.get(rel_path)
        if corpus_id:
            file_entry = get_corpus_entry(corpus_id)
            if file_entry.get("found"):
                metadata = file_entry["metadata"]
                # Include every labeled example (clean, detected, etc.), not
                # just one — showing the model both ends of the range gives
                # it something to calibrate against, not just a single
                # unlabeled snapshot with no contrast to judge severity by.
                examples = metadata.get("raw_content_examples") or []
                example_lines = "\n".join(
                    f"  [{ex.get('label', '?')}] {ex.get('content', '')}\n    ({ex.get('note', '')})"
                    for ex in examples
                )
                value_meanings = metadata.get("value_meanings") or {}
                meanings_lines = "\n".join(f"  {k}: {v}" for k, v in value_meanings.items())
                corpus_context = (
                    f"\n=== REFERENCE MATERIAL (illustrative only — NOT this hierarchy's data) ===\n"
                    f"{file_entry['explanation']}\n"
                    f"What different values typically mean:\n{meanings_lines}\n"
                    f"Labeled illustrative examples (none of these are real findings for this system):\n{example_lines}\n"
                    f"=== END REFERENCE MATERIAL ===\n"
                )

        evidence_texts.append(
            f"--- {rel_path} ---{corpus_context}\n"
            f"=== ACTUAL LIVE CONTENT FOR THIS HIERARCHY (this is what you must judge) ===\n"
            f"{content}\n"
            f"=== END ACTUAL LIVE CONTENT ==="
        )

    if not evidence_texts:
        # Evidence files were expected but none could be read — don't guess,
        # and say specifically WHY: a missing file usually means it was never
        # configured to sync from the client system to the RV server, which
        # is a different (and more informative) fact than "file exists and
        # is unreadable" or "confirmed clean".
        if missing_files:
            reasoning = (
                f"Raw evidence file(s) not found at this hierarchy's vault path: "
                f"{', '.join(missing_files)}. These files were not configured to be "
                f"copied to the RV server from the client system, so this could not "
                f"be independently verified beyond the tag's own status."
            )
        else:
            reasoning = (
                "Raw evidence file(s) exist but were unreadable; falling back to "
                "the tag's own 'not detected' status."
            )
        return {
            **state,
            "verification_outcome": "confirmed_clean",
            "verification_reasoning": reasoning,
        }

    combined_evidence = "\n\n".join(evidence_texts)
    if missing_files:
        # Confirmed real bug (config_drift, 2026-08-27): when SOME evidence
        # files existed and others didn't, this list was silently dropped —
        # the model was handed only the files that existed with no signal
        # that others were expected, and it fabricated a comparison against
        # a baseline file (sec_config_lin_verified.xml) that was never
        # actually read, confirmed absent from the real hierarchy on disk.
        # Missing files are now named explicitly so the model can't mistake
        # "not given to me" for "checked and matched".
        combined_evidence += (
            f"\n\n--- The following evidence file(s) were EXPECTED but NOT FOUND, "
            f"and are NOT included above: {', '.join(missing_files)}. Do not claim "
            f"to have compared against, read, or checked these files — treat them "
            f"as simply absent from what you were given. ---"
        )

    template = ChatPromptTemplate.from_messages([
        ("system",
         "You are a cybersecurity analyst double-checking a 'not detected' status "
         "for one specific attack type, using the same raw evidence the original "
         "detection script itself reads. Only flag a contradiction if the evidence "
         "clearly shows the attack occurred — routine noise or ambiguous content "
         "should be treated as confirming the clean status, not contradicting it.\n\n"
         "Each piece of evidence below is split into a REFERENCE MATERIAL section "
         "and an ACTUAL LIVE CONTENT section. The reference material shows what this "
         "file's format generally looks like, including illustrative example findings "
         "— none of those examples are real, and none of them happened on this system. "
         "Base your judgment ONLY on the ACTUAL LIVE CONTENT section. Do not mention, "
         "reference, or treat as evidence anything that appears only in the reference "
         "material's illustrative examples.\n\n"
         "A live content file may be a shared, multi-purpose status file containing "
         "many tags for many different attack types, not just this one — e.g. "
         "alertlog.xml or Alert.xml can list dozens of unrelated indicators in the "
         "same file. Only flag a contradiction if evidence SPECIFIC TO THIS ATTACK "
         "TYPE disagrees with its 'not detected' status. Other, unrelated tags in the "
         "same file being active is NOT evidence against this specific attack type's "
         "clean status, even if it looks like 'something is wrong' in the file overall "
         "— that's a different attack type's concern, not this one's.\n\n"
         "Some evidence content is itself just a restated pass/fail verdict (e.g. a "
         "single line like 'RESULT: attack detected' or 'INFO: not detected') with no "
         "further detail — that kind of content is corroboration of the tag, not "
         "independent evidence, since it was written by the same detection run as the "
         "tag itself. Give it little weight either way. Only specific, checkable detail "
         "— file paths, counts, timestamps, log excerpts — can justify a contradiction "
         "verdict.\n\n"
         "If the evidence block ends with a note naming files that were expected but "
         "not found, your reasoning must not claim to have compared against, read, or "
         "checked any of those named files — say plainly that they were unavailable "
         "instead."),
        ("user",
         "Attack type: {attack_type}\n"
         "What this status normally means: {meaning}\n\n"
         "Raw evidence:\n{evidence}\n\n"
         "Does this evidence confirm the system is clean, or contradict the "
         "'not detected' status?")
    ])

    try:
        structured_model = model.with_structured_output(EvidenceVerificationResult)
        result = (template | structured_model).invoke({
            "attack_type": state["attack_type"],
            "meaning": state["meaning"],
            "evidence": combined_evidence,
        })
        return {
            **state,
            "verification_outcome": result.outcome,
            "verification_reasoning": result.reasoning,
        }
    except Exception as e:
        return {
            **state,
            "verification_outcome": "confirmed_clean",
            "verification_reasoning": f"Verification pass failed ({e}); falling back to the tag's own status.",
        }


def verify_against_raw_logs_node(state: AttackState) -> AttackState:
    """For attack types with no dedicated evidence file but a genuinely
    confirmed raw-log pattern (see RAW_LOG_CHECKERS) — goes one step further
    back than verify_against_raw_evidence_node: instead of a per-attack
    evidence file, this reads the same underlying system logs the
    secure/messages/audit.log catch-all pipeline analyzes, and runs a
    deterministic, already-established pattern match against them."""
    hierarchy_root = _hierarchy_path(state["vault_root"], state["hierarchy"])
    checker = RAW_LOG_CHECKERS[state["attack_type"]]

    # RAW_LOG_FILE_PATTERNS entries are glob patterns, not exact filenames —
    # several of these logs are Julian-day rotated (confirmed on a real
    # hierarchy: rationalclient.log only ever exists as
    # rationalclient.log_NNN, gateway.log as gateway.log_NNN), so an
    # exact-name lookup silently always misses them.
    combined_text_parts = []
    missing_patterns = []
    for pattern in RAW_LOG_FILE_PATTERNS.get(state["attack_type"], []):
        matches = sorted(hierarchy_root.glob(pattern))
        if not matches:
            missing_patterns.append(pattern)
            continue
        for match_path in matches:
            content, existed = _read_text_file(match_path, max_chars=20000)
            if existed and content:
                combined_text_parts.append(content)

    if not combined_text_parts:
        reasoning = (
            f"Raw log file(s) not found at this hierarchy's vault path (patterns tried: "
            f"{', '.join(missing_patterns)}). These logs were not configured to be copied "
            f"to the RV server from the client system, so this could not be checked beyond "
            f"the tag's own status."
            if missing_patterns else
            "Raw log files exist but were unreadable; falling back to the tag's own status."
        )
        return {**state, "verification_outcome": "confirmed_clean", "verification_reasoning": reasoning}

    found, reasoning = checker("\n".join(combined_text_parts))

    # Cross-check against a purpose-built status file, ONLY where one is
    # confirmed to be genuinely independent evidence (not just the same tag
    # restated as text — see SUPPLEMENTARY_RAW_LOG_STATUS_FILES's docstring
    # for why user_breach's secOpsOutput_113 was removed from this role).
    supplementary_path = SUPPLEMENTARY_RAW_LOG_STATUS_FILES.get(state["attack_type"])
    if supplementary_path:
        supp_content, supp_existed = _read_text_file(hierarchy_root / supplementary_path, max_chars=2000)
        if supp_existed and supp_content:
            reasoning += f" Supplementary source ({supplementary_path}): \"{supp_content.strip()}\"."

    return {
        **state,
        "verification_outcome": "contradiction" if found else "confirmed_clean",
        "verification_reasoning": reasoning,
    }


def _read_corroborating_evidence(state: AttackState) -> str:
    """Reads this attack type's raw_evidence_files fresh, for display in the
    rendered report — used for BOTH outcomes (detected/discrepancy AND
    not_detected), not just detected cases, so a verified-clean result shows
    what was actually read to reach that conclusion instead of only an LLM's
    summary of it."""
    raw_files = state.get("raw_evidence_files") or []
    if not raw_files:
        return ""
    hierarchy_root = _hierarchy_path(state["vault_root"], state["hierarchy"])
    pieces = []
    for rel_path in raw_files:
        content, existed = _read_text_file(hierarchy_root / rel_path, max_chars=1500)
        if existed and content:
            pieces.append(f"--- {rel_path} ---\n{content}")
    return "\n\n".join(pieces)


def not_detected_clean_node(state: AttackState) -> AttackState:
    return {
        **state,
        "final_status": "not_detected",
        "corroborating_evidence_text": _read_corroborating_evidence(state),
    }


def discrepancy_node(state: AttackState) -> AttackState:
    return {**state, "final_status": "discrepancy"}


def attack_info_node(state: AttackState) -> AttackState:
    """Explain the attack + recommended actions, using the same
    search-then-synthesize approach as lib/log_analysis_workflow.py's own
    per-incident search/explain steps. Not a literal reuse of those
    functions — they're scoped to that module's own incident-type/dataset-
    example shape, which doesn't apply here. Same pattern, self-contained
    implementation."""
    attack_type = state["attack_type"]

    # Confirmed real bug (rootkit_malware, 2026-08-27): this node previously
    # only ran a generic web search on the attack type's NAME, never looking
    # at raw_evidence_files even when they existed and were available — so a
    # detected result got explained purely in the abstract ("what is a
    # rootkit") while the actual corroborating file on disk
    # (secOpsOutput_112) said something more specific ("Unknown binary
    # detected: /usr/lib/systemd/systemd-user-runtime-dir") that pointed to a
    # different real mechanism. Reading it here surfaces that real content in
    # the report instead of only a generic explanation.
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


def _format_provenance_chain(writer_script: str, status_file: str, tags_display: str) -> str:
    """Renders writer_script as a step-by-step chain from the root source
    down to the tag/file this workflow actually reads, instead of burying
    that trail in one dense 'written by ...' clause. writer_script has been
    written throughout this corpus as an arrow-delimited chain (" -> ")
    wherever a real multi-hop provenance was confirmed from source (e.g.
    "oneCloudFilerx -> config.xml's RansomDetected -> gatewayMonitor.sh ->
    alertlog.xml's AMS_Ransom_current_status") — this just re-renders that
    existing structure visually rather than parsing anything new. Entries
    with no confirmed multi-hop chain (writer_script has no " -> ") render
    as a single step, same as before, just reformatted."""
    hops = [h.strip() for h in writer_script.split(" -> ") if h.strip()]
    if not hops:
        hops = [writer_script]
    lines = [f"{i}. {hop}" for i, hop in enumerate(hops, start=1)]
    lines.append(f"{len(hops) + 1}. **`{status_file}` -> `{tags_display}`** *(this workflow reads here)*")
    return "\n".join(lines)


def render_markdown_section_node(state: AttackState) -> AttackState:
    attack_label = state["attack_type"].replace("_", " ").title()
    final_status = state["final_status"]

    # STATUS_MARKER (the HTML comment) always carries the real, precise
    # status for accurate summary counts — but not_detected_unverifiable is
    # displayed to the reader as plain "NOT DETECTED", since the
    # unverifiable/verified distinction is now conveyed by whether raw
    # evidence appears below, not by a separate status word.
    display_status = "not_detected" if final_status == "not_detected_unverifiable" else final_status

    lines = [f"## {attack_label}", ""]
    lines.append(f"<!-- {STATUS_MARKER}: {final_status} -->")
    lines.append(f"**Status:** {display_status.replace('_', ' ').upper()}")
    status_tags = state.get("status_tags") or [state["status_tag"]]
    tags_display = ", ".join(status_tags)
    lines.append(f"\n**Source chain:**\n{_format_provenance_chain(state['writer_script'], state['status_file'], tags_display)}")

    if final_status == "detected":
        triggered = state.get("triggered_tags") or status_tags
        if len(status_tags) > 1:
            lines.append(f"\n**Triggered tag(s):** `{', '.join(triggered)}` (out of `{', '.join(status_tags)}` checked)")
        lines.append(f"\n{state['meaning']}")
        if state.get("corroborating_evidence_text"):
            lines.append(f"\n### Corroborating raw evidence\n\n```\n{state['corroborating_evidence_text']}\n```")
        lines.append(f"\n### What this attack is / recommended actions\n\n{state.get('explainer_text', '')}")

    elif final_status == "discrepancy":
        lines.append(
            f"\n⚠ The status tag says 'not detected', but independent review of the raw "
            f"evidence disagreed: {state.get('verification_reasoning', '')}"
        )
        # Point at the dashboard-facing feature, never the internal script
        # filename — whoever reads this report has no way to "run
        # ransCheck.sh", but they can re-trigger a UI feature by name.
        feature_ref = state.get("ui_feature_name") or f"the feature that manages `{state['writer_script']}`"
        lines.append(
            f"\n**Recommended:** re-run **{feature_ref}** from the dashboard "
            f"for an authoritative fresh determination."
        )
        if state.get("corroborating_evidence_text"):
            lines.append(f"\n### Corroborating raw evidence\n\n```\n{state['corroborating_evidence_text']}\n```")
        lines.append(f"\n### What this attack is / recommended actions\n\n{state.get('explainer_text', '')}")

    elif final_status == "not_detected":
        lines.append(f"\n✅ Not detected. Verified against raw evidence: {state.get('verification_reasoning', '')}")
        if state.get("corroborating_evidence_text"):
            lines.append(f"\n### Raw evidence checked\n\n```\n{state['corroborating_evidence_text']}\n```")

    elif final_status == "not_detected_unverifiable":
        live_value_display = state.get("live_value")
        # file_contains_pattern schemas (e.g. config_drift, rootkit_malware)
        # can put an entire multi-line file's text into live_value — inline
        # backticks break on embedded newlines, so those render as a code
        # block instead of inline.
        if live_value_display and "\n" in str(live_value_display):
            value_line = f"currently reads:\n\n```\n{live_value_display}\n```"
        else:
            value_line = f"currently reads `{live_value_display}`."
        lines.append(
            f"\n✅ Not detected -- `{state['status_file']}` -> `{tags_display}` {value_line}\n\n"
            f"No independent evidence exists for this attack type, so this reading could not be "
            f"cross-checked against anything else — it reflects only what the tag itself reports."
        )
        lines.append(f"\n**What determines this status:**\n\n{state.get('meaning', '')}")

    elif final_status == "not_configured":
        vault_display = f"rationalVault/data/{state['hierarchy']}/{state['status_file']}"
        lines.append(
            f"\n❓ **File not configured for this system.** `{state['status_file']}` was not "
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

    workflow.add_node("resolve", resolve_attack_files_node)
    workflow.add_node("read_status", read_live_status_node)
    workflow.add_node("detected", detected_path_node)
    workflow.add_node("unverifiable", unverifiable_path_node)
    workflow.add_node("cannot_determine", cannot_determine_node)
    workflow.add_node("not_configured", not_configured_node)
    workflow.add_node("verify", verify_against_raw_evidence_node)
    workflow.add_node("verify_raw_logs", verify_against_raw_logs_node)
    workflow.add_node("not_detected_clean", not_detected_clean_node)
    workflow.add_node("discrepancy", discrepancy_node)
    workflow.add_node("attack_info", attack_info_node)
    workflow.add_node("render", render_markdown_section_node)

    workflow.set_entry_point("resolve")

    workflow.add_conditional_edges("resolve", route_after_resolve, {
        "cannot_determine": "cannot_determine",
        "read_status": "read_status",
    })

    workflow.add_conditional_edges("read_status", route_from_status_check, {
        "detected": "detected",
        "verify": "verify",
        "verify_raw_logs": "verify_raw_logs",
        "unverifiable": "unverifiable",
        "not_configured": "not_configured",
    })

    workflow.add_conditional_edges("verify", route_after_verification, {
        "discrepancy": "discrepancy",
        "confirmed_clean": "not_detected_clean",
    })

    workflow.add_conditional_edges("verify_raw_logs", route_after_verification, {
        "discrepancy": "discrepancy",
        "confirmed_clean": "not_detected_clean",
    })

    workflow.add_edge("detected", "attack_info")
    workflow.add_edge("discrepancy", "attack_info")
    workflow.add_edge("attack_info", "render")
    workflow.add_edge("not_detected_clean", "render")
    workflow.add_edge("unverifiable", "render")
    workflow.add_edge("cannot_determine", "render")
    workflow.add_edge("not_configured", "render")
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
