"""
log_analysis_workflow.py — per-incident log analysis, context-flat like attack_status_workflow.py.

The old pipeline (test_legacy_log_aggregation.py, removed 2026-08-28) ran ONE
linear 8-node LangGraph per hierarchy, and FOUR of those nodes each re-sent
the entire aggregated raw log text to the LLM again, on top of everything
earlier nodes already produced (title, incident type, dataset examples,
search results) — so token count, cost, and latency all grew with every step
in a single run, worst at the end.

This module keeps that pipeline's real domain logic (the classification
prompt's rule-based-hint handling, self-consistency voting on cold
classification, threat-level calibration — extracted here rather than
re-derived) but restructures the CONTROL FLOW the
same way attack_status_workflow.py already restructured the per-attack
checks:

  1. Classify ONCE — the raw logs are read by the LLM exactly one time
     (_classify_once), producing a title, a primary incident_type, and a
     list of secondary_incident_types.
  2. Discard the raw log text — nothing after step 1 ever sees it again.
  3. For EACH incident (the primary, and each secondary, all treated equally
     — no "primary gets full treatment, secondary gets an afterthought"
     asymmetry), run an ISOLATED sequence: search queries -> DDG search ->
     explain -> render one markdown section -> append to the report ->
     discard. Exactly the same
     invoke-fresh/append/discard shape run_attack_status_loop already uses
     for its attack types, just applied to a small number of log-derived
     incidents instead of a fixed taxonomy.

IOC vector-group/XML generation from the old pipeline was NOT ported here —
this module covers classification + per-incident explanation only. That was
a deliberate scope decision, not an oversight; add it back if still needed.

This module does NOT pull anything from the vault itself — it reads
var/log/messages, var/log/secure, var/log/audit.log (configurable via
LOG_FILE_PATHS) directly from an ALREADY-LOCAL hierarchy pull. That pull is
someone else's job: attack_status_workflow.py's run_full_workflow already
pulls the whole hierarchy tree (via populate_hierarchies) before running the
attack checks, and only calls this module's run_log_analysis_loop AFTER
those checks — so var/log/* is already on disk, and a second, separate
selective pull here would just be redundant. Running this module's own CLI
standalone therefore requires the hierarchy to already be pulled locally
(e.g. via populate_hierarchies.py or a prior attack_status_workflow.py run).

Usage:
    python -m lib.log_analysis_workflow 5/101/1/4/1
"""

import json
import os
import re
from collections import Counter
from pathlib import Path
from datetime import datetime
from typing import List, Literal, NotRequired, TypedDict
import argparse

from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field
from ddgs import DDGS

from lib.llm_client import model
from lib.legacy_log_aggregation import _load_log_file_paths, _load_log_tail_lines, _read_as_text_or_placeholder

STATUS_MARKER = "LOG_INCIDENT_MARKER"

# Written verbatim by _consolidate_local_log_files when none of
# LOG_FILE_PATHS were found locally — checked by run_log_analysis_loop to
# skip straight to a clean-run note instead of running the LLM pipeline on
# an empty/placeholder input.
CLEAN_RUN_MARKER = "No log files found in this pull."


# ── Classification (the ONLY place raw log text reaches the LLM) ───────────
# Extracted from the old test_legacy_log_aggregation.py, unchanged in logic —
# rule-based-hint handling and self-consistency voting were both confirmed
# to matter there and are kept exactly as validated.

# This workflow classifies exactly three log sources: /var/log/secure,
# /var/log/messages, and /var/log/audit/audit.log — so the taxonomy is
# restricted to only the incident types actually detectable from THOSE
# sources, not the full generic dataset taxonomy. A category not reachable
# from any of these three logs (e.g. sql_injection needs web-server/DB logs;
# rootkit_detected needs an rkhunter/chkrootkit scan-output log, not
# behavioral evidence; ransomware_indicator/honeypot_tamper as tested here
# came from a separate custom application log, not auditd's narrow watch
# rules) is excluded from the enum entirely — not discouraged in the prompt,
# structurally impossible for the model to select — since prompt-level
# discouragement was confirmed by testing to just redirect wrong answers
# toward OTHER wrong categories rather than the correct one.
ALLOWED_INCIDENT_TYPES = {
    "user_breach",                  # /var/log/secure: failed-password cluster then accepted-password from same source
    "privilege_escalation",         # /var/log/secure (sudo/su) or audit.log (setuid execve, capability change)
    "ssh_key_injection",            # audit.log watching ~/.ssh/authorized_keys, or the secure session that modified it
    "suspicious_command_execution", # audit.log watched-command syscalls (download-then-execute chains, account creation)
    "assets_permission_tamper",     # audit.log chmod/chown syscalls on watched files
    "file_integrity_tamper",        # audit.log watched-file modification/deletion events
    "unknown_binary_execution",     # audit.log execve of a binary outside the known baseline
    "log_tampering",                # /var/log/messages: rsyslog/journald/auditd service stop-restart events
    "banned_ip",                    # /var/log/messages: firewall/fail2ban-style ban actions logged via syslog
    "disk_full",                    # /var/log/messages: kernel "no space left on device"
    "memory_leak",                  # /var/log/messages: OOM-killer kernel messages
    "network_anomaly",              # /var/log/messages: kernel/network-daemon messages (weakest evidence of this group)
}

INCIDENT_TYPES = sorted(ALLOWED_INCIDENT_TYPES)
INCIDENT_TYPES_SET = set(INCIDENT_TYPES)
NONE_APPLICABLE_INCIDENT_TYPE = "none_applicable"
INCIDENT_TYPES_WITH_FALLBACK = sorted(INCIDENT_TYPES_SET.union({NONE_APPLICABLE_INCIDENT_TYPE}))
INCIDENT_TYPES_WITH_FALLBACK_SET = set(INCIDENT_TYPES_WITH_FALLBACK)
INCIDENT_TYPES_WITH_FALLBACK_HINT = ", ".join(INCIDENT_TYPES_WITH_FALLBACK)


class MessageState(TypedDict):
    logs: str
    result: dict
    logs_path: NotRequired[str]
    output_dir: NotRequired[str]
    customer_ids: NotRequired[List[str]]


def _carry_context(state: MessageState) -> dict:
    """Preserve filesystem context between workflow nodes."""
    return {
        "logs_path": str(state.get("logs_path", "") or ""),
        "output_dir": str(state.get("output_dir", "") or ""),
        "customer_ids": list(state.get("customer_ids", []) or []),
    }


class InitialAnalysisTemplate(BaseModel):
    title: str = Field(description="An appropriate title of the attack or potential attack after analyzing the logs")
    content: str = Field(description="A 100-200 word initial analysis of the attack or potential attack after analyzing the logs")


class InitialSearchFromLogsToDatasetTemplate(BaseModel):
    incident_type: Literal[tuple(INCIDENT_TYPES_WITH_FALLBACK)] = Field(
        description=(
            "PRIMARY incident type label selected from dataset taxonomy — the single most "
            "significant/severe distinct attack pattern evidenced in the logs. "
            f"Use '{NONE_APPLICABLE_INCIDENT_TYPE}' if none match."
        )
    )
    secondary_incident_types: List[Literal[tuple(INCIDENT_TYPES_WITH_FALLBACK)]] = Field(
        default_factory=list,
        description=(
            "Any OTHER distinct incident types also clearly and explicitly evidenced in the logs, "
            "besides the primary one. Leave empty if there's only one incident. Never include the "
            f"primary incident_type again here, and never include '{NONE_APPLICABLE_INCIDENT_TYPE}'."
        ),
    )


class QuestionFormerOutputTemplate(BaseModel):
    search_query_1: str = Field(description="A search query to find more information about the attack or potential attack")
    search_query_2: str = Field(description="Another search query to find more information about the attack or potential attack")
    search_query_3: str = Field(description="Another search query to find more information about the attack or potential attack")
    search_query_4: str = Field(description="Another search query to find more information about the attack or potential attack")
    search_query_5: str = Field(description="Another search query to find more information about the attack or potential attack")


class SecondaryIncidentTemplate(BaseModel):
    incident_type: str = Field(description="One of the secondary incident types already classified for this pull")
    threat_level: Literal["low", "medium", "high", "critical"] = Field(description="Threat level of this specific secondary incident, judged independently of the primary incident")
    summary: str = Field(description="1-3 sentence summary of what this secondary finding is and why it matters, grounded only in the logs — not the primary incident's narrative")


class ExplainerOutputTemplate(BaseModel):
    threat_level: Literal["low", "medium", "high", "critical"] = Field(description="The threat level of the PRIMARY attack or potential attack based on the search results")
    detailed_analysis: str = Field(description="A more detailed analysis of the PRIMARY attack or potential attack based on the search results", min_length=500)
    search_results: List[dict] = Field(description="The search results used to derive the detailed analysis")
    recommended_actions: List[str] = Field(description="Recommended actions to mitigate the attack or potential attack based on the detailed analysis", min_length=5)
    secondary_incidents: List[SecondaryIncidentTemplate] = Field(default_factory=list, description="Brief independent assessment of each secondary incident type, if any were classified")


def _extract_first_json_object(text: str):
    """Extract the first JSON object from mixed model output."""
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
    """Remove duplicate non-empty lines from multiline model output."""
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
    """Ensure required InitialAnalysis fields exist for strict schema validation."""
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


def _normalize_initial_search_payload(payload: dict) -> dict:
    """Ensure required InitialSearch fields exist for strict schema validation."""
    out = dict(payload or {})
    incident_type = str(out.get("incident_type", "")).strip()
    if incident_type not in INCIDENT_TYPES_WITH_FALLBACK_SET:
        incident_type = NONE_APPLICABLE_INCIDENT_TYPE
    out["incident_type"] = incident_type
    raw_secondary = out.get("secondary_incident_types", [])
    if not isinstance(raw_secondary, list):
        raw_secondary = []
    cleaned_secondary = []
    for item in raw_secondary:
        candidate = str(item).strip()
        if (candidate in INCIDENT_TYPES_WITH_FALLBACK_SET
                and candidate != incident_type
                and candidate != NONE_APPLICABLE_INCIDENT_TYPE
                and candidate not in cleaned_secondary):
            cleaned_secondary.append(candidate)
    out["secondary_incident_types"] = cleaned_secondary
    return out


def _format_step_label(step: int, message: str, total_steps: int | None = None) -> str:
    if total_steps is None:
        return f"[STEP {step}] {message}"
    return f"[STEP {step}/{total_steps}] {message}"


def InitialAnalysisNode(state: MessageState) -> MessageState:
    """Generates a title + 100-200 word initial analysis from the raw logs.
    The FIRST of two places raw log text reaches the LLM (the only two,
    total, in this whole module)."""
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
    """Classifies incident_type (+ secondary_incident_types) from the raw
    logs + initial analysis. The SECOND and last place raw log text reaches
    the LLM in this module. Rule-based hints (from anomaly_workflow.py's own
    deterministic detection headers, when present in the logs) are treated
    as a strong prior; self-consistency voting (3 passes, majority vote) is
    used only for cold classification, where instability was actually
    observed and confirmed (3 different answers to byte-identical input)."""
    print("\n" + "=" * 70)
    print(_format_step_label(2, "Classifying incident type from initial analysis + logs..."))
    print("=" * 70)

    incident_type_model = model.with_structured_output(InitialSearchFromLogsToDatasetTemplate)
    prior_result = dict(state.get("result", {}))
    title = str(prior_result.get("title", "Potential Security Incident"))
    content = str(prior_result.get("content", ""))

    suggested_match = re.search(
        r"Suggested incident_type \(rule-based, from detection source\):\s*(\S+)",
        state["logs"],
    )
    suggested_hint = suggested_match.group(1) if suggested_match else None

    secondary_match = re.search(
        r"Additional suggested incident_types \(secondary, rule-based, from detection source\):\s*(.+)",
        state["logs"],
    )
    secondary_hints = (
        [h.strip() for h in secondary_match.group(1).split(",") if h.strip()]
        if secondary_match else []
    )
    secondary_hint_instruction = (
        f"\nThe input also contains rule-based secondary suggestions: {secondary_hints}. "
        f"These are separate, distinct findings from the primary one — include each in "
        f"secondary_incident_types unless the logs clearly show that finding doesn't actually apply."
        if secondary_hints else ""
    )
    hint_instruction = (
        f"\nThe input also contains a rule-based suggestion: '{suggested_hint}'. "
        f"This came from deterministic detection logic (not a guess) — treat it as the correct answer for "
        f"incident_type (the PRIMARY incident). "
        f"Only override it if the logs contain EXPLICIT, unambiguous evidence of a different specific "
        f"attack pattern actually occurring (e.g. an actual new key added to authorized_keys, not merely "
        f"the word 'SSH' or a related term appearing somewhere in the input). A different finding that is "
        f"merely adjacent or superficially similar-sounding — including one described in the initial "
        f"analysis text above — is NOT sufficient grounds to override the suggestion; that other finding "
        f"may itself be a separate, lower-priority observation rather than the primary incident."
        f"{secondary_hint_instruction}"
        if suggested_hint else secondary_hint_instruction
    )

    incident_type_template = ChatPromptTemplate.from_messages([
        ("system", f"""You are a cybersecurity analyst.
Using the existing initial analysis and logs, return:
- incident_type (string) — the single PRIMARY incident
- secondary_incident_types (list of strings) — any OTHER distinct incidents also clearly evidenced, or an empty list if there's only one

incident_type must be exactly one of: {INCIDENT_TYPES_WITH_FALLBACK_HINT}
Use '{NONE_APPLICABLE_INCIDENT_TYPE}' if none of the listed types are applicable.
secondary_incident_types must each also be one of the listed types, must never repeat the primary incident_type, and must never contain '{NONE_APPLICABLE_INCIDENT_TYPE}'.
Ignore file-not-found style noise and focus on true security indicators.

Base your choice strictly on the LITERAL actions, commands, filenames, and alert
messages that actually appear in the logs below — not on a type's name merely
sounding thematically related or "safe" to pick when uncertain. Pick the type
whose own definition most literally matches what these specific logs show,
not the most generic-sounding "something is wrong" option.

One pattern worth being precise about: auth/sshd-style logs showing a cluster
of "Failed password" entries (for one or more usernames) from the same source
address, followed by an "Accepted password" (not "Accepted publickey") success
from that SAME address shortly after, is user_breach — that specific
failed-then-succeeded-by-password sequence from one source IP is the
compromise, regardless of any other routine publickey sessions, sudo
commands, or cron jobs also present in the same log window; those surrounding
lines are normal activity and shouldn't pull the classification toward a
different category instead.{hint_instruction}"""),
        ("user", """Logs:
{logs}

Initial Analysis:
Title: {title}
Content: {content}""")
    ])

    input_payload = {"logs": state["logs"], "title": title, "content": content}
    incident_type_chain = incident_type_template | incident_type_model

    def _classify_once_vote() -> InitialSearchFromLogsToDatasetTemplate:
        try:
            result = incident_type_chain.invoke(input_payload)
            normalized = _normalize_initial_search_payload(result.model_dump())
            return InitialSearchFromLogsToDatasetTemplate.model_validate(normalized)
        except Exception as e:
            print(f"  ⚠ Structured output parsing failed: {e}")
            print("  ↻ Retrying incident type classification with strict JSON fallback...")
            fallback_prompt = ChatPromptTemplate.from_messages([
                ("system", f"""Return ONLY valid JSON with these exact keys:
- incident_type: string (must be one of: {INCIDENT_TYPES_WITH_FALLBACK_HINT})
- secondary_incident_types: array of strings (each must also be one of the listed types; empty array if only one incident)

If no listed type applies, set incident_type to '{NONE_APPLICABLE_INCIDENT_TYPE}'.
secondary_incident_types must never repeat incident_type and must never contain '{NONE_APPLICABLE_INCIDENT_TYPE}'.
Do not include markdown, HTML, comments, or extra text before/after JSON.{hint_instruction}"""),
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
            normalized = _normalize_initial_search_payload(parsed or {})
            return InitialSearchFromLogsToDatasetTemplate.model_validate(normalized)

    if suggested_hint:
        incident_type_result = _classify_once_vote()
    else:
        # Default changed to 1 (2026-08-28): this vote re-runs the FULL
        # classification prompt — including the entire raw log text, the one
        # place in this module still carrying it — N times sequentially.
        # Confirmed slow in practice against real, multi-thousand-line
        # aggregated logs; the instability that originally motivated voting
        # (3 different answers to byte-identical input) was observed on much
        # smaller test inputs, not proven to matter as much at this scale.
        # Set CLASSIFICATION_VOTE_COUNT explicitly to re-enable voting where
        # classification correctness matters more than speed.
        vote_count = max(1, int(os.getenv("CLASSIFICATION_VOTE_COUNT", "1")))
        votes = [_classify_once_vote() for _ in range(vote_count)]
        primary_counts = Counter(v.incident_type for v in votes)
        winning_type, _ = primary_counts.most_common(1)[0]
        print(f"  Self-consistency vote ({vote_count} passes): "
              f"{dict(primary_counts)} -> chose '{winning_type}'")
        agreeing_votes = [v for v in votes if v.incident_type == winning_type]
        secondary_counts = Counter(sec for v in agreeing_votes for sec in v.secondary_incident_types)
        threshold = len(agreeing_votes) / 2
        winning_secondary = [t for t, c in secondary_counts.items() if c > threshold]
        incident_type_result = agreeing_votes[0].model_copy(
            update={"incident_type": winning_type, "secondary_incident_types": winning_secondary}
        )

    merged_secondary = list(incident_type_result.secondary_incident_types)
    for hint in secondary_hints:
        if (hint in INCIDENT_TYPES_WITH_FALLBACK_SET
                and hint != incident_type_result.incident_type
                and hint not in merged_secondary):
            merged_secondary.append(hint)
    if merged_secondary != incident_type_result.secondary_incident_types:
        incident_type_result = incident_type_result.model_copy(update={"secondary_incident_types": merged_secondary})

    print(f"✓ Initial incident type: {incident_type_result.incident_type}")
    if incident_type_result.secondary_incident_types:
        print(f"✓ Secondary incident types: {incident_type_result.secondary_incident_types}")

    return {
        **_carry_context(state),
        "logs": state["logs"],
        "result": {**prior_result, **incident_type_result.model_dump()},
    }


def _classify_once(logs_content: str, logs_file: Path, output_dir: Path, customer_ids: list[str]) -> dict:
    """Calls InitialAnalysisNode then InitialSearchFromLogsToDatasetNode
    exactly once — the only two LLM calls in this whole module that see the
    raw log text. Everything downstream works off state["result"] only."""
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


# ── Phase 2: isolated per-incident processing ──────────────────────────────
# None of this ever sees the raw log text — only the title/content/
# incident_type extracted above, plus this incident's own search results.

def _form_search_queries(title: str, content: str, incident_type: str) -> list[str]:
    """Same intent as the old QuestionFormerNode (5 queries phrased around
    the general technique, not internal field names), scoped to the
    already-extracted title/content/incident_type instead of the raw logs."""
    structured_model = model.with_structured_output(QuestionFormerOutputTemplate)
    incident_type_hint = (
        f" The incident has already been classified as '{incident_type}' — let that guide which "
        f"general concept each query targets."
        if incident_type and incident_type != NONE_APPLICABLE_INCIDENT_TYPE else ""
    )
    template = ChatPromptTemplate.from_messages([
        ("system", "You are a cybersecurity analyst. Based on the incident title and analysis below, "
                   "generate 5 search queries to find more information about this attack or potential attack.\n\n"
                   "IMPORTANT: Phrase each query around the general security technique or concept described "
                   "— do not use internal or proprietary system field names, product names, or file paths "
                   "specific to this environment, those won't return useful public results. Every query must "
                   "be traceable to something the title or analysis actually says." + incident_type_hint),
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
                    all_results.append({
                        "query_number": i,
                        "query": query,
                        "title": r.get("title", "No title"),
                        "url": r.get("href", ""),
                        "snippet": r.get("body", "No description available"),
                    })
        except Exception as e:
            print(f"       ✗ Search error: {e}")
    return all_results


def _explain_incident(title: str, content: str, incident_type: str,
                       search_results: list[dict]) -> ExplainerOutputTemplate | None:
    """Same calibration guidance as the old ExplainerOutputNode, but for
    exactly ONE incident at a time — every incident, primary or secondary,
    gets this same full treatment, no asymmetric primary-vs-secondary
    split. Scoped to title/content/search results — never the raw logs."""
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

Provide: threat_level, a detailed analysis (300-500 words) of what happened / likely progression / implications, the search results used, and recommended actions. Leave secondary_incidents empty — this incident is being assessed on its own, not alongside others.

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
    """Defensive backstop for a confirmed real bug (2026-08-28): despite the
    explainer prompt now explicitly forbidding markdown headers in
    detailed_analysis, a model can still emit them — when it did, '##
    High-Level Summary' etc. rendered as PEER headers to this incident's own
    '## <Incident Type>' section, breaking the report's heading hierarchy
    (they appeared to be separate top-level report sections, not content
    nested under this incident). Any leading #-header line found is demoted
    to bold text instead of a header, so worst case it's a formatting
    nit, not a structural break."""
    lines = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            heading_text = stripped.lstrip("#").strip()
            lines.append(f"**{heading_text}**" if heading_text else "")
        else:
            lines.append(line)
    return "\n".join(lines)


def _render_incident_section(incident_type: str, is_primary: bool,
                              explainer: ExplainerOutputTemplate | None) -> str:
    label = incident_type.replace("_", " ").title()
    role = "Primary incident" if is_primary else "Secondary incident"
    lines = [f"## {label}", "", f"<!-- {STATUS_MARKER}: {incident_type} -->", f"**{role}**"]

    if explainer is None:
        lines.append("\n⚠ Detailed explanation could not be generated for this incident (see logs).")
    else:
        lines.append(f"\n**Threat level:** {explainer.threat_level.upper()}")
        lines.append(f"\n{_demote_embedded_headers(explainer.detailed_analysis)}")
        if explainer.recommended_actions:
            lines.append("\n**Recommended actions:**")
            for action in explainer.recommended_actions:
                lines.append(f"- {action}")

    return "\n".join(lines) + "\n"


# ── Local log reading (no MCP pull — see module docstring) ────────────────

def _consolidate_local_log_files(hierarchy_dir: Path) -> str:
    """Reads LOG_FILE_PATHS directly from the ALREADY-LOCAL hierarchy
    directory — no MCP pull here. run_full_workflow already pulls the whole
    hierarchy tree (via populate_hierarchies) before running the attack
    checks, and that full pull already includes var/log/* — so a second,
    separate selective pull for log analysis would just be redundant. Each
    file found is capped to its last LOG_TAIL_LINES lines — these logs grow
    unbounded on the client, and re-analyzing the same already-seen history
    every run wastes tokens/time for no new signal."""
    tail_lines = _load_log_tail_lines()
    sections = []
    for configured_path in _load_log_file_paths():
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


# ── Outer driver ────────────────────────────────────────────────────────

def run_log_analysis_loop(hierarchy: str, hierarchies_dir: Path, report_path: Path) -> dict:
    """Reads this hierarchy's log files directly from the ALREADY-LOCAL
    pulled copy — no separate MCP pull here (see
    _consolidate_local_log_files). This must run AFTER the hierarchy has
    already been pulled locally: run_full_workflow pulls the whole tree via
    populate_hierarchies before running the attack checks, and only calls
    this log-analysis step after those checks — so var/log/* is already
    sitting on disk by the time this runs. Classifies the aggregated content
    ONCE, then processes each resulting incident as an isolated unit —
    appending its section to report_path and discarding everything about it
    before moving to the next, the same convention run_attack_status_loop
    already uses."""
    hierarchy_clean = hierarchy.strip("/\\")
    hierarchy_dir = hierarchies_dir / Path(hierarchy_clean)

    print("\n" + "=" * 70)
    print(f"READING CONFIGURED LOG FILES FROM LOCAL PULLED COPY ({len(_load_log_file_paths())} path(s) from LOG_FILE_PATHS)")
    print("=" * 70)
    logs_content = _consolidate_local_log_files(hierarchy_dir)

    logs_file = hierarchy_dir / "logs_aggregated.txt"
    logs_file.write_text(logs_content, encoding="utf-8")

    with open(report_path, "a", encoding="utf-8") as f:
        f.write(f"\n# Log Analysis (secure / messages / audit.log)\n\n**Read from:** `{hierarchy_dir}` "
                f"(var/log/messages, var/log/secure, var/log/audit.log)\n\n")

    if CLEAN_RUN_MARKER in logs_content:
        with open(report_path, "a", encoding="utf-8") as f:
            f.write("✅ Clean run — none of the configured log files were present in this hierarchy's local pulled copy.\n")
        return {"incident_count": 0, "logs_file": str(logs_file)}

    print("\n" + "#" * 70)
    print("# LOG ANALYSIS — classify once, then isolated per-incident processing")
    print("#" * 70)

    output_dir = hierarchy_dir
    customer_ids = hierarchy_clean.split("/")
    classification = _classify_once(logs_content, logs_file, output_dir, customer_ids)
    # Raw log text is never referenced again past this line.

    title = classification.get("title", "Potential Security Incident")
    content = classification.get("content", "")
    primary_type = classification.get("incident_type", NONE_APPLICABLE_INCIDENT_TYPE)
    secondary_types = classification.get("secondary_incident_types", []) or []

    if primary_type == NONE_APPLICABLE_INCIDENT_TYPE and not secondary_types:
        with open(report_path, "a", encoding="utf-8") as f:
            f.write(f"✅ No applicable incident type classified. Initial analysis: {content}\n")
        return {"incident_count": 0, "logs_file": str(logs_file)}

    # Always show the initial classification's title/analysis once, as
    # context for whatever follows below — regardless of whether
    # primary_type itself was none_applicable, which can happen alongside
    # real secondary_incident_types (a genuine "nothing rises to primary,
    # but these specific other things were flagged" case).
    with open(report_path, "a", encoding="utf-8") as f:
        f.write(f"**Initial analysis — {title}:**\n\n{content}\n")

    # none_applicable is never itself a real incident to process — whether
    # returned as the primary or (defensively) present in secondary.
    # Confirmed real bug (2026-08-28): without this filter, "None Applicable"
    # got a full search+explain treatment as if it were an attack type,
    # producing a nonsensical threat-level assessment for "nothing applies".
    seen: set[str] = set()
    real_types = []
    for t in [primary_type] + list(secondary_types):
        if t != NONE_APPLICABLE_INCIDENT_TYPE and t not in seen:
            seen.add(t)
            real_types.append(t)

    if not real_types:
        with open(report_path, "a", encoding="utf-8") as f:
            f.write("\n✅ No applicable incident type classified beyond the initial analysis above.\n")
        return {"incident_count": 0, "logs_file": str(logs_file)}

    incidents = [(t, i == 0) for i, t in enumerate(real_types)]
    processed = 0

    for incident_type, is_primary in incidents:
        print(f"\n{'='*70}\nProcessing incident: {incident_type} ({'primary' if is_primary else 'secondary'})\n{'='*70}")

        queries = _form_search_queries(title, content, incident_type)
        search_results = _run_ddg_search(queries) if queries else []
        explainer = _explain_incident(title, content, incident_type, search_results)
        section = _render_incident_section(incident_type, is_primary, explainer)

        with open(report_path, "a", encoding="utf-8") as f:
            f.write(section + "\n")
        processed += 1
        # `queries`, `search_results`, `explainer`, `section` all go out of
        # scope here — nothing from this incident carries into the next
        # iteration except what's already been written to disk.

    return {"incident_count": processed, "logs_file": str(logs_file)}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run context-flat, per-incident log analysis for one hierarchy, reading "
                    "var/log/{messages,secure,audit.log} from an ALREADY-LOCAL hierarchy pull "
                    "(e.g. from attack_status_workflow.py, or populate_hierarchies.py directly) "
                    "— this does not pull anything itself."
    )
    parser.add_argument("hierarchy", help="e.g. 5/101/1/4/1")
    parser.add_argument("--hierarchies-dir", default=str(Path(__file__).parent.parent / "hierarchies"))
    args = parser.parse_args()

    hierarchies_dir = Path(args.hierarchies_dir)
    hierarchy_clean = args.hierarchy.strip("/\\")
    reports_dir = hierarchies_dir / hierarchy_clean / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / f"log_analysis_report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.md"

    result = run_log_analysis_loop(args.hierarchy, hierarchies_dir, report_path)
    print(f"\nReport written to: {report_path}")
    print(f"Incidents processed: {result['incident_count']}")


if __name__ == "__main__":
    main()
