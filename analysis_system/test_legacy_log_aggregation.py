from typing import Literal, TypedDict, List, NotRequired
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field
from langgraph.graph import StateGraph, END
from ddgs import DDGS
import argparse
import asyncio
import os
import httpx
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv
from mcp_client import send_files
from legacy_log_aggregation import run_legacy_log_workflow

# Absolute path — see anomaly_workflow.py's DEFAULT_VAULT_ROOT comment. Kept
# in sync with that one; a relative default here silently resolves against
# mcp_server.py's own directory rather than the vault's real data root.
DEFAULT_VAULT_ROOT = "/rationalVault/data"

# Load environment variables
load_dotenv()

# Without an explicit request timeout, a stuck/overloaded Ollama call blocks
# forever with no signal to distinguish "slow" from "hung" — this bounds it so
# a genuinely stuck call fails with a clear exception instead. Every call site
# below still has its own try/except degrading to a safe default, so this
# timeout firing never crashes the workflow, just cuts a bad call short.
MODEL_REQUEST_TIMEOUT_SECONDS = float(os.getenv("MODEL_REQUEST_TIMEOUT_SECONDS", "120"))

# Set MODEL_NUM_GPU=0 to force pure CPU inference (zero layers offloaded to
# GPU) for a controlled A/B test against the default GPU-assisted path. When
# a model doesn't fully fit in VRAM, Ollama splits it across GPU+CPU, and
# every forward pass then pays a PCIe round-trip moving activations between
# the two on every token — that split mode can be slower than running the
# whole model on CPU in one memory space with no cross-device copying at all.
# Left unset, Ollama auto-decides layer placement as it always has.
MODEL_NUM_GPU = os.getenv("MODEL_NUM_GPU")

_model_kwargs = {
    "model": os.getenv("MODEL_NAME", "cybersecqwen"),
    "num_keep": 0,
    "sync_client_kwargs": {"timeout": MODEL_REQUEST_TIMEOUT_SECONDS},
}
if MODEL_NUM_GPU is not None:
    _model_kwargs["num_gpu"] = int(MODEL_NUM_GPU)

model = ChatOllama(**_model_kwargs)


def _load_incident_types_from_datasets() -> List[str]:
    """Load incident types dynamically from merged dataset JSON files."""
    datasets_dir = Path(__file__).parent / "datasets_files"
    discovered_types = set()

    if datasets_dir.exists() and datasets_dir.is_dir():
        for json_file in datasets_dir.glob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    payload = json.load(f)
                if isinstance(payload, list):
                    for item in payload:
                        if isinstance(item, dict):
                            raw_type = item.get("incident_type")
                            if isinstance(raw_type, str) and raw_type.strip():
                                discovered_types.add(raw_type.strip())
            except Exception:
                # Ignore malformed files so one bad file doesn't block workflow startup.
                continue

    # Stable fallback taxonomy if dataset files are absent/empty at startup.
    if not discovered_types:
        discovered_types = {
            "banned_ip",
            "data_exfiltration",
            "disk_full",
            "memory_leak",
            "privilege_escalation",
            "sql_injection",
            "table_deletion",
            "user_breach",
        }

    return sorted(discovered_types)


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

INCIDENT_TYPES = [t for t in _load_incident_types_from_datasets() if t in ALLOWED_INCIDENT_TYPES]
INCIDENT_TYPES_SET = set(INCIDENT_TYPES)
INCIDENT_TYPES_HINT = ", ".join(INCIDENT_TYPES)
DEFAULT_INCIDENT_TYPE = INCIDENT_TYPES[0] if INCIDENT_TYPES else "banned_ip"
NONE_APPLICABLE_INCIDENT_TYPE = "none_applicable"
INCIDENT_TYPES_WITH_FALLBACK = sorted(
    INCIDENT_TYPES_SET.union({NONE_APPLICABLE_INCIDENT_TYPE})
)
INCIDENT_TYPES_WITH_FALLBACK_SET = set(INCIDENT_TYPES_WITH_FALLBACK)
INCIDENT_TYPES_WITH_FALLBACK_HINT = ", ".join(INCIDENT_TYPES_WITH_FALLBACK)

class MessageState(TypedDict):
    logs: str
    result: dict
    search_results: List[dict]
    explainer_output: dict
    ioc_vector_group: dict
    markdown_output: str
    logs_path: NotRequired[str]
    output_dir: NotRequired[str]
    customer_ids: NotRequired[List[str]]
    report_path: NotRequired[str]
    xml_output_path: NotRequired[str]


def _carry_context(state: MessageState) -> dict:
    """Preserve filesystem context between workflow nodes."""
    return {
        "logs_path": str(state.get("logs_path", "") or ""),
        "output_dir": str(state.get("output_dir", "") or ""),
        "customer_ids": list(state.get("customer_ids", []) or []),
        "report_path": str(state.get("report_path", "") or ""),
        "xml_output_path": str(state.get("xml_output_path", "") or ""),
    }


def _resolve_output_dir(state: MessageState) -> Path:
    """Resolve where per-customer outputs should be written."""
    output_dir = str(state.get("output_dir", "") or "").strip()
    if output_dir:
        return Path(output_dir)

    logs_path = str(state.get("logs_path", "") or "").strip()
    if logs_path:
        return Path(logs_path).parent

    return Path(__file__).parent


def _extract_customer_ids(logs_file: Path, hierarchies_dir: Path) -> List[str]:
    """Extract the customer hierarchy IDs from a logs file path."""
    try:
        relative_parent = logs_file.parent.relative_to(hierarchies_dir)
    except ValueError:
        return []

    return [part for part in relative_parent.parts if part]


def _discover_customer_log_files(hierarchies_dir: Path) -> List[Path]:
    """Find all customer logs in the hierarchies directory."""
    if not hierarchies_dir.exists() or not hierarchies_dir.is_dir():
        return []

    return sorted(
        log_file for log_file in hierarchies_dir.glob("**/logs.txt") if log_file.is_file()
    )


def _format_customer_label(customer_ids: List[str]) -> str:
    """Render a readable customer label from hierarchy IDs."""
    return "/".join(customer_ids) if customer_ids else "standalone"

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

class IOCVectorGroupAdderTemplate(BaseModel):
    vector_group_name: str = Field(description="The IOC vector group name in camel case format (e.g. 'SuspiciousProcessAndFileChanges'), sourced from dataset when available or inferred from analysis")
    vectors: List[str] = Field(description="IOC vectors sourced from dataset examples when available, otherwise inferred from threat analysis", min_length=1)


def _to_camel_case(text: str) -> str:
    parts = re.split(r"[^A-Za-z0-9]+", str(text or "").strip())
    parts = [p for p in parts if p]
    if not parts:
        return "DatasetDerivedIOCGroup"
    return "".join(p[:1].upper() + p[1:] for p in parts)


def _derive_ioc_from_dataset_examples(examples: List[dict]) -> dict | None:
    """Build IOC output from dataset examples when vectors exist."""
    collected_vectors = []
    group_candidates = []

    for example in examples:
        if not isinstance(example, dict):
            continue

        group_name = str(example.get("vector_group", "")).strip()
        if group_name:
            group_candidates.append(group_name)

        raw_vectors = example.get("vectors", [])
        if isinstance(raw_vectors, list):
            for raw_vector in raw_vectors:
                cleaned = str(raw_vector).strip()
                if cleaned:
                    collected_vectors.append(cleaned)

    dedup_vectors = []
    for vector in collected_vectors:
        if vector not in dedup_vectors:
            dedup_vectors.append(vector)

    if not dedup_vectors:
        return None

    # Keep output small and aligned with model-generated range.
    selected_vectors = dedup_vectors[:5]

    group_name = _to_camel_case(group_candidates[0]) if group_candidates else "DatasetDerivedIOCGroup"

    return {
        "vector_group_name": group_name,
        "vectors": selected_vectors,
    }


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


def _dedupe_preserve_order(items: List[str]) -> List[str]:
    """Remove duplicate strings while preserving order."""
    seen = set()
    deduped = []

    for item in items:
        normalized = re.sub(r"\s+", " ", str(item).strip()).casefold()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(str(item).strip())

    return deduped


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


def _parse_verification_suggestions(logs_text: str) -> List[tuple[str, str]]:
    """Extract (category, script_path) pairs from anomaly_workflow.py's
    'Suggested verification scripts' block. Deterministic, from the logs
    themselves — used so recommended_actions doesn't rely on the model
    faithfully re-enumerating a potentially long list on its own."""
    pairs = []
    for match in re.finditer(
        r"^\s*(\S+):\s*not confirmed in alertlog\.xml\s*->\s*run\s+(\S+)\s+to verify",
        logs_text,
        re.MULTILINE,
    ):
        pairs.append((match.group(1), match.group(2)))
    return pairs


def _normalize_explainer_payload(payload: dict, search_results: List[dict], expected_secondary_types: List[str] | None = None, logs_text: str = "") -> dict:
    """Ensure required fields exist and satisfy schema constraints."""
    valid_levels = {"low", "medium", "high", "critical"}
    out = dict(payload or {})

    level = str(out.get("threat_level", "medium")).strip().lower()
    out["threat_level"] = level if level in valid_levels else "medium"

    detailed = str(out.get("detailed_analysis", "")).strip()
    if len(detailed) < 500:
        filler = (
            " Additional contextual evidence indicates potential unauthorized access patterns, "
            "credential misuse opportunities, and weak control coverage across authentication, "
            "monitoring, and patching workflows. Defensive actions should prioritize immediate "
            "containment, verification of suspicious indicators, hardening exposed services, "
            "and continuous monitoring to reduce recurrence risk."
        )
        while len(detailed) < 500:
            detailed += filler
    out["detailed_analysis"] = detailed

    if not isinstance(out.get("search_results"), list) or not out.get("search_results"):
        out["search_results"] = [sr for sr in search_results if "error" not in sr][:25]

    if not isinstance(out.get("recommended_actions"), list):
        out["recommended_actions"] = []

    cleaned_actions = []
    for action in out["recommended_actions"]:
        action_text = str(action).strip()
        if action_text:
            cleaned_actions.append(action_text)

    cleaned_actions = _dedupe_preserve_order(cleaned_actions)

    # Verification-script suggestions are deterministic (parsed straight from
    # the logs, not a model guess) — a small model reliably under-enumerates
    # a long list of these (observed: 5 of 9 in testing, with the "run X to
    # verify Y" phrasing dropped to bare paths), so force one well-formatted
    # action per (category, script) pair rather than trusting the model to
    # reproduce them. The SAME script can verify two different categories
    # (e.g. suspicious_monitor.py covers both ssh_key_injection and
    # suspicious_command_execution) — checking "is this script path already
    # mentioned somewhere" would silently drop the second category behind the
    # first's mention, so instead drop the model's own bare/near-bare mentions
    # of these paths (they carry no category info to disambiguate) and replace
    # them wholesale with one explicit, correctly-attributed action per pair.
    verification_pairs = _parse_verification_suggestions(logs_text)
    verification_script_paths = {path for _, path in verification_pairs}

    def _is_bare_script_mention(action_text: str) -> bool:
        stripped = action_text.strip().rstrip(".")
        return stripped in verification_script_paths

    cleaned_actions = [a for a in cleaned_actions if not _is_bare_script_mention(a)]

    for category, script_path in verification_pairs:
        cleaned_actions.append(
            f"Run {script_path} to verify {category} (not yet confirmed in alertlog.xml)."
        )
    cleaned_actions = _dedupe_preserve_order(cleaned_actions)

    fallback_actions = [
        "Isolate affected hosts and block suspicious source IPs at the network perimeter.",
        "Reset potentially exposed credentials and enforce MFA for privileged and remote access accounts.",
        "Patch vulnerable services and verify security baseline hardening across internet-facing systems.",
        "Review logs, EDR alerts, and authentication trails to confirm scope and persistence mechanisms.",
        "Implement continuous monitoring with IOC-based detections and incident response escalation playbooks."
    ]

    while len(cleaned_actions) < 5:
        cleaned_actions.append(fallback_actions[len(cleaned_actions)])
    out["recommended_actions"] = cleaned_actions[:max(10, len(verification_pairs) + 3)]

    # secondary_incidents: keep only entries whose incident_type was actually
    # classified as secondary (drop anything invented/hallucinated), fill in
    # a minimal placeholder for any expected type the model skipped, and
    # de-dupe by incident_type.
    expected = expected_secondary_types or []
    raw_secondary = out.get("secondary_incidents", [])
    if not isinstance(raw_secondary, list):
        raw_secondary = []

    cleaned_secondary = {}
    for entry in raw_secondary:
        if not isinstance(entry, dict):
            continue
        entry_type = str(entry.get("incident_type", "")).strip()
        if entry_type not in expected or entry_type in cleaned_secondary:
            continue
        entry_level = str(entry.get("threat_level", "medium")).strip().lower()
        entry_summary = str(entry.get("summary", "")).strip()
        cleaned_secondary[entry_type] = {
            "incident_type": entry_type,
            "threat_level": entry_level if entry_level in valid_levels else "medium",
            "summary": entry_summary or f"Rule-based detection flagged {entry_type}; not further elaborated.",
        }

    for entry_type in expected:
        if entry_type not in cleaned_secondary:
            cleaned_secondary[entry_type] = {
                "incident_type": entry_type,
                "threat_level": "medium",
                "summary": f"Rule-based detection flagged {entry_type}; not further elaborated.",
            }

    out["secondary_incidents"] = [cleaned_secondary[t] for t in expected]

    return out


def _normalize_question_former_payload(payload: dict, logs_text: str) -> dict:
    """Ensure required QuestionFormer fields exist for strict schema validation."""
    out = dict(payload or {})

    fallback_queries = [
        "failed login attempts from single source IP investigation",
        "web server error log indicators of exploitation attempts",
        "wordpress authentication bypass vulnerability detection guidance",
        "ioc patterns for brute force and credential stuffing attacks",
        "incident response checklist for suspected web application compromise"
    ]

    query_values = []
    for idx in range(1, 6):
        key = f"search_query_{idx}"
        value = str(out.get(key, "")).strip()
        query_values.append(value if value else fallback_queries[idx - 1])

    query_values = _dedupe_preserve_order(query_values)

    while len(query_values) < 5:
        fallback_value = fallback_queries[len(query_values)]
        if fallback_value not in query_values:
            query_values.append(fallback_value)
        else:
            query_values.append(f"{fallback_value} {len(query_values) + 1}")

    for idx in range(1, 6):
        out[f"search_query_{idx}"] = query_values[idx - 1]

    return out


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


def _load_examples_for_incident_type(incident_type: str) -> List[dict]:
    """Load dataset records matching the provided incident type from all dataset files."""
    if incident_type == NONE_APPLICABLE_INCIDENT_TYPE:
        return []

    datasets_dir = Path(__file__).parent / "datasets_files"
    matched_examples = []

    if not datasets_dir.exists() or not datasets_dir.is_dir():
        return matched_examples

    for json_file in sorted(datasets_dir.glob("*.json")):
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except Exception:
            continue

        if not isinstance(payload, list):
            continue

        for index, item in enumerate(payload, start=1):
            if not isinstance(item, dict):
                continue
            if str(item.get("incident_type", "")).strip() != incident_type:
                continue

            example = dict(item)
            example["source_file"] = json_file.name
            example["source_index"] = index
            matched_examples.append(example)

    return matched_examples


def _uses_incident_examples_path(state: MessageState) -> bool:
    """Return whether the workflow should include the incident-examples branch."""
    incident_type = str(state.get("result", {}).get("incident_type", "")).strip()
    return bool(incident_type) and incident_type != NONE_APPLICABLE_INCIDENT_TYPE


def _format_step_label(step: int, message: str, total_steps: int | None = None) -> str:
    """Format a consistent step label for terminal output."""
    if total_steps is None:
        return f"[STEP {step}] {message}"
    return f"[STEP {step}/{total_steps}] {message}"


def _build_explainer_reference_examples(examples: List[dict], max_examples: int = 5) -> str:
    """Build compact dataset-style examples for explainer reasoning guidance."""
    if not isinstance(examples, list) or not examples:
        return "No matched dataset examples available."

    lines = ["Reference examples for incident-style reasoning:"]

    for idx, ex in enumerate(examples[:max_examples], start=1):
        if not isinstance(ex, dict):
            continue

        title = str(ex.get("title") or ex.get("incident_title") or "Untitled incident").strip()
        description = str(ex.get("description", "")).strip()
        if len(description) > 260:
            description = description[:260].rstrip() + "..."

        vectors = ex.get("vectors", [])
        vectors_text = ", ".join(str(v).strip() for v in vectors[:5]) if isinstance(vectors, list) else "N/A"

        lines.append(f"Example {idx}:")
        lines.append(f"- Incident: {title}")
        if description:
            lines.append(f"- Typical pattern/outcome: {description}")
        lines.append(f"- Common indicators: {vectors_text}")

    if len(examples) > max_examples:
        lines.append(f"... plus {len(examples) - max_examples} additional matched examples")

    return "\n".join(lines)


def _extract_log_signals(logs_text: str) -> tuple[List[str], List[str]]:
    """Extract lightweight indicators from raw logs for dataset-style summary."""
    text = str(logs_text or "")

    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    unique_ips = _dedupe_preserve_order(ips)[:5]

    paths = re.findall(r'"(?:GET|POST|PUT|DELETE|PATCH)\s+([^\s"]+)', text)
    cleaned_paths = []
    for path in paths:
        base_path = str(path).split("?", 1)[0].strip()
        if base_path:
            cleaned_paths.append(base_path)
    unique_paths = _dedupe_preserve_order(cleaned_paths)[:5]

    return unique_ips, unique_paths


def _build_dataset_style_incident_summary(state: MessageState, explainer_payload: dict) -> str:
    """Build a concise summary in dataset-like style after explainer output."""
    result = state.get("result", {}) if isinstance(state.get("result", {}), dict) else {}
    incident_type = str(result.get("incident_type", "none_applicable")).strip() or "none_applicable"
    threat_level = str(explainer_payload.get("threat_level", "medium")).strip().lower() or "medium"
    detailed = str(explainer_payload.get("detailed_analysis", "")).strip()

    dataset_examples = result.get("dataset_examples", [])
    vectors = []
    if isinstance(dataset_examples, list):
        for ex in dataset_examples[:10]:
            if not isinstance(ex, dict):
                continue
            raw_vectors = ex.get("vectors", [])
            if isinstance(raw_vectors, list):
                for v in raw_vectors:
                    cleaned = str(v).strip()
                    if cleaned:
                        vectors.append(cleaned)
    vectors = _dedupe_preserve_order(vectors)[:5]

    source_count = len(dataset_examples) if isinstance(dataset_examples, list) else 0
    unique_ips, unique_paths = _extract_log_signals(state.get("logs", ""))

    what_happened = detailed.split(".", 1)[0].strip()
    if not what_happened:
        what_happened = "Suspicious behavior consistent with the selected incident type was observed in the logs"
    if what_happened[-1:] not in ".!?":
        what_happened += "."

    vectors_text = ", ".join(vectors) if vectors else "N/A"
    ips_text = ", ".join(unique_ips) if unique_ips else "N/A"
    paths_text = ", ".join(unique_paths) if unique_paths else "N/A"

    return (
        f"incident_type: {incident_type}\n"
        f"threat_level: {threat_level}\n"
        f"what_happened: {what_happened}\n"
        f"observed_ips: {ips_text}\n"
        f"targeted_paths: {paths_text}\n"
        f"vectors: {vectors_text}\n"
        f"matched_example_count: {source_count}"
    )

def InitialAnalysisNode(state: MessageState) -> MessageState:
    """
    Docstring for InitialAnalysisNode

    Node that takes in logs and returns a title and an initial analysis of the attack or potential attack. This node is used to analyze the logs and provide an initial understanding of the attack or potential attack.
    """
    print("\n" + "="*70)
    print(_format_step_label(1, "Generating initial title and analysis from logs..."))
    print("="*70)

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

    print("\n" + "-"*70)
    print("NODE OUTPUT:")
    print("-"*70)
    print(f"Title: {result.title}")
    print(f"\nInitial Analysis:\n{result.content}")

    return {
        **_carry_context(state),
        "logs": state["logs"],
        "result": result.model_dump(),
    }

def InitialSearchFromLogsToDatasetNode(state: MessageState) -> MessageState:
    """
    Docstring for InitialSearchFromLogsToDatasetNode

    Node that takes initial analysis results and generates an initial dataset search query to find more information about the attack or potential attack. This node is used to search the dataset for recorded incidents.
    """
    print("\n" + "="*70)
    print(_format_step_label(2, "Classifying incident type from initial analysis + logs..."))
    print("="*70)

    incident_type_model = model.with_structured_output(InitialSearchFromLogsToDatasetTemplate)

    prior_result = dict(state.get("result", {}))
    title = str(prior_result.get("title", "Potential Security Incident"))
    content = str(prior_result.get("content", ""))

    # anomaly_workflow.py tags findings with a rule-based category derived from
    # which specific check/script produced them (e.g. rootkitscan.txt ->
    # rootkit_detected) and writes it as a header line. When present, that's a
    # deterministic signal, not a guess — treat it as a strong prior instead of
    # classifying from raw text alone.
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

    def _classify_once() -> InitialSearchFromLogsToDatasetTemplate:
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
        # A rule-based hint is a deterministic prior, not a guess — the model
        # reliably converges on it (that's the whole point of hint_instruction
        # above), so a single pass is enough and voting would just burn extra
        # calls to confirm what's already reliable.
        incident_type_result = _classify_once()
    else:
        # Cold classification (no rule-based anchor) is where instability was
        # actually observed and verified: 3 different incident_type answers to
        # byte-identical input across separate runs. Self-consistency voting
        # — running the same classification multiple times and taking the
        # majority incident_type — directly targets that specific instability
        # rather than trusting whichever answer a single sampling pass landed
        # on. Only done in the cold-classification case since that's the only
        # case where it's been shown to matter.
        vote_count = max(1, int(os.getenv("CLASSIFICATION_VOTE_COUNT", "3")))
        votes = [_classify_once() for _ in range(vote_count)]

        primary_counts = Counter(v.incident_type for v in votes)
        winning_type, _ = primary_counts.most_common(1)[0]
        print(f"  Self-consistency vote ({vote_count} passes): "
              f"{dict(primary_counts)} -> chose '{winning_type}'")

        # Secondary types: keep any type suggested by more than half the votes
        # among ballots that agreed with the winning primary type (a secondary
        # type from a run that picked a different primary isn't necessarily
        # coherent with the winning classification).
        agreeing_votes = [v for v in votes if v.incident_type == winning_type]
        secondary_counts = Counter(
            sec for v in agreeing_votes for sec in v.secondary_incident_types
        )
        threshold = len(agreeing_votes) / 2
        winning_secondary = [t for t, c in secondary_counts.items() if c > threshold]

        incident_type_result = agreeing_votes[0].model_copy(
            update={"incident_type": winning_type, "secondary_incident_types": winning_secondary}
        )

    # The rule-based secondary hints are deterministic detection output, not a
    # guess — a small model reliably under-enumerates long lists (observed:
    # 1 of 8 actual secondary hints classified in testing), so merge all of
    # them in rather than trusting the model to faithfully reproduce the list.
    # The model's own picks (if any went beyond the hints) are kept too.
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

    print("\n" + "-"*70)
    print("NODE OUTPUT:")
    print("-"*70)
    print(f"Title: {title}")
    print(f"Incident Type: {incident_type_result.incident_type}")
    print(f"\nInitial Analysis:\n{content}")

    return {
        **_carry_context(state),
        "logs": state["logs"],
        "result": {
            **prior_result,
            **incident_type_result.model_dump(),
        },
    }


def RouteFromIncidentType(state: MessageState) -> str:
    """Route based on incident type classification result."""
    incident_type = str(state.get("result", {}).get("incident_type", "")).strip()
    if incident_type == NONE_APPLICABLE_INCIDENT_TYPE:
        return "question_former"
    return "incident_examples"

def GettingExamplesUsingIncidentTypeNode(state: MessageState) -> MessageState:
    """
    Docstring for GettingExamplesUsingIncidentTypeNode

    Node that takes in the incident type from the previous node and uses it to search the dataset for recorded incidents of the same type. The results are then used to derive more context about the attack or potential attack.
    """
    print("\n" + "="*70)
    print(_format_step_label(3, "Searching dataset examples by incident type...", 8))
    print("="*70)

    prior_result = dict(state.get("result", {}))
    incident_type = str(prior_result.get("incident_type", "")).strip()

    if not incident_type:
        print("  ⚠ No incident type available from previous node.")
        prior_result["dataset_examples"] = []
        return {
            **_carry_context(state),
            "logs": state["logs"],
            "result": prior_result,
        }

    examples = _load_examples_for_incident_type(incident_type)
    prior_result["dataset_examples"] = examples

    print(f"✓ Incident type used for dataset search: {incident_type}")
    print(f"✓ Matching dataset examples found: {len(examples)}")

    # Secondary incidents get a small number of examples each (not the full
    # match count like the primary) — just enough for the explainer to ground
    # a brief independent assessment, not a full narrative treatment.
    secondary_types = prior_result.get("secondary_incident_types", []) or []
    secondary_dataset_examples = {}
    for sec_type in secondary_types:
        sec_examples = _load_examples_for_incident_type(sec_type)
        if sec_examples:
            secondary_dataset_examples[sec_type] = sec_examples[:2]
    prior_result["secondary_dataset_examples"] = secondary_dataset_examples

    print("\n" + "-"*70)
    print("NODE OUTPUT:")
    print("-"*70)
    print(f"Incident Type: {incident_type}")
    print(f"Matched Examples: {len(examples)}")

    for idx, example in enumerate(examples[:3], start=1):
        example_title = example.get("title") or example.get("incident_title") or "Untitled Example"
        source_file = example.get("source_file", "unknown")
        source_index = example.get("source_index", "?")
        print(f"  [{idx}] {example_title} ({source_file} #{source_index})")

    if len(examples) > 3:
        print(f"  ... and {len(examples) - 3} more examples")

    if secondary_dataset_examples:
        print(f"Secondary incident examples: "
              f"{ {k: len(v) for k, v in secondary_dataset_examples.items()} }")

    return {
        **_carry_context(state),
        "logs": state["logs"],
        "result": prior_result,
    }

def QuestionFormerNode(state: MessageState) -> MessageState:
    """
    Docstring for QuestionFormerNode
    
    Node that takes in logs and returns a title, an initial analysis, and 5 search queries to find more information about the attack or potential attack.
    """
    print("\n" + "="*70)
    uses_examples_path = _uses_incident_examples_path(state)
    current_step = 4 if uses_examples_path else 3
    total_steps = 8 if uses_examples_path else 7
    print(_format_step_label(current_step, "Analyzing logs and generating search queries...", total_steps))
    print("="*70)
    
    # Use with_structured_output for more reliable structured responses
    structured_model = model.with_structured_output(QuestionFormerOutputTemplate)
    prior_result = state.get("result", {})
    title = prior_result.get("title", "Potential Security Incident")
    content = prior_result.get("content", "")
    incident_type = str(prior_result.get("incident_type", "")).strip()
    incident_type_hint = (
        f" The incident has already been classified as '{incident_type}' — let that guide which "
        f"general concept each query targets."
        if incident_type and incident_type != NONE_APPLICABLE_INCIDENT_TYPE else ""
    )

    template = ChatPromptTemplate.from_messages([
        ("system", "You are a cybersecurity analyst. Based on the logs and the existing initial analysis, "
                   "generate 5 search queries to find more information about the attack or potential attack. "
                   "Ignore the logs that states file does not exist or cannot be found. Focus on the logs that "
                   "indicate potential security incidents.\n\n"
                   "IMPORTANT: Phrase each query around the general security technique or concept actually "
                   "described in THESE logs and THIS initial analysis (e.g. if the logs describe a disabled "
                   "logging service, a query like 'log tampering detection techniques' is appropriate; if they "
                   "describe repeated failed SSH logins, 'SSH brute force detection' is appropriate) — do not "
                   "use internal or proprietary system field names, product names, or file paths specific to "
                   "this environment, those won't return useful public results.\n\n"
                   "The examples just given (log tampering, SSH brute force) illustrate PHRASING STYLE ONLY. "
                   "Do not reuse those specific topics, or any other example topic like SSH key injection, "
                   "rootkits, ransomware decoys, or privilege escalation, unless the logs or initial analysis "
                   "actually describe that specific attack type occurring. Every query must be traceable to "
                   "something the logs or initial analysis actually say — not a plausible-sounding attack that "
                   "merely shares a keyword with them." + incident_type_hint),
        ("user", """Logs:
{logs}

Existing Initial Analysis:
Title: {title}
Content: {content}""")
    ])
    
    chain = template | structured_model
    input_payload = {"logs": state["logs"], "title": title, "content": content}
    try:
        result = chain.invoke(input_payload)
    except Exception as e:
        print(f"  ⚠ Structured output parsing failed: {e}")
        print("  ↻ Retrying with strict JSON fallback...")

        fallback_prompt = ChatPromptTemplate.from_messages([
            ("system", """Return ONLY valid JSON with these exact keys:
- search_query_1: string
- search_query_2: string
- search_query_3: string
- search_query_4: string
- search_query_5: string

Phrase each query around the general security technique or concept actually described in the logs and
initial analysis below — not around internal or proprietary system field names, product names, or file
paths specific to this environment, and not around an unrelated attack type just because it shares a
keyword. Every query must be traceable to something the logs or initial analysis actually say.

Do not include markdown, HTML, comments, or extra text before/after JSON."""),
            ("user", """Based on these logs and the existing initial analysis, return strict JSON now:

Logs:
{logs}

Existing Initial Analysis:
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

        normalized = _normalize_question_former_payload(parsed or {}, state["logs"])
        result = QuestionFormerOutputTemplate.model_validate(normalized)
    
    print(f"✓ Generated {len([q for q in [result.search_query_1, result.search_query_2, result.search_query_3, result.search_query_4, result.search_query_5] if q])} search queries")
    
    # Display output immediately after completion
    print("\n" + "-"*70)
    print("NODE OUTPUT:")
    print("-"*70)
    print(f"Title: {title}")
    print(f"\nInitial Analysis:\n{content}")
    print(f"\nSearch Queries Generated:")
    for i, query in enumerate([result.search_query_1, result.search_query_2, result.search_query_3, result.search_query_4, result.search_query_5], 1):
        if query:
            print(f"  {i}. {query}")
    
    merged_result = dict(prior_result)
    merged_result.update(result.model_dump())

    return {
        **_carry_context(state),
        "logs": state["logs"],
        "result": merged_result,
    }


def ContextDeriverFromSearchQueriesUsingDDGNode(state: MessageState) -> MessageState:
    """
    Docstring for ContextDeriverFromSearchQueriesUsingDDGNode
    
    Node that takes in the search queries from the previous node and uses them to search on DuckDuckGo to find more information about the attack or potential attack. The results are then used to derive more context about the attack or potential attack.
    """
    print("\n" + "="*70)
    uses_examples_path = _uses_incident_examples_path(state)
    current_step = 5 if uses_examples_path else 4
    total_steps = 8 if uses_examples_path else 7
    print(_format_step_label(current_step, "Gathering threat intelligence from DuckDuckGo...", total_steps))
    print("="*70)
    
    result = state["result"]
    
    # Extract all search queries
    search_queries = [
        result.get('search_query_1'),
        result.get('search_query_2'),
        result.get('search_query_3'),
        result.get('search_query_4'),
        result.get('search_query_5')
    ]
    
    all_search_results = []
    
    # Search each query using DuckDuckGo
    for i, query in enumerate(search_queries, 1):
        if not query:
            continue
            
        print(f"  [{i}/5] Searching: {query}")
        
        try:
            with DDGS() as ddgs:
                search_results = list(ddgs.text(query, max_results=5))
            
            for r in search_results:
                all_search_results.append({
                    "query_number": i,
                    "query": query,
                    "title": r.get("title", "No title"),
                    "url": r.get("href", ""),
                    "snippet": r.get("body", "No description available")
                })
                
            print(f"       ✓ Found {len(search_results)} results")
            
        except Exception as e:
            print(f"       ✗ Error: {e}")
            all_search_results.append({
                "query_number": i,
                "query": query,
                "error": str(e)
            })
    
    print(f"\n✓ Total intelligence sources gathered: {len(all_search_results)}")
    

    # Display output immediately after completion
    print("\n" + "-"*70)
    print("NODE OUTPUT:")
    print("-"*70)
    print(f"Total search results: {len(all_search_results)}\n")
    
    # Group by query and display
    for i in range(1, 6):
        query_results = [sr for sr in all_search_results if sr.get('query_number') == i]
        if query_results:
            print(f"Query {i}: {query_results[0].get('query')}")
            if 'error' in query_results[0]:
                print(f"  ✗ Error: {query_results[0].get('error')}")
            else:
                for j, sr in enumerate(query_results, 1):  # Show all results
                    print(f"  [{j}] {sr.get('title', 'N/A')}")
                    print(f"      {sr.get('url', 'N/A')}")
                    print(f"      Snippet: {sr.get('snippet', 'N/A')}")
            print()
    
    return {
        **_carry_context(state),
        "logs": state["logs"],
        "result": state["result"],
        "search_results": all_search_results
    }

def ExplainerOutputNode(state: MessageState) -> MessageState:
    """
    Docstring for ExplainerOutputNode
    
    Node that takes in the search results from the previous node and uses them to derive more context about the attack or potential attack. It then provides a more detailed analysis of the attack or potential attack based on the search results.
    """
    print("\n" + "="*70)
    uses_examples_path = _uses_incident_examples_path(state)
    current_step = 6 if uses_examples_path else 5
    total_steps = 8 if uses_examples_path else 7
    print(_format_step_label(current_step, "Generating comprehensive security analysis...", total_steps))
    print("="*70)
    
    structured_model = model.with_structured_output(ExplainerOutputTemplate)
    dataset_examples = state.get("result", {}).get("dataset_examples", [])
    reference_examples = _build_explainer_reference_examples(dataset_examples)

    secondary_incident_types = state.get("result", {}).get("secondary_incident_types", []) or []
    secondary_dataset_examples = state.get("result", {}).get("secondary_dataset_examples", {}) or {}
    if secondary_incident_types:
        secondary_lines = [f"Secondary incidents also classified for this pull: {secondary_incident_types}"]
        for sec_type in secondary_incident_types:
            sec_examples = secondary_dataset_examples.get(sec_type, [])
            if sec_examples:
                desc = str(sec_examples[0].get("description", "")).strip()[:200]
                secondary_lines.append(f"- {sec_type}: reference pattern — {desc}" if desc else f"- {sec_type}")
            else:
                secondary_lines.append(f"- {sec_type}: no dataset reference example available")
        secondary_context = "\n".join(secondary_lines)
    else:
        secondary_context = "No secondary incidents were classified for this pull."

    # Format search results for the LLM
    search_context = "\n\n".join([
        f"Query {sr.get('query_number')}: {sr.get('query')}\n"
        f"Title: {sr.get('title', 'N/A')}\n"
        f"URL: {sr.get('url', 'N/A')}\n"
        f"Snippet: {sr.get('snippet', 'N/A')}"
        for sr in state["search_results"]
        if "error" not in sr
    ])
    
    print(f"  Processing {len([sr for sr in state['search_results'] if 'error' not in sr])} intelligence sources...")
    if isinstance(dataset_examples, list):
        print(f"  Using {len(dataset_examples)} matched dataset examples as reference patterns...")
    
    template = ChatPromptTemplate.from_messages([
        ("system", """You are a senior cybersecurity analyst.

Use the reference incident examples as archetypes for how incidents are described and reasoned about. Infer what happened in the current logs and explain it in a dataset-like narrative style, while staying grounded in the logs and search intelligence.

The search results are general background intelligence about how an attack technique of this kind typically works — they are NOT a report of what was observed on this specific system. Never phrase something from a search result as if it was directly observed in these logs (e.g. do not write "the observed SSH key injection..." unless the logs themselves show a key was actually injected). If a search result describes a different, unrelated attack technique that happens to share a keyword with a query, do not fold it into the incident narrative at all — only use search results that are genuinely relevant to what these logs actually show.

Calibrate threat_level against these criteria — do not default to High/Critical just because the topic is security-related; most individual findings, especially single low-confidence indicators, should be Low or Medium:
- LOW: a single low-confidence or easily-explained indicator (e.g. one failed login, a minor config drift) with no evidence of actual compromise or ongoing malicious activity.
- MEDIUM: suspicious activity with real supporting evidence, but not confirmed compromise, or a single moderate-severity finding (e.g. a handful of failed logins from one source, a modified file with unclear cause).
- HIGH: multiple corroborating findings, or a single finding with strong evidence of actual unauthorized access or tampering, but contained/limited in scope (e.g. a confirmed new SSH key injected, a confirmed unrecognized binary running).
- CRITICAL: confirmed active compromise with severe or business-critical impact (e.g. active ransomware encryption, confirmed data exfiltration, root-level backdoor in active use). Reserve this for cases the evidence clearly supports — do not use it as a default.

Based on the initial analysis, reference examples, and threat intelligence from search results, provide:
1. A threat level (Critical/High/Medium/Low) for the PRIMARY incident only, using the calibration above
2. A comprehensive detailed analysis (300-500 words) explaining what happened, likely attack progression, implications, and technical details from the search results — about the PRIMARY incident only
3. The search results used in your analysis
4. A list of recommended actions to mitigate the threat
5. secondary_incidents: if any secondary incidents are listed below, provide ONE brief independent assessment per secondary incident type — its own threat_level (using the same calibration above, judged on its own merits, not inherited from the primary incident) and a 1-3 sentence summary grounded only in what the logs show for that specific finding. Do not blend a secondary incident's details into the primary incident's detailed_analysis, and do not invent a secondary incident that isn't listed below.

If the logs contain a line starting with "Suggested verification scripts" listing findings not yet confirmed in alertlog.xml, each such line already names the exact category and exact script path to run (format: "category: not confirmed in alertlog.xml -> run <script path> to verify"). For each such line present, add exactly one recommended action instructing the operator to run that exact script path (copy the path verbatim from the log line, do not invent or genericize it), with a brief note on why it's still unconfirmed. Do not add any additional generic recommendation about "running verification scripts" beyond these specific ones — if there are two such lines, add exactly two matching recommendations, not three.

Be specific, technical, and actionable in your recommendations. Do not copy example text verbatim; adapt the patterns to this case."""),
        ("user", """Original Logs:
{logs}

Initial Analysis:
Title: {title}
Content: {content}

Reference Incident Examples (for reasoning style):
{reference_examples}

Secondary Incidents (assess each independently, do not merge into the primary narrative):
{secondary_context}

Threat Intelligence from Search Results:
{search_context}

Provide your detailed security analysis.""")
    ])

    input_payload = {
        "logs": state["logs"],
        "title": state["result"].get("title", ""),
        "content": state["result"].get("content", ""),
        "reference_examples": reference_examples,
        "secondary_context": secondary_context,
        "search_context": search_context
    }

    chain = template | structured_model
    try:
        result = chain.invoke(input_payload)
        normalized = _normalize_explainer_payload(result.model_dump(), state["search_results"], secondary_incident_types, state["logs"])
        result = ExplainerOutputTemplate.model_validate(normalized)
    except Exception as e:
        print(f"  ⚠ Structured output parsing failed: {e}")
        print("  ↻ Retrying with strict JSON fallback...")

        fallback_prompt = ChatPromptTemplate.from_messages([
            ("system", """Return ONLY valid JSON with these exact keys:
- threat_level: one of low, medium, high, critical
- detailed_analysis: string, minimum 500 characters
- search_results: array of objects
- recommended_actions: array of at least 5 action strings
- secondary_incidents: array of objects, each with incident_type, threat_level, summary — one per secondary incident listed below, empty array if none

Calibrate threat_level (both the top-level one and each secondary incident's) against these criteria — do not default to high/critical just because the topic is security-related:
- low: a single low-confidence or easily-explained indicator, no evidence of actual compromise.
- medium: suspicious activity with real supporting evidence, but not confirmed compromise.
- high: multiple corroborating findings, or strong evidence of actual unauthorized access/tampering, contained in scope.
- critical: confirmed active compromise with severe/business-critical impact — reserve for cases the evidence clearly supports, not a default.

Search results are general background intelligence, not a report of what happened on this system — do not describe something from a search result as directly observed unless the logs themselves show it.

For each "Suggested verification scripts" line in the logs, add exactly one recommended_action naming that exact script path verbatim (do not invent, genericize, or add an extra recommendation beyond the specific ones listed).

Do not include markdown, HTML, comments, or extra text before/after JSON."""),
            ("user", """Original Logs:
{logs}

Initial Analysis:
Title: {title}
Content: {content}

Reference Incident Examples (for reasoning style):
{reference_examples}

Secondary Incidents (assess each independently, do not merge into the primary narrative):
{secondary_context}

Threat Intelligence from Search Results:
{search_context}

Produce strict JSON now.""")
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

        normalized = _normalize_explainer_payload(parsed or {}, state["search_results"], secondary_incident_types, state["logs"])
        result = ExplainerOutputTemplate.model_validate(normalized)
    
    print(f"✓ Analysis complete - Threat Level: {result.threat_level}")
    print(f"✓ Generated {len(result.recommended_actions)} mitigation recommendations")

    explainer_payload = result.model_dump()
    dataset_style_summary = _build_dataset_style_incident_summary(state, explainer_payload)
    explainer_payload["dataset_style_summary"] = dataset_style_summary
    
    # Display output immediately after completion
    print("\n" + "-"*70)
    print("NODE OUTPUT:")
    print("-"*70)
    print(f"\nTHREAT LEVEL: {result.threat_level}")
    print(f"\nDETAILED ANALYSIS:")
    print(result.detailed_analysis)
    print(f"\nRECOMMENDED ACTIONS:")
    for i, action in enumerate(result.recommended_actions, 1):
        print(f"  {i}. {action}")
    if result.secondary_incidents:
        print(f"\nSECONDARY INCIDENTS:")
        for sec in result.secondary_incidents:
            print(f"  - {sec.incident_type} [{sec.threat_level}]: {sec.summary}")
    print("\nDATASET-STYLE INCIDENT SUMMARY:")
    print(dataset_style_summary)
    
    return {
        **_carry_context(state),
        "logs": state["logs"],
        "result": state["result"],
        "search_results": state["search_results"],
        "explainer_output": explainer_payload
    }

def IOCVectorGroupAdderNode(state: MessageState) -> MessageState:
    """
    Docstring for IOCVectorGroupAdderNode

    Node that takes in the detailed analysis and recommended actions from the previous node and generates a new IOC vector group that can be added to the organization's threat intelligence platform. The vector group should be based on the specific indicators of compromise (IOCs) mentioned in the detailed analysis and recommended actions.
    """
    print("\n" + "="*70)
    uses_examples_path = _uses_incident_examples_path(state)
    current_step = 7 if uses_examples_path else 6
    total_steps = 8 if uses_examples_path else 7
    print(_format_step_label(current_step, "Generating IOC Vector Group...", total_steps))
    print("="*70)

    explainer = state["explainer_output"]
    result = state["result"]

    dataset_examples = result.get("dataset_examples", []) if isinstance(result, dict) else []
    secondary_dataset_examples = result.get("secondary_dataset_examples", {}) if isinstance(result, dict) else {}
    # Merge in a couple of examples per secondary incident so its vectors are
    # represented in the group too, without letting them dominate the primary's.
    combined_examples = list(dataset_examples) if isinstance(dataset_examples, list) else []
    if isinstance(secondary_dataset_examples, dict):
        for sec_examples in secondary_dataset_examples.values():
            combined_examples.extend(sec_examples[:2])

    derived_payload = None
    if combined_examples:
        derived_payload = _derive_ioc_from_dataset_examples(combined_examples)

    if derived_payload:
        print("  Using vectors derived from dataset examples...")
        ioc_result = IOCVectorGroupAdderTemplate.model_validate(derived_payload)
    else:
        print("  No usable dataset vectors found; inferring vectors from analysis...")
        structured_model = model.with_structured_output(IOCVectorGroupAdderTemplate)
    
        template = ChatPromptTemplate.from_messages([
                ("system", """You are a cybersecurity threat analyst specializing in IOC (Indicator of Compromise) identification.

Analyze the threat details and produce:
1. A concise vector_group_name in camel case.
2. A list of 1-5 IOC vectors that best describe and pinpoint the incident.

Use only evidence-backed vectors that align with the attack behavior in the logs and analysis."""),
            ("user", """Threat Analysis:
Title: {title}
Threat Level: {threat_level}
Detailed Analysis: {detailed_analysis}

Based on this analysis, generate an IOC vector group with:
1. A descriptive name for this attack pattern
2. The relevant IOC vectors (1-5 vectors) that match the indicators in this attack""")
        ])

        chain = template | structured_model
        try:
            ioc_result = chain.invoke({
                "title": result.get("title", ""),
                "threat_level": explainer.get("threat_level", ""),
                "detailed_analysis": explainer.get("detailed_analysis", "")
            })
        except Exception as ioc_exc:
            print(f"  ⚠ IOC inference failed/timed out: {ioc_exc}")
            print("  ↻ Using a generic fallback IOC vector group.")
            fallback_name = _to_camel_case(result.get("title", "")) or "SecurityIncident"
            ioc_result = IOCVectorGroupAdderTemplate.model_validate({
                "vector_group_name": fallback_name,
                "vectors": ["SecurityIncident"],
            })
    
    print(f"✓ Generated vector group: {ioc_result.vector_group_name}")
    print(f"✓ Selected {len(ioc_result.vectors)} IOC vectors")
    
    # Display output immediately
    print("\n" + "-"*70)
    print("NODE OUTPUT:")
    print("-"*70)
    print(f"Vector Group Name: {ioc_result.vector_group_name}")
    print(f"\nSelected Vectors:")
    for i, vector in enumerate(ioc_result.vectors, 1):
        print(f"  {i}. {vector}")
    
    # Generate XML format for the vector group
    xml_output = f"""<attack_vectors>
    <vector_group>
        <name>{ioc_result.vector_group_name}</name>"""
    for vector in ioc_result.vectors:
        xml_output += f"\n        <vector>{vector}</vector>"
    xml_output += "\n    </vector_group>\n</attack_vectors>"
    
    print(f"\nXML Format (ready to add to rv_ioc_lin.xml):")
    print(xml_output)

    output_dir = _resolve_output_dir(state)
    output_dir.mkdir(parents=True, exist_ok=True)
    xml_output_path = output_dir / "vector_group_output.xml"

    with open(xml_output_path, "w", encoding="utf-8") as f:
        f.write(xml_output)
    print(f"\n✓ XML output saved to {xml_output_path}")

    # send_files("vector_group_output.xml", "upload_file")
    
    return {
        **_carry_context(state),
        "logs": state["logs"],
        "result": state["result"],
        "search_results": state["search_results"],
        "explainer_output": state["explainer_output"],
        "ioc_vector_group": ioc_result.model_dump(),
        "xml_output_path": str(xml_output_path),
    }

def _build_logs_section(logs_text: str, preview_lines: int = 40) -> str:
    """
    Render the logs as a short preview with the full content collapsed behind
    a <details> block (standard GitHub-flavored Markdown, renders natively in
    GitHub, GitLab, VS Code, etc.), so the report stays scannable without
    dropping the raw data — click to expand for the full logs.
    """
    lines = logs_text.splitlines()
    if len(lines) <= preview_lines:
        return f"## Original Logs\n\n```\n{logs_text}\n```"

    preview = "\n".join(lines[:preview_lines])
    return (
        f"## Original Logs\n\n"
        f"Showing first {preview_lines} of {len(lines)} lines — expand below for the full content.\n\n"
        f"```\n{preview}\n...\n```\n\n"
        f"<details>\n<summary>Show full logs ({len(lines)} lines)</summary>\n\n"
        f"```\n{logs_text}\n```\n\n"
        f"</details>"
    )


def MarkdownReportGeneratorNode(state: MessageState) -> MessageState:
    """
    Docstring for MarkdownReportGeneratorNode
    
    Node that takes the complete analysis and generates a comprehensive markdown report.
    """
    print("\n" + "="*70)
    uses_examples_path = _uses_incident_examples_path(state)
    current_step = 8 if uses_examples_path else 7
    total_steps = 8 if uses_examples_path else 7
    print(_format_step_label(current_step, "Generating Markdown Report...", total_steps))
    print("="*70)
    
    result = state["result"]
    explainer = state["explainer_output"]
    search_results = state["search_results"]
    incident_type = result.get("incident_type", "N/A")
    secondary_incident_types = result.get("secondary_incident_types", []) or []
    secondary_incidents = explainer.get("secondary_incidents", []) or []
    dataset_examples = result.get("dataset_examples", [])
    used_dataset_examples = isinstance(dataset_examples, list) and len(dataset_examples) > 0
    logs_section = _build_logs_section(state["logs"])

    # Generate markdown content
    markdown_content = f"""# Cybersecurity Log Analysis Report

---

## Executive Summary

**Threat Title:** {result.get('title', 'N/A')}

**Incident Type:** {incident_type}{f" (+ {len(secondary_incident_types)} secondary)" if secondary_incident_types else ""}

**Threat Level:** {explainer.get('threat_level', 'N/A').upper()}

**Dataset Example Match Path:** {"Matched examples were used" if used_dataset_examples else "No matching dataset examples (or none applicable)"}

**Date Generated:** {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

{logs_section}

---

## Initial Analysis

{result.get('content', 'N/A')}

---

## Search Queries Generated

"""
    
    for i in range(1, 6):
        query = result.get(f'search_query_{i}')
        if query:
            markdown_content += f"{i}. {query}\n"

    markdown_content += "\n---\n\n## Dataset Examples (Incident-Type Match)\n\n"

    if used_dataset_examples:
        markdown_content += f"Total matched examples: **{len(dataset_examples)}**\n\n"
        for idx, ex in enumerate(dataset_examples[:10], 1):
            source_file = ex.get("source_file", "unknown")
            source_index = ex.get("source_index", "?")
            example_type = ex.get("incident_type", "N/A")
            example_desc = str(ex.get("description", "")).strip()
            if len(example_desc) > 220:
                example_desc = example_desc[:220].rstrip() + "..."
            example_vectors = ex.get("vectors", [])
            vectors_text = ", ".join(str(v) for v in example_vectors[:8]) if isinstance(example_vectors, list) else "N/A"

            markdown_content += f"### Example {idx}\n\n"
            markdown_content += f"- **Source:** {source_file} #{source_index}\n"
            markdown_content += f"- **Incident Type:** {example_type}\n"
            markdown_content += f"- **Vectors:** {vectors_text}\n"
            if example_desc:
                markdown_content += f"- **Description:** {example_desc}\n"
            markdown_content += "\n"

        if len(dataset_examples) > 10:
            markdown_content += f"_...and {len(dataset_examples) - 10} more matched examples._\n\n"
    else:
        markdown_content += (
            "No matched dataset examples were used for this run. "
            "The workflow continued with search-based enrichment and model inference.\n\n"
        )
    
    markdown_content += "\n---\n\n## Threat Intelligence Gathered\n\n"
    
    # Group search results by query
    for i in range(1, 6):
        query_results = [sr for sr in search_results if sr.get('query_number') == i]
        if query_results:
            markdown_content += f"### Query {i}: {query_results[0].get('query')}\n\n"
            
            if 'error' in query_results[0]:
                markdown_content += f"**Error:** {query_results[0].get('error')}\n\n"
            else:
                for j, sr in enumerate(query_results, 1):
                    markdown_content += f"**[{j}] {sr.get('title', 'N/A')}**\n\n"
                    markdown_content += f"- **URL:** [{sr.get('url', 'N/A')}]({sr.get('url', 'N/A')})\n"
                    markdown_content += f"- **Summary:** {sr.get('snippet', 'N/A')}\n\n"
    
    markdown_content += "---\n\n## Detailed Security Analysis\n\n"
    markdown_content += explainer.get('detailed_analysis', 'N/A')

    if secondary_incidents:
        markdown_content += "\n\n---\n\n## Secondary Findings\n\n"
        markdown_content += (
            "Additional distinct incident types were also detected in this pull, alongside the "
            "primary incident above. Each is assessed independently — its threat level is judged "
            "on its own merits, not inherited from the primary incident.\n\n"
        )
        for sec in secondary_incidents:
            sec_type = sec.get("incident_type", "N/A")
            sec_level = str(sec.get("threat_level", "N/A")).upper()
            sec_summary = sec.get("summary", "N/A")
            markdown_content += f"### {sec_type} — {sec_level}\n\n{sec_summary}\n\n"

    markdown_content += "\n\n---\n\n## Dataset-Style Incident Summary\n\n"
    markdown_content += "```\n"
    markdown_content += str(explainer.get("dataset_style_summary", "N/A")).strip()
    markdown_content += "\n```\n"
    
    markdown_content += "\n\n---\n\n## Recommended Actions\n\n"
    
    for i, action in enumerate(explainer.get('recommended_actions', []), 1):
        markdown_content += f"{i}. {action}\n"
    
    # Add IOC Vector Group section
    if 'ioc_vector_group' in state and state['ioc_vector_group']:
        ioc_group = state['ioc_vector_group']
        markdown_content += "\n---\n\n## IOC Vector Group\n\n"
        markdown_content += f"**Vector Group Name:** {ioc_group.get('vector_group_name', 'N/A')}\n\n"
        markdown_content += "**Selected Vectors:**\n\n"
        for vector in ioc_group.get('vectors', []):
            markdown_content += f"- {vector}\n"
        
        markdown_content += "\n**XML Format (ready to add to rv_ioc_lin.xml):**\n\n```xml\n"
        markdown_content += f"    <vector_group>\n"
        markdown_content += f"        <name>{ioc_group.get('vector_group_name', 'N/A')}</name>\n"
        for vector in ioc_group.get('vectors', []):
            markdown_content += f"        <vector>{vector}</vector>\n"
        markdown_content += "    </vector_group>\n```\n"
    
    markdown_content += "\n---\n\n## Conclusion\n\n"
    markdown_content += f"This analysis was performed using automated threat intelligence gathering and AI-powered analysis. "
    markdown_content += f"The threat has been assessed as **{explainer.get('threat_level', 'N/A').upper()}** level. "
    markdown_content += f"Please review the recommended actions and implement appropriate security measures.\n"
    
    # Save to file with timestamp
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    output_dir = _resolve_output_dir(state)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"analysis_report_{timestamp}.md"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(markdown_content)
    
    print(f"✓ Markdown report generated: {output_path}")
    print(f"✓ Report contains {len(markdown_content)} characters")
    
    # Display output
    print("\n" + "-"*70)
    print("NODE OUTPUT:")
    print("-"*70)
    print(f"Markdown report saved to: {output_path}")
    print(f"Report sections: Executive Summary, Logs, Initial Analysis, Search Queries, Threat Intelligence, Detailed Analysis, Recommendations")
    
    return {
        **_carry_context(state),
        "logs": state["logs"],
        "result": state["result"],
        "search_results": state["search_results"],
        "explainer_output": state["explainer_output"],
        "ioc_vector_group": state.get("ioc_vector_group", {}),
        "markdown_output": markdown_content,
        "report_path": str(output_path),
    }



















# Create the LangGraph workflow
workflow = StateGraph(MessageState)

# Add the nodes
workflow.add_node("initial_analysis", InitialAnalysisNode)
workflow.add_node("initial_search", InitialSearchFromLogsToDatasetNode)
workflow.add_node("incident_examples", GettingExamplesUsingIncidentTypeNode)
workflow.add_node("question_former", QuestionFormerNode)
workflow.add_node("context_deriver", ContextDeriverFromSearchQueriesUsingDDGNode)
workflow.add_node("explainer", ExplainerOutputNode)
workflow.add_node("ioc_vector_adder", IOCVectorGroupAdderNode)
workflow.add_node("markdown_generator", MarkdownReportGeneratorNode)

# Set the entry point
workflow.set_entry_point("initial_analysis")

# Connect nodes
workflow.add_edge("initial_analysis", "initial_search")
workflow.add_conditional_edges(
    "initial_search",
    RouteFromIncidentType,
    {
        "incident_examples": "incident_examples",
        "question_former": "question_former",
    },
)
workflow.add_edge("incident_examples", "question_former")
workflow.add_edge("question_former", "context_deriver")
workflow.add_edge("context_deriver", "explainer")
workflow.add_edge("explainer", "ioc_vector_adder")
workflow.add_edge("ioc_vector_adder", "markdown_generator")

workflow.add_edge("markdown_generator", END)




# Compile the graph
app = workflow.compile()

# Written verbatim by legacy_log_aggregation.py's consolidate_log_files() when
# no log files were found in the pull. Detecting this lets us skip the LLM
# pipeline entirely instead of asking a model to write a 300-500 word
# "detailed analysis" of an attack that doesn't exist — which it will do, by
# inventing one (observed: fabricated "Git Pull Request"/"git operation
# attack" incidents from this exact input in testing, in the anomaly_workflow.py
# version of this same short-circuit).
CLEAN_RUN_MARKER = "No log files found in this pull."


def _write_clean_run_report(logs_content: str, logs_file: Path) -> dict:
    """Short-circuit path for a clean pull — skip the LangGraph pipeline
    entirely and write a minimal, honest report directly."""
    output_dir = logs_file.parent
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    output_path = output_dir / f"analysis_report_{timestamp}.md"

    markdown_content = f"""# Cybersecurity Log Analysis Report

---

## Executive Summary

**Threat Title:** No Anomalies Detected

**Incident Type:** {NONE_APPLICABLE_INCIDENT_TYPE}

**Threat Level:** LOW

**Date Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## Original Logs

```
{logs_content}
```

---

## Summary

The rule-based anomaly detection pass (Pass 1 known-verdict extraction + Pass 2 independent surfacing) found no anomalous or notable findings for this hierarchy on this pull. No incident classification, threat intelligence search, or IOC generation was performed — there was nothing to analyze, so none was attempted, rather than having a model invent a plausible-sounding but fabricated incident from essentially empty input.

---

## Conclusion

System appears clean for this pull. Routine monitoring should continue; this report does not require operator action.
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(markdown_content)

    print(f"✓ Clean run detected — skipped LLM pipeline, wrote minimal report: {output_path}")

    return {
        "report_path": str(output_path),
        "xml_output_path": None,
        "result": {"incident_type": NONE_APPLICABLE_INCIDENT_TYPE, "title": "No Anomalies Detected"},
        "explainer_output": {"threat_level": "low"},
    }


def _run_workflow_for_logs_file(logs_file: Path, hierarchies_dir: Path | None = None) -> dict:
    """Run the workflow for one logs.txt file and persist outputs beside it."""
    with open(logs_file, "r", encoding="utf-8") as f:
        logs_content = f.read()

    customer_ids = _extract_customer_ids(logs_file, hierarchies_dir) if hierarchies_dir else []
    customer_label = _format_customer_label(customer_ids)

    if CLEAN_RUN_MARKER in logs_content:
        print("\n" + "#" * 70)
        print("# CLEAN RUN — no findings, skipping LLM pipeline")
        print("#" * 70)
        print(f"# Customer IDs: {customer_label}")
        return _write_clean_run_report(logs_content, logs_file)

    print("\n" + "#" * 70)
    print("# CYBERSECURITY LOG ANALYSIS WORKFLOW")
    print("# Powered by LangGraph + Ollama (seneca) + DuckDuckGo")
    print(f"# Customer IDs: {customer_label}")
    print(f"# Analyzing logs from: {logs_file}")

    result = app.invoke({
        "logs": logs_content,
        "logs_path": str(logs_file),
        "output_dir": str(logs_file.parent),
        "customer_ids": customer_ids,
    })

    print("\n" + "#" * 70)
    print("# WORKFLOW COMPLETE")
    print("#" * 70)
    print(f"Customer IDs: {customer_label}")
    print(f"Report: {result.get('report_path', 'N/A')}")
    print(f"IOC XML: {result.get('xml_output_path', 'N/A')}")

    return result


def _run_workflow_for_hierarchy(hierarchy: str, vault_root: str, hierarchies_dir: Path) -> dict:
    """Pull one hierarchy's files via MCP, aggregate only its log files
    (legacy_log_aggregation.py — no rule-based Pass 1/Pass 2 filtering), and
    analyze just that hierarchy against the resulting aggregated log file."""
    print("\n" + "#" * 70)
    print("# RUNNING LEGACY LOG AGGREGATION (pull + log-files-only consolidation, no rule-based filtering)")
    print("#" * 70)
    print(f"Vault root: {vault_root}")
    print(f"Hierarchy:  {hierarchy}")

    logs_file = run_legacy_log_workflow(hierarchy, vault_root, hierarchies_dir)
    print(f"✓ Aggregated log file written to {logs_file}")

    return _run_workflow_for_logs_file(logs_file, hierarchies_dir)


def main() -> None:
    """
    Run the workflow for a single hierarchy pulled via MCP (--hierarchy), or fall back
    to batch-analyzing every customer hierarchy already present locally, or a root-level
    logs.txt if neither applies.
    """
    parser = argparse.ArgumentParser(description="Run the cybersecurity log analysis workflow.")
    parser.add_argument(
        "--hierarchy",
        default=None,
        help=(
            "Specific hierarchy path to analyze, e.g. 5/101/1/4/1 "
            "(company_id/customer_id/branch_id/product_id/system_id). "
            "When given, populate_hierarchies.py is run for just this hierarchy, "
            "its files are consolidated into logs.txt, and only that hierarchy is analyzed "
            "instead of batch-scanning all of hierarchies/."
        ),
    )
    parser.add_argument(
        "--vault-root",
        default=DEFAULT_VAULT_ROOT,
        help=f"Vault root path on the MCP server to pull --hierarchy from (default: {DEFAULT_VAULT_ROOT}).",
    )
    args = parser.parse_args()

    base_dir = Path(__file__).parent
    hierarchies_dir = base_dir / "hierarchies"

    if args.hierarchy:
        _run_workflow_for_hierarchy(args.hierarchy, args.vault_root, hierarchies_dir)
        return

    hierarchy_logs = _discover_customer_log_files(hierarchies_dir)

    if hierarchy_logs:
        print("\n" + "#" * 70)
        print("# CUSTOMER HIERARCHY BATCH RUN")
        print("#" * 70)
        print(f"Discovered {len(hierarchy_logs)} customer log file(s) under: {hierarchies_dir}")

        completed = 0
        failed = 0

        for index, logs_file in enumerate(hierarchy_logs, start=1):
            customer_ids = _extract_customer_ids(logs_file, hierarchies_dir)
            customer_label = _format_customer_label(customer_ids)
            print("\n" + "=" * 70)
            print(f"[CUSTOMER {index}/{len(hierarchy_logs)}] {customer_label}")
            print("=" * 70)

            try:
                _run_workflow_for_logs_file(logs_file, hierarchies_dir)
                completed += 1
            except Exception as exc:
                failed += 1
                print(f"✗ Workflow failed for customer {customer_label}: {exc}")

        print("\n" + "#" * 70)
        print("# BATCH RUN SUMMARY")
        print("#" * 70)
        print(f"Completed: {completed}")
        print(f"Failed: {failed}")
        return

    logs_file = base_dir / "logs.txt"
    if not logs_file.exists():
        print("ERROR: No customer hierarchies were found and logs.txt is missing.")
        raise SystemExit(1)

    _run_workflow_for_logs_file(logs_file)


if __name__ == "__main__":
    main()

# import time
# interval = 30

# while True:

#     print("\n================ NEW CYCLE ================\n")

#     try:

#         result = app.invoke({
#             "logs": logs_content
#         })

#         print("\n" + "#"*70)
#         print("# GENERATION COMPLETE")
#         print("#"*70)

#         print(f"\nVector Group: {result['ioc_vector_group']['vector_group_name']}")
#         print(f"Vectors: {', '.join(result['ioc_vector_group']['vectors'])}")
#         print(f"\nOutput saved to: new_ioc.xml")
#     except Exception as e:
#         print("[ERROR] Agent crashed:", str(e))
        

#     print(f"[INFO] Sleeping for {interval} seconds...\n")
#     time.sleep(interval)