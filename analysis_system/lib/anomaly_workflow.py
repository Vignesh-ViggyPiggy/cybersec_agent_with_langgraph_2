"""
anomaly_workflow.py — standalone anomaly-detection workflow.

Separate from lib/log_analysis_workflow.py for now, per design: this pulls one hierarchy's full
data (existing rationalVault/data/<hierarchy> tree, plus /athinio/security
and the relevant /var/log sources), then runs it through two passes:

  Pass 1 — known findings: extract verdicts the source scripts already
  computed (status fields, severity flags, non-zero counters).

  Pass 2 — independent anomaly surfacing: diff-against-last-pull, line
  frequency/rarity analysis, and structure-aware pattern matching, applied
  to the genuinely raw files that have no upstream verdict — so this catches
  things a fixed threshold rule might miss, not just what's already flagged.

Output: hierarchies/<hierarchy>/anomaly_findings.txt — only this (not the
raw pulled files) is meant to eventually feed into lib/log_analysis_workflow.py's
per-incident pipeline (not yet wired in — that pipeline currently reads
LOG_FILE_PATHS' three canonical log files directly, not this file).

Usage:
    python anomaly_workflow.py 5/101/1/4/1
    python anomaly_workflow.py 5/101/1/4/1 --vault-root rationalVault/data
"""

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET

# Windows consoles sometimes default to a non-UTF-8 codepage (cp1252), which
# can't encode characters like the checkmark used in progress output below.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8")
        except Exception:
            pass

from lib.mcp_client import fetch_directory_files, decode_file_content
from lib.populate_hierarchies import populate_hierarchies as pull_hierarchy_from_vault

# Absolute path — mcp_server.py's BASE_DIR is wherever it happens to be
# running from (Path(__file__).parent), so a relative default here silently
# resolves to the wrong location if that script ever moves (as it did during
# the hierarchy_system/analysis_system split) or if the vault's real data
# root isn't actually nested under wherever the server script lives.
DEFAULT_VAULT_ROOT = "/rationalVault/data"
CACHE_DIRNAME = ".anomaly_cache"

# (remote absolute path, local subdirectory under the hierarchy folder)
EXTRA_SOURCES = [
    ("/athinio/security", "athinio/security"),
    ("/var/log/osstatus.log", "var_log"),
    ("/var/log/secure", "var_log"),
    ("/var/log/rkhunter/rkhunter.log", "var_log"),
    ("/var/log/audit/audit.log", "var_log"),
    ("/var/log/log_disable.log", "var_log"),  # written by secOpsScript_120 when it detects log tampering
]

# blacklist_unique_binaries.txt is deliberately NOT in this list even though
# network_anamoly.sh also writes to it — that filename collides with
# secOpsScript_112's own "new unknown binary" tracking file, and the latter is
# the more specific signal, so it gets its own dedicated check/category below.
POST_LEARNING_FILES = [
    "blacklist_learned_ips.txt", "blacklist_ip_ports.txt",
    "blacklist_listen_ports.txt", "blacklist_listen_bins.txt",
]

UNKNOWN_BINARY_RAW_FILE = "blacklist_unique_binaries.txt"

KILLED_FILES = ["killed_processes.txt", "killed_blacklists_processes.txt", "killed_unknown_binaries.txt"]

# Written by Alert1.sh/Alert.sh's binmod()/libmod() hash-integrity sweep —
# the actual list of files that failed the check behind Bin/Lib_current_status.
BIN_LIB_MODIFY_FILES = ["binmodify.txt", "libmodify.txt"]

# Written by secOpsScript_113 alongside User_breach/suspicious_user_login.
USER_BREACH_RAW_FILES = ["user_breached_users.txt", "locked_user_breached_users.txt"]

# rChecker's own raw diff-output files (gatewayMonitor.sh, secOpsScript_128,
# rchecker1.sh, secOps_ransCheck all shell out to /athinio/bin/rChecker and
# grep this exact string in the result) — no ALERT/Attack label of their own,
# so catch_all_scan's severity-keyword sweep would otherwise miss them.
RCHECKER_OUTPUT_FILES = ["rcheckOutput", "rcheckOutput.txt", "rCheckerOutput"]
RCHECKER_FOUND_RE = re.compile(r"Ransomware corruption FOund", re.I)

EXPLICITLY_HANDLED = {
    "outputfile.xml", "alertlog.xml", "suspicious_authentication.xml", "user_incident.xml",
    "breach.xml", "rootkitscan.txt", "monitorstatus.xml", "user_breach_violations.xml",
    "ignored_alert.xml", "ignored_alert_bs.xml",
    "blacklist_ip.xml", "blacklist_ipports.xml", "config_dift.xml", "identity_baseline.json",
    "assets_report.xml", "logScan.log",
    "suspicious_config.xml", "secOpsOutput_128",
    "baseline_cmd.json", "baseline_log_tamper.json", "baseline_ssh.json", "baseline_file_integrity.json",
    *POST_LEARNING_FILES, *KILLED_FILES, *BIN_LIB_MODIFY_FILES, *USER_BREACH_RAW_FILES,
    *RCHECKER_OUTPUT_FILES, UNKNOWN_BINARY_RAW_FILE,
}

SEVERITY_KEYWORD_RE = re.compile(r"\b(ALERT|Attack|ATTACK|CRITICAL|WARNING)\b")
TIMESTAMP_ATTR_RE = re.compile(r'generated(_at)?="[^"]*"')
WATCHED_AUDIT_COMMANDS = {"su", "sudo", "passwd", "useradd", "userdel", "chmod", "chown", "nc", "ncat", "wget", "curl"}
SSHD_FAIL_RE = re.compile(r'sshd\[\d+\]:\s+Failed password for (?:invalid user )?(\S+) from (\S+)')
SSHD_ACCEPT_RE = re.compile(r'sshd\[\d+\]:\s+Accepted password for (\S+) from (\S+)')


# ======================================================================
# Pull stage
# ======================================================================

def pull_extra_sources(hierarchy_dir: Path) -> None:
    """Pull /athinio/security and the relevant /var/log sources for this hierarchy."""
    for remote_path, local_subdir in EXTRA_SOURCES:
        try:
            entries = fetch_directory_files(remote_path)
        except Exception as exc:
            print(f"  ! Failed to fetch {remote_path}: {exc}")
            continue
        if not entries:
            print(f"  - Nothing returned for {remote_path} (may not exist on this system)")
            continue
        for entry in entries:
            rel = entry.get("relative_path")
            if not rel:
                continue
            target = hierarchy_dir / local_subdir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(decode_file_content(entry))
        print(f"  + Pulled {remote_path} -> {local_subdir}/ ({len(entries)} file(s))")


# ======================================================================
# Shared XML helpers
# ======================================================================

SYSTEM_DIR_MARKER = "alertlog.xml"


def _resolve_system_dir(hierarchy_dir: Path) -> Path:
    """
    The vault's layout for a hierarchy's system files has changed once already
    (nested under athinio/system/, then flat directly under the hierarchy
    folder) — resolve it at runtime by checking for a known marker file,
    rather than "non-empty", which a stale leftover file can satisfy falsely.
    """
    nested = hierarchy_dir / "athinio" / "system"
    if (nested / SYSTEM_DIR_MARKER).exists():
        return nested
    if (hierarchy_dir / SYSTEM_DIR_MARKER).exists():
        return hierarchy_dir
    # Marker absent from both (e.g. a clean-slate test run) — fall back to
    # whichever location actually has content.
    if nested.is_dir() and any(nested.iterdir()):
        return nested
    return hierarchy_dir


def _xml_root(path: Path):
    try:
        return ET.parse(path).getroot()
    except Exception:
        return None


def _text(root, tag, default=""):
    if root is None:
        return default
    el = root.find(f".//{tag}")
    if el is None or el.text is None:
        return default
    return el.text.strip()


# ======================================================================
# Pass 1 — known findings (extract, don't detect)
# ======================================================================

def check_outputfile(system_dir: Path):
    path = system_dir / "outputfile.xml"
    if not path.exists():
        return None
    root = _xml_root(path)
    status = _text(root, "file_status")
    filename = _text(root, "filename")
    if status.strip().upper() == "YES":
        return f"[outputfile.xml] file_status=YES filename={filename}"
    return None


def check_alertlog(system_dir: Path):
    path = system_dir / "alertlog.xml"
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return None
    return f"[alertlog.xml] (always included in full — the aggregation hub)\n{text}"


def check_suspicious_authentication(system_dir: Path):
    path = system_dir / "suspicious_authentication.xml"
    if not path.exists():
        return None
    root = _xml_root(path)
    if root is None:
        return None
    total_critical = _text(root, "total_critical", "0")
    total_warnings = _text(root, "total_warnings", "0")
    overall_status = _text(root, "overall_status", "")

    if total_critical == "0" and total_warnings == "0":
        return None

    lines = [f"[suspicious_authentication.xml] overall_status={overall_status} "
             f"total_critical={total_critical} total_warnings={total_warnings}"]

    for check_el in root.findall("check"):
        check_name = check_el.get("name", check_el.get("id", "?"))
        for container in check_el:
            tag = container.tag
            if tag == "ip_analysis":
                for ip_el in container.findall("ip"):
                    if ip_el.get("brute_force") == "true":
                        lines.append(
                            f"  [{check_name}] BRUTE_FORCE ip={ip_el.get('address')} "
                            f"count={ip_el.get('count')} action={ip_el.get('recommended_action', '')}"
                        )
                continue
            prefix = tag.split("_")[0]
            if prefix in ("critical", "suspicious", "warning"):
                if container.get("count", "0") == "0":
                    continue
                for child in container:
                    if child.tag == "none":
                        continue
                    attrs = " ".join(f"{k}={v}" for k, v in child.attrib.items())
                    text_val = (child.text or "").strip()
                    lines.append(f"  [{check_name}] {attrs} {text_val}".rstrip())

    return "\n".join(lines)


def check_user_incident(system_dir: Path):
    path = system_dir / "user_incident.xml"
    if not path.exists():
        return None
    root = _xml_root(path)
    if root is None:
        return None
    ignored_path = system_dir / "ignored_alert.xml"
    ignored_root = _xml_root(ignored_path) if ignored_path.exists() else None

    lines = []
    for el in root.iter():
        if el.tag.endswith("_intrusion") and (el.text or "").strip() == "1":
            base = el.tag[: -len("_intrusion")]
            ignore_flag = _text(ignored_root, f"{base}_ignore") if ignored_root is not None else ""
            if ignore_flag == "1":
                continue
            lines.append(f"  {el.tag}=1 (not dismissed)")
    if not lines:
        return None
    return "[user_incident.xml] active intrusion flags:\n" + "\n".join(lines)


def check_breach(system_dir: Path):
    path = system_dir / "breach.xml"
    if not path.exists():
        return None
    root = _xml_root(path)
    attack = _text(root, "attack", "0")
    if attack == "0":
        return None
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    return f"[breach.xml] attack=1\n{text}"


def check_rootkitscan(system_dir: Path):
    path = system_dir / "rootkitscan.txt"
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8", errors="replace")
    warning_lines = [l.strip() for l in text.splitlines() if l.strip().startswith("Warning:")]
    if not warning_lines and "Suspect files: 0" in text and "Possible rootkits: 0" in text:
        return None
    summary_match = re.search(r"System checks summary.*", text, re.S)
    parts = ["[rootkitscan.txt] warnings:"] + [f"  {l}" for l in warning_lines]
    if summary_match:
        parts.append(summary_match.group(0)[:400])
    return "\n".join(parts)


def check_monitorstatus(system_dir: Path):
    path = system_dir / "monitorstatus.xml"
    if not path.exists():
        return None
    root = _xml_root(path)
    rootkit = _text(root, "rootkit", "0")
    if rootkit != "0":
        return f"[monitorstatus.xml] rootkit={rootkit}"
    return None


def check_user_breach_violations(system_dir: Path):
    path = system_dir / "user_breach_violations.xml"
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text or "<sessions" not in text:
        return None
    return f"[user_breach_violations.xml]\n{text}"


def check_post_learning_anomalies(system_dir: Path):
    findings = []
    for name in POST_LEARNING_FILES:
        path = system_dir / name
        if not path.exists():
            continue
        lines = [l for l in path.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
        if lines:
            findings.append(f"[{name}] {len(lines)} new entr{'y' if len(lines) == 1 else 'ies'}:\n"
                             + "\n".join(f"  {l}" for l in lines[:20]))
    return findings


def check_killed_files(system_dir: Path):
    findings = []
    for name in KILLED_FILES:
        path = system_dir / name
        if not path.exists():
            continue
        lines = [l for l in path.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
        if lines:
            findings.append(f"[{name}] {len(lines)} entries (already auto-remediated):\n"
                             + "\n".join(f"  {l}" for l in lines[-10:]))
    return findings


def check_param_cmd_flags(system_dir: Path):
    findings = []
    for path in sorted(system_dir.glob("param_cmd_*.xml")):
        root = _xml_root(path)
        if root is None:
            continue
        for field in ("enforce", "kill_unknow_binary", "migrate_blacklist"):
            if _text(root, field) == "1":
                findings.append(f"[{path.name}] {field}=1 (operator action in flight)")
    return findings


def check_osstatus_log(var_log_dir: Path):
    path = var_log_dir / "osstatus.log"
    if not path.exists():
        return None
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    notable = [l for l in lines if re.search(r"\b(ALERT|Attack|ATTACK)\b", l)]
    learning = [l for l in lines if "learning phase" in l.lower()]
    parts = []
    if notable:
        parts.append("[osstatus.log] ALERT/Attack lines:\n" + "\n".join(f"  {l}" for l in notable))
    if learning:
        parts.append(f"[osstatus.log] {len(learning)} line(s) show an active learning phase "
                      f"(detection suppressed for that check, not necessarily clean)")
    return "\n".join(parts) if parts else None


def check_security_dir(security_dir: Path):
    findings = []
    for name in ("clamav", "file_sensitive", "sensitive_data"):
        path = security_dir / name
        if path.exists() and path.stat().st_size > 0:
            text = path.read_text(encoding="utf-8", errors="replace").strip()
            findings.append(f"[/athinio/security/{name}] flagged:\n{text[:500]}")
    return findings


def check_binary_lib_modifications(system_dir: Path):
    """
    Independent re-derivation of Bin/Lib_current_status: Alert1.sh's binmod()/
    libmod() functions hash every file under /usr/bin, /athinio/bin,
    /usr/lib, /athinio/lib etc. against a reference and list mismatches here
    before setting the alertlog.xml flag. Reading the list directly catches
    tamper even if the flag-write step didn't run or failed.
    """
    findings = []
    for name in BIN_LIB_MODIFY_FILES:
        path = system_dir / name
        if not path.exists():
            continue
        lines = [l for l in path.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
        if lines:
            findings.append(f"[{name}] {len(lines)} modified file(s) (hash mismatch vs. reference):\n"
                             + "\n".join(f"  {l}" for l in lines[:20]))
    return findings


def check_unknown_binary_raw(system_dir: Path):
    """
    secOpsScript_112's own new-binary tracking file — same detection this
    script uses to decide whether to set Unknown_binary=1 in alertlog.xml.
    """
    path = system_dir / UNKNOWN_BINARY_RAW_FILE
    if not path.exists():
        return None
    lines = [l for l in path.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
    if not lines:
        return None
    return (f"[{UNKNOWN_BINARY_RAW_FILE}] {len(lines)} unrecognized binary(ies) "
            f"(secOpsScript_112's own detection list):\n" + "\n".join(f"  {l}" for l in lines[:20]))


def check_user_breach_raw_lists(system_dir: Path):
    """secOpsScript_113's own breached/locked-username lists, alongside User_breach."""
    findings = []
    for name in USER_BREACH_RAW_FILES:
        path = system_dir / name
        if not path.exists():
            continue
        lines = [l for l in path.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
        if lines:
            findings.append(f"[{name}] {len(lines)} user(s):\n" + "\n".join(f"  {l}" for l in lines[:20]))
    return findings


def check_rchecker_raw_output(system_dir: Path):
    """
    /athinio/bin/rChecker's own diff-output files. gatewayMonitor.sh,
    secOpsScript_128, rchecker1.sh and secOps_ransCheck all grep this exact
    string ("Ransomware corruption FOund") to decide whether to set a
    ransomware/honeypot flag — reading it directly here means the same
    verdict surfaces even if the wrapper script never got to the sed step.
    """
    findings = []
    for name in RCHECKER_OUTPUT_FILES:
        path = system_dir / name
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace").strip()
        if text and RCHECKER_FOUND_RE.search(text):
            findings.append(f"[{name}] rChecker raw diff flags corruption:\n{text[:500]}")
    return findings


def check_honeypot_scan_output(system_dir: Path):
    """
    secOpsScript_128's own log — the per-folder honeypot-copy ransomcheck plus
    immutability/monitoring sweep. Handled separately from catch_all_scan
    because its "Attack : Ransomeware corruption Found" line reads identically
    to the plain ransomware check's output, which would otherwise get
    mis-tagged as ransomware_indicator instead of honeypot_tamper.
    """
    path = system_dir / "secOpsOutput_128"
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = [l.strip() for l in text.splitlines() if SEVERITY_KEYWORD_RE.search(l)]
    if not lines:
        return None
    return "[secOpsOutput_128] honeypot-folder scan flagged:\n" + "\n".join(f"  {l[:200]}" for l in lines[-10:])


def check_log_disable_log(var_log_dir: Path):
    """secOpsScript_120's own log — the log-tampering-vs-ransomware disambiguation trail."""
    path = var_log_dir / "log_disable.log"
    if not path.exists():
        return None
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    alert_lines = [l for l in lines if SEVERITY_KEYWORD_RE.search(l)]
    if not alert_lines:
        return None
    return f"[log_disable.log] {len(alert_lines)} alert line(s):\n" + "\n".join(f"  {l}" for l in alert_lines[-10:])


# Verified against the actual /athinio/bin scripts that write alertlog.xml
# (secOps_ransCheck, gatewayMonitor.sh, secOpsScript_78/98/99/112/113/120/128/136,
# Alert.sh/Alert1.sh, rChecker_md.sh, rchecker1.sh, break_alert.sh, network_anamoly.sh,
# hour.sh) — every field below is one this codebase actually sets, and the priority
# order follows how secOpsScript_78 itself aggregates sub-checks into a verdict.
ALERTLOG_CATEGORY_PRIORITY = [
    (["Ransom_current_status", "AMS_Ransom_current_status", "tierNas_ransom",
      "DB_Ransom_current_status", "Process_current_value"], "ransomware_indicator"),
    (["Unknown_binary"], "unknown_binary_execution"),
    (["network_anamoly", "network_disk_sus"], "network_anomaly"),
    (["Honeypot_process", "Honeypot", "special_files_honeypot"], "honeypot_tamper"),
    (["Bin_current_status", "Lib_current_status"], "file_integrity_tamper"),
    (["log_disable"], "log_tampering"),
    (["Break-in_status", "suspicious_user_login", "User_breach", "Breach_val"], "user_breach"),
]


def _infer_alertlog_category(text: str):
    """alertlog.xml aggregates many flags; pick the highest-priority one that's actually set (=1)."""
    for fields, category in ALERTLOG_CATEGORY_PRIORITY:
        for field in fields:
            if re.search(rf"<{re.escape(field)}>1</{re.escape(field)}>", text):
                return category
    return None


SUSPICIOUS_AUTH_CHECK_TO_CATEGORY = [
    ("ssh_key_injection", "ssh_key_injection"),
    ("log_tampering", "log_tampering"),
    ("file_integrity", "file_integrity_tamper"),
    ("suspicious_commands", "suspicious_command_execution"),
    ("auth_failures", "user_breach"),
]


def _infer_suspicious_auth_category(text: str):
    for check_name, category in SUSPICIOUS_AUTH_CHECK_TO_CATEGORY:
        if f"[{check_name}]" in text:
            return category
    return None


# Known log-message phrases the source scripts write verbatim (confirmed by
# reading them directly, e.g. identity_assets_mapping.py's own
# 'Attack : Assets permissions tampering detected "{path}"' message) — used
# to categorize free-text findings (osstatus.log, logScan.log, catch-all
# hits) where there's no structured field to key off of, but the wording
# itself unambiguously identifies what happened.
KNOWN_PHRASE_CATEGORY_PATTERNS = [
    # Two real spellings exist in this codebase: "Ransomeware" (typo'd, used in
    # human-readable log lines) and "Ransomware ... FOund" (correct spelling,
    # used in rChecker's own raw diff-output files) — match both.
    (re.compile(r"Ransomeware corruption|Ransomware corruption|ATTACK-R", re.I), "ransomware_indicator"),
    (re.compile(r"Assets permissions tampering", re.I), "assets_permission_tamper"),
    (re.compile(r"Unknown binary detected", re.I), "unknown_binary_execution"),
    (re.compile(r"Binary files tamper detected", re.I), "file_integrity_tamper"),
    (re.compile(r"network_anamoly|network anomaly", re.I), "network_anomaly"),
    (re.compile(r"SSH KEY INJECTION", re.I), "ssh_key_injection"),
    (re.compile(r"Honeypot", re.I), "honeypot_tamper"),
    (re.compile(r"log[ _-]?tamper", re.I), "log_tampering"),
    (re.compile(r"Break-?in", re.I), "user_breach"),
    (re.compile(r"rootkit", re.I), "rootkit_detected"),
]


def _infer_category_from_phrase(text: str):
    for pattern, category in KNOWN_PHRASE_CATEGORY_PATTERNS:
        if pattern.search(text):
            return category
    return None


# Categories that DO have a corresponding alertlog.xml flag — same field
# groupings as ALERTLOG_CATEGORY_PRIORITY above, reused to check whether
# alertlog.xml's own checks already caught what a finding suggests.
# Categories not listed here (rootkit_detected, ssh_key_injection,
# suspicious_command_execution, assets_permission_tamper) have no alertlog.xml
# field at all — those live in suspicious_authentication.xml / assets_report.xml
# instead, so alertlog.xml structurally can't speak to them.
CATEGORY_TO_ALERTLOG_FIELDS = {
    "ransomware_indicator": ["Ransom_current_status", "AMS_Ransom_current_status", "tierNas_ransom",
                              "DB_Ransom_current_status", "Process_current_value"],
    "unknown_binary_execution": ["Unknown_binary"],
    "network_anomaly": ["network_anamoly", "network_disk_sus"],
    "honeypot_tamper": ["Honeypot_process", "Honeypot", "special_files_honeypot"],
    "file_integrity_tamper": ["Bin_current_status", "Lib_current_status"],
    "log_tampering": ["log_disable"],
    "user_breach": ["Break-in_status", "suspicious_user_login", "User_breach", "Breach_val"],
}

# Which /athinio/bin script actually writes the alertlog.xml field(s) for each
# category — confirmed by reading the real scripts, not guessed from filenames.
# Where a category is set by more than one script (e.g. honeypot detection is
# split across rChecker_md.sh, secOpsScript_78 and secOpsScript_128), this
# points at the one that owns the dedicated, most direct check.
CATEGORY_TO_VERIFICATION_SCRIPT = {
    "rootkit_detected": "/athinio/bin/rkhunter.sh",
    "ssh_key_injection": "/athinio/bin/suspicious_monitor.py",       # check4_ssh
    "log_tampering": "/athinio/bin/secOpsScript_120",                # sets log_disable
    "suspicious_command_execution": "/athinio/bin/suspicious_monitor.py",  # check2_commands
    "user_breach": "/athinio/bin/secOpsScript_113",                  # sets User_breach/suspicious_user_login
    "network_anomaly": "/athinio/bin/network_anamoly.sh",
    "ransomware_indicator": "/athinio/bin/secOps_ransCheck",
    "file_integrity_tamper": "/athinio/bin/Alert1.sh",
    "honeypot_tamper": "/athinio/bin/secOpsScript_128",              # sets special_files_honeypot
    "unknown_binary_execution": "/athinio/bin/secOpsScript_112",
    "assets_permission_tamper": "/athinio/bin/identity_assets_mapping.py",
}


def _alertlog_confirmed_categories(system_dir: Path) -> set:
    """Which categories does alertlog.xml's own flags already confirm (=1)?"""
    path = system_dir / "alertlog.xml"
    if not path.exists():
        return set()
    text = path.read_text(encoding="utf-8", errors="replace")
    confirmed = set()
    for category, fields in CATEGORY_TO_ALERTLOG_FIELDS.items():
        for field in fields:
            if re.search(rf"<{re.escape(field)}>1</{re.escape(field)}>", text):
                confirmed.add(category)
                break
    return confirmed


def suggest_verification_scripts(hierarchy_dir: Path, all_findings) -> list:
    """
    For every category a finding suggests, check whether alertlog.xml's own
    flags already confirm it. If not — either alertlog.xml has no field for
    that category, or the field exists but isn't set — the rule-based agent
    hasn't independently caught this pattern, so point at the specific
    /athinio/bin script that would check for it directly.
    """
    system_dir = _resolve_system_dir(hierarchy_dir)
    confirmed = _alertlog_confirmed_categories(system_dir)

    seen_categories = []
    for _, category in all_findings:
        if category and category not in seen_categories:
            seen_categories.append(category)

    suggestions = []
    for category in seen_categories:
        if category in confirmed:
            continue
        script = CATEGORY_TO_VERIFICATION_SCRIPT.get(category)
        if not script:
            continue
        suggestions.append(f"  {category}: not confirmed in alertlog.xml -> run {script} to verify")

    return suggestions


def run_pass1(hierarchy_dir: Path):
    """Returns a list of (finding_text, suggested_incident_type_or_None)."""
    system_dir = _resolve_system_dir(hierarchy_dir)
    security_dir = hierarchy_dir / "athinio" / "security"
    var_log_dir = hierarchy_dir / "var_log"

    findings = []

    result = check_outputfile(system_dir)
    if result:
        findings.append((result, None))

    result = check_alertlog(system_dir)
    if result:
        findings.append((result, _infer_alertlog_category(result)))

    result = check_suspicious_authentication(system_dir)
    if result:
        findings.append((result, _infer_suspicious_auth_category(result)))

    result = check_user_incident(system_dir)
    if result:
        findings.append((result, None))

    result = check_breach(system_dir)
    if result:
        findings.append((result, "ransomware_indicator"))

    result = check_rootkitscan(system_dir)
    if result:
        findings.append((result, "rootkit_detected"))

    result = check_monitorstatus(system_dir)
    if result:
        findings.append((result, "rootkit_detected"))

    result = check_user_breach_violations(system_dir)
    if result:
        findings.append((result, "user_breach"))

    findings.extend((f, "network_anomaly") for f in check_post_learning_anomalies(system_dir))
    findings.extend((f, "unknown_binary_execution") for f in check_killed_files(system_dir))
    findings.extend((f, None) for f in check_param_cmd_flags(system_dir))

    osstatus_result = check_osstatus_log(var_log_dir)
    if osstatus_result:
        findings.append((osstatus_result, _infer_category_from_phrase(osstatus_result)))

    findings.extend((f, None) for f in check_security_dir(security_dir))

    # Independent re-derivations of the same signals the /athinio/bin scripts
    # themselves check, read straight from their raw output — these surface a
    # verdict even if the corresponding alertlog.xml flag-write step didn't run.
    findings.extend((f, "file_integrity_tamper") for f in check_binary_lib_modifications(system_dir))

    result = check_unknown_binary_raw(system_dir)
    if result:
        findings.append((result, "unknown_binary_execution"))

    findings.extend((f, "user_breach") for f in check_user_breach_raw_lists(system_dir))
    findings.extend((f, "ransomware_indicator") for f in check_rchecker_raw_output(system_dir))

    result = check_honeypot_scan_output(system_dir)
    if result:
        findings.append((result, "honeypot_tamper"))

    result = check_log_disable_log(var_log_dir)
    if result:
        findings.append((result, "log_tampering"))

    return findings


# ======================================================================
# Pass 2 — independent anomaly surfacing (diff / frequency / pattern)
# ======================================================================

def _normalize_line(line: str) -> str:
    """Strip volatile timestamp attributes so unchanged content doesn't look changed."""
    return TIMESTAMP_ATTR_RE.sub("", line).strip()


def diff_against_cache(file_path: Path, cache_dir: Path, cache_key: str, max_new_lines=20):
    if not file_path.exists():
        return None
    cache_path = cache_dir / (cache_key.replace("/", "__") + ".cache")

    current_text = file_path.read_text(encoding="utf-8", errors="replace")
    current_lines = {_normalize_line(l) for l in current_text.splitlines() if l.strip()}

    if not cache_path.exists():
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(current_text, encoding="utf-8")
        return f"[{cache_key}] first pull — establishing baseline, nothing to diff yet ({len(current_lines)} lines)"

    previous_text = cache_path.read_text(encoding="utf-8", errors="replace")
    previous_lines = {_normalize_line(l) for l in previous_text.splitlines() if l.strip()}

    added = current_lines - previous_lines
    removed = previous_lines - current_lines
    cache_path.write_text(current_text, encoding="utf-8")

    if not added and not removed:
        return None

    lines = [f"[{cache_key}] changed since last pull: +{len(added)} / -{len(removed)}"]
    for l in list(added)[:max_new_lines]:
        lines.append(f"  + {l}")
    if len(added) > max_new_lines:
        lines.append(f"  ... and {len(added) - max_new_lines} more added")
    for l in list(removed)[:max_new_lines]:
        lines.append(f"  - {l}")
    if len(removed) > max_new_lines:
        lines.append(f"  ... and {len(removed) - max_new_lines} more removed")
    return "\n".join(lines)


def diff_json_against_cache(file_path: Path, cache_dir: Path, cache_key: str, max_items=20):
    if not file_path.exists():
        return None
    try:
        current_data = json.loads(file_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None
    if not isinstance(current_data, dict):
        return None

    cache_path = cache_dir / (cache_key.replace("/", "__") + ".json")
    if not cache_path.exists():
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(current_data), encoding="utf-8")
        return f"[{cache_key}] first pull — establishing baseline ({len(current_data)} entries)"

    try:
        previous_data = json.loads(cache_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        previous_data = {}
    cache_path.write_text(json.dumps(current_data), encoding="utf-8")

    prev_keys = set(previous_data.keys())
    curr_keys = set(current_data.keys())
    added_keys = curr_keys - prev_keys
    removed_keys = prev_keys - curr_keys
    changed_keys = {k for k in (curr_keys & prev_keys) if current_data[k] != previous_data[k]}

    if not added_keys and not removed_keys and not changed_keys:
        return None

    lines = [f"[{cache_key}] changed since last pull: "
             f"+{len(added_keys)} new / -{len(removed_keys)} removed / ~{len(changed_keys)} modified paths"]
    for k in list(added_keys)[:max_items]:
        lines.append(f"  + new path: {k}")
    for k in list(removed_keys)[:max_items]:
        lines.append(f"  - removed path: {k}")
    for k in list(changed_keys)[:max_items]:
        lines.append(f"  ~ permission change: {k}")
    return "\n".join(lines)


def analyze_logscan(system_dir: Path, cache_dir: Path, rare_threshold=2, max_report=15):
    path = system_dir / "logScan.log"
    if not path.exists():
        return None
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()

    def template(line: str) -> str:
        t = re.sub(r"^\w+ \d{1,2} \d{4} \d{2}:\d{2}:\d{2}", "", line)
        t = re.sub(r"\d+", "#", t)
        return t.strip()

    counts = Counter(template(l) for l in lines if l.strip())

    cache_path = cache_dir / "logScan_template_counts.json"
    previous_counts = {}
    if cache_path.exists():
        try:
            previous_counts = json.loads(cache_path.read_text(encoding="utf-8"))
        except Exception:
            previous_counts = {}
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(counts), encoding="utf-8")

    findings = []

    rare = sorted(((t, c) for t, c in counts.items() if c <= rare_threshold), key=lambda x: x[1])
    if rare:
        findings.append(f"[logScan.log] {len(rare)} rare line pattern(s) (occurred <= {rare_threshold}x):")
        findings.extend(f"  ({c}x) {t[:200]}" for t, c in rare[:max_report])

    spikes = [(t, previous_counts.get(t, 0), c) for t, c in counts.items()
              if previous_counts.get(t, 0) > 0 and c > previous_counts[t] * 3 and c - previous_counts[t] > 5]
    if spikes:
        findings.append(f"[logScan.log] {len(spikes)} pattern(s) spiked vs last run:")
        findings.extend(f"  {prev}x -> {c}x: {t[:200]}" for t, prev, c in spikes[:max_report])

    return "\n".join(findings) if findings else None


def analyze_secure(hierarchy_dir: Path, max_report=15):
    path = hierarchy_dir / "var_log" / "secure"
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8", errors="replace")
    fails = SSHD_FAIL_RE.findall(text)
    accepts = SSHD_ACCEPT_RE.findall(text)
    if not fails and not accepts:
        return None

    lines = []
    if fails:
        by_ip = Counter(ip for _, ip in fails)
        lines.append(f"[secure] {len(fails)} genuine sshd auth failure(s) from {len(by_ip)} IP(s):")
        lines.extend(f"  {count}x from {ip}" for ip, count in by_ip.most_common(max_report))
    if accepts:
        lines.append(f"[secure] {len(accepts)} accepted password login(s):")
        lines.extend(f"  {user} from {ip}" for user, ip in accepts[:max_report])
    return "\n".join(lines)


def analyze_audit_log(hierarchy_dir: Path, max_report=15):
    path = hierarchy_dir / "var_log" / "audit.log"
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8", errors="replace")
    findings = []
    for line in text.splitlines():
        if "type=SYSCALL" not in line:
            continue
        comm_m = re.search(r'comm="([^"]+)"', line)
        if not comm_m or comm_m.group(1) not in WATCHED_AUDIT_COMMANDS:
            continue
        findings.append(line.strip())
    if not findings:
        return None
    out = [f"[audit.log] {len(findings)} watched-command execution(s):"]
    out.extend(f"  {l[:250]}" for l in findings[:max_report])
    if len(findings) > max_report:
        out.append(f"  ... and {len(findings) - max_report} more")
    return "\n".join(out)


def analyze_rkhunter_log(hierarchy_dir: Path, rootkit_flagged: bool, max_report=20):
    if not rootkit_flagged:
        return None
    path = hierarchy_dir / "var_log" / "rkhunter.log"
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8", errors="replace")
    warnings = [l.strip() for l in text.splitlines() if l.strip().startswith("Warning:")]
    if not warnings:
        return None
    out = [f"[rkhunter.log] full warning detail ({len(warnings)} lines), deep-dive since rootkitscan.txt flagged something:"]
    out.extend(f"  {l}" for l in warnings[:max_report])
    return "\n".join(out)


# When system_dir resolves to the hierarchy root itself (flat layout), these
# sibling subdirectories/files are handled elsewhere and must not be swept up
# by catch_all_scan's recursive walk.
CATCH_ALL_EXCLUDE_DIR_NAMES = {".anomaly_cache", "var_log", "athinio"}
CATCH_ALL_EXCLUDE_TOP_LEVEL_NAMES = {"vector_group_output.xml", "logs.txt", "anomaly_findings.txt"}


def catch_all_scan(system_dir: Path, hierarchy_dir: Path, max_report=10):
    findings = []
    for path in sorted(system_dir.rglob("*")):
        if not path.is_file() or path.name in EXPLICITLY_HANDLED or path.name.startswith("param_cmd_"):
            continue

        rel_to_hierarchy = path.relative_to(hierarchy_dir)
        parts = rel_to_hierarchy.parts
        if parts and parts[0] in CATCH_ALL_EXCLUDE_DIR_NAMES:
            continue
        if len(parts) == 1 and (parts[0] in CATCH_ALL_EXCLUDE_TOP_LEVEL_NAMES or parts[0].startswith("analysis_report_")):
            continue

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        hits = [l.strip() for l in text.splitlines() if SEVERITY_KEYWORD_RE.search(l)]
        if hits:
            rel = path.relative_to(system_dir)
            findings.append(f"[{rel}] {len(hits)} labeled line(s) (caught by safety-net scan):\n"
                             + "\n".join(f"  {l[:200]}" for l in hits[:max_report]))
    return "\n".join(findings) if findings else None


DIFF_FILE_CATEGORY = {
    "blacklist_ip.xml": None,       # routine threat-feed maintenance, not itself an event on this host
    "blacklist_ipports.xml": None,
    "config_dift.xml": "file_integrity_tamper",
    "assets_report.xml": "assets_permission_tamper",
}


def run_pass2(hierarchy_dir: Path, cache_dir: Path):
    """Returns a list of (finding_text, suggested_incident_type_or_None)."""
    findings = []
    system_dir = _resolve_system_dir(hierarchy_dir)

    for name, category in DIFF_FILE_CATEGORY.items():
        result = diff_against_cache(system_dir / name, cache_dir, name)
        if result:
            findings.append((result, category))

    result = diff_json_against_cache(system_dir / "identity_baseline.json", cache_dir, "identity_baseline.json")
    if result:
        findings.append((result, "assets_permission_tamper"))

    result = analyze_logscan(system_dir, cache_dir)
    if result:
        findings.append((result, _infer_category_from_phrase(result)))

    result = analyze_secure(hierarchy_dir)
    if result:
        # Only the genuine-failure branch of this finding maps to a category;
        # an accepted-login-only result isn't itself an incident.
        category = "user_breach" if "genuine sshd auth failure" in result else None
        findings.append((result, category))

    result = analyze_audit_log(hierarchy_dir)
    if result:
        findings.append((result, "suspicious_command_execution"))

    rootkit_flagged = check_rootkitscan(system_dir) is not None
    result = analyze_rkhunter_log(hierarchy_dir, rootkit_flagged)
    if result:
        findings.append((result, "rootkit_detected"))

    result = catch_all_scan(system_dir, hierarchy_dir)
    if result:
        findings.append((result, _infer_category_from_phrase(result)))

    return findings


# ======================================================================
# Entry point
# ======================================================================

def run_anomaly_detection(hierarchy: str, vault_root: str, hierarchies_dir: Path) -> Path:
    hierarchy_clean = hierarchy.strip("/\\")
    hierarchy_dir = hierarchies_dir / Path(hierarchy_clean)

    print("\n" + "=" * 70)
    print("PULLING HIERARCHY DATA")
    print("=" * 70)
    pull_hierarchy_from_vault(vault_root, hierarchies_dir, hierarchy_clean)

    print("\n" + "=" * 70)
    print("PULLING ADDITIONAL SOURCES (/athinio/security, /var/log/*)")
    print("=" * 70)
    pull_extra_sources(hierarchy_dir)

    cache_dir = hierarchy_dir / CACHE_DIRNAME

    print("\n" + "=" * 70)
    print("PASS 1 — KNOWN FINDINGS")
    print("=" * 70)
    pass1_findings = run_pass1(hierarchy_dir)
    print(f"{len(pass1_findings)} finding(s)")

    print("\n" + "=" * 70)
    print("PASS 2 — INDEPENDENT ANOMALY SURFACING")
    print("=" * 70)
    pass2_findings = run_pass2(hierarchy_dir, cache_dir)
    print(f"{len(pass2_findings)} finding(s)")

    all_findings = pass1_findings + pass2_findings
    output_path = hierarchy_dir / "anomaly_findings.txt"

    # Pass 1's tags are more authoritative than Pass 2's (known verdicts vs.
    # independent surfacing), and within each pass, findings were appended in
    # roughly descending severity order — so the first distinct category is a
    # reasonable "primary" incident, with any other distinct categories found
    # in the same pull surfaced as secondary incidents rather than dropped.
    seen_categories = []
    for _, cat in all_findings:
        if cat and cat not in seen_categories:
            seen_categories.append(cat)
    suggested_category = seen_categories[0] if seen_categories else None
    secondary_categories = seen_categories[1:]

    # Findings whose category alertlog.xml's own checks haven't already
    # confirmed (=1) — point at the specific /athinio/bin script that would
    # verify them directly, since the rule-based agent hasn't caught it itself.
    verification_suggestions = suggest_verification_scripts(hierarchy_dir, all_findings)

    header = (f"Anomaly detection run: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
              f"Hierarchy: {hierarchy_clean}\n")
    if suggested_category:
        header += f"Suggested incident_type (rule-based, from detection source): {suggested_category}\n"
    if secondary_categories:
        header += (f"Additional suggested incident_types (secondary, rule-based, from detection source): "
                   f"{', '.join(secondary_categories)}\n")
    if verification_suggestions:
        header += "Suggested verification scripts (findings not yet confirmed in alertlog.xml):\n"
        header += "\n".join(verification_suggestions) + "\n"
    header += "\n"

    finding_texts = [text for text, _ in all_findings]
    if not finding_texts:
        content = header + "No anomalous or notable findings detected in this pull.\n"
    else:
        content = header + "\n\n".join(finding_texts) + "\n"

    output_path.write_text(content, encoding="utf-8")
    print(f"\n✓ Wrote {len(finding_texts)} finding(s) to {output_path}"
          + (f" (suggested_category={suggested_category}"
             + (f", secondary={secondary_categories}" if secondary_categories else "")
             + ")" if suggested_category else ""))
    if verification_suggestions:
        print("  Verification script suggestions:")
        for line in verification_suggestions:
            print(f"  {line}")
    return output_path


def main():
    parser = argparse.ArgumentParser(
        description="Standalone anomaly-detection workflow (pull + Pass 1 + Pass 2), separate from lib/log_analysis_workflow.py for now."
    )
    parser.add_argument("hierarchy", help="e.g. 5/101/1/4/1")
    parser.add_argument("--vault-root", default=DEFAULT_VAULT_ROOT)
    parser.add_argument("--dest", default=str(Path(__file__).parent / "hierarchies"))
    args = parser.parse_args()

    run_anomaly_detection(args.hierarchy, args.vault_root, Path(args.dest))


if __name__ == "__main__":
    main()
