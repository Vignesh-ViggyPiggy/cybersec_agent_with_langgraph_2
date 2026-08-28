"""
legacy_log_aggregation.py — shared config/helpers for reading the three
canonical security logs, plus a standalone MCP-pull CLI.

Two things live here:
  1. Config/helpers used by BOTH this file's own standalone pull-and-inspect
     CLI (main(), below) AND lib/log_analysis_workflow.py's production path:
     _load_log_file_paths() / _load_log_tail_lines() (env-var config) and
     _read_as_text_or_placeholder() (tail-capped file reading). Production
     log analysis (via attack_status_workflow.py) does NOT call this file's
     pull functions — it reads directly from the hierarchy directory
     attack_status_workflow.py's own populate_hierarchies() call already
     populated. See lib/log_analysis_workflow.py's module docstring.
  2. A standalone MCP-pull CLI (pull_configured_log_files, consolidate_log_files,
     run_legacy_log_workflow, main()) for manually pulling + inspecting just
     the configured log paths for one hierarchy, independent of a full
     attack_status_workflow.py run — useful for debugging what's actually on
     the vault without running the whole pipeline.

LOG_FILE_PATHS is a comma-separated list where each entry is either:
  - an absolute server-side path, fetched as-is and the same for every
    hierarchy (e.g. /var/log/secure), or
  - a path relative to this hierarchy's own vault folder, resolved as
    <vault_root>/<hierarchy>/<path> (e.g. var/log/messages).

Usage:
    python -m lib.legacy_log_aggregation 5/101/1/4/1
    python -m lib.legacy_log_aggregation 5/101/1/4/1 --vault-root /rationalVault/data
"""

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

# Windows consoles sometimes default to a non-UTF-8 codepage; match the same
# reconfiguration anomaly_workflow.py does so this behaves the same way there.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8")
        except Exception:
            pass

load_dotenv()

from lib.mcp_client import fetch_directory_files, decode_file_content
from lib.anomaly_workflow import DEFAULT_VAULT_ROOT

AGGREGATED_FILENAME = "logs_aggregated.txt"

# Fallback if LOG_FILE_PATHS isn't set in .env — the three canonical
# security logs this pipeline is named after (secure/messages/audit.log),
# hierarchy-relative so each hierarchy's own copy is pulled, not one fixed
# server-wide path.
DEFAULT_LOG_FILE_PATHS = [
    "var/log/messages",
    "var/log/secure",
    "var/log/audit.log",
]


def _load_log_file_paths() -> list[str]:
    raw = os.getenv("LOG_FILE_PATHS", "")
    paths = [p.strip() for p in raw.split(",") if p.strip()]
    return paths or DEFAULT_LOG_FILE_PATHS


# How many of the most recent lines to keep per log file — these files grow
# unbounded on the client, and re-analyzing the same already-seen history
# every run wastes tokens/time for no new signal. Only the tail actually
# changes run to run.
def _load_log_tail_lines() -> int:
    # Default lowered from 2000 to 300 (2026-08-28): with voting off, this is
    # the last major lever on the classification step's prompt size — the
    # ONE call that still carries full raw log text. At 2000 lines/file x up
    # to 3 files, that's up to 6000 lines in a single local-Ollama call,
    # confirmed slow in practice. 300/file (900 total) is still a meaningful
    # recent window; raise via LOG_TAIL_LINES if a workload needs to look
    # further back than that.
    raw = os.getenv("LOG_TAIL_LINES", "").strip()
    try:
        return int(raw) if raw else 300
    except ValueError:
        return 300


def _read_as_text_or_placeholder(path: Path, tail_lines: int) -> str:
    """Non-UTF-8 (binary) files are included as a placeholder line rather
    than raw bytes, matching the old consolidation behavior. Text files are
    capped to their last tail_lines lines — these logs grow unbounded on the
    client, and re-sending the same already-seen history to the LLM every
    run wastes tokens for no new signal; only the tail actually changes
    between runs."""
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


def _pull_one_configured_path(configured_path: str, vault_root: str, hierarchy_clean: str, hierarchy_dir: Path) -> list[Path]:
    """
    Fetch one LOG_FILE_PATHS entry and write it under hierarchy_dir, mirroring
    its own path shape locally. configured_path may name either a single file
    or a directory on the server — mcp_server.py's fetch_directory_files
    handles both, we just need to know which happened to place the result
    correctly (a single-file fetch returns one entry whose relative_path is
    just the bare filename, with no directory prefix to preserve). Returns the
    local paths actually written, so the caller can consolidate exactly those
    files rather than re-deriving (or over-broadly guessing) what landed
    where — hierarchy_dir is shared with other pull mechanisms (e.g.
    attack_status_workflow.py's full hierarchy pull), so anything not tracked
    explicitly here would otherwise get swept into consolidation too.
    """
    is_absolute = configured_path.startswith("/")
    if is_absolute:
        server_path = configured_path
    else:
        server_path = f"{vault_root.rstrip('/')}/{hierarchy_clean}/{configured_path.strip('/')}"

    try:
        entries = fetch_directory_files(server_path)
    except Exception as exc:
        print(f"  ! Failed to fetch {server_path}: {exc}")
        return []
    if not entries:
        print(f"  - Nothing returned for {server_path} (may not exist on this system)")
        return []

    server_leaf = Path(server_path.rstrip("/")).name
    is_single_file_fetch = len(entries) == 1 and entries[0].get("relative_path") == server_leaf

    if is_absolute:
        local_base = (
            Path(server_path.rstrip("/")).parent.as_posix().lstrip("/")
            if is_single_file_fetch else server_path.strip("/")
        )
    else:
        if is_single_file_fetch:
            parent = Path(configured_path.strip("/")).parent.as_posix()
            local_base = "" if parent == "." else parent
        else:
            local_base = configured_path.strip("/")

    written: list[Path] = []
    for entry in entries:
        rel = entry.get("relative_path")
        if not rel:
            continue
        target = (hierarchy_dir / local_base / rel) if local_base else (hierarchy_dir / rel)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(decode_file_content(entry))
        written.append(target)

    print(f"  + Pulled {server_path} -> {local_base or '.'}/ ({len(entries)} file(s))")
    return written


def pull_configured_log_files(vault_root: str, hierarchy_clean: str, hierarchy_dir: Path) -> list[Path]:
    """Pull ONLY the paths listed in LOG_FILE_PATHS (.env) — nothing else is
    fetched from the vault at all, unlike anomaly_workflow.py's whole-tree
    pull plus hardcoded EXTRA_SOURCES. Returns every local file path actually
    written, for consolidate_log_files to scope itself to."""
    written: list[Path] = []
    for configured_path in _load_log_file_paths():
        written.extend(_pull_one_configured_path(configured_path, vault_root, hierarchy_clean, hierarchy_dir))
    return written


def consolidate_log_files(hierarchy_dir: Path, pulled_files: list[Path]) -> str:
    """
    Concatenate exactly the files pull_configured_log_files() actually wrote
    into one heading-delimited string, each capped to its last
    LOG_TAIL_LINES lines. FIX (2026-08-28): this used to rglob() the whole
    hierarchy_dir tree instead of taking an explicit file list — harmless
    when hierarchy_dir held only this pull's own files, but hierarchy_dir is
    shared with other pull mechanisms (e.g. attack_status_workflow.py's full
    hierarchy pull writes into the same directory), so a real run swept up
    everything already sitting there — XML files, compiled binaries, every
    bin/ script — 184,682 lines from one hierarchy instead of the 3
    configured log files. Taking the exact pulled-file list (rather than
    re-deriving or re-globbing) is the only way to guarantee this stays
    scoped to what was actually configured, regardless of what else shares
    the directory.
    """
    tail_lines = _load_log_tail_lines()
    sections = []
    for path in sorted(set(pulled_files)):
        if not path.is_file():
            continue
        rel = path.relative_to(hierarchy_dir)
        content = _read_as_text_or_placeholder(path, tail_lines)
        sections.append(f"===== {rel.as_posix()} =====\n{content}")

    if not sections:
        return "No log files found in this pull.\n"

    return "\n\n".join(sections) + "\n"


def run_legacy_log_workflow(hierarchy: str, vault_root: str, hierarchies_dir: Path) -> Path:
    """Pull ONLY the log paths configured in .env's LOG_FILE_PATHS (nothing
    else from the vault) and aggregate them into one file. Standalone helper
    for manual pull-and-inspect use — the production path
    (lib/log_analysis_workflow.py's run_log_analysis_loop) does NOT call
    this; it reads from an already-local hierarchy pull instead. Returns the
    path to the aggregated file."""
    hierarchy_clean = hierarchy.strip("/\\")
    hierarchy_dir = hierarchies_dir / Path(hierarchy_clean)

    configured_paths = _load_log_file_paths()
    print("\n" + "=" * 70)
    print(f"PULLING CONFIGURED LOG FILES ONLY ({len(configured_paths)} path(s) from LOG_FILE_PATHS)")
    print("=" * 70)
    for p in configured_paths:
        print(f"  - {p}")
    pulled_files = pull_configured_log_files(vault_root, hierarchy_clean, hierarchy_dir)

    print("\n" + "=" * 70)
    print(f"CONSOLIDATING LOG FILES ONLY (legacy-style aggregation, last {_load_log_tail_lines()} lines/file)")
    print("=" * 70)
    content = consolidate_log_files(hierarchy_dir, pulled_files)

    output_path = hierarchy_dir / AGGREGATED_FILENAME
    output_path.write_text(content, encoding="utf-8")

    line_count = content.count("\n")
    print(f"\n✓ Wrote aggregated log file to {output_path} ({line_count} lines)")
    return output_path


def main():
    parser = argparse.ArgumentParser(
        description="Legacy-style hierarchy preprocessing: pull ONLY the paths configured in .env's "
                    "LOG_FILE_PATHS (nothing else fetched from the vault), then aggregate them into one "
                    "heading-delimited file instead of running rule-based Pass 1/Pass 2 filtering."
    )
    parser.add_argument("hierarchy", help="e.g. 5/101/1/4/1")
    parser.add_argument("--vault-root", default=DEFAULT_VAULT_ROOT)
    parser.add_argument("--dest", default=str(Path(__file__).parent.parent / "hierarchies"))
    args = parser.parse_args()

    hierarchies_dir = Path(args.dest)
    run_legacy_log_workflow(args.hierarchy, args.vault_root, hierarchies_dir)
    print("\nTo analyze the aggregated file, run attack_status_workflow.py for this hierarchy "
          "(it calls lib/log_analysis_workflow.py's run_log_analysis_loop automatically).")


if __name__ == "__main__":
    main()
