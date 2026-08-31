"""
migrate_corpus_schema.py — one-time conversion of corpus_documents/attack_*.json
from the old status_file/status_tag(s)/value_schema/verification_category/
raw_evidence_files schema to the new evidence_sources schema (see
EVIDENCE_ENGINE_DESIGN.md).

Mechanical for every shape except check_raw_logs (user_breach,
gateway_unauthorized_breakin), which need a real regex reconstructed from
the old RAW_LOG_CHECKERS Python functions — hand-crafted here (see
_CHECK_RAW_LOGS_OVERRIDES below), not derived automatically, since a
Python function's logic can't be mechanically translated to a declarative
pattern in general.

Leaves raw_content_examples/value_meanings in place under a new
`examples`/inline `meaning` shape on each generated evidence source;
top-level status_file/status_tag(s)/value_schema/verification_category/
raw_evidence_files are removed once migrated (the new schema replaces
them entirely, not alongside them).

Usage:
    python scripts/migrate_corpus_schema.py             # writes changes
    python scripts/migrate_corpus_schema.py --dry-run    # prints diffs only
"""
import argparse
import copy
import json
import re
from pathlib import Path

DOCS_DIR = Path(__file__).parent.parent / "analysis_system" / "corpus_documents"

# Hand-crafted regex reconstructions for the two check_raw_logs attack types
# — see attack_status_workflow.py's old RAW_LOG_CHECKERS for the Python this
# replaces. Both confirmed to reproduce the same real-world matches: a
# backreference correlates the same captured value across two points in the
# combined text (case A), or a plain literal substring stands in for a
# single-line "in" check (case B).
_CHECK_RAW_LOGS_OVERRIDES = {
    "user_breach": {
        "file": ["var/log/secure", "rationalVault/log/rationalclient.log"],
        "pattern": (
            r"sshd\[\d+\]:\s+Failed password for (?:invalid user )?\S+ from "
            r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?"
            r"sshd\[\d+\]:\s+Accepted password for \S+ from (?P=ip)"
        ),
        "flags": ["DOTALL"],
        "meaning": "Found failed password attempts followed by a successful password login from the same source address.",
    },
    "gateway_unauthorized_breakin": {
        "file": "home/athinio/data/1cloudFiler/log/gateway.log",
        "pattern": "Break-in Attempt",
        "flags": [],
        "meaning": "Found a line containing 'Break-in Attempt' in gateway.log.",
    },
}


def _tag_source(status_file: str, tag: str, value_meanings: dict) -> dict:
    return {
        "tier": "primary",
        "file": status_file,
        "read_as": "xml_tag",
        "tag": tag,
        "known_patterns": [
            {"value": "1", "detected": True, "meaning": value_meanings.get("1", "Detected.")},
        ],
        "default_verdict": "not_detected",
        "default_meaning": value_meanings.get("0", "Clean."),
    }


def _pattern_source(status_file: str, detected_regex: str, value_meanings: dict) -> dict:
    # Word-boundary matching, not plain substring -- "no 'Tampered' anywhere
    # in the file" contains "any" as a substring of "anywhere", which a
    # naive `"any" in k` check would wrongly match as the DETECTED key.
    detected_meaning = next(
        (v for k, v in value_meanings.items() if "present" in k or re.search(r"\bany\b", k, re.IGNORECASE)),
        "Detected.",
    )
    clean_meaning = next(
        (v for k, v in value_meanings.items() if re.search(r"\bno\b", k, re.IGNORECASE)),
        "Clean.",
    )
    return {
        "tier": "primary",
        "file": status_file,
        "read_as": "text",
        "known_patterns": [
            {"pattern": detected_regex, "detected": True, "meaning": detected_meaning},
        ],
        "default_verdict": "not_detected",
        "default_meaning": clean_meaning,
    }


def _non_empty_source(status_file: str, value_meanings: dict) -> dict:
    return {
        "tier": "primary",
        "file": status_file,
        "read_as": "text",
        "known_patterns": [
            {"non_empty": True, "detected": True, "meaning": next(
                (v for k, v in value_meanings.items() if "content" in k), "Detected."
            )},
        ],
        "default_verdict": "not_detected",
        "default_meaning": next((v for k, v in value_meanings.items() if "missing" in k or "empty" in k), "Clean."),
    }


def build_evidence_sources(metadata: dict) -> list[dict]:
    attack_type = metadata["attack_type"]
    status_file = metadata["status_file"]
    value_schema = metadata.get("value_schema", {"type": "binary_flag"})
    schema_type = value_schema.get("type", "binary_flag")
    verification_category = metadata["verification_category"]
    value_meanings = metadata.get("value_meanings", {})
    raw_evidence_files = metadata.get("raw_evidence_files", [])
    raw_content_examples = metadata.get("raw_content_examples", [])

    # --- Primary tier ---
    primary: list[dict] = []
    if schema_type == "binary_flag":
        tags = metadata.get("status_tags") or [metadata["status_tag"]]
        for tag in tags:
            primary.append(_tag_source(status_file, tag, value_meanings))
    elif schema_type == "count_greater_than_zero":
        tag = metadata.get("status_tag")
        # count sources still read one XML tag's text -- reuse xml_tag read_as,
        # just with a min_value pattern instead of an exact "1" value.
        primary.append({
            "tier": "primary",
            "file": status_file,
            "read_as": "xml_tag",
            "tag": tag,
            "known_patterns": [
                {"min_value": 1, "detected": True, "meaning": next(
                    (v for k, v in value_meanings.items() if k.startswith("N")), "Detected."
                )},
            ],
            "default_verdict": "not_detected",
            "default_meaning": value_meanings.get("0", "Clean."),
        })
    elif schema_type == "file_contains_pattern":
        primary.append(_pattern_source(status_file, value_schema.get("detected_regex", ""), value_meanings))
    elif schema_type == "file_non_empty":
        primary.append(_non_empty_source(status_file, value_meanings))
    else:
        raise ValueError(f"{attack_type}: unhandled value_schema type {schema_type!r}")

    # --- Verification tier ---
    verification: list[dict] = []
    if verification_category in ("readable_report", "diffable_snapshot_files"):
        if raw_evidence_files:
            # ALL evidence files combined into ONE source, read together --
            # matches the old verify_against_raw_evidence_node, which always
            # joined every raw_evidence_files entry into a single LLM call
            # rather than judging each file in isolation (a file that's
            # ambiguous alone, e.g. an expected-empty detail file, can be
            # entirely clear read alongside its sibling file).
            verification.append({
                "tier": "verification",
                "file": list(raw_evidence_files),
                "read_as": "text",
                "known_patterns": [],
                "judgment_allowed": True,
                "examples": copy.deepcopy(raw_content_examples),
                # Matches the old verify_against_raw_evidence_node's explicit
                # fallback when NONE of the expected evidence files exist:
                # "could not be independently verified beyond the tag's own
                # status" -> confirmed_clean, not a red flag for a file that
                # was simply never configured to sync from the client.
                "default_verdict": "not_detected",
                "default_meaning": "Evidence file(s) not found; falling back to the tag's own clean status.",
            })
    elif verification_category == "check_raw_logs":
        override = _CHECK_RAW_LOGS_OVERRIDES.get(attack_type)
        if not override:
            raise ValueError(f"{attack_type}: check_raw_logs with no hand-crafted regex override -- add one.")
        verification.append({
            "tier": "verification",
            "file": override["file"],
            "read_as": "text",
            "rotates": True,
            "known_patterns": [
                {"pattern": override["pattern"], "flags": override["flags"], "detected": True,
                 "meaning": override["meaning"]},
            ],
            "default_verdict": "not_detected",
            "default_meaning": "No matching pattern found in the available logs.",
        })
    # requires_live_recompute / opaque_binary_only -> no verification tier at all,
    # even if raw_evidence_files is set (that field only ever fed corroborating
    # display in the old code, never independent verification, for these
    # categories -- see DOCUMENTATION.md §5.4's "Verified against" column).

    return primary + verification


def migrate_one(path: Path, dry_run: bool) -> bool:
    doc = json.loads(path.read_text(encoding="utf-8"))
    metadata = doc["metadata"]
    if "evidence_sources" in metadata:
        return False  # already migrated

    evidence_sources = build_evidence_sources(metadata)

    new_metadata = {
        "attack_type": metadata["attack_type"],
        "evidence_sources": evidence_sources,
    }
    for passthrough in ("writer_script", "ui_feature_name", "ui_feature_name_note", "confidence",
                         "caveat", "data_source_reliable", "related_entries"):
        if passthrough in metadata:
            new_metadata[passthrough] = metadata[passthrough]

    doc["metadata"] = new_metadata

    if dry_run:
        print(f"--- {path.name} ---")
        print(json.dumps(evidence_sources, indent=2))
    else:
        path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    migrated, skipped = 0, 0
    for path in sorted(DOCS_DIR.glob("attack_*.json")):
        if migrate_one(path, args.dry_run):
            migrated += 1
            print(f"{'[dry-run] ' if args.dry_run else ''}migrated: {path.name}")
        else:
            skipped += 1
            print(f"already migrated, skipped: {path.name}")

    print(f"\n{migrated} migrated, {skipped} already up to date.")


if __name__ == "__main__":
    main()
