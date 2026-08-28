"""
attack_status_data.py — resolves which attack types are known and enabled,
backed by corpus_server.py's vector store.

attack_taxonomy.json has been retired. Its 9 entries now live as
corpus_documents/attack_*.json, ingested into the same corpus that also
holds raw-evidence-file and schema-definition entries. This means there's
one source of truth instead of two that could drift out of sync — the
earlier design (a flat JSON file the workflow read directly, separate from
the vector corpus used for semantic search) risked exactly that.

Requires corpus_server.py to be running (python corpus_server.py from
analysis_system/) — this module has no local fallback if it isn't.
"""
import os
import warnings

from lib.corpus_client import list_corpus_entries, get_corpus_entry


def get_known_attack_types() -> list[str]:
    """Every attack_type currently in the corpus — entries carrying an
    attack_type metadata field, as opposed to raw-evidence/schema entries
    that don't (aide_report_txt, rv_ioc_lin_xml, etc.)."""
    entries = list_corpus_entries()
    return sorted(
        e["metadata"]["attack_type"]
        for e in entries
        if "attack_type" in e.get("metadata", {})
    )


def get_enabled_attack_types() -> list[str]:
    """Which of the known attack types this run should actually check —
    see ENABLED_ATTACK_TYPES in .env.example. Unset/empty means all known
    types; unknown names are dropped with a warning, not a crash."""
    known = get_known_attack_types()
    raw = os.getenv("ENABLED_ATTACK_TYPES", "").strip()
    if not raw:
        return known

    requested = [name.strip() for name in raw.split(",") if name.strip()]
    enabled = [name for name in requested if name in known]

    unknown = set(requested) - set(enabled)
    if unknown:
        warnings.warn(
            f"ENABLED_ATTACK_TYPES named unknown attack type(s), skipped: {sorted(unknown)}. "
            f"Known types: {known}"
        )

    return enabled


def get_attack_entry(attack_type: str) -> dict:
    """Fetch one attack type's full corpus entry. Exact id lookup, not
    semantic search — attack_type is always a known key here, resolved from
    get_enabled_attack_types(), so there's no free-text query to search
    against. Corpus ids for attack-type entries are prefixed with
    'attack_' (e.g. attack_type='ransomware' -> corpus id 'attack_ransomware')
    to keep them distinct from file-level entries like 'aide_report_txt'."""
    entry = get_corpus_entry(f"attack_{attack_type}")
    if not entry.get("found"):
        raise KeyError(f"No corpus entry for attack type: {attack_type!r}")
    return entry
