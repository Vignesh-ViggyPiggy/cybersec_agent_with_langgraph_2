"""
db.py — SQLite persistence + query layer for CTI/STIX data. One file,
two tiers:

  - observables: atomic IOCs (ioc_type, ioc_value) extracted from STIX
    indicator patterns AT INGEST TIME, not at query time -- a STIX
    pattern like "[ipv4-addr:value = '203.0.113.7']" is a mini query
    language, not something you want to re-parse on every lookup.
    Exact-match, indexed -- this is the deterministic tier.

  - intel_narratives: attack-pattern/malware/campaign description text
    with an embedding vector attached, for similarity search. The
    embedding is stored as a serialized float32 blob (via numpy), and
    similarity ranking happens in Python after loading every row --
    deliberately NOT using a vector-search SQLite extension (sqlite-vec
    etc.), since those need a compiled C extension that isn't reliably
    available everywhere, and a linear cosine-similarity scan is
    genuinely fast enough at the realistic scale here (thousands of
    narrative objects, not millions).

stix_objects keeps the raw STIX JSON verbatim for full fidelity;
sync_state tracks a per-source watermark for incremental re-ingestion.
"""
import json
import sqlite3
from pathlib import Path

import numpy as np

SCHEMA = """
CREATE TABLE IF NOT EXISTS stix_objects (
    stix_id  TEXT PRIMARY KEY,
    type     TEXT NOT NULL,
    source   TEXT NOT NULL,
    modified TEXT,
    raw      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS observables (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator_id TEXT,
    ioc_type     TEXT NOT NULL,
    ioc_value    TEXT NOT NULL,
    valid_from   TEXT,
    valid_until  TEXT,
    source       TEXT NOT NULL,
    UNIQUE(ioc_type, ioc_value, indicator_id)
);
CREATE INDEX IF NOT EXISTS idx_observables_lookup ON observables(ioc_type, ioc_value);

CREATE TABLE IF NOT EXISTS intel_narratives (
    stix_id         TEXT PRIMARY KEY,
    source          TEXT NOT NULL,
    title           TEXT,
    narrative       TEXT NOT NULL,
    mitre_technique TEXT,
    embedding       BLOB
);

CREATE TABLE IF NOT EXISTS sync_state (
    source         TEXT PRIMARY KEY,
    last_synced_at TEXT NOT NULL
);
"""


def get_connection(db_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def _embedding_to_blob(embedding: list[float]) -> bytes:
    return np.asarray(embedding, dtype=np.float32).tobytes()


def _blob_to_embedding(blob: bytes) -> np.ndarray:
    return np.frombuffer(blob, dtype=np.float32)


# ── Writes ──────────────────────────────────────────────────────────────

def upsert_stix_object(conn: sqlite3.Connection, stix_id: str, type_: str,
                        source: str, modified: str | None, raw: dict) -> None:
    conn.execute(
        "INSERT INTO stix_objects (stix_id, type, source, modified, raw) VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(stix_id) DO UPDATE SET type=excluded.type, source=excluded.source, "
        "modified=excluded.modified, raw=excluded.raw",
        (stix_id, type_, source, modified, json.dumps(raw)),
    )
    conn.commit()


def upsert_observable(conn: sqlite3.Connection, indicator_id: str | None, ioc_type: str,
                       ioc_value: str, valid_from: str | None, valid_until: str | None,
                       source: str) -> None:
    conn.execute(
        "INSERT INTO observables (indicator_id, ioc_type, ioc_value, valid_from, valid_until, source) "
        "VALUES (?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(ioc_type, ioc_value, indicator_id) DO UPDATE SET "
        "valid_from=excluded.valid_from, valid_until=excluded.valid_until, source=excluded.source",
        (indicator_id, ioc_type, ioc_value, valid_from, valid_until, source),
    )
    conn.commit()


def upsert_narrative(conn: sqlite3.Connection, stix_id: str, source: str, title: str | None,
                      narrative: str, mitre_technique: str | None, embedding: list[float]) -> None:
    conn.execute(
        "INSERT INTO intel_narratives (stix_id, source, title, narrative, mitre_technique, embedding) "
        "VALUES (?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(stix_id) DO UPDATE SET source=excluded.source, title=excluded.title, "
        "narrative=excluded.narrative, mitre_technique=excluded.mitre_technique, "
        "embedding=excluded.embedding",
        (stix_id, source, title, narrative, mitre_technique, _embedding_to_blob(embedding)),
    )
    conn.commit()


def get_sync_state(conn: sqlite3.Connection, source: str) -> str | None:
    row = conn.execute("SELECT last_synced_at FROM sync_state WHERE source = ?", (source,)).fetchone()
    return row["last_synced_at"] if row else None


def set_sync_state(conn: sqlite3.Connection, source: str, timestamp: str) -> None:
    conn.execute(
        "INSERT INTO sync_state (source, last_synced_at) VALUES (?, ?) "
        "ON CONFLICT(source) DO UPDATE SET last_synced_at=excluded.last_synced_at",
        (source, timestamp),
    )
    conn.commit()


# ── Reads ───────────────────────────────────────────────────────────────

def lookup_observables(conn: sqlite3.Connection, tokens: list[str]) -> list[dict]:
    """Exact-match lookup -- tokens are candidate IOC values already
    extracted from log/evidence text by the caller (an IP, a domain, a
    hash), not free text to search within."""
    if not tokens:
        return []
    placeholders = ",".join("?" for _ in tokens)
    rows = conn.execute(
        f"SELECT ioc_type, ioc_value, indicator_id, valid_from, valid_until, source "
        f"FROM observables WHERE ioc_value IN ({placeholders})",
        tokens,
    ).fetchall()
    return [dict(r) for r in rows]


def get_relevant_narratives(conn: sqlite3.Connection, query_embedding: list[float],
                             top_k: int = 3) -> list[dict]:
    """Loads every narrative's embedding and ranks by cosine similarity
    in Python. Fine at the realistic scale of ingested behavioral
    narratives (thousands, not millions) -- see module docstring."""
    rows = conn.execute(
        "SELECT stix_id, source, title, narrative, mitre_technique, embedding FROM intel_narratives"
    ).fetchall()
    if not rows:
        return []

    query_vec = np.asarray(query_embedding, dtype=np.float32)
    query_norm = np.linalg.norm(query_vec) or 1.0

    scored = []
    for row in rows:
        vec = _blob_to_embedding(row["embedding"])
        denom = (np.linalg.norm(vec) * query_norm) or 1.0
        similarity = float(np.dot(vec, query_vec) / denom)
        scored.append((similarity, row))

    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [
        {"stix_id": row["stix_id"], "source": row["source"], "title": row["title"],
         "narrative": row["narrative"], "mitre_technique": row["mitre_technique"],
         "similarity": similarity}
        for similarity, row in scored[:top_k]
    ]


def stats(conn: sqlite3.Connection) -> dict:
    return {
        "stix_objects": conn.execute("SELECT COUNT(*) FROM stix_objects").fetchone()[0],
        "observables": conn.execute("SELECT COUNT(*) FROM observables").fetchone()[0],
        "intel_narratives": conn.execute("SELECT COUNT(*) FROM intel_narratives").fetchone()[0],
    }
