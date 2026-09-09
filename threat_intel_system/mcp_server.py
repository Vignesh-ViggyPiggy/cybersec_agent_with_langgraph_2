"""
mcp_server.py — exposes the SQLite-backed CTI/STIX store over MCP, the
same transport hierarchy_system and analysis_system already use to talk
to each other. This is what makes "separate system or same system"
purely a config choice, not an architecture choice: run this on the
analysis machine itself and point THREAT_INTEL_SERVER_URL at
localhost, or run it on a third machine and point at that machine's
address instead -- analysis_system's calling code doesn't change either
way, only the URL in its .env does (same pattern as MCP_SERVER_URL for
hierarchy_system).

Two tools:
  lookup_observables(tokens)      -- Tier 1, exact-match IOC lookup
  get_relevant_narratives(text)   -- Tier 2, embeds `text` here (so the
                                      embedding model only needs to be
                                      available on THIS machine, not on
                                      every caller) and ranks stored
                                      narratives against it
"""
import os

from dotenv import load_dotenv
from fastmcp import FastMCP

load_dotenv()

import db
import embeddings

DB_PATH = os.getenv("DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "threat_intel.db"))

mcp = FastMCP("Threat-Intel")


def _conn():
    return db.get_connection(DB_PATH)


@mcp.tool()
def lookup_observables(tokens: list[str]) -> list[dict]:
    """Exact-match lookup against the atomic-IOC table. `tokens` are
    candidate values the caller already extracted from evidence/log
    text (an IP, a domain, a hash) -- this does not search free text."""
    conn = _conn()
    try:
        return db.lookup_observables(conn, tokens)
    finally:
        conn.close()


@mcp.tool()
def get_relevant_narratives(text: str, top_k: int = 3) -> list[dict]:
    """Embeds `text` (e.g. raw log content, or a summary of it) and
    returns the top_k most similar ingested threat-intel narratives
    (attack-pattern/malware/campaign descriptions), ranked by cosine
    similarity."""
    query_embedding = embeddings.embed(text)
    conn = _conn()
    try:
        return db.get_relevant_narratives(conn, query_embedding, top_k=top_k)
    finally:
        conn.close()


@mcp.tool()
def stats() -> dict:
    """Row counts per table -- a quick sanity check that ingestion
    actually populated the store."""
    conn = _conn()
    try:
        return db.stats(conn)
    finally:
        conn.close()


if __name__ == "__main__":
    mcp.run(
        transport="http",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8003")),
    )
