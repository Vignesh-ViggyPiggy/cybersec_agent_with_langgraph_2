# corpus_server.py — local API in front of the attack-corpus vector store.
#
# Built as its own small service (not a plain import) because, unlike
# attack_status_data.py's fixed taxonomy, this corpus is meant to be written
# to by more than one independent process over time: the detection workflow
# reads it, and the human-review contribution workflow (not yet built) will
# both read AND write it, likely as its own separately-running process. An
# embedded vector store like Chroma is fine for one owning process, but
# multiple processes opening its files directly is exactly the kind of
# concurrent-write risk a thin service in front avoids — so this server is
# that single owning process, and everyone else talks to it over MCP,
# matching the same pattern already used by hierarchy_system/mcp_server.py
# and trigger_mcp_server.py for the same underlying reason (shared state,
# multiple consumers).
#
# Embeddings use Ollama's own nomic-embed-text model rather than chromadb's
# default (sentence-transformers/HuggingFace) so this stays inside the one
# local runtime already used for everything else in this project. Requires:
#   ollama pull nomic-embed-text
from fastmcp import FastMCP
from pathlib import Path
from dotenv import load_dotenv
import chromadb
import json
import os

from langchain_ollama import OllamaEmbeddings

load_dotenv()

mcp = FastMCP("Attack-Corpus")

DB_PATH = Path(os.getenv("CORPUS_DB_PATH", str(Path(__file__).parent / "corpus_db")))
EMBED_MODEL = os.getenv("CORPUS_EMBED_MODEL", "nomic-embed-text")

_client = chromadb.PersistentClient(path=str(DB_PATH))
_embeddings = OllamaEmbeddings(model=EMBED_MODEL)
_collection = _client.get_or_create_collection("attack_corpus")


def _flatten_metadata(metadata: dict) -> dict:
    """Chroma metadata values must be flat str/int/float/bool — lists/dicts
    get JSON-encoded so nothing is silently dropped."""
    flat = {}
    for key, value in (metadata or {}).items():
        if value is None:
            continue
        if isinstance(value, (list, dict)):
            flat[key] = json.dumps(value)
        else:
            flat[key] = value
    return flat


def _unflatten_metadata(metadata: dict) -> dict:
    """Best-effort reverse of _flatten_metadata — a value that round-trips
    through json.loads as a list/dict is restored; anything else (including
    a plain string that happens to not be JSON) is left as-is."""
    restored = {}
    for key, value in (metadata or {}).items():
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                if isinstance(parsed, (list, dict)):
                    restored[key] = parsed
                    continue
            except json.JSONDecodeError:
                pass
        restored[key] = value
    return restored


@mcp.tool()
def add_corpus_entry(id: str, explanation: str, metadata: dict) -> str:
    """Add or update (upsert) one corpus entry. `explanation` is what gets
    embedded for semantic search — the natural-language description, not
    the file's raw content. A real content example (raw XML/text) belongs in
    metadata (e.g. metadata["raw_content_example"]), stored and retrievable
    alongside the explanation but deliberately not embedded itself, since
    embedding raw XML/text doesn't help similarity search the way a
    description does."""
    embedding = _embeddings.embed_query(explanation)
    _collection.upsert(
        ids=[id],
        embeddings=[embedding],
        documents=[explanation],
        metadatas=[_flatten_metadata(metadata)],
    )
    return f"{id} added/updated"


@mcp.tool()
def get_corpus_entry(id: str) -> dict:
    """Exact lookup by id — no embedding/similarity involved. This is what
    the detection workflow's fixed per-attack loop should use."""
    result = _collection.get(ids=[id])
    if not result["ids"]:
        return {"found": False}
    return {
        "found": True,
        "id": result["ids"][0],
        "explanation": result["documents"][0],
        "metadata": _unflatten_metadata(result["metadatas"][0]),
    }


@mcp.tool()
def query_corpus(text: str, n_results: int = 3) -> list[dict]:
    """Semantic search — for free-text questions and, later, for the
    contribution workflow to check a new submission against existing
    entries before committing it."""
    embedding = _embeddings.embed_query(text)
    results = _collection.query(query_embeddings=[embedding], n_results=n_results)
    if not results["ids"] or not results["ids"][0]:
        return []
    return [
        {
            "id": results["ids"][0][i],
            "explanation": results["documents"][0][i],
            "metadata": _unflatten_metadata(results["metadatas"][0][i]),
            "distance": results["distances"][0][i],
        }
        for i in range(len(results["ids"][0]))
    ]


@mcp.tool()
def list_corpus_entries() -> list[dict]:
    """Everything currently in the corpus — for inspection/debugging, not
    for the detection workflow's runtime path."""
    result = _collection.get()
    return [
        {
            "id": result["ids"][i],
            "explanation": result["documents"][i],
            "metadata": _unflatten_metadata(result["metadatas"][i]),
        }
        for i in range(len(result["ids"]))
    ]


@mcp.tool()
def delete_corpus_entry(id: str) -> str:
    _collection.delete(ids=[id])
    return f"{id} deleted"


if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=8003)
