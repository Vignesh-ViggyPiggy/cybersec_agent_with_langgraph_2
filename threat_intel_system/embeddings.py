"""
embeddings.py — the single shared embedding client, same convention as
analysis_system/lib/llm_client.py. Uses nomic-embed-text via Ollama
(already available locally in this project) -- no external embedding
API, no new service to run.
"""
import os
from langchain_ollama import OllamaEmbeddings

EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "nomic-embed-text")

_embedder = OllamaEmbeddings(model=EMBEDDING_MODEL)


def embed(text: str) -> list[float]:
    return _embedder.embed_query(text)
