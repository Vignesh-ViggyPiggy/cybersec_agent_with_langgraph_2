# corpus_client.py — talks to corpus_server.py over MCP.
#
# Reuses mcp_client.py's _extract_tool_result rather than re-implementing
# FastMCP result-envelope unwrapping — that exact logic was already a fixed
# bug once in this repo (see mcp_client.py's own docstring/history), no
# reason to risk reintroducing it in a second, slightly different copy.
import asyncio
import os
from fastmcp import Client
from dotenv import load_dotenv

from lib.mcp_client import _extract_tool_result

load_dotenv()

CORPUS_SERVER_URL = os.getenv("CORPUS_SERVER_URL") or "http://127.0.0.1:8003/mcp"


async def _call_async(tool_name: str, args: dict):
    client = Client(CORPUS_SERVER_URL)
    async with client:
        result = await client.call_tool(tool_name, args)
        return _extract_tool_result(result)


def add_corpus_entry(id: str, explanation: str, metadata: dict) -> str:
    return asyncio.run(_call_async("add_corpus_entry", {"id": id, "explanation": explanation, "metadata": metadata}))


def get_corpus_entry(id: str) -> dict:
    return asyncio.run(_call_async("get_corpus_entry", {"id": id}))


def query_corpus(text: str, n_results: int = 3) -> list:
    return asyncio.run(_call_async("query_corpus", {"text": text, "n_results": n_results}))


def list_corpus_entries() -> list:
    return asyncio.run(_call_async("list_corpus_entries", {}))


def delete_corpus_entry(id: str) -> str:
    return asyncio.run(_call_async("delete_corpus_entry", {"id": id}))
