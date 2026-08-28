import asyncio
import base64
import os
from fastmcp import Client
from dotenv import load_dotenv

load_dotenv()

MCP_SERVER_URL = os.getenv("MCP_SERVER_URL") or "http://100.90.44.5:8000/mcp"


async def send_files_async(file, toolname, relative_path=None):

    client = Client(MCP_SERVER_URL)

    # read file produced by log analyzer
    with open(file, "r", encoding="utf-8") as f:
        content = f.read()

    async with client:
        result = await client.call_tool(
            toolname,
            {
                "relative_path": relative_path or file,
                "content": content
            }
        )
        return _extract_tool_result(result)


def send_files(file, toolname, relative_path=None):
    """
    Upload a local file to the vault's upload_file tool. relative_path controls
    where it lands on the vault (e.g. "5/101/1/4/1/analysis_report_....md");
    defaults to the local file path if omitted.
    """
    return asyncio.run(send_files_async(file, toolname, relative_path))


def _to_plain(obj):
    """Recursively convert fastmcp/pydantic result objects into plain dict/list/scalar values."""
    if isinstance(obj, dict):
        return {k: _to_plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_plain(v) for v in obj]

    model_dump = getattr(obj, "model_dump", None)
    if callable(model_dump):
        return _to_plain(model_dump())

    # fastmcp wraps bare `dict`/`list` return annotations in a pydantic
    # RootModel client-side; unwrap it via its `.root` attribute.
    if hasattr(obj, "root"):
        return _to_plain(obj.root)

    return obj


def _unwrap_result_envelope(value):
    """
    Some fastmcp versions wrap a bare list/scalar return value in a
    {"result": <value>} envelope in the wire-format JSON (observed: a tool
    annotated to return List[dict] came back as {'result': []} instead of
    a bare list). A real fetch_directory_files/upload_file result is never
    itself shaped like {"result": ...}, so unwrapping this is unambiguous.
    """
    if isinstance(value, dict) and set(value.keys()) == {"result"}:
        return value["result"]
    return value


def _extract_tool_result(result):
    """
    Pull the plain Python value out of a fastmcp CallToolResult.

    Prefer the raw JSON text blocks in `result.content` over `result.data` /
    `result.structured_content`: those attributes can come back as
    fastmcp-internal pydantic wrapper objects (e.g. a `Root` RootModel) whose
    shape varies by fastmcp version, whereas the wire-format JSON always
    decodes to plain dict/list/scalar values via json.loads.
    """
    content = getattr(result, "content", None)
    if content:
        import json
        for block in content:
            text = getattr(block, "text", None)
            if text:
                try:
                    return _unwrap_result_envelope(json.loads(text))
                except json.JSONDecodeError:
                    continue

    structured = getattr(result, "structured_content", None)
    if structured:
        return _unwrap_result_envelope(_to_plain(structured))

    data = getattr(result, "data", None)
    if data is not None:
        return _unwrap_result_envelope(_to_plain(data))

    return _unwrap_result_envelope(_to_plain(result))


async def fetch_directory_files_async(root_path, toolname="fetch_directory_files"):
    client = Client(MCP_SERVER_URL)

    async with client:
        result = await client.call_tool(toolname, {"root_path": root_path})
        return _extract_tool_result(result)


def fetch_directory_files(root_path, toolname="fetch_directory_files"):
    """
    Ask the MCP server to recursively read every file under root_path (a path
    on the server's filesystem) and return each file's relative path,
    content, and encoding ("utf-8" or "base64" for binary files).
    """
    return asyncio.run(fetch_directory_files_async(root_path, toolname))


def decode_file_content(entry: dict) -> bytes:
    """Turn a fetch_directory_files() entry back into raw bytes."""
    content = entry.get("content", "")
    if entry.get("encoding") == "base64":
        return base64.b64decode(content)
    return content.encode("utf-8")

# send_files("new_ioc.xml", "upload_file")