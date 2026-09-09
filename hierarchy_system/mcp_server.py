from fastmcp import FastMCP
from pathlib import Path
from dotenv import load_dotenv
import base64
import os

load_dotenv()

mcp = FastMCP("Internal-AI")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# The real vault data root is an absolute, filesystem-root-level path
# (/rationalVault/data), unrelated to wherever this script's repo checkout
# happens to live — it is NOT BASE_DIR/rationalVault/data. Override via
# DATA_ROOT env var if a deployment's real path differs.
DATA_ROOT = Path(os.getenv("DATA_ROOT", "/rationalVault/data")).resolve()


def _read_file_entry(file_path: Path, relative_path: str) -> dict:
    raw = file_path.read_bytes()
    try:
        content = raw.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        content = base64.b64encode(raw).decode("ascii")
        encoding = "base64"

    return {
        "relative_path": relative_path,
        "content": content,
        "encoding": encoding,
    }


@mcp.tool()
def fetch_directory_files(root_path: str) -> list[dict]:
    """
    Recursively read every file under root_path on the server filesystem and
    return each one's path (relative to root_path) plus its content, so a
    caller can reconstruct the same directory tree locally. If root_path
    points directly at a single file rather than a directory, returns just
    that file, using its own filename as relative_path.
    """
    base = Path(root_path)
    if not base.is_absolute():
        base = Path(BASE_DIR) / base
    if not base.exists():
        return []

    if base.is_file():
        return [_read_file_entry(base, base.name)]

    if not base.is_dir():
        return []

    files = []
    for file_path in sorted(base.rglob("*")):
        if not file_path.is_file():
            continue
        files.append(_read_file_entry(file_path, file_path.relative_to(base).as_posix()))

    return files


@mcp.tool()
def upload_file(relative_path: str, content: str) -> str:
    """
    Write content to relative_path under rationalVault/data on this machine,
    preserving hierarchy structure (e.g. "5/101/1/4/1/analysis_report_....md")
    so results land alongside the source files they were generated from.
    """
    target = (DATA_ROOT / relative_path).resolve()

    if not str(target).startswith(str(DATA_ROOT)):
        return "Rejected: path escapes data directory"

    if not content or len(content.strip()) == 0:
        print("⚠️ Empty content received — skipping overwrite.")
        return "Empty content ignored"

    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())

    print(f"\nFile saved at: {target}")

    return f"{relative_path} stored successfully"


def _split_csv(raw: str) -> list[str]:
    return [p.strip() for p in raw.split(",") if p.strip()]


@mcp.tool()
def get_attack_checklist() -> dict:
    """
    Parse THIS machine's own .env for the attack-checking configuration and
    return it as one structured dict — the single source of truth for which
    attack types get checked, in what order, and against which files/tags on
    this hierarchy's vault. The analysis machine calls this once per run
    instead of carrying any of this configuration itself: no local corpus
    file, no database, no embedding/RAG lookup — everything the analysis
    workflow needs to know about this vault's checks lives here, on the
    machine that actually owns the data being checked.

    .env variables read (see .env.example for the full schema/worked
    examples):
      ATTACK_ORDER                 comma-separated attack_type keys, defines
                                    both which types are checked and in what
                                    order.
      ATTACK_PRIMARY_<type>        comma-separated list of co-equal primary
                                    evidence sources (any one reading
                                    "detected" makes the whole attack type
                                    "detected"). Each source is "<path>[#tag]"
                                    — a bare path reads the whole file as
                                    text; "#tag" reads one XML element's text
                                    from that path. ";" inside one entry joins
                                    multiple files that get combined into ONE
                                    reading (e.g. two logs that only make
                                    sense read together).
      ATTACK_VERIFY_<type>         same shape, the verification tier (only
                                    reached once every primary source reads
                                    clean). Optional.
      ATTACK_WRITER_<type>         human-readable provenance chain shown in
                                    the report's "Source chain". Optional,
                                    defaults to "unknown".
      ATTACK_UI_FEATURE_<type>     dashboard feature name referenced in a
                                    discrepancy's recommended re-run. Optional.
      ATTACK_RELIABLE_<type>       "false" marks this attack type's data
                                    source as known-unreliable — the workflow
                                    reports "cannot determine" instead of
                                    reading it at all. Defaults to true.
      ATTACK_CAVEAT_<type>         free-text note rendered under "Cannot
                                    determine" (and available generally).
                                    Optional.
      LOG_FILE_PATHS                comma-separated list of paths the
                                    catch-all log-analysis pass reads (each
                                    either an absolute server-side path, or
                                    one relative to this hierarchy's own
                                    vault folder). Optional — the analysis
                                    machine falls back to the three
                                    canonical security logs
                                    (var/log/messages, var/log/secure,
                                    var/log/audit.log) if unset.
    """
    order = _split_csv(os.getenv("ATTACK_ORDER", ""))
    attacks = {}
    for attack_type in order:
        attacks[attack_type] = {
            "primary": _split_csv(os.getenv(f"ATTACK_PRIMARY_{attack_type}", "")),
            "verify": _split_csv(os.getenv(f"ATTACK_VERIFY_{attack_type}", "")),
            "writer": os.getenv(f"ATTACK_WRITER_{attack_type}", "unknown"),
            "ui_feature": os.getenv(f"ATTACK_UI_FEATURE_{attack_type}") or None,
            "reliable": os.getenv(f"ATTACK_RELIABLE_{attack_type}", "true").strip().lower() != "false",
            "caveat": os.getenv(f"ATTACK_CAVEAT_{attack_type}") or None,
        }
    return {
        "order": order,
        "attacks": attacks,
        "log_file_paths": _split_csv(os.getenv("LOG_FILE_PATHS", "")),
    }


if __name__ == "__main__":
    mcp.run(
        transport="http",
        host="0.0.0.0",
        port=8002
    )
