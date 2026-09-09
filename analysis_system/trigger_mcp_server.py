# trigger_mcp_server.py
from fastmcp import FastMCP
from pathlib import Path

from analysis import run_full_workflow, DEFAULT_VAULT_ROOT

mcp = FastMCP("Analysis-Trigger")

HIERARCHIES_DIR = Path(__file__).parent / "hierarchies"


@mcp.tool()
def analyze_hierarchy(hierarchy: str, vault_root: str = DEFAULT_VAULT_ROOT) -> dict:
    """
    Run the full analysis workflow for one hierarchy path (e.g. "5/101/1/4/1")
    — every per-attack status check (per hierarchy_system's attack
    checklist, no local corpus), followed by secure/messages/audit.log
    analysis as a catch-all, all in one report. Pulls that hierarchy's files
    from the vault, then pushes the finished report back alongside the
    source files; run_full_workflow handles both internally.
    """
    result = run_full_workflow(hierarchy, vault_root, HIERARCHIES_DIR)

    return {
        "hierarchy": hierarchy,
        "report_path": result.get("report_path"),
        "summary_counts": result.get("summary_counts"),
        "log_analysis": result.get("log_analysis"),
    }


if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=8001)
