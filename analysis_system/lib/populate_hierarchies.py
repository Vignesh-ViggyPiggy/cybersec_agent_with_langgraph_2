"""
Manually-run script that pulls customer files from a rationalVault path on the
MCP server and lays them out under hierarchies/ in this project, mirroring
the server-side {company_id}/{customer_id}/{branch_id}/{product_id}/{system_id}
structure so attack_status_workflow.py can pick them up on its next run.

Pass --hierarchy to scope both the server-side fetch and the local write to a
single customer's tree, so only that hierarchy's files are sent for analysis
instead of the whole vault.

Usage:
    python populate_hierarchies.py rationalVault/data
    python populate_hierarchies.py rationalVault/data --hierarchy 2/1/1/1/1
    python populate_hierarchies.py rationalVault/data --hierarchy 2/1/1/1/1 --dest hierarchies
"""

import argparse
from pathlib import Path

from lib.mcp_client import fetch_directory_files, decode_file_content


def populate_hierarchies(root_path: str, dest_dir: Path, hierarchy: str | None = None) -> None:
    prefix = Path()
    server_path = root_path

    if hierarchy:
        hierarchy_clean = hierarchy.strip("/\\").replace("\\", "/")
        server_path = f"{root_path.rstrip('/')}/{hierarchy_clean}"
        prefix = Path(hierarchy_clean)

    print(f"Fetching files from server path: {server_path}")
    entries = fetch_directory_files(server_path)

    if not entries:
        print("No files returned. Check that the path exists on the server.")
        return

    print(f"Received {len(entries)} file(s) from server.")

    copied = 0
    skipped = 0

    for entry in entries:
        relative_path = entry.get("relative_path")
        if not relative_path:
            continue

        # Re-prepend the hierarchy prefix the server dropped, since it only
        # saw paths relative to the narrower folder we asked it to walk.
        local_relative_path = prefix / relative_path
        target = dest_dir / local_relative_path
        new_bytes = decode_file_content(entry)

        if target.exists() and target.is_file() and target.read_bytes() == new_bytes:
            skipped += 1
            continue

        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(new_bytes)
        copied += 1
        print(f"  + {local_relative_path.as_posix()}")

    print("\nDone.")
    print(f"Copied:  {copied}")
    print(f"Skipped (unchanged): {skipped}")
    print(f"Destination: {dest_dir}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Pull customer files from a server-side rationalVault path into hierarchies/ via MCP."
    )
    parser.add_argument(
        "root_path",
        help="Vault root path on the MCP server (e.g. rationalVault/data).",
    )
    parser.add_argument(
        "--hierarchy",
        default=None,
        help=(
            "Specific hierarchy subpath under root_path to pull, e.g. 2/1/1/1/1 "
            "(company_id/customer_id/branch_id/product_id/system_id). "
            "Only that customer's files are fetched and written locally; "
            "omit to pull everything under root_path."
        ),
    )
    parser.add_argument(
        "--dest",
        default=str(Path(__file__).parent / "hierarchies"),
        help="Local destination directory (defaults to ./hierarchies next to this script).",
    )
    args = parser.parse_args()

    populate_hierarchies(args.root_path, Path(args.dest), args.hierarchy)


if __name__ == "__main__":
    main()
