"""
ingest_mitre_attack.py — pulls the real MITRE ATT&CK Enterprise STIX 2.1
bundle (github.com/mitre-attack/attack-stix-data, fully open, no auth)
and loads its attack-pattern objects into intel_narratives -- the Tier-2
"what does this technique look like" layer for log-analysis retrieval.

Usage:
    python ingest_mitre_attack.py            # full bundle
    python ingest_mitre_attack.py --limit 20 # quick test run
"""
import argparse
import json
import os
import urllib.request
from datetime import datetime, timezone

from dotenv import load_dotenv

load_dotenv()

import db
import embeddings

BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
SOURCE_NAME = "mitre-attack-enterprise"
DB_PATH = os.getenv("DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "threat_intel.db"))


def _mitre_technique_id(stix_obj: dict) -> str | None:
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=None, help="Only ingest the first N attack-pattern objects (for a quick test).")
    args = parser.parse_args()

    print(f"Fetching {BUNDLE_URL} ...")
    with urllib.request.urlopen(BUNDLE_URL) as resp:
        bundle = json.loads(resp.read().decode("utf-8"))

    objects = [o for o in bundle.get("objects", []) if o.get("type") == "attack-pattern" and not o.get("revoked")]
    if args.limit:
        objects = objects[: args.limit]
    print(f"{len(objects)} attack-pattern objects to ingest.")

    conn = db.get_connection(DB_PATH)
    for i, obj in enumerate(objects, 1):
        description = (obj.get("description") or "").strip()
        if not description:
            continue
        technique_id = _mitre_technique_id(obj)
        title = obj.get("name") or technique_id or obj["id"]

        db.upsert_stix_object(conn, obj["id"], obj["type"], SOURCE_NAME, obj.get("modified"), obj)

        embedding = embeddings.embed(f"{title}: {description}")
        db.upsert_narrative(conn, obj["id"], SOURCE_NAME, title, description, technique_id, embedding)

        if i % 25 == 0 or i == len(objects):
            print(f"  [{i}/{len(objects)}] {title}")

    db.set_sync_state(conn, SOURCE_NAME, datetime.now(timezone.utc).isoformat())
    print(f"\nDone. {db.stats(conn)}")
    conn.close()


if __name__ == "__main__":
    main()
