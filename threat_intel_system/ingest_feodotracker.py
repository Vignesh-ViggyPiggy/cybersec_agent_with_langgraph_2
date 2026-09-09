"""
ingest_feodotracker.py — pulls the real Feodo Tracker botnet C2 IP
blocklist (feodotracker.abuse.ch, CC0-licensed, no auth required) into
observables -- Tier 1, the atomic-IOC exact-match layer.

Not a STIX feed -- abuse.ch's own JSON schema -- so this is a real
example of the cross-feed normalization discussed earlier: mapping a
non-STIX source's fields onto the same internal (ioc_type, ioc_value)
shape the STIX-derived observables use, so lookup_observables doesn't
need to know or care which feed an IOC came from.

Usage:
    python ingest_feodotracker.py
"""
import json
import os
import urllib.request
from datetime import datetime, timezone

from dotenv import load_dotenv

load_dotenv()

import db

FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
SOURCE_NAME = "feodotracker"
DB_PATH = os.getenv("DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "threat_intel.db"))


def main() -> None:
    print(f"Fetching {FEED_URL} ...")
    req = urllib.request.Request(FEED_URL, headers={"User-Agent": "threat_intel_system/ingest"})
    with urllib.request.urlopen(req) as resp:
        entries = json.loads(resp.read().decode("utf-8"))
    print(f"{len(entries)} botnet C2 IP entries to ingest.")

    conn = db.get_connection(DB_PATH)
    for entry in entries:
        ip = entry["ip_address"]
        # No natural STIX indicator id on this feed -- synthesize a stable
        # one from (ip, port) so re-ingesting the same entry updates it in
        # place instead of accumulating duplicate rows (SQLite's UNIQUE
        # constraint never treats two NULLs as equal, so leaving
        # indicator_id unset here would silently break dedup on re-run).
        indicator_id = f"feodotracker:{ip}:{entry.get('port')}"

        db.upsert_stix_object(
            conn, indicator_id, "observed-data", SOURCE_NAME, entry.get("last_online"), entry,
        )
        db.upsert_observable(
            conn,
            indicator_id=indicator_id,
            ioc_type="ipv4-addr",
            ioc_value=ip,
            valid_from=entry.get("first_seen"),
            # "online" means still confirmed active -- no expiry yet;
            # "offline" means last confirmed active on last_online.
            valid_until=None if entry.get("status") == "online" else entry.get("last_online"),
            source=f"{SOURCE_NAME}:{entry.get('malware', 'unknown')}",
        )

    db.set_sync_state(conn, SOURCE_NAME, datetime.now(timezone.utc).isoformat())
    print(f"\nDone. {db.stats(conn)}")
    conn.close()


if __name__ == "__main__":
    main()
