# ingest_corpus.py — loads every file in corpus_documents/ into the running
# corpus_server.py via corpus_client.py.
#
# corpus_documents/*.json is the human-editable source (add a new attack/file
# explanation by dropping a new JSON file here, no code change); the vector
# store built by corpus_server.py is the runtime index built FROM it — same
# "author in a simple format, ingest into the store" split already used for
# attack_taxonomy.json -> attack_status_data.py, just with a real embedding
# step in between here since these entries need to be semantically
# searchable, not just exact-key looked up.
#
# Requires corpus_server.py already running (python corpus_server.py).
from pathlib import Path
import json

from lib.corpus_client import add_corpus_entry

DOCS_DIR = Path(__file__).parent / "corpus_documents"


def main():
    json_files = sorted(DOCS_DIR.glob("*.json"))
    if not json_files:
        print(f"No .json files found in {DOCS_DIR}")
        return

    for json_file in json_files:
        with open(json_file, "r", encoding="utf-8") as f:
            doc = json.load(f)

        if "id" not in doc or "explanation" not in doc:
            print(f"SKIPPED {json_file.name}: missing required 'id' or 'explanation' field")
            continue

        # Only `explanation` gets embedded for semantic search — the raw
        # content example lives in metadata (see raw_content_example),
        # stored and retrievable but not itself embedded, since embedding
        # raw XML/text doesn't help similarity search the way a natural-
        # language description does.
        result = add_corpus_entry(doc["id"], doc["explanation"], doc.get("metadata", {}))
        print(f"{json_file.name} -> {result}")


if __name__ == "__main__":
    main()
