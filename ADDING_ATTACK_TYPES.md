# Adding a New Attack Type — Cookbook by Evidence Shape

Companion to [DOCUMENTATION.md](DOCUMENTATION.md) §5, which explains how
the attack-status graph works; this file is a practical reference for
adding a **new** attack type, organized by what evidence you actually
have for it.

## The one constraint that shapes everything below

The graph supports exactly **one primary read** (`status_file` +
`status_tag`/`status_tags`, read by `read_live_status_node`) and **at most
one verification path** per attack type — either `readable_report`/
`diffable_snapshot_files` (an LLM checks `raw_evidence_files` against the
"not detected" claim), or `check_raw_logs` (a deterministic regex/phrase
match against a log), never both as independent checks. `route_from_status_check`
routes to exactly one.

If your real attack has more candidate evidence sources than that, pick
the strongest one as the actual verification path; any others become
**corroborating-only** display via `raw_evidence_files` — shown in the
report whenever the graph actually reaches `not_detected_clean_node` or
`attack_info_node` (i.e. `detected`, or `not_detected` verified clean
through `readable_report`/`check_raw_logs`), but never for
`opaque_binary_only`/`requires_live_recompute` types, which skip straight
to `unverifiable_path_node` and never read `raw_evidence_files` at all.

**"A status" vs. "a particular output pattern" only changes anything when
that file is the *primary* read.** A tag needs `value_schema.type:
"binary_flag"` (or `"count_greater_than_zero"`); a free-text scan needs
`"file_contains_pattern"` + `detected_regex`. As secondary,
corroborating-only evidence, the distinction doesn't matter —
`raw_evidence_files` just reads the file's raw text either way.

## The one place that ever needs a real code change

`check_raw_logs` verification. Its glob patterns and matcher are
hardcoded in `analysis_system/attack_status_workflow.py` (log files
rotate, so an exact filename would silently break), not data-driven:

```python
# 1. Register the glob pattern(s) for this attack type's log(s)
RAW_LOG_FILE_PATTERNS: dict[str, list[str]] = {
    ...,
    "<attack_type>": ["var/log/osstatus.log*"],   # glob, in case it rotates
}

# 2. Write a deterministic checker -- plain regex/phrase match, no LLM call
def _check_<attack_type>_raw_logs(log_text: str) -> tuple[bool, str]:
    matches = [line for line in log_text.splitlines() if "<your pattern>" in line]
    if matches:
        return True, f"Found {len(matches)} matching line(s), e.g.: {matches[0].strip()}"
    return False, "No matching pattern found in the available logs."

# 3. Register it
RAW_LOG_CHECKERS = {
    ..., "<attack_type>": _check_<attack_type>_raw_logs,
}
```

Everything else in this file is pure `corpus_documents/attack_<type>.json`
data — no code change, just `python ingest_corpus.py` afterward to load
it, and the new attack type is live from the next run.

## Reference table

| # | Sources given | Primary `status_file` | `value_schema` | `verification_category` | `raw_evidence_files` (corroborating) | Code change? |
|---|---|---|---|---|---|---|
| 1 | Alert.xml tag + XML status + log pattern | `Alert.xml` | `binary_flag` | `check_raw_logs` (verified against `osstatus.log`) | `["athinio/system/example_1_output.xml"]` | Yes — log checker |
| 2 | Alert.xml tag + XML output pattern + log pattern | `Alert.xml` | `binary_flag` | `check_raw_logs` (verified against `osstatus.log`) | `["athinio/system/example_2_output.xml"]` | Yes — log checker |
| 3 | Alert.xml tag + log pattern only | `Alert.xml` | `binary_flag` | `check_raw_logs` (verified against `osstatus.log`) | *(none)* | Yes — log checker |
| 4 | No Alert.xml; XML status + log pattern | `athinio/system/example_4_output.xml` | `binary_flag` | `check_raw_logs` (verified against `osstatus.log`) | *(none)* | Yes — log checker |
| 5 | No Alert.xml; XML output pattern + log pattern | `athinio/system/example_5_output.xml` | `file_contains_pattern` | `check_raw_logs` (verified against `osstatus.log`) | *(none)* | Yes — log checker |
| 6 | Only log pattern | `var/log/osstatus.log` (as the primary file itself) | `file_contains_pattern` | `opaque_binary_only` | *(none)* | No — see caveat below |
| 7 | Alert.xml status + XML status, no log | `Alert.xml` | `binary_flag` | `readable_report` | `["athinio/system/example_7_output.xml"]` | No |
| 8 | Alert.xml status + XML output pattern, no log | `Alert.xml` | `binary_flag` | `readable_report` | `["athinio/system/example_8_output.xml"]` | No |
| 9 | Only Alert.xml status | `Alert.xml` | `binary_flag` | `opaque_binary_only` | *(none)* | No |
| 10 | Only XML status | `athinio/system/example_10_output.xml` | `binary_flag` | `opaque_binary_only` | *(none)* | No |
| 11 | Only XML output pattern | `athinio/system/example_11_output.xml` | `file_contains_pattern` | `opaque_binary_only` | *(none)* | No |
| 12 | Only log pattern, no other evidence | *(same shape as #6)* | `file_contains_pattern` | `opaque_binary_only` | *(none)* | No — see caveat below |

**Caveat for rows 6/12 (log-only, no tag anywhere)**: treating
`osstatus.log` as the *primary* `status_file` with `file_contains_pattern`
(the same mechanism `rootkit_malware`/`config_drift` use on their own
output files) only works if `osstatus.log` is a single flat file on the
real system — `read_live_status_node`'s `file_contains_pattern` path reads
one exact filename, no glob, no rotation awareness. If `osstatus.log`
turns out to rotate (like `rationalclient.log`/`gateway.log` were
confirmed to, elsewhere in this corpus), reading it as a fixed exact path
would risk the exact same silent "always not found" bug those two had
before being fixed — **confirm on a real hierarchy first** (look for an
`osstatus.log_NNN`-style suffix). If it does rotate, use `check_raw_logs`
instead: point `status_file` at any file on that hierarchy you know
reliably exists but never itself indicates detection, so
`read_live_status_node` always reports "not triggered" and the graph
falls through to `verify_raw_logs_node`'s glob-based, rotation-safe read.

Also worth noting: rows 1-2 vs. 7-8 look similar but differ in what
actually gets verified. In 1/2, `example_N_output.xml` is *never
independently checked* — only the log pattern is; the XML file is shown
for context only. In 7/8, `example_N_output.xml` *is* what gets checked
(by an LLM, via `readable_report`) — there's no log at all in that shape.
Don't read "`raw_evidence_files` present" as "this file is being
verified" — check `verification_category` for that.

## The 12 examples, in full

Each block below is a complete, ready-to-adapt
`corpus_documents/attack_example_N.json`. Replace `explanation`,
`writer_script`, the tag/pattern names, and `value_meanings` with your
real ones — the field *shapes* (which schema type, which category, which
files) are what matters here.

### Example 1 — Alert.xml tag + XML status + log pattern

```json
{
  "id": "attack_example_1",
  "explanation": "Placeholder description of what example attack 1 means when detected -- replace with the real mechanism once confirmed.",
  "metadata": {
    "attack_type": "example_1",
    "status_file": "Alert.xml",
    "status_tag": "example_attack_1",
    "writer_script": "unknown -- example entry",
    "confidence": "example",
    "verification_category": "check_raw_logs",
    "value_schema": {"type": "binary_flag"},
    "raw_evidence_files": ["athinio/system/example_1_output.xml"],
    "value_meanings": {
      "0": "Clean -- no indicator active.",
      "1": "Detected -- see athinio/system/example_1_output.xml and osstatus.log for detail."
    }
  }
}
```

Code addition: register `"example_1"` in `RAW_LOG_FILE_PATTERNS` and
`RAW_LOG_CHECKERS` per the recipe above, matching your real log pattern.

### Example 2 — Alert.xml tag + XML output pattern + log pattern

```json
{
  "id": "attack_example_2",
  "explanation": "Placeholder description of what example attack 2 means when detected -- replace with the real mechanism once confirmed.",
  "metadata": {
    "attack_type": "example_2",
    "status_file": "Alert.xml",
    "status_tag": "example_attack_2",
    "writer_script": "unknown -- example entry",
    "confidence": "example",
    "verification_category": "check_raw_logs",
    "value_schema": {"type": "binary_flag"},
    "raw_evidence_files": ["athinio/system/example_2_output.xml"],
    "value_meanings": {
      "0": "Clean -- no indicator active.",
      "1": "Detected -- see athinio/system/example_2_output.xml (raw output pattern) and osstatus.log for detail."
    }
  }
}
```

Code addition: register `"example_2"` in `RAW_LOG_FILE_PATTERNS` and
`RAW_LOG_CHECKERS`.

### Example 3 — Alert.xml tag + log pattern only

```json
{
  "id": "attack_example_3",
  "explanation": "Placeholder description of what example attack 3 means when detected -- replace with the real mechanism once confirmed.",
  "metadata": {
    "attack_type": "example_3",
    "status_file": "Alert.xml",
    "status_tag": "example_attack_3",
    "writer_script": "unknown -- example entry",
    "confidence": "example",
    "verification_category": "check_raw_logs",
    "value_schema": {"type": "binary_flag"},
    "value_meanings": {
      "0": "Clean -- no indicator active.",
      "1": "Detected -- see osstatus.log for the matching pattern."
    }
  }
}
```

Code addition: register `"example_3"` in `RAW_LOG_FILE_PATTERNS` and
`RAW_LOG_CHECKERS`. This is the exact same shape as the real
`user_breach`/`gateway_unauthorized_breakin` entries — use those as a
template.

### Example 4 — No Alert.xml; XML status (primary) + log pattern

```json
{
  "id": "attack_example_4",
  "explanation": "Placeholder description of what example attack 4 means when detected -- replace with the real mechanism once confirmed.",
  "metadata": {
    "attack_type": "example_4",
    "status_file": "athinio/system/example_4_output.xml",
    "status_tag": "ExampleStatus",
    "writer_script": "unknown -- example entry",
    "confidence": "example",
    "verification_category": "check_raw_logs",
    "value_schema": {"type": "binary_flag"},
    "value_meanings": {
      "0": "Clean -- no indicator active.",
      "1": "Detected -- confirmed by the matching pattern in osstatus.log."
    }
  }
}
```

Code addition: register `"example_4"` in `RAW_LOG_FILE_PATTERNS` and
`RAW_LOG_CHECKERS`.

### Example 5 — No Alert.xml; XML output pattern (primary) + log pattern

```json
{
  "id": "attack_example_5",
  "explanation": "Placeholder description of what example attack 5 means when detected -- replace with the real mechanism once confirmed.",
  "metadata": {
    "attack_type": "example_5",
    "status_file": "athinio/system/example_5_output.xml",
    "status_tag": "N/A -- text scan for 'YourPattern', not a tag read",
    "writer_script": "unknown -- example entry",
    "confidence": "example",
    "verification_category": "check_raw_logs",
    "value_schema": {"type": "file_contains_pattern", "detected_regex": "YourPattern"},
    "value_meanings": {
      "no 'YourPattern' in the file": "Clean, pending log verification.",
      "'YourPattern' present": "Detected."
    }
  }
}
```

Code addition: register `"example_5"` in `RAW_LOG_FILE_PATTERNS` and
`RAW_LOG_CHECKERS`. Note the primary read here is *itself* a pattern scan
(`file_contains_pattern`) — the log check only ever runs when that scan
already came back clean, as independent confirmation.

### Example 6 — Only log pattern (log itself is the primary file)

```json
{
  "id": "attack_example_6",
  "explanation": "Placeholder description of what example attack 6 means when detected -- replace with the real mechanism once confirmed. Confirm osstatus.log doesn't rotate on the real system before using this shape -- see the caveat above.",
  "metadata": {
    "attack_type": "example_6",
    "status_file": "var/log/osstatus.log",
    "status_tag": "N/A -- text scan for 'YourPattern', not a tag read",
    "writer_script": "unknown -- example entry",
    "confidence": "example",
    "verification_category": "opaque_binary_only",
    "value_schema": {"type": "file_contains_pattern", "detected_regex": "YourPattern"},
    "value_meanings": {
      "no 'YourPattern' in the file": "Clean.",
      "'YourPattern' present": "Detected."
    }
  }
}
```

No code change — same mechanism as `rootkit_malware`/`config_drift`,
just pointed at `osstatus.log` instead of a `secOpsOutput_N` file.

### Example 7 — Alert.xml status + XML status, no log

```json
{
  "id": "attack_example_7",
  "explanation": "Placeholder description of what example attack 7 means when detected -- replace with the real mechanism once confirmed.",
  "metadata": {
    "attack_type": "example_7",
    "status_file": "Alert.xml",
    "status_tag": "example_attack_7",
    "writer_script": "unknown -- example entry",
    "confidence": "example",
    "verification_category": "readable_report",
    "value_schema": {"type": "binary_flag"},
    "raw_evidence_files": ["athinio/system/example_7_output.xml"],
    "value_meanings": {
      "0": "Clean -- no indicator active.",
      "1": "Detected -- see athinio/system/example_7_output.xml for detail."
    }
  }
}
```

No code change — `verify_against_raw_evidence_node` already handles any
`readable_report` type generically.

### Example 8 — Alert.xml status + XML output pattern, no log

```json
{
  "id": "attack_example_8",
  "explanation": "Placeholder description of what example attack 8 means when detected -- replace with the real mechanism once confirmed.",
  "metadata": {
    "attack_type": "example_8",
    "status_file": "Alert.xml",
    "status_tag": "example_attack_8",
    "writer_script": "unknown -- example entry",
    "confidence": "example",
    "verification_category": "readable_report",
    "value_schema": {"type": "binary_flag"},
    "raw_evidence_files": ["athinio/system/example_8_output.xml"],
    "value_meanings": {
      "0": "Clean -- no indicator active.",
      "1": "Detected -- see athinio/system/example_8_output.xml (raw output pattern) for detail."
    }
  }
}
```

No code change.

### Example 9 — Only Alert.xml status

```json
{
  "id": "attack_example_9",
  "explanation": "Placeholder description of what example attack 9 means when detected -- replace with the real mechanism once confirmed.",
  "metadata": {
    "attack_type": "example_9",
    "status_file": "Alert.xml",
    "status_tag": "example_attack_9",
    "writer_script": "unknown -- example entry",
    "confidence": "example",
    "verification_category": "opaque_binary_only",
    "value_schema": {"type": "binary_flag"},
    "value_meanings": {
      "0": "Clean -- no indicator active.",
      "1": "Detected."
    }
  }
}
```

No code change — the simplest possible shape.

### Example 10 — Only XML status

```json
{
  "id": "attack_example_10",
  "explanation": "Placeholder description of what example attack 10 means when detected -- replace with the real mechanism once confirmed.",
  "metadata": {
    "attack_type": "example_10",
    "status_file": "athinio/system/example_10_output.xml",
    "status_tag": "ExampleStatus",
    "writer_script": "unknown -- example entry",
    "confidence": "example",
    "verification_category": "opaque_binary_only",
    "value_schema": {"type": "binary_flag"},
    "value_meanings": {
      "0": "Clean -- no indicator active.",
      "1": "Detected."
    }
  }
}
```

No code change.

### Example 11 — Only XML output pattern

```json
{
  "id": "attack_example_11",
  "explanation": "Placeholder description of what example attack 11 means when detected -- replace with the real mechanism once confirmed.",
  "metadata": {
    "attack_type": "example_11",
    "status_file": "athinio/system/example_11_output.xml",
    "status_tag": "N/A -- text scan for 'YourPattern', not a tag read",
    "writer_script": "unknown -- example entry",
    "confidence": "example",
    "verification_category": "opaque_binary_only",
    "value_schema": {"type": "file_contains_pattern", "detected_regex": "YourPattern"},
    "value_meanings": {
      "no 'YourPattern' in the file": "Clean.",
      "'YourPattern' present": "Detected."
    }
  }
}
```

No code change.

### Example 12 — Only log pattern, no other evidence

```json
{
  "id": "attack_example_12",
  "explanation": "Placeholder description of what example attack 12 means when detected -- replace with the real mechanism once confirmed. Same shape as example 6 -- confirm osstatus.log doesn't rotate before using this.",
  "metadata": {
    "attack_type": "example_12",
    "status_file": "var/log/osstatus.log",
    "status_tag": "N/A -- text scan for 'YourPattern', not a tag read",
    "writer_script": "unknown -- example entry",
    "confidence": "example",
    "verification_category": "opaque_binary_only",
    "value_schema": {"type": "file_contains_pattern", "detected_regex": "YourPattern"},
    "value_meanings": {
      "no 'YourPattern' in the file": "Clean.",
      "'YourPattern' present": "Detected."
    }
  }
}
```

No code change — identical shape to example 6, listed separately only to
match the requested coverage.

## After writing any of these

```bash
python ingest_corpus.py   # corpus_server.py must already be running
```

The new attack type is live from the next run onward — picked up
automatically by `get_known_attack_types()`, checked through the exact
same generic graph as every other one, with no further wiring beyond
whatever `check_raw_logs` code addition its row calls for.
