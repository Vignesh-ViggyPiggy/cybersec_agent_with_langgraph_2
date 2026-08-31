# Adding a New Attack Type — Cookbook by Evidence Shape

Companion to [DOCUMENTATION.md](DOCUMENTATION.md) §5 and
[EVIDENCE_ENGINE_DESIGN.md](EVIDENCE_ENGINE_DESIGN.md) (the design this
cookbook now reflects, as implemented). Practical reference for adding a
**new** attack type, organized by what evidence you actually have for it.

## The model: two tiers, both just evidence_sources

Every attack type is one ordered `evidence_sources` list, split into two
tiers:

- **`tier: "primary"`** — the live status read(s). All primary sources are
  co-equal: if you have several (e.g. a multi-tag attack type), *any one*
  reading `detected` makes the whole attack type `detected`. This is how
  a case like "Alert.xml tag A, tag B, tag C, any one counts" is expressed
  — three primary sources, not one primary plus special-cased siblings.
- **`tier: "verification"`** — only reached once every primary source
  reads clean. The first verification source to read `detected` makes the
  result a `discrepancy` (tag said clean, evidence disagreed). If none are
  configured, a clean primary result is `not_detected_unverifiable`
  (unverified, not suspicious). If every configured verification source
  reads clean, `not_detected` (verified).

Each source resolves the same way regardless of what kind of file it
reads — an XML tag, a text/log pattern scan, a rotating log file:

1. Try each of its `known_patterns` in order (free, deterministic, tried
   first). Four matcher kinds:
   - `{"value": "1", "detected": true}` — exact string equality (tag reads)
   - `{"min_value": 1, "detected": true}` — `int(value) >= N` (count-style checks)
   - `{"non_empty": true, "detected": true}` — file has any content at all
   - `{"pattern": "...", "detected": true}` — regex search, **supports named
     groups + backreferences** — this is what replaces a bespoke Python
     matcher for a correlated check (e.g. "the same IP in a Failed line,
     then an Accepted line" — see the log-only examples below)
2. If nothing matched and the source has `default_verdict` set, use that
   (this is what makes "no pattern found" resolve to a definite clean
   result instead of hanging as unresolved — also applies when the file
   is missing entirely, e.g. a verification file that was simply never
   configured to sync).
3. If nothing matched and `judgment_allowed: true`, fall back to an LLM
   judgment call grounded by the source's `examples`.
4. Otherwise, `inconclusive`.

**Multi-file sources**: `"file"` can be a list — every listed path (each
glob-expanded if `"rotates": true`) is read and combined into ONE blob
before pattern-matching or judging, not judged file-by-file. This matters
for two real cases: a correlation pattern that needs to see two files
together (`user_breach`'s sshd signal spans `var/log/secure` and
`rationalclient.log`), and a multi-file LLM judgment where one file alone
is ambiguous but combined with its sibling is clear (e.g. a detail file
that's legitimately empty when clean, read alongside a summary file).

**Zero Python changes for any of the 12 shapes below** — including the
ones that previously needed a `RAW_LOG_CHECKERS` function. That was the
entire point of this redesign; see EVIDENCE_ENGINE_DESIGN.md §1 for why.

## Reference table

| # | Sources given | Primary tier | Verification tier |
|---|---|---|---|
| 1 | Alert.xml tag + XML status + log pattern | 1 `xml_tag` source | 1 `text` source (log, `rotates: true`) — the XML status becomes a *separate, non-verifying* corroborating-display-only source is unnecessary here; fold it into the same verification source's `file` list if you want it shown alongside the log, or add it as its own verification-tier `judgment_allowed` source |
| 2 | Alert.xml tag + XML output pattern + log pattern | 1 `xml_tag` source | 1 `text` source (log, `rotates: true`) |
| 3 | Alert.xml tag + log pattern only | 1 `xml_tag` source | 1 `text` source (log, `rotates: true`) |
| 4 | No Alert.xml; XML status + log pattern | 1 `xml_tag` source (on the XML file directly) | 1 `text` source (log, `rotates: true`) |
| 5 | No Alert.xml; XML output pattern + log pattern | 1 `text` source (`known_patterns` regex) | 1 `text` source (log, `rotates: true`) |
| 6 | Only log pattern | 1 `text` source (the log itself, `rotates: true`) | *(none — this one source is the whole chain)* |
| 7 | Alert.xml status + XML status, no log | 1 `xml_tag` source | 1 `judgment_allowed` `text` source |
| 8 | Alert.xml status + XML output pattern, no log | 1 `xml_tag` source | 1 `judgment_allowed` `text` source |
| 9 | Only Alert.xml status | 1 `xml_tag` source | *(none)* |
| 10 | Only XML status | 1 `xml_tag` source | *(none)* |
| 11 | Only XML output pattern | 1 `text` source (`known_patterns` regex) | *(none)* |
| 12 | Only log pattern, no other evidence | 1 `text` source (the log itself, `rotates: true`) | *(none — same shape as #6)* |

Row 1/2/3 all reduce to the same real shape once you stop distinguishing
"tag" from "pattern" at the verification tier — see the note in §7.1 of
the old cookbook version: the distinction only ever mattered for a
*primary* read, never for secondary/verification evidence, which just
gets read as text either way.

## The 12 examples, in full

Each block is a complete, ready-to-adapt
`corpus_documents/attack_example_N.json`. Replace `explanation`,
`writer_script`, tag/pattern names, and `meaning` text with your real
ones — the field *shapes* are what matters here.

### Example 1 — Alert.xml tag + XML status + log pattern

```json
{
  "id": "attack_example_1",
  "explanation": "Placeholder description of what example attack 1 means when detected.",
  "metadata": {
    "attack_type": "example_1",
    "writer_script": "unknown -- example entry",
    "confidence": "example",
    "evidence_sources": [
      {
        "tier": "primary",
        "file": "Alert.xml",
        "read_as": "xml_tag",
        "tag": "example_attack_1",
        "known_patterns": [{"value": "1", "detected": true, "meaning": "Detected."}],
        "default_verdict": "not_detected",
        "default_meaning": "Clean."
      },
      {
        "tier": "verification",
        "file": ["athinio/system/example_1_output.xml", "var/log/osstatus.log"],
        "read_as": "text",
        "rotates": true,
        "known_patterns": [
          {"pattern": "YourLogPattern", "detected": true, "meaning": "Matching pattern found in the combined evidence."}
        ],
        "default_verdict": "not_detected",
        "default_meaning": "No matching pattern found."
      }
    ]
  }
}
```

### Example 2 — Alert.xml tag + XML output pattern + log pattern

Same shape as Example 1 — the "XML output pattern" vs. "XML status" wording
doesn't change anything at the verification tier, since both just become
raw text handed to the same `known_patterns`/regex check:

```json
{
  "id": "attack_example_2",
  "explanation": "Placeholder description of what example attack 2 means when detected.",
  "metadata": {
    "attack_type": "example_2",
    "writer_script": "unknown -- example entry",
    "confidence": "example",
    "evidence_sources": [
      {
        "tier": "primary",
        "file": "Alert.xml",
        "read_as": "xml_tag",
        "tag": "example_attack_2",
        "known_patterns": [{"value": "1", "detected": true, "meaning": "Detected."}],
        "default_verdict": "not_detected",
        "default_meaning": "Clean."
      },
      {
        "tier": "verification",
        "file": ["athinio/system/example_2_output.xml", "var/log/osstatus.log"],
        "read_as": "text",
        "rotates": true,
        "known_patterns": [
          {"pattern": "YourLogPattern", "detected": true, "meaning": "Matching pattern found in the combined evidence."}
        ],
        "default_verdict": "not_detected",
        "default_meaning": "No matching pattern found."
      }
    ]
  }
}
```

### Example 3 — Alert.xml tag + log pattern only

```json
{
  "id": "attack_example_3",
  "explanation": "Placeholder description of what example attack 3 means when detected.",
  "metadata": {
    "attack_type": "example_3",
    "writer_script": "unknown -- example entry",
    "confidence": "example",
    "evidence_sources": [
      {
        "tier": "primary",
        "file": "Alert.xml",
        "read_as": "xml_tag",
        "tag": "example_attack_3",
        "known_patterns": [{"value": "1", "detected": true, "meaning": "Detected."}],
        "default_verdict": "not_detected",
        "default_meaning": "Clean."
      },
      {
        "tier": "verification",
        "file": "var/log/osstatus.log",
        "read_as": "text",
        "rotates": true,
        "known_patterns": [
          {"pattern": "YourLogPattern", "detected": true, "meaning": "Matching pattern found in osstatus.log."}
        ],
        "default_verdict": "not_detected",
        "default_meaning": "No matching pattern found in the available logs."
      }
    ]
  }
}
```

This is the real shape `user_breach` and `gateway_unauthorized_breakin`
use — see their real `corpus_documents/attack_user_breach.json` /
`attack_gateway_unauthorized_breakin.json` entries for a genuine
correlation pattern (a backreference matching the same IP across two log
lines) and a plain phrase match, respectively.

### Example 4 — No Alert.xml; XML status (primary) + log pattern

```json
{
  "id": "attack_example_4",
  "explanation": "Placeholder description of what example attack 4 means when detected.",
  "metadata": {
    "attack_type": "example_4",
    "writer_script": "unknown -- example entry",
    "confidence": "example",
    "evidence_sources": [
      {
        "tier": "primary",
        "file": "athinio/system/example_4_output.xml",
        "read_as": "xml_tag",
        "tag": "ExampleStatus",
        "known_patterns": [{"value": "1", "detected": true, "meaning": "Detected."}],
        "default_verdict": "not_detected",
        "default_meaning": "Clean."
      },
      {
        "tier": "verification",
        "file": "var/log/osstatus.log",
        "read_as": "text",
        "rotates": true,
        "known_patterns": [
          {"pattern": "YourLogPattern", "detected": true, "meaning": "Matching pattern found in osstatus.log."}
        ],
        "default_verdict": "not_detected",
        "default_meaning": "No matching pattern found in the available logs."
      }
    ]
  }
}
```

### Example 5 — No Alert.xml; XML output pattern (primary) + log pattern

```json
{
  "id": "attack_example_5",
  "explanation": "Placeholder description of what example attack 5 means when detected.",
  "metadata": {
    "attack_type": "example_5",
    "writer_script": "unknown -- example entry",
    "confidence": "example",
    "evidence_sources": [
      {
        "tier": "primary",
        "file": "athinio/system/example_5_output.xml",
        "read_as": "text",
        "known_patterns": [{"pattern": "YourPattern", "detected": true, "meaning": "Detected."}],
        "default_verdict": "not_detected",
        "default_meaning": "Clean, pending log verification."
      },
      {
        "tier": "verification",
        "file": "var/log/osstatus.log",
        "read_as": "text",
        "rotates": true,
        "known_patterns": [
          {"pattern": "YourLogPattern", "detected": true, "meaning": "Matching pattern found in osstatus.log."}
        ],
        "default_verdict": "not_detected",
        "default_meaning": "No matching pattern found in the available logs."
      }
    ]
  }
}
```

The primary source here is itself a pattern scan — the verification tier
only ever runs when that scan already came back clean, as independent
confirmation.

### Example 6 — Only log pattern (log itself is the primary file)

```json
{
  "id": "attack_example_6",
  "explanation": "Placeholder description of what example attack 6 means when detected.",
  "metadata": {
    "attack_type": "example_6",
    "writer_script": "unknown -- example entry",
    "confidence": "example",
    "evidence_sources": [
      {
        "tier": "primary",
        "file": "var/log/osstatus.log",
        "read_as": "text",
        "rotates": true,
        "known_patterns": [{"pattern": "YourPattern", "detected": true, "meaning": "Detected."}],
        "default_verdict": "not_detected",
        "default_meaning": "Clean."
      }
    ]
  }
}
```

Unlike the old design, there's no rotation caveat to worry about here —
`rotates: true` glob-matches the file regardless of whether it's a single
flat file or rotates on the real system, so this shape is safe by default.

### Example 7 — Alert.xml status + XML status, no log

```json
{
  "id": "attack_example_7",
  "explanation": "Placeholder description of what example attack 7 means when detected.",
  "metadata": {
    "attack_type": "example_7",
    "writer_script": "unknown -- example entry",
    "confidence": "example",
    "evidence_sources": [
      {
        "tier": "primary",
        "file": "Alert.xml",
        "read_as": "xml_tag",
        "tag": "example_attack_7",
        "known_patterns": [{"value": "1", "detected": true, "meaning": "Detected."}],
        "default_verdict": "not_detected",
        "default_meaning": "Clean."
      },
      {
        "tier": "verification",
        "file": "athinio/system/example_7_output.xml",
        "read_as": "text",
        "known_patterns": [],
        "judgment_allowed": true,
        "default_verdict": "not_detected",
        "default_meaning": "Evidence file not found; falling back to the tag's own clean status.",
        "examples": [
          {"label": "clean", "content": "...", "note": "..."},
          {"label": "detected", "content": "...", "note": "..."}
        ]
      }
    ]
  }
}
```

### Example 8 — Alert.xml status + XML output pattern, no log

Same shape as Example 7 — again, the distinction between "status" and
"output pattern" only matters for a primary read, not a verification one:

```json
{
  "id": "attack_example_8",
  "explanation": "Placeholder description of what example attack 8 means when detected.",
  "metadata": {
    "attack_type": "example_8",
    "writer_script": "unknown -- example entry",
    "confidence": "example",
    "evidence_sources": [
      {
        "tier": "primary",
        "file": "Alert.xml",
        "read_as": "xml_tag",
        "tag": "example_attack_8",
        "known_patterns": [{"value": "1", "detected": true, "meaning": "Detected."}],
        "default_verdict": "not_detected",
        "default_meaning": "Clean."
      },
      {
        "tier": "verification",
        "file": "athinio/system/example_8_output.xml",
        "read_as": "text",
        "known_patterns": [],
        "judgment_allowed": true,
        "default_verdict": "not_detected",
        "default_meaning": "Evidence file not found; falling back to the tag's own clean status.",
        "examples": []
      }
    ]
  }
}
```

### Example 9 — Only Alert.xml status

```json
{
  "id": "attack_example_9",
  "explanation": "Placeholder description of what example attack 9 means when detected.",
  "metadata": {
    "attack_type": "example_9",
    "writer_script": "unknown -- example entry",
    "confidence": "example",
    "evidence_sources": [
      {
        "tier": "primary",
        "file": "Alert.xml",
        "read_as": "xml_tag",
        "tag": "example_attack_9",
        "known_patterns": [{"value": "1", "detected": true, "meaning": "Detected."}],
        "default_verdict": "not_detected",
        "default_meaning": "Clean."
      }
    ]
  }
}
```

The simplest possible shape — one source, no verification tier at all.

### Example 10 — Only XML status

```json
{
  "id": "attack_example_10",
  "explanation": "Placeholder description of what example attack 10 means when detected.",
  "metadata": {
    "attack_type": "example_10",
    "writer_script": "unknown -- example entry",
    "confidence": "example",
    "evidence_sources": [
      {
        "tier": "primary",
        "file": "athinio/system/example_10_output.xml",
        "read_as": "xml_tag",
        "tag": "ExampleStatus",
        "known_patterns": [{"value": "1", "detected": true, "meaning": "Detected."}],
        "default_verdict": "not_detected",
        "default_meaning": "Clean."
      }
    ]
  }
}
```

### Example 11 — Only XML output pattern

```json
{
  "id": "attack_example_11",
  "explanation": "Placeholder description of what example attack 11 means when detected.",
  "metadata": {
    "attack_type": "example_11",
    "writer_script": "unknown -- example entry",
    "confidence": "example",
    "evidence_sources": [
      {
        "tier": "primary",
        "file": "athinio/system/example_11_output.xml",
        "read_as": "text",
        "known_patterns": [{"pattern": "YourPattern", "detected": true, "meaning": "Detected."}],
        "default_verdict": "not_detected",
        "default_meaning": "Clean."
      }
    ]
  }
}
```

### Example 12 — Only log pattern, no other evidence

Identical shape to Example 6, listed separately only to match the
requested coverage:

```json
{
  "id": "attack_example_12",
  "explanation": "Placeholder description of what example attack 12 means when detected.",
  "metadata": {
    "attack_type": "example_12",
    "writer_script": "unknown -- example entry",
    "confidence": "example",
    "evidence_sources": [
      {
        "tier": "primary",
        "file": "var/log/osstatus.log",
        "read_as": "text",
        "rotates": true,
        "known_patterns": [{"pattern": "YourPattern", "detected": true, "meaning": "Detected."}],
        "default_verdict": "not_detected",
        "default_meaning": "Clean."
      }
    ]
  }
}
```

## Other value_schema equivalents

Two matcher kinds not shown above, for completeness:

- **A count-style tag** (any nonzero value is a finding): use `xml_tag` with
  `known_patterns: [{"min_value": 1, "detected": true, "meaning": "..."}]`
  instead of `{"value": "1", ...}`.
- **A file checked for presence, not a specific value** (e.g. a ban-list
  file that's either empty or has content): use `read_as: "text"` with
  `known_patterns: [{"non_empty": true, "detected": true, "meaning": "..."}]`.

## After writing any of these

```bash
python ingest_corpus.py   # corpus_server.py must already be running
```

The new attack type is live from the next run onward — picked up
automatically by `get_known_attack_types()`, checked through the exact
same generic engine as every other one, with no further wiring at all.
