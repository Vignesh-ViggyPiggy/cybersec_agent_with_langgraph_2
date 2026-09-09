# Adding a New Attack Type — Cookbook

Companion to [DOCUMENTATION.md](DOCUMENTATION.md) and
[EVIDENCE_ENGINE_DESIGN.md](EVIDENCE_ENGINE_DESIGN.md) (the design this
cookbook reflects, as implemented). Practical reference for adding a
**new** attack type to a vault's checklist.

## The model: everything is config, on the vault machine

Every attack type is entirely described by `.env` variables in
`hierarchy_system/.env` — **no code change on either machine is needed to
add one.** The analysis machine has no local knowledge of which attack
types exist; it fetches the whole checklist fresh from
`get_attack_checklist` once per run.

## Step 1 — add it to `ATTACK_ORDER`

```bash
ATTACK_ORDER=...,existing_type,my_new_attack_type
```

A type left out of this list is never checked at all, regardless of
whether its other `ATTACK_*` variables are still set — so you can disable
a type temporarily by removing it here without deleting its configuration.

## Step 2 — configure its evidence source(s)

`ATTACK_PRIMARY_my_new_attack_type` is required; everything else is
optional. Each source is `"<path>[#tag]"`:

| Shape | Spec | Example |
|---|---|---|
| Single XML tag | `path#tag` | `Alert.xml#my_flag` |
| Whole file as text | `path` (no `#`) | `athinio/system/secOpsOutput_99` |
| Multiple files, one combined reading | `pathA;pathB` | `rationalVault/log/rationalclient.log;var/log/osstatus.log` |
| Multiple co-equal sources | comma-separated | `Alert.xml#tag_a,Alert.xml#tag_b` |

**Co-equal sources** (comma-separated): *any one* reading `detected` makes
the whole attack type `detected`. This is how a multi-tag attack type is
expressed — see `ransomware`'s real config:
```bash
ATTACK_PRIMARY_ransomware=Alert.xml#Ransom,Alert.xml#bin,Alert.xml#lib,Alert.xml#honeypot,Alert.xml#Process
```
five co-equal primary sources, not one primary plus four special-cased
checks.

**Combined multi-file readings** (`;`-joined, inside one source entry):
use this when two files only make sense interpreted together — e.g. a
detection line teed to two different logs simultaneously, or a log whose
meaning depends on context from a sibling file. The combined content gets
a `--- path ---` header per file before being judged as one reading.

**Every plain-text path is glob-matched as a prefix** (`path*`) — this
transparently handles rotating logs (`gateway.log` on the real vault is
always `gateway.log_NNN`, never the bare name) without a separate
"rotates" flag.

## Step 3 — add optional metadata

```bash
ATTACK_VERIFY_my_new_attack_type=...       # same shape as PRIMARY; only
                                            # reached once every primary
                                            # source reads clean
ATTACK_WRITER_my_new_attack_type="..."     # human-readable provenance
                                            # chain, shown in the report's
                                            # "Source chain" — confirm this
                                            # against the REAL writer
                                            # script's source before
                                            # writing it, not just a guess
                                            # from the tag name
ATTACK_UI_FEATURE_my_new_attack_type="..." # dashboard feature name --
                                            # parsed and stored, but not
                                            # currently rendered anywhere
                                            # in the report (it was only
                                            # used by a "re-run this from
                                            # the dashboard" recommendation
                                            # that no longer exists); safe
                                            # to leave unset
ATTACK_RELIABLE_my_new_attack_type=false   # marks the data source itself
                                            # as known-unreliable -- the
                                            # workflow reports "cannot
                                            # determine" instead of
                                            # reading it at all, regardless
                                            # of its current value
ATTACK_CAVEAT_my_new_attack_type="..."     # free-text note, rendered under
                                            # "NOT CONFIGURED" when
                                            # ATTACK_RELIABLE_<type>=false
                                            # (and kept as documentation
                                            # generally otherwise)
```

`ATTACK_RELIABLE_<type>=false` is for a source you've confirmed is
structurally untrustworthy — e.g. a file that's never truncated between
runs, so a "Tampered" reading could be stale from weeks ago rather than
from this run. Don't reach for it just because a source has no
`ATTACK_VERIFY_<type>` configured — an unverified primary source is
already treated as exactly as final as a verified one (there's no
separate "unverifiable" status); `ATTACK_RELIABLE_<type>=false` is only
for a source you've actually confirmed can't be trusted at all.

## Step 4 — decide whether the model needs new training examples

This is the one step that isn't a pure config edit, and it's genuinely
optional most of the time.

**Usually nothing is needed.** `cybersecqwen` generalizes the basic
"tag reads 1 → detected, tag reads 0 → clean" pattern extremely well to
attack types and tag names it has never seen — confirmed via an
exhaustive sweep of every configured tag at both values across the whole
`.env` (130 cases, 99.2% pass, including many attack types whose writer
is "unknown -- no detection writer confirmed" and were never in any
training set). If your new source is a straightforward single-tag or
multi-tag ALERT-style reading, just add the `.env` config and test it —
it will very likely already work correctly with zero retraining.

**New training examples are worth adding when:**
- The evidence source is a **free-text log**, not an XML tag — the model
  has much less exposure to arbitrary log-line phrasing than to the
  `<ALERT><Tag>value</Tag></ALERT>` shape, so a genuinely novel log format
  benefits from at least one worked detected/clean example.
- The real detection logic has a **surface-vocabulary trap** — content
  that *sounds* alarming (a kill signal, an error code, an unfamiliar
  process name) but isn't the actual ground truth, or vice versa. Confirm
  the real writer script's exact trigger condition from source before
  writing the example; don't infer it from the tag name.
- The evidence involves **correlation across lines/files** (e.g.
  `user_breach`'s "failed logins from an IP, then a success from the same
  IP" pattern) rather than a single value read in isolation.

If none of those apply, skip this step — don't add training data
speculatively for a pattern the model already handles.

### Adding the training examples

Training examples for new-attack-type coverage and evidence-source gaps
live in `cybersecqwen_finetune/generate_new_attack_examples.py`, separate
from the corpus-derived bulk of the dataset. Two helpers:

- `_row(source, tag, value, detected, explanation)` — for an XML-tag
  reading; wraps content as `<ALERT>\n  <Tag>value</Tag>\n</ALERT>`,
  matching exactly how every real tag reading is sent to the model.
- `_row_text(source, content, detected, explanation)` — for a free-text
  log source; sends `content` as-is, no wrapper.

Add one DETECTED + one CLEAN example (a matched pair) using real or
realistic content, then:

```bash
cd cybersecqwen_finetune
python generate_new_attack_examples.py   # prints a row count, sanity check
python build_combined_dataset.py         # folds into finetune_dataset/train.jsonl + val.jsonl
```

Retrain (`kaggle_finetune_cybersecqwen.ipynb`), then validate — see
**Testing a new or changed source** below.

**If a single example doesn't stick across a retrain**, don't
immediately add a second, differently-labeled example hoping variety
fixes it — first add 2-4 *more variations of the same pattern* (different
process names/PIDs/timestamps, same ground truth) to actually shift the
weight of evidence, since a lone counter-example can get outweighed by
the base model's own prior. If it *still* doesn't stick after that, and
the real writer script's own logic turns out to be a plain literal-string
grep (not a judgment call at all), that's the signal to use the
deterministic exception instead of continuing to retrain — see
**When the "judgment" isn't actually a judgment** below.

## When the "judgment" isn't actually a judgment

Before writing training examples for a source that seems to consistently
resist the model's judgment, check what the *real* writer script actually
does. Some detection scripts are themselves just a `grep` for one fixed
literal phrase — there's no ambiguity to model, and no amount of training
data reliably teaches a semantic classifier to behave like an exact-match
lookup when the input's surface vocabulary is misleading (confirmed: one
real case needed 5 retrains and 7 training rows before this became the
right call instead of "one more example").

If you've confirmed this from the real writer script's source, add the
pair to `analysis.py`'s `LITERAL_PHRASE_SOURCES` registry instead:

```python
LITERAL_PHRASE_SOURCES: dict[tuple[str, str], str] = {
    ("gateway_unauthorized_breakin", "home/athinio/data/1cloudFiler/log/gateway.log"): "Possible Break-in Attempt",
    ("my_new_attack_type", "path/to/the.log"): "The Exact Literal Phrase",
}
```

`_evaluate_source` checks this before ever calling the model — an exact
substring match, resolved in effectively zero time, no LLM call, no
training data needed. Scope it to exactly the `(attack_type, file)` pair
you've confirmed; don't reach for it as a shortcut for a source you
haven't actually verified is a plain grep in the real script.

## Testing a new or changed source

Two levels, cheapest first:

**1. Direct evidence-source test** — no vault, no MCP, just the real
resolution path with synthetic files:
```python
import analysis
from pathlib import Path
import tempfile

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    (root / "Alert.xml").write_text("<ROOT>\n  <my_flag>1</my_flag>\n</ROOT>", encoding="utf-8")
    result = analysis._evaluate_source(root, "my_new_attack_type", "Alert.xml#my_flag", "primary")
    print(result["verdict"], result["meaning"])
```
This calls `_evaluate_source` — the same function the real pipeline uses
— so it exercises the `LITERAL_PHRASE_SOURCES` shortcut too, if
applicable, unlike calling `_judge_content_with_model` directly.

**2. Full-checklist regression sweep** — before treating any model
change as validated, re-run the same sweep this project uses after every
retrain: every tag in every configured attack type, at both DETECTED(1)
and CLEAN(0), through `_evaluate_source`. A single new/changed source
passing in isolation doesn't rule out a regression elsewhere — this
sweep is what actually caught (and reconfirmed) the `gateway.log` trap
case across five separate retrains, and is the fastest way to get a
complete accuracy picture rather than spot-checking one case at a time.

## Real example — a genuinely new type, no training needed

```bash
ATTACK_ORDER=...,disk_encryption_disabled
ATTACK_PRIMARY_disk_encryption_disabled=Alert.xml#disk_encryption_status
ATTACK_WRITER_disk_encryption_disabled="unknown -- new tag, no detection writer confirmed"
ATTACK_CAVEAT_disk_encryption_disabled="New, low-confidence attack type. Semantics inferred from the tag name only."
```

That's the whole addition. No `ATTACK_VERIFY_`, no training data — this
is exactly the shape (`Alert.xml#<tag>`, simple binary flag) the model
already generalizes correctly, confirmed by the exhaustive sweep covering
this exact pattern across dozens of other attack types. Test it with the
direct evidence-source snippet above before considering it done; only
reach for the training-data or literal-phrase paths if that test surfaces
a real problem.
