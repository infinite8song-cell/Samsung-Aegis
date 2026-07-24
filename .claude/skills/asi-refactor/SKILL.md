---
name: asi-refactor
description: >-
  Refactor a codebase by applying an ASI dead-code report — comment out the
  functions the report proved are never executed by the test-vector corpus, then
  clean up the live code — WITHOUT calling any LLM API to do it (you, the agent,
  do the editing directly with your own tools). Use this whenever the user has an
  ASI report (report.json / report.md from `asi run`) and wants to act on it:
  "apply the ASI report", "refactor based on the dead-code report", "comment out
  the dead code the report found", "reflect the report and refactor", "remove the
  unused functions from the report", or asks to run `asi refactor` without the
  Claude API / without an API key. Also trigger when someone points at a
  report.json full of dead functions and asks you to do something about it. Prefer
  this over the API-backed `asi refactor` (no `--comment-only`) whenever the user
  wants the refactoring driven by you rather than by a programmatic API call.
---

# ASI Refactor (report-driven, agent-executed)

You have an ASI dead-code report and you're going to act on it. ASI already did
the hard, exact part — it *ran the test vectors and measured which functions
never executed*. Your job is to **apply that ground truth**: disable the dead
functions and tidy the surviving code, then prove you didn't break anything by
re-running the same harness.

The important design choice this skill makes: **the intelligence comes from you,
not from an API call.** ASI's `refactor` command has an LLM mode that calls the
Anthropic API — you are the replacement for that. You read the report and edit
files with Read/Edit/Write. The only ASI command you run is the deterministic,
API-free `--comment-only` step, which does the exact, line-accurate commenting so
you never have to eyeball line numbers.

## Inputs

- **`report.json`** (required) — produced by `asi run`. Ground truth for what is
  dead. If you only have `report.md`, that's fine for reading, but the JSON is
  easier to parse and drives the tooling.
- **The ASI config** (`asi.json`) used to produce the report — needed for the
  `--comment-only` step and for re-verification.
- The **project root** (the code being refactored).

If no report exists yet, generate one first: `python3 -m asi run -c asi.json`.
Do not refactor from a stale report — if the code changed since the report was
written, re-run `asi run` so the line numbers match.

## The report format (what you're reading)

```json
{
  "summary": { "functions_dead": 3, "functions_live": 3, "vectors_ok": 3, "vectors_failed": 0 },
  "dead": [ { "file": "calc.c", "name": "mul", "start_line": 14, "end_line": 14, "hits": 0 } ],
  "live": [ { "file": "calc.c", "name": "main", "hits": 3 } ]
}
```

- `dead[]` — functions with `hits == 0`: never executed by any vector. These are
  what you comment out.
- `live[]` — sorted by `hits` (hottest first): the functions that *do* run.
  The top entries are your optimisation targets if the user also wants tidying.
- **`summary.vectors_failed > 0` is a red flag.** A function that only runs on a
  failing path can look dead. If any vectors failed, say so and get the corpus
  healthy before deleting anything — don't silently comment out code that a
  broken test run just failed to reach.

## Workflow

### 1. Orient

Read `report.json`. Note the dead count, which files they live in, and whether
any vectors failed. Skim `report.md` for the human-readable grouping. Confirm the
config path and that the ASI package is runnable (`python3 -m asi --version`;
if ASI lives in a subdir, set `PYTHONPATH=<that-dir>` or `cd` into it).

If `vectors_failed > 0`, stop and surface it. The report's dead list is only
trustworthy when the corpus ran clean.

### 2. Comment out the dead functions — deterministically, no API

Let ASI do the exact commenting from the report's line ranges. This is
language-aware (Python `#`, C/C++ `#if 0 … #endif`, others `//`) and never
misplaces a line:

```bash
# writes into an output dir (safe, review the diff there)
python3 -m asi refactor -c asi.json --comment-only --out asi_refactored
# …or edit the tree directly, keeping <file>.asi.bak backups:
python3 -m asi refactor -c asi.json --comment-only --in-place
```

`--comment-only` is the whole point: it is pure and deterministic and **calls no
API**. Use it rather than hand-commenting — matching line numbers by eye is
exactly the kind of error the tool exists to prevent.

> If ASI isn't available in the environment, fall back to doing the commenting
> yourself: for each `dead[]` entry, open `file`, and comment out lines
> `start_line`–`end_line` in that language's style. But prefer the command.

Do **not** run `asi refactor` *without* `--comment-only` — that path calls the
Anthropic API, which is exactly what this skill exists to avoid.

### 3. Refactor the live code — this is your part

Now improve the surviving code. Work one file at a time, using Read to see the
current state (post-commenting if you used `--in-place`) and Edit to change it.
Be guided by, and bounded by, these principles:

- **Dead code stays commented.** The `ASI: dead code` blocks are proven-unused —
  don't delete them (leave an auditable trail) and never re-enable them.
- **Preserve the public API and observable behaviour of live code.** Don't rename
  or change the signature of anything still in use; don't change what live
  functions compute or return. The test vectors are your contract.
- **Dead code often reveals more dead code.** A live helper that was *only* called
  by now-commented functions is itself unused — but trust the report, not your
  guess: it will already be in `dead[]` (it was never executed either). If you
  think something is now unreachable but it isn't in the report, leave it and note
  it; re-running the harness (step 4) is what confirms deadness, not intuition.
- **Optimisation is secondary and conservative.** If the user wants speed, the
  `live[]` hotspots (highest `hits`) are where it matters — but only make
  behaviour-preserving changes, and prefer clarity over cleverness.
- **Tidy, don't rewrite.** Clarify local names, drop redundant locals, fix
  formatting, remove a comment that only described deleted code. When a change
  isn't clearly behaviour-preserving, don't make it.

Match the surrounding code's style. Keep license headers and meaningful comments.

### 4. Verify by re-running the harness — the safety net

This is what makes the refactor trustworthy: **the same tool that found the dead
code validates your edit.** Re-run ASI on the refactored code:

```bash
python3 -m asi run -c asi.json
```

Check the new report against these expectations:

- **Vectors still pass** — `vectors_failed` is still 0 (or unchanged). If a vector
  now fails, you changed observable behaviour. Fix it or revert that file.
- **No live function went dark** — every function that was `live` before and still
  exists in the code is still `live`. A previously-live function showing up as
  dead means your refactor stopped exercising it → behaviour changed.
- **Dead count drops to ~0** — the functions you commented out are no longer part
  of the analysed source (they're commented), so the fresh report should show
  little or no remaining dead code. Anything still flagged is a new finding worth
  a look.

For compiled projects, also run the project's own build/tests (e.g. the config's
`refactor.verify` command, or `make`) to catch anything coverage can't.

If verification fails and you used `--in-place`, restore from the `.asi.bak`
backups (or `git checkout`) and narrow down the offending edit.

### 5. Report back

Summarise concretely: which functions were commented out (file:line), what you
changed in the live code and why, and the before/after verification numbers
(vectors passing, live/dead counts). Point the user at the diff. Remind them that
"dead" means *uncovered by this corpus* — if a commented function is needed on a
path the vectors don't exercise, the corpus, not the code, is what to fix.

## Guardrails

- **Never call an LLM/refactoring API to do the editing.** You are the refactorer.
  The only ASI command in this skill is `--comment-only` (deterministic, no API).
- **Keep it under version control / backups.** Prefer `--out` first, or ensure the
  tree is committed before `--in-place`.
- **Behaviour preservation beats cleverness.** The vectors are the contract; a
  smaller, faster, prettier file that fails a vector is a regression.
- **Trust the measurement, not intuition, for deadness.** If you believe code is
  dead but it isn't in the report, the resolution is to re-run the harness, not to
  delete it.
