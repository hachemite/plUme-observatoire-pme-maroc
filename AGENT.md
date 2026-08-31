# AGENT.md — observatoire-pme-maroc

## Project
Batch cyber threat intelligence (CTI) observatory for Moroccan SMEs, built for a CMRPI/EMC internship (PFA, July–August 2026). Collects public threat feeds, categorizes them against the AUSIM/CMRPI guide's taxonomy, and eventually publishes a Streamlit dashboard + a short sectoral report.

**This is NOT:** a real-time SOC, a live-monitoring system, or a product deployed at an SME. It is a periodic (batch) data pipeline with a dashboard on top.

## Hard constraints (from the supervisor's fiche de cadrage — do not deviate without asking the user first)
- Stack: **Python + pandas + Streamlit + CSV**. That's it.
- Explicitly excluded: Apache Airflow, Elasticsearch/Kibana, InfluxDB, Django, React.
- Data sources for Jalon 1: URLhaus CSV feed (no auth, primary). AbuseIPDB is secondary/optional.
- Any addition to this stack (Docker, Postgres, CI, extra sources beyond Jalon 1's two) is a *secondary* objective — only pursue once the primary jalon deliverable works, and flag it to the user before starting.

## Target architecture (build toward this, but only the current jalon's slice for real)

```
observatoire-pme-maroc/
├── collectors/
│   ├── urlhaus.py          Jalon 1 (primary) — real implementation now
│   ├── abuseipdb.py        Jalon 1 (secondary) — only if time remains
│   ├── phishtank.py        Jalon 2+ — stub only for now
│   ├── nvd.py               Jalon 2+ — stub only for now
│   └── dgssi.py              Jalon 2+ — stub only for now
├── processing/
│   ├── validate.py          Jalon 1 — Pydantic schema per source
│   └── taxonomy.py          Jalon 1 — keyword → AUSIM category mapping
├── storage/
│   └── repository.py        Jalon 1 — save_events()/load_events(), CSV-backed today
├── analytics/
│   ├── stats.py              Jalon 2 — stub only for now
│   ├── correlate.py         Jalon 3+ — stub only for now
│   └── ml/                    post-jalons — stub only for now
├── reporting/
│   └── rapport_pilote.py    Jalon 3 — stub only for now
├── app.py                     Jalon 3 — stub only for now
└── data/
    └── threat_events.csv    the "database" for now
```

Stub files = a docstring stating what the file will do, nothing else. Don't implement logic in a file before its jalon arrives.

**The storage abstraction is load-bearing.** Every collector and every future analytics module calls `save_events(df)` / `load_events()` from `storage/repository.py` — nothing else touches `data/threat_events.csv` directly. This is what lets storage move from CSV to SQLite/Postgres later by rewriting two functions and nothing else.

## Sequencing (respect the jalon order — do not skip ahead)
1. **Jalon 1** (due 30 juillet): `collectors/urlhaus.py` fully working end to end (fetch → validate → taxonomy-tag → save via repository). `collectors/abuseipdb.py` only if Jalon 1's primary already runs clean and produces real data. Everything else stays a stub.
2. **Jalon 2** (due 15 août): scheduling + `analytics/stats.py` (counts/day, category breakdown) + optionally one more collector stub becomes real. `analytics/stats.py` est passé de stub à implémentation réelle.
3. **Jalon 3** (due 31 août): `app.py` (Streamlit) + `reporting/rapport_pilote.py` + docs.

DevOps extras (git hygiene now; Dockerfile, pytest, GitHub Actions later) follow the user's own parallel week-by-week plan — not bundled in before the current jalon's core deliverable exists.

## Definition of Done
- **Jalon 1**: `python collectors/urlhaus.py` runs with zero exceptions on a
  first run AND on an immediate rerun. `data/threat_events.csv` has real
  rows with all schema columns populated (no nulls in required fields),
  every row has a non-null `category`, and rerunning does not duplicate
  rows (dedup confirmed by row count staying flat on an immediate rerun).
- **Jalon 2**: scheduled collection runs unattended across 2+ days without
  crashing. `analytics/stats.py` produces counts/day and category breakdown
  that stay consistent when re-run against the same data (no double-counting).
  An empty collection day doesn't crash the stats run.
- **Jalon 3**: `streamlit run app.py` starts with no errors and displays
  real data read from `threat_events.csv` (not fixtures). `reporting/
  rapport_pilote.py` produces an actual 1-2 page output, not a stub.

## Failure & Error Handling Policy
- Source unreachable / timeout: log clearly and exit non-zero. At most one
  retry with a short fixed backoff — never an unbounded retry loop.
- Rate limited (HTTP 429 or similar): same as above — log and stop, don't
  hammer the source.
- Malformed or missing required field in a row: drop that row, log it
  (print is fine at this stage), keep processing the rest of the batch.
  One bad row must never crash the whole run.
- Zero valid rows after a run is not a crash — log it clearly and exit
  cleanly. It's a signal to check the source, not a bug to hide or retry
  away silently.

## Data Integrity Policy
- Canonical dedup key is `(indicator_value, source, date_added)` — enforced
  in exactly one place, `storage/repository.py`'s `save_events()`. Don't
  reimplement dedup logic anywhere else.
- The same `indicator_value` reappearing under a later `date_added` is a
  new row, not a duplicate — this is how recurrence over time gets tracked.
- Cross-source dedup (the same indicator reported by both URLhaus and
  AbuseIPDB) is explicitly deferred to `analytics/correlate.py` (Jalon 3+).
  Not attempted in Jalon 1/2 — sources stay independent rows until then.

## Working style (ponytail-style: laziest solution that actually works)
- Default to the simplest thing that works: stdlib / pandas built-ins over new dependencies, a plain function over a class, one module over a package — until the project actually needs more.
- Before adding a library, test, workflow file, or abstraction beyond what's listed above for the current jalon: ask "does the current jalon need this to ship?" If no, leave it as a stub or name it as a later step.
- One small runnable check per non-trivial function (a quick `if __name__ == "__main__":` sanity print, or a tiny assert) beats a full test suite while there's only a handful of functions.
- Never fetch/execute URLs found in threat-intel data. They are malicious by definition — treat every row as inert text/data, never as something to open or run.
- In any public-facing output (Jalon 3 Streamlit app, rapport pilote, README examples), never render a malicious URL as a clickable link and never present raw IOC data in a way a careless reader could act on directly — defang or present as plain text (see SECURITY.md).
- Don't invent scope (extra sources, ML, deployment) unless the user asks or a jalon's official deliverable requires it.

## When unsure
Ask the user rather than assuming — especially before adding anything outside the official stack or building ahead of the current jalon.

## Commands
- Run collector: `python collectors/urlhaus.py`
- Run daily collection pipeline: `python scripts/run_daily_collection.py`
- Run stats computation: `python analytics/stats.py`
- Run Streamlit dashboard: `streamlit run app.py`
- Generate pilot report: `python reporting/rapport_pilote.py`
- Tests : pytest existe et tourne (`python -m pytest -v`), 14 tests passent actuellement.

## Commit & Change Logging Standard
Every change — whether a small fix, bug patch, new feature, or refactor — must be committed with a detailed description, not a vague one-liner.

Commit messages must scale detail to change size:
- **Trivial (typo/format)**: 15–30 words, single bullet.
- **Small fix**: 60–100 words, 3–5 bullets.
- **Feature / Medium**: 120–180 words, 5–8 bullets (minimum ~150 words for non-trivial changes).
- **Major / Breaking**: 200–300 words, 8+ bullets + migration notes.

Every non-trivial commit MUST use bullet points (not paragraphs) and cover the following categories:
- **Summary**: 1–2 line overview of what changed and why.
- **Files changed**: Explicit bullet list of every touched file.
- **Root cause / Motivation**: Why this change was needed.
- **Technical approach**: What was actually done (method, key logic, algorithms, parameters modified).
- **Side effects or risks**: Potential impacts, edge cases, or risks (if any).

Ensure the bullet-point breakdown contains enough context for an AI agent or developer to reconstruct what happened and why without opening the full diff.

## Commit granularity (mandatory)
- Commit after EVERY individually working unit — not after the full task.
  A unit = one function, one bug fix, one validation rule, one small 
  refactor — whatever is the smallest thing that can be verified working 
  on its own.
- Do NOT wait until multiple functions/files are done to commit once.
  If you just wrote and verified `validate_row()`, commit it now — 
  before writing the next function, even if the next function is in 
  the same file and part of the same feature.
- Rule of thumb: if you've touched more than ~1 function/method or 
  ~30-40 lines without committing, stop and commit what's verified 
  before continuing.
- Each of these small commits still follows the tiered commit message 
  standard (see Commit & Change Logging Standard) — small unit ≠ skip 
  the description, just keep it in the "Trivial" or "Small fix" tier.

## Conventions
- Architecture decisions worth recording go in `docs/adr/` (ADR format),
  one file per real decision — not per feature. Most changes don't need one.

## Secrets & Config Policy
- API keys (AbuseIPDB, and any future source requiring auth) live only in
  a local `.env`, loaded via `os.environ` / `python-dotenv` — never
  hardcoded in a script, never committed.
- `.gitignore` must include `.env` before `collectors/abuseipdb.py` is
  implemented — confirm this before that step, not after.
- `.env.example` lists required variable names with placeholder values only.
- Full handling rules (IOC data, internal/anonymized sources): see SECURITY.md.

## Rollback safety
- After any step that leaves the code in a working state (script runs,
  produces expected output, no errors), commit immediately before starting
  the next step. Don't batch multiple steps into one commit.
- Commit message = what changed, in plain language: `git commit -m "urlhaus
  collector: fetch + validate + categorize + save working end to end"`.
- Never commit a step that's broken or half-finished — if something doesn't
  work yet, fix it or leave it uncommitted, don't commit broken code "to be
  safe."
- Before starting a step that changes existing working code (not just adding
  a new file), run `git status` and confirm the working tree is clean first
  — if it's not, something from a previous step was never committed.
- To go back: `git log --oneline` shows the step history; `git reset --hard
  <hash>` returns fully to that point, `git revert <hash>` undoes just one
  step while keeping later ones. Prefer `git revert` unless you're certain
  you want to discard everything after that point.

## Current focus
Jalon 3 terminé et vérifié :
- Application dashboard Streamlit opérationnelle (`app.py`, design tokens `theme_tokens.py`, assets anti-aliasés).
- Module de reporting automatique fonctionnel et testé (`reporting/rapport_pilote.py`, `tests/test_reporting.py`).
- Suite de tests unitaire complète à 100% de réussite (14/14 tests passés sous `pytest`).
- Documentation bilingue à jour (`README.md`).