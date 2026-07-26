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
2. **Jalon 2** (due 15 août): scheduling + `analytics/stats.py` (counts/day, category breakdown) + optionally one more collector stub becomes real.
3. **Jalon 3** (due 31 août): `app.py` (Streamlit) + `reporting/rapport_pilote.py` + docs.

DevOps extras (git hygiene now; Dockerfile, pytest, GitHub Actions later) follow the user's own parallel week-by-week plan — not bundled in before the current jalon's core deliverable exists.

## Working style (ponytail-style: laziest solution that actually works)
- Default to the simplest thing that works: stdlib / pandas built-ins over new dependencies, a plain function over a class, one module over a package — until the project actually needs more.
- Before adding a library, test, workflow file, or abstraction beyond what's listed above for the current jalon: ask "does the current jalon need this to ship?" If no, leave it as a stub or name it as a later step.
- One small runnable check per non-trivial function (a quick `if __name__ == "__main__":` sanity print, or a tiny assert) beats a full test suite while there's only a handful of functions.
- Never fetch/execute URLs found in threat-intel data. They are malicious by definition — treat every row as inert text/data, never as something to open or run.
- Don't invent scope (extra sources, ML, deployment) unless the user asks or a jalon's official deliverable requires it.

## When unsure
Ask the user rather than assuming — especially before adding anything outside the official stack or building ahead of the current jalon.

## Commands
- Run collector: `python collectors/urlhaus.py`
- No build step, no lint config, no test suite yet — these don't exist
  until Jalon 2+. Don't invoke `docker compose`, `pytest`, or a linter;
  none are set up.

## Conventions
- Commits: plain, descriptive messages (`git commit -m "add urlhaus collector"`)
  is enough. No branch strategy needed for a solo 6-week project — commit
  to `main`, small commits, one per working step.
- Architecture decisions worth recording go in `docs/adr/` (ADR format),
  one file per real decision — not per feature. Most changes don't need one.

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
Jalon 1 (due 30 juillet): `collectors/urlhaus.py` end to end, working,
producing real rows in `data/threat_events.csv`. Nothing past step 5 of
the Jalon 1 prompt until this is confirmed working with real output shown.