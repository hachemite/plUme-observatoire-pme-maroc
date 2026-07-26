# ADR 0001: CSV-backed storage behind a repository interface

## Status
Accepted

## Context
The supervisor's fiche de cadrage mandates CSV storage (explicitly excludes
Postgres/Airflow/etc. for this internship). But the project may outgrow CSV
if data volume or query needs grow past Jalon 3.

## Decision
All storage access goes through `storage/repository.py`'s two functions:
`save_events(df)` and `load_events()`. No other module reads/writes
`data/threat_events.csv` directly. Today these two functions are CSV-backed.

## Alternatives considered
- **Direct pandas CSV calls scattered across collectors/analytics**: rejected
  — couples every module to the file format, expensive to change later.
- **SQLite now**: rejected — not in the approved stack for this internship,
  and CSV is sufficient for the data volumes expected in 2 months.
- **Postgres now**: rejected — explicitly excluded by supervisor, adds
  infra the timeline doesn't need.

## Consequences
- If storage ever needs to move to SQLite/Postgres, only these two
  functions change — collectors, processing, and analytics modules are
  unaffected.
- Slight overhead now (an extra function call instead of `df.to_csv()`
  inline) in exchange for that isolation.