# SECURITY.md — observatoire-pme-maroc

This is a student/research project (PFA internship). This file covers practical hygiene for handling threat-intelligence data and secrets, not a formal vulnerability-disclosure program.

## Secrets
- API keys (AbuseIPDB, etc.) live only in a local `.env`, never committed.
- `.env.example` in the repo lists required variable names with placeholder values only.
- `.gitignore` must include `.env`, `*.csv` under `data/` if any collected data could contain sensitive fields, and any local venv folders.
- If a key is ever committed by mistake: rotate it immediately (don't just delete the commit — assume it's compromised).

## Handling threat-intelligence data (URLhaus / AbuseIPDB)
- The malicious URLs/IPs collected are **data, never destinations**. Never open, curl, or execute a URL/IP from the dataset for "checking" — treat every row as inert text.
- Store raw feed data as-is (CSV/text); don't render collected URLs as clickable links anywhere (scripts, notebooks, Streamlit app).
- If displaying malicious URLs in the Streamlit dashboard or the rapport pilote, keep them as plain, non-clickable text (or defang them, e.g. `hxxp://`) to avoid accidental clicks by report readers.

## Internal / anonymized data (if EMC helpline signalements are obtained later)
- Any internal PME-reported data must be anonymized before it touches this repo or the dashboard — no company names, no identifying details, aggregate/categorize instead.
- Confirm with the supervisor what level of anonymization is acceptable before including any internal source.

## Repo hygiene
- No secrets, no real company names, no personal data in commit history — a mistake here isn't just embarrassing, it could leak information about an SME's actual exposure.
- Public repo (if pushed to GitHub) should only ever contain public feed data (URLhaus is public by nature) — keep any internal/EMC-sourced data in a local, untracked folder unless explicitly cleared for the public repo.

## Scope note
This is a batch/offline observatory, not a live system with an attack surface of its own (no exposed API, no user auth, no production deployment target defined yet). Revisit this file if/when a real deployment (e.g. Streamlit Community Cloud) goes live — add a note here about what's public vs private on that deployment.
