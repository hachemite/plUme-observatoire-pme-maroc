# ADR 0002: Mixed-timezone datetime parsing in analytics pipeline

## Status
Accepted

## Context
`data/threat_events.csv` stores timestamps originating from multiple heterogeneous threat intelligence feeds. URLhaus provides naive UTC timestamps (e.g. `2026-06-27 00:02:07` without offset), while AbuseIPDB provides ISO 8601 strings with an explicit UTC offset (e.g. `2026-08-15 00:17:02+00:00`).

Calling `pd.to_datetime(df["date_added"], errors="coerce")` without explicit timezone handling caused pandas to fail on mixed timezones, silently converting all AbuseIPDB records (500+ rows) into `NaT`, which were subsequently dropped during daily aggregations in `analytics/stats.py`.

## Decision
All date conversions in `analytics/stats.py` must use explicit ISO 8601 UTC parsing:
`pd.to_datetime(df["date_added"], format="ISO8601", utc=True, errors="coerce")`.

In addition, an explicit diagnostic check is enforced: if any rows result in `NaT` after conversion, a warning is printed to the console detailing the exact number of dropped records and their sources, preventing silent data loss per the Failure & Error Handling Policy in `AGENT.md`.

## Alternatives considered
- **`errors="raise"` without `utc=True`**: rejected — causes the entire pipeline to crash immediately upon encountering mixed timezone strings instead of normalizing them.
- **Regex string manipulation (stripping `+00:00`)**: rejected — brittle, fragile across different datetime string representations, and fails if feeds provide non-zero UTC offsets.
- **Enforcing datetime normalization at ingestion time in collectors**: deferred — preserving raw source strings in `threat_events.csv` maintains auditability; normalization is safely handled at the analytics aggregation layer.

## Consequences
- Guarantees 100% lossless multi-source aggregation in `data/daily_stats.csv` across naive and offset-aware timestamps.
- Any future data source (e.g., DGSSI / CERT-MA advisory feeds) must either provide ISO 8601 compatible timestamp formats or require explicit verification and extension of the datetime parser during integration.
