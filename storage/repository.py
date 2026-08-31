"""Storage repository module: SQLite-backed operational persistence of threat events,
indicator lifecycle tracking, and run history, with CSV raw archival export.
"""

from pathlib import Path
import sqlite3
import pandas as pd
from typing import Optional

# Absolute paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_FILE = DATA_DIR / "threat_events.csv"
DB_FILE = DATA_DIR / "db.sqlite3"

STANDARD_COLUMNS = [
    "event_id",
    "source",
    "date_added",
    "indicator_type",
    "indicator_value",
    "raw_threat_tag",
    "tags",
    "country_code",
    "status",
    "category",
    "severity",
    "sector_hint",
]

# Canonical deduplication subset key as per Data Integrity Policy
DEDUP_COLUMNS = ["indicator_value", "source", "date_added"]


def init_db(db_path: Optional[Path] = None) -> None:
    """Initialize the SQLite database schema if not already present."""
    target_db = db_path or DB_FILE
    target_db.parent.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(target_db)
    cur = conn.cursor()

    # Table 1: Indicator lifecycle entities
    cur.execute("""
    CREATE TABLE IF NOT EXISTS indicators (
        indicator_value TEXT PRIMARY KEY,
        indicator_type TEXT,
        first_seen TEXT,
        last_seen TEXT,
        times_seen INTEGER DEFAULT 1,
        category TEXT,
        severity TEXT,
        source TEXT,
        sector_hint TEXT,
        country_code TEXT,
        cross_source_confirmed INTEGER DEFAULT 0,
        tags TEXT,
        status TEXT,
        raw_threat_tag TEXT
    );
    """)

    # Table 2: Execution collection runs
    cur.execute("""
    CREATE TABLE IF NOT EXISTS collection_runs (
        run_id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_timestamp TEXT,
        source TEXT,
        row_count INTEGER,
        status TEXT
    );
    """)

    # Table 3: Raw events operational store
    cur.execute("""
    CREATE TABLE IF NOT EXISTS events (
        event_id TEXT,
        source TEXT,
        date_added TEXT,
        indicator_type TEXT,
        indicator_value TEXT,
        raw_threat_tag TEXT,
        tags TEXT,
        country_code TEXT,
        status TEXT,
        category TEXT,
        severity TEXT,
        sector_hint TEXT,
        PRIMARY KEY (indicator_value, source, date_added)
    );
    """)

    # Fast query indices
    cur.execute("CREATE INDEX IF NOT EXISTS idx_indicators_category ON indicators(category);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_indicators_country ON indicators(country_code);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_indicators_times_seen ON indicators(times_seen);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_date ON events(date_added);")

    conn.commit()
    conn.close()


def save_events(df: pd.DataFrame) -> None:
    """Save threat events DataFrame to SQLite operational storage with UPSERT on indicators,
    event deduplication, run logging, and CSV raw archival synchronization.

    Args:
        df: DataFrame containing threat events to store.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    init_db(DB_FILE)

    if df.empty:
        if not DATA_FILE.exists():
            pd.DataFrame(columns=STANDARD_COLUMNS).to_csv(DATA_FILE, index=False)
        return

    df = df.copy()

    # Ensure all standard columns exist
    for col in STANDARD_COLUMNS:
        if col not in df.columns:
            df[col] = ""

    df = df[STANDARD_COLUMNS]
    df_clean = df.astype(str).fillna("")

    # --- 1. SQLite Storage Operations ---
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    # A. Insert / Deduplicate into events table
    for _, row in df_clean.iterrows():
        cur.execute("""
        INSERT OR REPLACE INTO events (
            event_id, source, date_added, indicator_type, indicator_value,
            raw_threat_tag, tags, country_code, status, category, severity, sector_hint
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            row.get("event_id", ""),
            row.get("source", ""),
            row.get("date_added", ""),
            row.get("indicator_type", ""),
            row.get("indicator_value", ""),
            row.get("raw_threat_tag", ""),
            row.get("tags", ""),
            row.get("country_code", ""),
            row.get("status", ""),
            row.get("category", ""),
            row.get("severity", ""),
            row.get("sector_hint", "")
        ))

    # B. UPSERT into indicators table
    for _, row in df_clean.iterrows():
        ioc = row.get("indicator_value", "")
        if not ioc:
            continue
        date_str = row.get("date_added", "")
        itype = row.get("indicator_type", "")
        cat = row.get("category", "")
        sev = row.get("severity", "")
        src = row.get("source", "")
        sect = row.get("sector_hint", "")
        cc = row.get("country_code", "")
        tags_str = row.get("tags", "")
        status_str = row.get("status", "")
        raw_tag = row.get("raw_threat_tag", "")

        cur.execute("""
        INSERT INTO indicators (
            indicator_value, indicator_type, first_seen, last_seen, times_seen,
            category, severity, source, sector_hint, country_code, cross_source_confirmed,
            tags, status, raw_threat_tag
        ) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, 0, ?, ?, ?)
        ON CONFLICT(indicator_value) DO UPDATE SET
            last_seen = excluded.last_seen,
            times_seen = indicators.times_seen + 1,
            category = CASE WHEN excluded.category != 'ransomware_malware' AND excluded.category != '' THEN excluded.category ELSE indicators.category END,
            severity = CASE WHEN excluded.severity != 'unknown' AND excluded.severity != '' THEN excluded.severity ELSE indicators.severity END,
            country_code = COALESCE(NULLIF(excluded.country_code, ''), indicators.country_code),
            tags = CASE WHEN excluded.tags != '' THEN excluded.tags ELSE indicators.tags END,
            status = excluded.status
        """, (
            ioc, itype, date_str, date_str, cat, sev, src, sect, cc, tags_str, status_str, raw_tag
        ))

    # C. Record run history
    first_date = df_clean["date_added"].min() if not df_clean.empty else "N/A"
    first_source = df_clean["source"].iloc[0] if not df_clean.empty else "collector"
    cur.execute("""
    INSERT INTO collection_runs (run_timestamp, source, row_count, status)
    VALUES (?, ?, ?, 'completed')
    """, (first_date, first_source, len(df_clean)))

    conn.commit()
    conn.close()

    # --- 2. CSV Archival Synchronization (Preserves backward compatibility) ---
    if DATA_FILE.exists() and DATA_FILE.stat().st_size > 0:
        existing_df = pd.read_csv(DATA_FILE, dtype=str).fillna("")
        for col in STANDARD_COLUMNS:
            if col not in existing_df.columns:
                existing_df[col] = ""
        existing_df = existing_df[STANDARD_COLUMNS]
        combined_df = pd.concat([existing_df, df_clean], ignore_index=True)
    else:
        combined_df = df_clean

    if not combined_df.empty:
        combined_df = combined_df.drop_duplicates(subset=DEDUP_COLUMNS, keep="last")

    combined_df.to_csv(DATA_FILE, index=False)


def load_events() -> pd.DataFrame:
    """Load threat events from SQLite operational storage, falling back to CSV if database is empty.

    Returns:
        pd.DataFrame: DataFrame of stored threat events matching STANDARD_COLUMNS.
    """
    if DB_FILE.exists() and DB_FILE.stat().st_size > 0:
        try:
            conn = sqlite3.connect(DB_FILE)
            df = pd.read_sql_query("SELECT * FROM events ORDER BY date_added ASC", conn)
            conn.close()
            if not df.empty:
                for col in STANDARD_COLUMNS:
                    if col not in df.columns:
                        df[col] = ""
                return df[STANDARD_COLUMNS].astype(str)
        except Exception:
            pass

    if DATA_FILE.exists() and DATA_FILE.stat().st_size > 0:
        return pd.read_csv(DATA_FILE, dtype=str)

    return pd.DataFrame(columns=STANDARD_COLUMNS)


def load_indicators() -> pd.DataFrame:
    """Load indicator entities and lifecycle tracking from SQLite indicators table.

    Returns:
        pd.DataFrame: DataFrame containing indicator lifecycle records.
    """
    if DB_FILE.exists() and DB_FILE.stat().st_size > 0:
        try:
            conn = sqlite3.connect(DB_FILE)
            df = pd.read_sql_query("SELECT * FROM indicators ORDER BY times_seen DESC, last_seen DESC", conn)
            conn.close()
            return df
        except Exception:
            pass
    return pd.DataFrame()


def load_collection_runs() -> pd.DataFrame:
    """Load history of collection runs.

    Returns:
        pd.DataFrame: DataFrame containing collection run records.
    """
    if DB_FILE.exists() and DB_FILE.stat().st_size > 0:
        try:
            conn = sqlite3.connect(DB_FILE)
            df = pd.read_sql_query("SELECT * FROM collection_runs ORDER BY run_id DESC", conn)
            conn.close()
            return df
        except Exception:
            pass
    return pd.DataFrame(columns=["run_id", "run_timestamp", "source", "row_count", "status"])
