"""Database migration script: migrates threat_events.csv into SQLite operational store (db.sqlite3)."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import sqlite3
import pandas as pd
from analytics.geoip import tag_country
from analytics.correlate import extract_host_or_ip, IPV4_REGEX, get_confirmed_cross_source_ips

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
CSV_FILE = DATA_DIR / "threat_events.csv"
DB_FILE = DATA_DIR / "db.sqlite3"


def init_db(db_path: Path):
    """Create the SQLite operational schema."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # Table 1: Indicators lifecycle table
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

    # Table 2: Collection runs table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS collection_runs (
        run_id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_timestamp TEXT,
        source TEXT,
        row_count INTEGER,
        status TEXT
    );
    """)

    # Table 3: Raw event history
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

    # Indices for high-speed queries
    cur.execute("CREATE INDEX IF NOT EXISTS idx_indicators_category ON indicators(category);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_indicators_country ON indicators(country_code);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_indicators_times_seen ON indicators(times_seen);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_date ON events(date_added);")

    conn.commit()
    conn.close()


def migrate():
    """Migrate historical data from CSV to SQLite."""
    print(f"[Migration] Reading raw CSV from {CSV_FILE}...")
    if not CSV_FILE.exists():
        print(f"[Error] {CSV_FILE} does not exist.")
        return

    df = pd.read_csv(CSV_FILE, dtype=str).fillna("")
    print(f"[Migration] Loaded {len(df)} total rows from CSV.")

    init_db(DB_FILE)
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    # 1. Insert into events table
    print("[Migration] Inserting into raw 'events' table...")
    events_inserted = 0
    for _, row in df.iterrows():
        try:
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
            events_inserted += 1
        except Exception as e:
            print(f"[Warning] Error inserting event row: {e}")

    conn.commit()
    print(f"[Migration] Successfully inserted {events_inserted} events into 'events' table.")

    # 2. Compute cross-source confirmed IPs
    confirmed_ips = get_confirmed_cross_source_ips(df)
    print(f"[Migration] Identified {len(confirmed_ips)} cross-source confirmed IPs: {confirmed_ips}")

    # 3. Aggregate indicators lifecycle: first_seen, last_seen, times_seen
    print("[Migration] Aggregating indicator lifecycles...")
    grouped = df.groupby("indicator_value")
    
    indicators_inserted = 0
    for ioc, grp in grouped:
        dates = grp["date_added"].dropna().tolist()
        first_seen = min(dates) if dates else ""
        last_seen = max(dates) if dates else ""
        times_seen = len(grp)

        # Dominant source & type
        source = grp["source"].iloc[0]
        itype = grp["indicator_type"].iloc[0]
        category = grp["category"].iloc[0]
        severity = grp["severity"].iloc[0]
        sector_hint = grp["sector_hint"].iloc[0] if "sector_hint" in grp.columns else ""
        tags = grp["tags"].iloc[0] if "tags" in grp.columns else ""
        status = grp["status"].iloc[0] if "status" in grp.columns else ""
        raw_threat_tag = grp["raw_threat_tag"].iloc[0] if "raw_threat_tag" in grp.columns else ""

        # Country code
        country_code = grp["country_code"].iloc[0] if "country_code" in grp.columns else ""
        if not country_code or country_code.lower() == "unknown":
            host = extract_host_or_ip(ioc)
            if IPV4_REGEX.match(host):
                resolved_cc = tag_country(host)
                if resolved_cc:
                    country_code = resolved_cc

        # Cross-source confirmed check
        host = extract_host_or_ip(ioc)
        is_confirmed = 1 if (ioc in confirmed_ips or host in confirmed_ips) else 0

        cur.execute("""
        INSERT OR REPLACE INTO indicators (
            indicator_value, indicator_type, first_seen, last_seen, times_seen,
            category, severity, source, sector_hint, country_code, cross_source_confirmed,
            tags, status, raw_threat_tag
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ioc, itype, first_seen, last_seen, times_seen,
            category, severity, source, sector_hint, country_code, is_confirmed,
            tags, status, raw_threat_tag
        ))
        indicators_inserted += 1

    conn.commit()
    print(f"[Migration] Successfully created {indicators_inserted} unique indicator entities.")

    # 4. Synthesize collection_runs history
    print("[Migration] Recording collection runs history...")
    date_source_counts = df.groupby([df["date_added"].str[:10], "source"]).size()
    for (d_str, src), count in date_source_counts.items():
        cur.execute("""
        INSERT INTO collection_runs (run_timestamp, source, row_count, status)
        VALUES (?, ?, ?, 'completed')
        """, (f"{d_str} 00:00:00", src, int(count)))

    conn.commit()
    conn.close()

    print("[Migration] Migration to SQLite completed successfully!")


if __name__ == "__main__":
    migrate()
