"""Collector for URLhaus malicious URL CSV feed (Jalon 1 Primary Source)."""

import io
import sys
from pathlib import Path
import pandas as pd
import requests

# Add parent directory to sys.path to enable imports when run directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from processing.validate import validate_rows
from processing.taxonomy import categorize, severity, sector_hint
from storage.repository import save_events, load_events



URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"


def fetch_urlhaus_feed(url: str = URLHAUS_CSV_URL) -> pd.DataFrame:
    """Fetch recent malicious URLs from URLhaus CSV feed using requests with timeout=30.
    Strips comment lines and parses into DataFrame matching ThreatEvent schema.

    Args:
        url: Direct URL to URLhaus recent CSV feed.

    Returns:
        pd.DataFrame: Formatted DataFrame matching ThreatEvent schema.
    """
    headers = {"User-Agent": "ObservatoirePMEMaroc/1.0 (CMRPI/EMC Internship)"}
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()

    content = resp.text
    lines = content.splitlines()
    data_lines = []
    header_found = False

    for line in lines:
        if line.startswith("#"):
            if "id,dateadded,url" in line.lower():
                header_line = line.lstrip("# ").strip()
                data_lines.append(header_line)
                header_found = True
        elif line.strip():
            data_lines.append(line)

    if not data_lines or not header_found:
        raw_df = pd.read_csv(
            io.StringIO(content),
            comment="#",
            names=[
                "id",
                "dateadded",
                "url",
                "url_status",
                "last_online",
                "threat",
                "tags",
                "urlhaus_link",
                "reporter",
            ],
            on_bad_lines="skip",
            dtype=str,
        )
    else:
        clean_csv = "\n".join(data_lines)
        raw_df = pd.read_csv(io.StringIO(clean_csv), on_bad_lines="skip", dtype=str)

    raw_df.columns = [str(c).strip().strip('"# ').lower() for c in raw_df.columns]

    # Map URLhaus columns directly to ThreatEvent schema
    formatted_df = pd.DataFrame()
    formatted_df["event_id"] = "urlhaus_" + raw_df["id"].astype(str)
    formatted_df["source"] = "urlhaus"
    formatted_df["date_added"] = raw_df["dateadded"]
    formatted_df["indicator_type"] = "url"
    formatted_df["indicator_value"] = raw_df["url"]
    formatted_df["raw_threat_tag"] = raw_df.get("threat", raw_df.get("threat_type", ""))
    formatted_df["tags"] = raw_df.get("tags", "").fillna("").astype(str)
    formatted_df["country_code"] = ""

    status_series = raw_df.get("url_status", "offline").astype(str).str.lower()
    formatted_df["status"] = status_series.apply(lambda s: "online" if s == "online" else "offline")

    return formatted_df



def run_pipeline() -> None:
    """Run full collection pipeline: fetch -> validate_rows -> categorize -> save_events."""
    print("[URLhaus] Fetching feed from abuse.ch via requests...")
    raw_df = fetch_urlhaus_feed()
    print(f"[URLhaus] Parsed {len(raw_df)} raw records.")

    print("[URLhaus] Validating rows against ThreatEvent schema...")
    validated_df = validate_rows(raw_df)
    print(f"[URLhaus] Validated {len(validated_df)} clean rows.")

    print("[URLhaus] Categorizing threats with taxonomy...")
    categorized_df = categorize(validated_df)
    enriched_df = severity(categorized_df)
    enriched_df = sector_hint(enriched_df)

    print("[URLhaus] Saving events to storage repository...")
    save_events(enriched_df)



    saved_events = load_events()
    print(f"\n[URLhaus Pipeline Completed]")
    print(f"Total rows saved in repository: {len(saved_events)}")
    print("\nPreview of first 5 saved rows:")
    print(saved_events.head(5).to_string(index=False))


if __name__ == "__main__":
    run_pipeline()

