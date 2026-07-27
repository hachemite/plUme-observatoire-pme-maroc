"""Collector for AbuseIPDB IP blacklist feed (Jalon 1 Secondary Source)."""

import os
import sys
from pathlib import Path
import pandas as pd
import requests
from dotenv import load_dotenv

# Add parent directory to sys.path to enable imports when run directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from processing.validate import validate_rows
from processing.taxonomy import categorize, severity, sector_hint
from storage.repository import save_events, load_events



# Load environment variables from .env file
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/blacklist"


def fetch_abuseipdb_feed(limit: int = 100) -> pd.DataFrame:
    """Fetch blacklisted IP addresses from AbuseIPDB API v2.

    Args:
        limit: Maximum number of IP records to fetch.

    Returns:
        pd.DataFrame: Formatted DataFrame matching ThreatEvent schema.
    """
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key or api_key.strip() == "" or api_key == "your_abuseipdb_api_key_here":
        print("[AbuseIPDB Error] Missing or unconfigured ABUSEIPDB_API_KEY in .env file.")
        print("Please configure a valid AbuseIPDB API key in your local .env file.")
        sys.exit(1)

    headers = {
        "Key": api_key,
        "Accept": "application/json",
        "User-Agent": "ObservatoirePMEMaroc/1.0 (CMRPI/EMC Internship)",
    }
    params = {"limit": limit}

    try:
        resp = requests.get(ABUSEIPDB_API_URL, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        json_data = resp.json()
    except requests.exceptions.RequestException as exc:
        print(f"[AbuseIPDB Error] Failed to fetch feed from API: {exc}")
        sys.exit(1)

    data_list = json_data.get("data", [])
    if not data_list:
        print("[AbuseIPDB Warning] Empty dataset returned from API.")
        return pd.DataFrame()

    raw_df = pd.DataFrame(data_list)

    # Map AbuseIPDB columns directly to ThreatEvent schema
    formatted_df = pd.DataFrame()
    formatted_df["event_id"] = "abuseipdb_" + raw_df["ipAddress"].astype(str)
    formatted_df["source"] = "abuseipdb"
    formatted_df["date_added"] = raw_df["lastReportedAt"]
    formatted_df["indicator_type"] = "ip"
    formatted_df["indicator_value"] = raw_df["ipAddress"]
    formatted_df["raw_threat_tag"] = "abuse_reported"
    formatted_df["tags"] = "confidence_" + raw_df["abuseConfidenceScore"].astype(str)
    formatted_df["country_code"] = raw_df.get("countryCode", "").fillna("").astype(str)
    formatted_df["status"] = "reported"

    return formatted_df


def run_pipeline() -> None:
    """Run full collection pipeline: fetch -> validate_rows -> categorize -> save_events."""
    print("[AbuseIPDB] Fetching feed from API v2...")
    raw_df = fetch_abuseipdb_feed()
    if raw_df.empty:
        print("[AbuseIPDB] No records retrieved.")
        return

    print(f"[AbuseIPDB] Parsed {len(raw_df)} raw records.")

    print("[AbuseIPDB] Validating rows against ThreatEvent schema...")
    validated_df = validate_rows(raw_df)
    print(f"[AbuseIPDB] Validated {len(validated_df)} clean rows.")

    print("[AbuseIPDB] Categorizing threats with taxonomy...")
    categorized_df = categorize(validated_df)
    enriched_df = severity(categorized_df)
    enriched_df = sector_hint(enriched_df)

    print("[AbuseIPDB] Saving events to storage repository...")
    save_events(enriched_df)



    saved_events = load_events()
    print(f"\n[AbuseIPDB Pipeline Completed]")
    print(f"Total rows saved in repository: {len(saved_events)}")
    print("\nPreview of first 5 saved rows:")
    print(saved_events.head(5).to_string(index=False))


if __name__ == "__main__":
    run_pipeline()
