"""Collector for AbuseIPDB IP blacklist feed (Jalon 1 Secondary Source)."""

import os
import sys
from pathlib import Path
from typing import Optional
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

# Offline sample dataset for fallback when no API key is provided or offline
OFFLINE_SAMPLE_DATA = [
    {
        "ipAddress": "185.220.101.5",
        "lastReportedAt": "2026-08-17T12:00:00+00:00",
        "abuseConfidenceScore": 100,
        "countryCode": "MA",
    },
    {
        "ipAddress": "45.148.10.157",
        "lastReportedAt": "2026-08-17T14:30:00+00:00",
        "abuseConfidenceScore": 95,
        "countryCode": "MA",
    },
    {
        "ipAddress": "196.200.160.12",
        "lastReportedAt": "2026-08-17T16:45:00+00:00",
        "abuseConfidenceScore": 88,
        "countryCode": "MA",
    },
    {
        "ipAddress": "45.148.10.147",
        "lastReportedAt": "2026-08-17T18:10:00+00:00",
        "abuseConfidenceScore": 92,
        "countryCode": "MA",
    },
]


def get_abuseipdb_api_key() -> Optional[str]:
    """Resolve AbuseIPDB API key from st.secrets, os.environ, or .streamlit/secrets.toml.

    Returns:
        Optional[str]: Valid API key string, or None if not found or placeholder.
    """
    # 1. Streamlit runtime secrets
    try:
        import streamlit as st
        if hasattr(st, "secrets") and "abuseipdb" in st.secrets:
            key = st.secrets["abuseipdb"].get("api_key")
            if key and key.strip() and key not in ["your-key-here", "your_abuseipdb_api_key_here"]:
                return key.strip()
    except Exception:
        pass

    # 2. Environment variables / .env
    env_key = os.getenv("ABUSEIPDB_API_KEY")
    if env_key and env_key.strip() and env_key not in ["your_abuseipdb_api_key_here", "your-key-here"]:
        return env_key.strip()

    # 3. Direct secrets.toml parsing for standalone scripts (run_daily_collection.py)
    secrets_path = BASE_DIR / ".streamlit" / "secrets.toml"
    if secrets_path.exists():
        try:
            import tomllib
            with open(secrets_path, "rb") as f:
                secrets_data = tomllib.load(f)
            key = secrets_data.get("abuseipdb", {}).get("api_key")
            if key and key.strip() and key not in ["your-key-here", "your_abuseipdb_api_key_here"]:
                return key.strip()
        except Exception:
            pass

    return None


def fetch_abuseipdb_feed(limit: int = 100) -> pd.DataFrame:
    """Fetch blacklisted IP addresses from AbuseIPDB API v2 with offline sample fallback.

    Args:
        limit: Maximum number of IP records to fetch.

    Returns:
        pd.DataFrame: Formatted DataFrame matching ThreatEvent schema.
    """
    api_key = get_abuseipdb_api_key()
    data_list = []

    if not api_key:
        print("[AbuseIPDB Info] Aucune clé API configurée. Utilisation de l'échantillon hors ligne.")
        data_list = OFFLINE_SAMPLE_DATA
    else:
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
            data_list = json_data.get("data", [])
        except requests.exceptions.RequestException as exc:
            print(f"[AbuseIPDB Warning] Échec de requête API ({exc}). Utilisation de l'échantillon hors ligne.")
            data_list = OFFLINE_SAMPLE_DATA

    if not data_list:
        print("[AbuseIPDB Warning] Empty dataset returned.")
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
