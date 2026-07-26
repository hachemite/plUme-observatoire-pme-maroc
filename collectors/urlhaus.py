"""Collector for URLhaus malicious URL CSV feed (Jalon 1 Primary Source)."""

import io
import sys
from pathlib import Path
import urllib.request
import pandas as pd

# Add parent directory to sys.path to enable imports when run directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from processing.validate import validate_urlhaus_dataframe
from processing.taxonomy import enrich_with_taxonomy
from storage.repository import save_events

URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"


def fetch_urlhaus_feed(url: str = URLHAUS_CSV_URL) -> pd.DataFrame:
    """Fetch recent malicious URLs from the URLhaus CSV feed.

    Args:
        url: Direct URL to URLhaus recent CSV feed.

    Returns:
        pd.DataFrame: Raw DataFrame parsed from CSV feed.
    """
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "ObservatoirePMEMaroc/1.0 (CMRPI/EMC Internship)"},
    )

    with urllib.request.urlopen(req, timeout=30) as response:
        content = response.read().decode("utf-8", errors="replace")

    # Filter out header comment lines starting with '#' except header definition line
    lines = content.splitlines()
    data_lines = []
    header_found = False

    for line in lines:
        if line.startswith("#"):
            if "id,dateadded,url" in line.lower():
                header_line = line.lstrip("# ").strip()
                data_lines.append(header_line)
                header_found = True
        else:
            if line.strip():
                data_lines.append(line)

    if not data_lines or not header_found:
        # Fallback parsing using comment='#'
        return pd.read_csv(
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
        )

    clean_csv = "\n".join(data_lines)
    return pd.read_csv(io.StringIO(clean_csv), on_bad_lines="skip")


def run_collector() -> int:
    """Run full URLhaus collection pipeline: fetch -> validate -> categorize -> save.

    Returns:
        int: Number of records stored in repository.
    """
    print("[URLhaus] Fetching feed from abuse.ch...")
    raw_df = fetch_urlhaus_feed()
    print(f"[URLhaus] Fetched {len(raw_df)} raw rows.")

    print("[URLhaus] Validating schema...")
    validated_df = validate_urlhaus_dataframe(raw_df)
    print(f"[URLhaus] Validated {len(validated_df)} clean rows.")

    print("[URLhaus] Enriching with AUSIM taxonomy...")
    enriched_df = enrich_with_taxonomy(validated_df)

    print("[URLhaus] Saving events to storage repository...")
    total_saved = save_events(enriched_df)
    print(f"[URLhaus] Successfully saved events. Total repository records: {total_saved}")
    return total_saved


if __name__ == "__main__":
    run_collector()
