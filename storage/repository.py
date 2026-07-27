"""Storage repository module for CSV-backed persistence of threat events."""

from pathlib import Path
import pandas as pd

# Absolute path to data file ensuring repository works regardless of current directory
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_FILE = DATA_DIR / "threat_events.csv"

STANDARD_COLUMNS = [
    "id",
    "source",
    "url",
    "url_status",
    "threat_type",
    "tags",
    "date_added",
    "reporter",
    "category",
    "target_sector",
]

# Canonical deduplication subset key as per Data Integrity Policy
DEDUP_COLUMNS = ["indicator_value", "source", "date_added"]


def save_events(df: pd.DataFrame) -> None:
    """Save threat events DataFrame to CSV storage with deduplication on
    (indicator_value, source, date_added). Creates file with header if missing.

    Args:
        df: DataFrame containing threat events to store.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Ensure required columns exist
    for col in STANDARD_COLUMNS:
        if col not in df.columns:
            df[col] = ""

    # Derive indicator_value if missing (defaults to url field for URLhaus)
    if "indicator_value" not in df.columns:
        df["indicator_value"] = df["url"]

    if DATA_FILE.exists() and DATA_FILE.stat().st_size > 0:
        existing_df = pd.read_csv(DATA_FILE, dtype=str)
        if "indicator_value" not in existing_df.columns:
            existing_df["indicator_value"] = existing_df.get("url", "")
        combined_df = pd.concat([existing_df, df], ignore_index=True)
    else:
        combined_df = df

    if not combined_df.empty:
        # Deduplicate on canonical key: (indicator_value, source, date_added)
        dedup_subset = [col for col in DEDUP_COLUMNS if col in combined_df.columns]
        combined_df = combined_df.drop_duplicates(subset=dedup_subset, keep="last")

    combined_df.to_csv(DATA_FILE, index=False)


def load_events() -> pd.DataFrame:
    """Load threat events from CSV storage.

    Returns:
        pd.DataFrame: DataFrame of stored threat events or an empty DataFrame
        with correct columns if the file doesn't exist.
    """
    if DATA_FILE.exists() and DATA_FILE.stat().st_size > 0:
        return pd.read_csv(DATA_FILE, dtype=str)
    return pd.DataFrame(columns=STANDARD_COLUMNS)

