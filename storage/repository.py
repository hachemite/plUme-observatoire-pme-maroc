"""Storage repository module for CSV-backed persistence of threat events."""

from pathlib import Path
import pandas as pd

# Absolute path to data file ensuring repository works regardless of current directory
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_FILE = DATA_DIR / "threat_events.csv"

STANDARD_COLUMNS = [
    "event_id",
    "source",
    "date_added",
    "indicator_type",
    "indicator_value",
    "raw_threat_tag",
    "tags",
    "status",
    "category",
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

    if df.empty:
        if not DATA_FILE.exists():
            pd.DataFrame(columns=STANDARD_COLUMNS).to_csv(DATA_FILE, index=False)
        return

    df = df.copy()

    # Ensure all standard columns exist
    for col in STANDARD_COLUMNS:
        if col not in df.columns:
            df[col] = ""

    # Align columns to exact standard schema
    df = df[STANDARD_COLUMNS]

    if DATA_FILE.exists() and DATA_FILE.stat().st_size > 0:
        existing_df = pd.read_csv(DATA_FILE, dtype=str)
        # Re-align existing columns if file was from older schema
        for col in STANDARD_COLUMNS:
            if col not in existing_df.columns:
                existing_df[col] = ""
        existing_df = existing_df[STANDARD_COLUMNS]
        combined_df = pd.concat([existing_df, df], ignore_index=True)
    else:
        combined_df = df

    if not combined_df.empty:
        # Deduplicate on canonical key: (indicator_value, source, date_added)
        combined_df = combined_df.drop_duplicates(subset=DEDUP_COLUMNS, keep="last")

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


