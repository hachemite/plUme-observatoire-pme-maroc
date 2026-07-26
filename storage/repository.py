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


def save_events(df: pd.DataFrame) -> int:
    """Save threat events DataFrame to CSV storage with deduplication.

    Args:
        df: DataFrame containing threat events to store.

    Returns:
        int: Total number of records saved in storage.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if df.empty:
        if DATA_FILE.exists():
            return len(pd.read_csv(DATA_FILE))
        return 0

    # Align columns to standard schema
    for col in STANDARD_COLUMNS:
        if col not in df.columns:
            df[col] = ""
    df = df[STANDARD_COLUMNS]

    if DATA_FILE.exists() and DATA_FILE.stat().st_size > 0:
        existing_df = pd.read_csv(DATA_FILE)
        combined_df = pd.concat([existing_df, df], ignore_index=True)
        # Deduplicate by id and source
        dedup_df = combined_df.drop_duplicates(subset=["id", "source"], keep="last")
    else:
        dedup_df = df.drop_duplicates(subset=["id", "source"], keep="last")

    dedup_df.to_csv(DATA_FILE, index=False)
    return len(dedup_df)


def load_events() -> pd.DataFrame:
    """Load threat events from CSV storage.

    Returns:
        pd.DataFrame: DataFrame of stored threat events or empty DataFrame if none exist.
    """
    if DATA_FILE.exists() and DATA_FILE.stat().st_size > 0:
        return pd.read_csv(DATA_FILE)
    return pd.DataFrame(columns=STANDARD_COLUMNS)
