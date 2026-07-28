"""Validation module defining Pydantic schemas per threat data source."""

from datetime import datetime
from typing import Literal
import pandas as pd
from pydantic import BaseModel, Field, ValidationError


class ThreatEvent(BaseModel):
    """Pydantic model representing a single validated threat event."""

    event_id: str
    source: str
    date_added: datetime
    indicator_type: Literal["url", "ip"]
    indicator_value: str
    raw_threat_tag: str
    tags: str = ""
    country_code: str = ""
    status: Literal["online", "offline", "reported"]





def validate_rows(df: pd.DataFrame) -> pd.DataFrame:
    """Validate each row against ThreatEvent model.
    Drops and prints (doesn't raise) any invalid rows, returning clean DataFrame.

    Args:
        df: Input DataFrame containing candidate threat event rows.

    Returns:
        pd.DataFrame: Clean DataFrame containing only valid rows.
    """
    if df.empty:
        return pd.DataFrame()

    valid_records = []

    for idx, row in df.iterrows():
        try:
            record_dict = row.to_dict()
            # Map alternative column names if present
            if "event_id" not in record_dict and "id" in record_dict:
                record_dict["event_id"] = str(record_dict["id"])
            if "indicator_value" not in record_dict and "url" in record_dict:
                record_dict["indicator_value"] = str(record_dict["url"])
            if "indicator_type" not in record_dict:
                record_dict["indicator_type"] = "url"
            if "raw_threat_tag" not in record_dict:
                record_dict["raw_threat_tag"] = str(record_dict.get("threat_type", record_dict.get("threat", "")))
            if "status" not in record_dict:
                status_val = str(record_dict.get("url_status", "offline")).lower()
                record_dict["status"] = "online" if status_val == "online" else "offline"
            if "source" not in record_dict:
                record_dict["source"] = "urlhaus"

            event = ThreatEvent(**record_dict)
            valid_records.append(event.model_dump())
        except (ValidationError, Exception) as exc:
            print(f"[Validation Warning] Row {idx} dropped due to validation error: {exc}")

    return pd.DataFrame(valid_records)
