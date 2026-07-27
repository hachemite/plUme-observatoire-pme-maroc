"""Validation module defining Pydantic schemas per threat data source."""

from datetime import datetime
from typing import Literal, Optional
import pandas as pd
from pydantic import BaseModel, Field, ValidationError


class ThreatEvent(BaseModel):
    """Pydantic model representing a single validated threat event."""

    event_id: str
    source: str
    date_added: datetime
    indicator_type: Literal["url"]
    indicator_value: str
    raw_threat_tag: str
    tags: str = ""
    status: Literal["online", "offline", "reported"]




class URLhausRow(BaseModel):
    """Raw record schema for URLhaus CSV feed."""

    id: str
    dateadded: str
    url: str
    url_status: str
    threat: str
    tags: Optional[str] = ""
    reporter: Optional[str] = ""


class ThreatEventSchema(BaseModel):
    """Normalized schema for threat events in the observatory."""

    id: str
    source: str = "urlhaus"
    url: str
    url_status: str = "unknown"
    threat_type: str = "unknown"
    tags: str = ""
    date_added: str = ""
    reporter: str = "anonymous"
    category: str = "Autre"
    target_sector: str = "Général"


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


def validate_urlhaus_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Validate and normalize a URLhaus DataFrame using Pydantic schemas.

    Args:
        df: Raw DataFrame parsed from URLhaus CSV.

    Returns:
        pd.DataFrame: Cleaned and validated DataFrame matching normalized columns.
    """
    if df.empty:
        return pd.DataFrame(
            columns=[
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
        )

    # Standardize column names from URLhaus feed (strip whitespace/quotes)
    df = df.copy()
    df.columns = [str(c).strip().strip('"# ').lower() for c in df.columns]

    # Map column names if needed
    col_map = {
        "date_added": "dateadded",
        "last_online": "last_online",
        "urlhaus_link": "urlhaus_link",
    }
    df = df.rename(columns=col_map)

    valid_records = []
    for idx, row in df.iterrows():
        try:
            raw_data = {
                "id": str(row.get("id", "")).strip(),
                "dateadded": str(row.get("dateadded", "")).strip(),
                "url": str(row.get("url", "")).strip(),
                "url_status": str(row.get("url_status", "unknown")).strip(),
                "threat": str(row.get("threat", "unknown")).strip(),
                "tags": str(row.get("tags", "")).strip() if pd.notna(row.get("tags")) else "",
                "reporter": str(row.get("reporter", "anonymous")).strip()
                if pd.notna(row.get("reporter"))
                else "anonymous",
            }
            # Skip invalid rows without URL or ID
            if not raw_data["url"] or not raw_data["id"] or raw_data["id"] == "nan":
                continue

            validated_raw = URLhausRow(**raw_data)
            normalized = ThreatEventSchema(
                id=validated_raw.id,
                source="urlhaus",
                url=validated_raw.url,
                url_status=validated_raw.url_status,
                threat_type=validated_raw.threat,
                tags=validated_raw.tags or "",
                date_added=validated_raw.dateadded,
                reporter=validated_raw.reporter or "anonymous",
            )
            valid_records.append(normalized.model_dump())
        except (ValidationError, Exception) as exc:
            print(f"[Validation Warning] Skipping URLhaus row {idx}: {exc}")
            continue

    return pd.DataFrame(valid_records)
