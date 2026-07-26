"""Validation module defining Pydantic schemas per threat data source."""

from typing import List, Optional
import pandas as pd
from pydantic import BaseModel, Field, ValidationError


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
    for _, row in df.iterrows():
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
        except (ValidationError, Exception):
            continue

    return pd.DataFrame(valid_records)
