"""Tests for processing/validate.py module."""

import pandas as pd
import pytest
from datetime import datetime
from processing.validate import ThreatEvent, validate_rows


def test_well_formed_row_passes_validation():
    """Test that a well-formed dictionary passes ThreatEvent validation."""
    valid_data = {
        "event_id": "test_100",
        "source": "urlhaus",
        "date_added": datetime(2026, 7, 27, 0, 0, 0),
        "indicator_type": "url",
        "indicator_value": "http://clean-test.com",
        "raw_threat_tag": "phishing",
        "tags": "test_tag",
        "status": "online",
    }

    event = ThreatEvent(**valid_data)
    assert event.event_id == "test_100"
    assert event.source == "urlhaus"
    assert event.indicator_value == "http://clean-test.com"


def test_row_missing_indicator_value_is_dropped():
    """Test that a row missing indicator_value is dropped by validate_rows(), not raised."""
    bad_df = pd.DataFrame([
        {
            "event_id": "test_bad",
            "source": "urlhaus",
            "date_added": "2026-07-27 00:00:00",
            "indicator_type": "url",
            # indicator_value / url is missing or None
            "raw_threat_tag": "malware",
            "status": "online",
        }
    ])
    # Set indicator_value to None explicitly so Pydantic validation fails
    bad_df["indicator_value"] = None

    clean_df = validate_rows(bad_df)
    assert isinstance(clean_df, pd.DataFrame)
    assert clean_df.empty


def test_validate_rows_on_empty_dataframe():
    """Test that validate_rows() on an empty DataFrame returns an empty DataFrame and doesn't crash."""
    empty_df = pd.DataFrame()
    result_df = validate_rows(empty_df)
    assert isinstance(result_df, pd.DataFrame)
    assert result_df.empty
