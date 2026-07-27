"""Tests for storage/repository.py module."""

import os
import pandas as pd
import pytest
from storage import repository


@pytest.fixture(autouse=True)
def isolate_data_dir(tmp_path, monkeypatch):
    """Fixture ensuring save_events and load_events operate in a temporary directory."""
    temp_data_dir = tmp_path / "data"
    temp_data_file = temp_data_dir / "threat_events.csv"

    monkeypatch.setattr(repository, "DATA_DIR", temp_data_dir)
    monkeypatch.setattr(repository, "DATA_FILE", temp_data_file)
    return temp_data_file


def test_save_events_creates_file_with_correct_header():
    """Test that save_events() creates a file with correct header when none exists."""
    df_sample = pd.DataFrame([
        {
            "event_id": "test_1",
            "source": "test_source",
            "date_added": "2026-07-27 00:00:00",
            "indicator_type": "url",
            "indicator_value": "http://example.com",
            "raw_threat_tag": "malware",
            "tags": "test",
            "status": "online",
            "category": "ransomware_malware",
            "severity": "unknown",
        }
    ])

    repository.save_events(df_sample)

    assert repository.DATA_FILE.exists()
    df_loaded = pd.read_csv(repository.DATA_FILE)
    assert list(df_loaded.columns) == repository.STANDARD_COLUMNS
    assert len(df_loaded) == 1
    assert df_loaded.iloc[0]["event_id"] == "test_1"


def test_save_events_deduplication():
    """Test that calling save_events() twice with overlapping (indicator_value, source, date_added) does not duplicate rows."""
    row = {
        "event_id": "test_dup",
        "source": "test_source",
        "date_added": "2026-07-27 00:00:00",
        "indicator_type": "url",
        "indicator_value": "http://duplicate.com",
        "raw_threat_tag": "phishing",
        "tags": "phish",
        "status": "online",
        "category": "phishing",
        "severity": "unknown",
    }

    df1 = pd.DataFrame([row])
    repository.save_events(df1)
    assert len(repository.load_events()) == 1

    # Call save_events a second time with exact same dedup key
    df2 = pd.DataFrame([row])
    repository.save_events(df2)
    assert len(repository.load_events()) == 1


def test_load_events_on_missing_file():
    """Test that load_events() on a missing file returns an empty DataFrame with right columns, not an error."""
    if repository.DATA_FILE.exists():
        os.remove(repository.DATA_FILE)

    df_empty = repository.load_events()
    assert isinstance(df_empty, pd.DataFrame)
    assert df_empty.empty
    assert list(df_empty.columns) == repository.STANDARD_COLUMNS
