"""Tests for SQLite operational storage in storage/repository.py."""

import sqlite3
import pandas as pd
import pytest
from storage import repository


@pytest.fixture(autouse=True)
def isolate_data_dir(tmp_path, monkeypatch):
    """Fixture ensuring save_events and load_events operate in a temporary directory."""
    temp_data_dir = tmp_path / "data"
    temp_data_file = temp_data_dir / "threat_events.csv"
    temp_db_file = temp_data_dir / "db.sqlite3"

    monkeypatch.setattr(repository, "DATA_DIR", temp_data_dir)
    monkeypatch.setattr(repository, "DATA_FILE", temp_data_file)
    monkeypatch.setattr(repository, "DB_FILE", temp_db_file)
    return temp_db_file


def test_sqlite_upsert_and_lifecycle_tracking():
    """Test that first save initializes indicator lifecycle, second save increments times_seen and updates last_seen while first_seen is fixed."""
    # First save: First sighting of indicator
    df1 = pd.DataFrame([
        {
            "event_id": "evt_1",
            "source": "urlhaus",
            "date_added": "2026-07-01 10:00:00",
            "indicator_type": "url",
            "indicator_value": "http://malicious-site.example/payload.exe",
            "raw_threat_tag": "exe",
            "tags": "elf,mirai",
            "country_code": "MA",
            "status": "online",
            "category": "ransomware_malware",
            "severity": "medium",
            "sector_hint": "unknown",
        }
    ])

    repository.save_events(df1)

    indicators_df1 = repository.load_indicators()
    assert len(indicators_df1) == 1
    ioc_row1 = indicators_df1.iloc[0]
    assert ioc_row1["indicator_value"] == "http://malicious-site.example/payload.exe"
    assert ioc_row1["first_seen"] == "2026-07-01 10:00:00"
    assert ioc_row1["last_seen"] == "2026-07-01 10:00:00"
    assert ioc_row1["times_seen"] == 1
    assert ioc_row1["country_code"] == "MA"

    # Second save: Later sighting of same indicator
    df2 = pd.DataFrame([
        {
            "event_id": "evt_2",
            "source": "urlhaus",
            "date_added": "2026-08-15 18:30:00",
            "indicator_type": "url",
            "indicator_value": "http://malicious-site.example/payload.exe",
            "raw_threat_tag": "exe",
            "tags": "elf,mirai",
            "country_code": "MA",
            "status": "offline",
            "category": "ransomware_malware",
            "severity": "high",
            "sector_hint": "unknown",
        }
    ])

    repository.save_events(df2)

    indicators_df2 = repository.load_indicators()
    assert len(indicators_df2) == 1
    ioc_row2 = indicators_df2.iloc[0]
    assert ioc_row2["indicator_value"] == "http://malicious-site.example/payload.exe"
    assert ioc_row2["first_seen"] == "2026-07-01 10:00:00", "first_seen must remain fixed to earliest date"
    assert ioc_row2["last_seen"] == "2026-08-15 18:30:00", "last_seen must update to newest date"
    assert ioc_row2["times_seen"] == 2, "times_seen must increment on duplicate"
    assert ioc_row2["status"] == "offline"


def test_sqlite_collection_runs_logging():
    """Test that collection runs are logged with timestamps and row counts."""
    df = pd.DataFrame([
        {
            "event_id": "run_test_1",
            "source": "abuseipdb",
            "date_added": "2026-08-20 00:00:00",
            "indicator_type": "ip",
            "indicator_value": "192.0.2.1",
            "raw_threat_tag": "ddos",
            "tags": "ddos",
            "country_code": "US",
            "status": "online",
            "category": "ddos_extortion",
            "severity": "high",
            "sector_hint": "banking",
        }
    ])

    repository.save_events(df)

    runs_df = repository.load_collection_runs()
    assert len(runs_df) >= 1
    assert runs_df.iloc[0]["source"] == "abuseipdb"
    assert runs_df.iloc[0]["row_count"] == 1
    assert runs_df.iloc[0]["status"] == "completed"


def test_sqlite_load_events_returns_all_events():
    """Test that load_events returns event-level records from SQLite with standard columns."""
    df = pd.DataFrame([
        {
            "event_id": f"evt_{i}",
            "source": "urlhaus",
            "date_added": f"2026-08-0{i+1} 12:00:00",
            "indicator_type": "url",
            "indicator_value": f"http://sample{i}.org",
            "raw_threat_tag": "botnet",
            "tags": "bot",
            "country_code": "NL",
            "status": "online",
            "category": "ransomware_malware",
            "severity": "medium",
            "sector_hint": "unknown",
        }
        for i in range(5)
    ])

    repository.save_events(df)

    loaded = repository.load_events()
    assert len(loaded) == 5
    assert set(repository.STANDARD_COLUMNS).issubset(set(loaded.columns))
