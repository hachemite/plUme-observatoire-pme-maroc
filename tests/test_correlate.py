"""Unit tests for analytics/correlate.py cross-source correlation module."""

import pandas as pd
import pytest
from analytics.correlate import (
    extract_host_or_ip,
    find_cross_source_matches,
    get_confirmed_cross_source_ips,
    tag_cross_source_confirmed,
)


def test_extract_host_or_ip_various_formats():
    """Host/IP extraction handles URLs with ports, paths, schemes, and direct IPs."""
    assert extract_host_or_ip("http://192.168.1.50:8080/bin.sh") == "192.168.1.50"
    assert extract_host_or_ip("https://example.com/malware.exe") == "example.com"
    assert extract_host_or_ip("45.148.10.157") == "45.148.10.157"
    assert extract_host_or_ip("http://admin:pass@10.0.0.1:9000/test") == "10.0.0.1"
    assert extract_host_or_ip("") == ""
    assert extract_host_or_ip(None) == ""


def test_find_cross_source_matches_empty():
    """Empty dataframe returns an empty matches DataFrame."""
    empty_df = pd.DataFrame()
    matches = find_cross_source_matches(empty_df)
    assert matches.empty


def test_find_cross_source_matches_synthetic_matching_and_non_matching():
    """Synthetic dataset with known matching and non-matching IPs produces exact matches."""
    sample_data = pd.DataFrame([
        # URLhaus rows
        {
            "event_id": "url-1",
            "source": "urlhaus",
            "date_added": "2026-08-01 10:00:00",
            "indicator_type": "url",
            "indicator_value": "http://198.51.100.10:8080/payload.sh",
            "category": "ransomware_malware",
            "severity": "medium",
        },
        {
            "event_id": "url-2",
            "source": "urlhaus",
            "date_added": "2026-08-02 12:00:00",
            "indicator_type": "url",
            "indicator_value": "http://203.0.113.50/malware.exe",
            "category": "ransomware_malware",
            "severity": "medium",
        },
        # AbuseIPDB rows
        {
            "event_id": "abuse-1",
            "source": "abuseipdb",
            "date_added": "2026-08-01 11:00:00",
            "indicator_type": "ip",
            "indicator_value": "198.51.100.10",
            "category": "ddos_extortion",
            "severity": "high",
        },
        {
            "event_id": "abuse-2",
            "source": "abuseipdb",
            "date_added": "2026-08-03 14:00:00",
            "indicator_type": "ip",
            "indicator_value": "192.0.2.1",
            "category": "ddos_extortion",
            "severity": "high",
        },
    ])

    matches = find_cross_source_matches(sample_data)
    assert len(matches) == 1
    assert matches.iloc[0]["matched_ip"] == "198.51.100.10"
    assert matches.iloc[0]["event_id_urlhaus"] == "url-1"
    assert matches.iloc[0]["event_id_abuseipdb"] == "abuse-1"
    assert matches.iloc[0]["category_urlhaus"] == "ransomware_malware"
    assert matches.iloc[0]["category_abuseipdb"] == "ddos_extortion"


def test_tag_cross_source_confirmed():
    """tag_cross_source_confirmed properly adds boolean flags to matching rows."""
    sample_data = pd.DataFrame([
        {"source": "urlhaus", "indicator_value": "http://198.51.100.10/payload.sh"},
        {"source": "urlhaus", "indicator_value": "http://203.0.113.50/other.exe"},
        {"source": "abuseipdb", "indicator_value": "198.51.100.10"},
        {"source": "abuseipdb", "indicator_value": "192.0.2.1"},
    ])

    tagged = tag_cross_source_confirmed(sample_data)
    assert "cross_source_confirmed" in tagged.columns
    assert tagged.loc[0, "cross_source_confirmed"] == True
    assert tagged.loc[1, "cross_source_confirmed"] == False
    assert tagged.loc[2, "cross_source_confirmed"] == True
    assert tagged.loc[3, "cross_source_confirmed"] == False
