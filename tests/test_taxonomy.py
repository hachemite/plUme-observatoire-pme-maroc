"""Tests for processing/taxonomy.py module."""

import pandas as pd
import pytest
from processing.taxonomy import categorize


def test_row_with_phishing_tag_categorizes_as_phishing():
    """Test that a row with tags='phishing' categorizes as 'phishing'."""
    df_phish = pd.DataFrame([
        {
            "event_id": "test_p1",
            "source": "urlhaus",
            "date_added": "2026-07-27 00:00:00",
            "indicator_type": "url",
            "indicator_value": "http://fake-login-bank.com",
            "raw_threat_tag": "unknown",
            "tags": "phishing,credential_stealer",
            "status": "online",
        }
    ])

    result_df = categorize(df_phish)
    assert result_df.iloc[0]["category"] == "phishing"


def test_urlhaus_row_no_keyword_match_defaults_to_ransomware_malware():
    """Test that a urlhaus row with no keyword match defaults to 'ransomware_malware'."""
    df_urlhaus_unknown = pd.DataFrame([
        {
            "event_id": "test_u1",
            "source": "urlhaus",
            "date_added": "2026-07-27 00:00:00",
            "indicator_type": "url",
            "indicator_value": "http://xyz123abc-no-match.com",
            "raw_threat_tag": "unknown_tag_xyz",
            "tags": "",
            "status": "online",
        }
    ])

    result_df = categorize(df_urlhaus_unknown)
    assert result_df.iloc[0]["category"] == "ransomware_malware"


def test_abuseipdb_row_no_keyword_match_defaults_to_ddos_extortion():
    """Test that an abuseipdb row with no keyword match defaults to 'ddos_extortion'."""
    df_abuse_unknown = pd.DataFrame([
        {
            "event_id": "test_a1",
            "source": "abuseipdb",
            "date_added": "2026-07-27 00:00:00",
            "indicator_type": "ip",
            "indicator_value": "192.168.1.1",
            "raw_threat_tag": "abuse_reported",
            "tags": "confidence_100",
            "status": "reported",
        }
    ])

    result_df = categorize(df_abuse_unknown)
    assert result_df.iloc[0]["category"] == "ddos_extortion"
