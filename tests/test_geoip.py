"""Unit tests for analytics/geoip.py offline GeoIP geolocation module."""

import pandas as pd
import pytest
from analytics.geoip import tag_country, tag_dataframe_countries


def test_tag_country_known_morocco_ips():
    """Known Moroccan telecom/ISP CIDRs resolve to MA."""
    assert tag_country("105.154.20.1") == "MA"
    assert tag_country("196.200.150.5") == "MA"
    assert tag_country("41.140.10.20") == "MA"


def test_tag_country_known_foreign_ips():
    """Known foreign cloud/ISP IP ranges resolve correctly."""
    assert tag_country("8.8.8.8") == "US"
    assert tag_country("182.122.239.67") == "CN"
    assert tag_country("42.177.240.94") == "CN"
    assert tag_country("45.148.10.157") == "NL"


def test_tag_country_invalid_inputs():
    """Non-IP strings, empty strings, and None return None."""
    assert tag_country("") is None
    assert tag_country(None) is None
    assert tag_country("invalid_ip") is None
    assert tag_country("999.999.999.999") is None


def test_tag_dataframe_countries_enrichment():
    """DataFrame enrichment preserves existing codes and resolves URLs and raw IPs."""
    sample_df = pd.DataFrame([
        {
            "source": "abuseipdb",
            "indicator_value": "45.148.10.157",
            "country_code": "NL",
        },
        {
            "source": "urlhaus",
            "indicator_value": "http://105.154.20.1:8080/malware.sh",
            "country_code": None,
        },
        {
            "source": "urlhaus",
            "indicator_value": "http://182.122.239.67/bin.sh",
            "country_code": "unknown",
        },
        {
            "source": "urlhaus",
            "indicator_value": "https://unknown-domain.top/payload.exe",
            "country_code": None,
        },
    ])

    enriched = tag_dataframe_countries(sample_df)
    assert enriched.loc[0, "country_code"] == "NL"
    assert enriched.loc[1, "country_code"] == "MA"
    assert enriched.loc[2, "country_code"] == "CN"
    assert enriched.loc[3, "country_code"] == "unknown"
