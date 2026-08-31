"""Offline GeoIP geolocation module for threat indicators.

Provides fast, in-memory IP-to-Country resolution using an offline CIDR block database
(data/geoip_country.csv) with integer interval binary search and LRU caching.
Eliminates external API rate limits and network latency for high-volume threat feeds.
"""

import bisect
import ipaddress
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import pandas as pd

from analytics.correlate import extract_host_or_ip, IPV4_REGEX

# In-memory lookup cache to avoid re-resolving duplicate IPs
_GEOIP_CACHE: Dict[str, Optional[str]] = {}

# Interval index: list of (start_int, end_int, country_code) sorted by start_int
_INTERVALS: List[Tuple[int, int, str]] = []
_STARTS: List[int] = []
_DB_LOADED = False


def _load_geoip_db() -> None:
    """Load and index offline GeoIP CIDR database from data/geoip_country.csv."""
    global _INTERVALS, _STARTS, _DB_LOADED
    if _DB_LOADED:
        return

    csv_path = Path(__file__).resolve().parent.parent / "data" / "geoip_country.csv"
    if not csv_path.exists():
        _DB_LOADED = True
        return

    intervals = []
    try:
        df_geo = pd.read_csv(csv_path)
        for _, row in df_geo.iterrows():
            net_str = str(row.get("network", "")).strip()
            cc = str(row.get("country_code", "")).strip().upper()
            if not net_str or not cc:
                continue
            try:
                net = ipaddress.IPv4Network(net_str, strict=False)
                start_int = int(net.network_address)
                end_int = int(net.broadcast_address)
                intervals.append((start_int, end_int, cc))
            except Exception:
                continue
    except Exception:
        pass

    intervals.sort(key=lambda x: x[0])
    _INTERVALS = intervals
    _STARTS = [x[0] for x in intervals]
    _DB_LOADED = True


def tag_country(ip: str) -> Optional[str]:
    """Resolve an IPv4 address to its ISO 3166-1 alpha-2 country code.

    Uses binary search over indexed integer intervals with LRU caching.

    Args:
        ip (str): Raw IPv4 address string (e.g. '105.154.20.1' or '45.148.10.157').

    Returns:
        Optional[str]: 2-letter uppercase country code (e.g. 'MA', 'CN', 'US') or None if unmapped.
    """
    if not ip or not isinstance(ip, str):
        return None

    cleaned_ip = ip.strip()
    if not IPV4_REGEX.match(cleaned_ip):
        return None

    # Check cache
    if cleaned_ip in _GEOIP_CACHE:
        return _GEOIP_CACHE[cleaned_ip]

    if not _DB_LOADED:
        _load_geoip_db()

    if not _INTERVALS:
        _GEOIP_CACHE[cleaned_ip] = None
        return None

    try:
        ip_int = int(ipaddress.IPv4Address(cleaned_ip))
    except Exception:
        _GEOIP_CACHE[cleaned_ip] = None
        return None

    # Binary search on interval start addresses
    idx = bisect.bisect_right(_STARTS, ip_int) - 1
    if idx >= 0:
        start_int, end_int, cc = _INTERVALS[idx]
        if start_int <= ip_int <= end_int:
            _GEOIP_CACHE[cleaned_ip] = cc
            return cc

    _GEOIP_CACHE[cleaned_ip] = None
    return None


def tag_dataframe_countries(df: pd.DataFrame) -> pd.DataFrame:
    """Enrich a threat events DataFrame with resolved country codes.

    Preserves existing native country codes from AbuseIPDB and geolocates
    extracted IP addresses for URLhaus and other unmapped records.

    Args:
        df (pd.DataFrame): Threat events DataFrame.

    Returns:
        pd.DataFrame: DataFrame copy with updated 'country_code' column.
    """
    if df.empty:
        return df.copy()

    res = df.copy()

    def resolve_row_cc(row) -> str:
        # Preserve valid existing 2-letter country code (from AbuseIPDB)
        existing = str(row.get("country_code", "")).strip().upper()
        if existing and existing not in ("NAN", "NONE", "UNKNOWN") and len(existing) == 2:
            return existing

        # Extract host or IP from indicator value
        val = str(row.get("indicator_value", ""))
        host_or_ip = extract_host_or_ip(val)
        if host_or_ip and IPV4_REGEX.match(host_or_ip):
            cc = tag_country(host_or_ip)
            if cc:
                return cc
        return "unknown"

    res["country_code"] = res.apply(resolve_row_cc, axis=1)
    return res
