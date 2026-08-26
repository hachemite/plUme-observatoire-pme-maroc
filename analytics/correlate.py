"""Cross-source threat intelligence correlation and corroboration module.

Extracts network hosts/IPs across heterogeneous feeds (e.g. URLhaus malware URLs
vs. AbuseIPDB malicious IP reports) to detect multi-source corroborated threats.
"""

import re
from typing import Optional, Set
from urllib.parse import urlparse
import pandas as pd

# Regex matching standard IPv4 addresses (4 octets between 0-255)
IPV4_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


def extract_host_or_ip(value: str) -> str:
    """Extract host or IPv4 address from a raw indicator string (URL or IP).

    Handles URLs with/without schemes, custom ports, userinfo, paths, and query strings.

    Args:
        value (str): Raw indicator string (e.g. 'http://192.168.1.1:8080/bin.sh' or '1.1.1.1').

    Returns:
        str: Extracted lowercase hostname or IP address without port/path.
    """
    if not isinstance(value, str) or not value.strip():
        return ""

    raw = value.strip()

    # If it is already a direct IPv4 string, return it stripped
    if IPV4_REGEX.match(raw):
        return raw.lower()

    # Otherwise parse as URL
    url_to_parse = raw if "://" in raw else "http://" + raw
    try:
        parsed = urlparse(url_to_parse)
        netloc = parsed.netloc or parsed.path.split("/")[0]
        # Remove userinfo (user:pass@)
        if "@" in netloc:
            netloc = netloc.split("@")[-1]
        # Remove port (:8080)
        host = netloc.split(":")[0].strip().lower()
        return host
    except Exception:
        return ""


def find_cross_source_matches(df: pd.DataFrame) -> pd.DataFrame:
    """Identify cross-source corroborated indicators matching between feeds.

    Extracts IPs from URLhaus malware distribution URLs and performs an inner join
    against AbuseIPDB reported malicious IP addresses.

    Args:
        df (pd.DataFrame): Threat events DataFrame containing 'source' and 'indicator_value'.

    Returns:
        pd.DataFrame: Merged DataFrame of matching event pairs with metadata from both sources.
    """
    if df.empty or "source" not in df.columns or "indicator_value" not in df.columns:
        return pd.DataFrame()

    # Split datasets by source
    urlhaus_mask = df["source"].astype(str).str.lower() == "urlhaus"
    abuse_mask = df["source"].astype(str).str.lower() == "abuseipdb"

    urlhaus_df = df[urlhaus_mask].copy()
    abuse_df = df[abuse_mask].copy()

    if urlhaus_df.empty or abuse_df.empty:
        return pd.DataFrame()

    # Extract normalized host/IP for joining
    urlhaus_df["matched_ip"] = urlhaus_df["indicator_value"].apply(extract_host_or_ip)
    abuse_df["matched_ip"] = abuse_df["indicator_value"].apply(extract_host_or_ip)

    # Filter to valid IPv4 matches only
    urlhaus_df = urlhaus_df[urlhaus_df["matched_ip"].apply(lambda ip: bool(IPV4_REGEX.match(ip)))]
    abuse_df = abuse_df[abuse_df["matched_ip"].apply(lambda ip: bool(IPV4_REGEX.match(ip)))]

    if urlhaus_df.empty or abuse_df.empty:
        return pd.DataFrame()

    # Inner join on matched_ip
    matches = pd.merge(
        urlhaus_df,
        abuse_df,
        on="matched_ip",
        suffixes=("_urlhaus", "_abuseipdb"),
    )

    return matches


def get_confirmed_cross_source_ips(df: pd.DataFrame) -> Set[str]:
    """Retrieve the set of unique IP addresses corroborated across multiple sources.

    Args:
        df (pd.DataFrame): Threat events DataFrame.

    Returns:
        Set[str]: Set of unique corroborated IP address strings.
    """
    matches = find_cross_source_matches(df)
    if matches.empty or "matched_ip" not in matches.columns:
        return set()
    return set(matches["matched_ip"].dropna().unique())


def tag_cross_source_confirmed(df: pd.DataFrame) -> pd.DataFrame:
    """Add 'cross_source_confirmed' boolean column to the events DataFrame.

    A row is marked True if its indicator value (or extracted host) is corroborated
    across both URLhaus and AbuseIPDB feeds.

    Args:
        df (pd.DataFrame): Threat events DataFrame.

    Returns:
        pd.DataFrame: DataFrame copy enriched with 'cross_source_confirmed' column.
    """
    if df.empty:
        res = df.copy()
        res["cross_source_confirmed"] = pd.Series(dtype=bool)
        return res

    confirmed_ips = get_confirmed_cross_source_ips(df)
    res = df.copy()

    # Determine confirmation for each row
    extracted_hosts = res["indicator_value"].apply(extract_host_or_ip)
    res["cross_source_confirmed"] = extracted_hosts.isin(confirmed_ips)
    return res
