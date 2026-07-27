"""Taxonomy module for categorizing threat events into canonical categories."""

import pandas as pd

# Canonical category key definitions
CAT_PHISHING = "phishing"
CAT_MALWARE = "ransomware_malware"
CAT_WEB_ATTACK = "web_attack"
CAT_DDOS = "ddos_extortion"

# Keyword dictionary mapping threat keywords/tags to one of 4 canonical categories
THREAT_KEYWORD_MAP = {
    CAT_PHISHING: [
        "phish",
        "credential",
        "login",
        "bank",
        "spoof",
        "hameçonnage",
        "fake-page",
        "account",
    ],
    CAT_WEB_ATTACK: [
        "web",
        "injection",
        "sqli",
        "xss",
        "webshell",
        "exploit",
        "owasp",
        "command-execution",
        "rce",
    ],
    CAT_DDOS: [
        "ddos",
        "dos",
        "extortion",
        "flood",
        "amplification",
    ],
    CAT_MALWARE: [
        "malware",
        "ransomware",
        "trojan",
        "virus",
        "dropper",
        "payload",
        "botnet",
        "emotet",
        "lokibot",
        "agenttesla",
        "formbook",
        "asyncrat",
        "remcos",
        "qakbot",
        "exe",
        "elf",
        "apk",
        "rat",
        "stealer",
    ],
}


def categorize_text(text: str) -> str:
    """Categorize text string into one of 4 canonical threat categories.
    Defaults to 'ransomware_malware' if no keywords match.
    """
    text_lower = str(text).lower()

    # Check categories in priority order
    for cat in [CAT_PHISHING, CAT_WEB_ATTACK, CAT_DDOS, CAT_MALWARE]:
        keywords = THREAT_KEYWORD_MAP[cat]
        if any(kw in text_lower for kw in keywords):
            return cat

    # Default to ransomware_malware
    return CAT_MALWARE


def categorize(df: pd.DataFrame) -> pd.DataFrame:
    """Add a `category` column to the DataFrame using the keyword dictionary.
    Checks `tags` first, falling back to `raw_threat_tag`, then `indicator_value`,
    and finally defaulting to `ransomware_malware`.

    Args:
        df: DataFrame containing threat data.

    Returns:
        pd.DataFrame: DataFrame with updated `category` column.
    """
    if df.empty:
        df = df.copy()
        df["category"] = []
        return df

    df = df.copy()
    categories = []

    for _, row in df.iterrows():
        tags_str = str(row.get("tags", "")) if pd.notna(row.get("tags")) else ""
        raw_tag_str = str(row.get("raw_threat_tag", row.get("threat_type", ""))) if pd.notna(row.get("raw_threat_tag", row.get("threat_type"))) else ""
        indicator_str = str(row.get("indicator_value", row.get("url", ""))) if pd.notna(row.get("indicator_value", row.get("url"))) else ""

        # Step 1: Check tags first
        cat = None
        if tags_str.strip():
            for c in [CAT_PHISHING, CAT_WEB_ATTACK, CAT_DDOS, CAT_MALWARE]:
                if any(kw in tags_str.lower() for kw in THREAT_KEYWORD_MAP[c]):
                    cat = c
                    break

        # Step 2: Fall back to raw_threat_tag
        if not cat and raw_tag_str.strip():
            for c in [CAT_PHISHING, CAT_WEB_ATTACK, CAT_DDOS, CAT_MALWARE]:
                if any(kw in raw_tag_str.lower() for kw in THREAT_KEYWORD_MAP[c]):
                    cat = c
                    break

        # Step 3: Fall back to indicator_value / URL
        if not cat and indicator_str.strip():
            for c in [CAT_PHISHING, CAT_WEB_ATTACK, CAT_DDOS, CAT_MALWARE]:
                if any(kw in indicator_str.lower() for kw in THREAT_KEYWORD_MAP[c]):
                    cat = c
                    break

        # Step 4: Source-aware fallback defaults
        # Judgment Call: AbuseIPDB blacklists lack tag fields; IP blacklists correlate strongly
        # with brute-force / DDoS / botnet activity rather than URL malware downloads.
        # Therefore, default abuseipdb events to ddos_extortion, while keeping ransomware_malware
        # as default for urlhaus.
        if not cat:
            source_val = str(row.get("source", "")).strip().lower()
            if source_val == "abuseipdb":
                cat = CAT_DDOS
            else:
                cat = CAT_MALWARE

        categories.append(cat)

    df["category"] = categories
    return df




def classify_threat(threat_type: str = "", tags: str = "", url: str = "") -> str:
    """Legacy helper for classification."""
    return categorize_text(f"{threat_type} {tags} {url}")


def enrich_with_taxonomy(df: pd.DataFrame) -> pd.DataFrame:
    """Enrich DataFrame using taxonomy categorization."""
    return categorize(df)
