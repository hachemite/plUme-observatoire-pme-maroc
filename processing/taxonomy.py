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
        # Combine all relevant text fields for keyword matching
        raw_tag = str(row.get("raw_threat_tag", row.get("threat_type", row.get("tags", ""))))
        url = str(row.get("indicator_value", row.get("url", "")))
        combined_text = f"{raw_tag} {url}"

        cat = categorize_text(combined_text)
        categories.append(cat)

    df["category"] = categories
    return df


def classify_threat(threat_type: str = "", tags: str = "", url: str = "") -> str:
    """Legacy helper for classification."""
    return categorize_text(f"{threat_type} {tags} {url}")


def enrich_with_taxonomy(df: pd.DataFrame) -> pd.DataFrame:
    """Enrich DataFrame using taxonomy categorization."""
    return categorize(df)
