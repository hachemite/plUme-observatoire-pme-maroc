"""Taxonomy module for categorizing threat events according to the AUSIM/CMRPI guide."""

import pandas as pd

# Priority threat categories for Moroccan SMEs (AUSIM/CMRPI Guide)
CAT_PHISHING = "Phishing / ingénierie sociale / credential theft"
CAT_MALWARE = "Ransomware / malware"
CAT_WEB_ATTACK = "Attaques web / injection"
CAT_DDOS = "DDoS / extorsion"
CAT_OTHER = "Autre"

# Primary sector mapping for Moroccan SMEs
SECTOR_MAP = {
    CAT_PHISHING: "Banque / Finance",
    CAT_MALWARE: "Services",
    CAT_WEB_ATTACK: "Commerce / E-commerce",
    CAT_DDOS: "Commerce / E-commerce",
    CAT_OTHER: "Général",
}


def classify_threat(threat_type: str = "", tags: str = "", url: str = "") -> str:
    """Classify a threat into an AUSIM category based on threat type, tags, and URL.

    Args:
        threat_type: Raw threat classification string.
        tags: Tags associated with the threat indicator.
        url: Threat indicator URL.

    Returns:
        str: Mapped AUSIM category name.
    """
    text = f"{threat_type} {tags} {url}".lower()

    # Phishing / Credential theft keywords
    if any(
        kw in text
        for kw in [
            "phish",
            "credential",
            "login",
            "bank",
            "spoof",
            "hameçonnage",
            "fake-page",
            "account",
        ]
    ):
        return CAT_PHISHING

    # Ransomware / Malware keywords
    if any(
        kw in text
        for kw in [
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
        ]
    ):
        return CAT_MALWARE

    # Web attack / injection / OWASP keywords
    if any(
        kw in text
        for kw in [
            "web",
            "injection",
            "sqli",
            "xss",
            "webshell",
            "exploit",
            "owasp",
            "command-execution",
            "rce",
        ]
    ):
        return CAT_WEB_ATTACK

    # DDoS / Extorsion keywords
    if any(kw in text for kw in ["ddos", "dos", "extortion", "flood", "amplification"]):
        return CAT_DDOS

    return CAT_OTHER


def map_target_sector(category: str) -> str:
    """Map an AUSIM threat category to the most vulnerable Moroccan SME sector.

    Args:
        category: AUSIM threat category.

    Returns:
        str: Target SME sector name.
    """
    return SECTOR_MAP.get(category, "Général")


def enrich_with_taxonomy(df: pd.DataFrame) -> pd.DataFrame:
    """Enrich DataFrame with AUSIM category and target sector classifications.

    Args:
        df: DataFrame containing threat events.

    Returns:
        pd.DataFrame: Enriched DataFrame with 'category' and 'target_sector'.
    """
    if df.empty:
        return df

    df = df.copy()
    categories = []
    sectors = []

    for _, row in df.iterrows():
        cat = classify_threat(
            threat_type=str(row.get("threat_type", "")),
            tags=str(row.get("tags", "")),
            url=str(row.get("url", "")),
        )
        sec = map_target_sector(cat)
        categories.append(cat)
        sectors.append(sec)

    df["category"] = categories
    df["target_sector"] = sectors
    return df
