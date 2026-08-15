"""Taxonomy module for categorizing threat events into canonical categories."""

import re
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


def severity(df: pd.DataFrame) -> pd.DataFrame:
    """Add a `severity` column to the DataFrame.
    - AbuseIPDB: derived from abuseConfidenceScore in `tags`.
      Buckets: 'high' (>=90), 'medium' (50-89), 'low' (<50).
    - URLhaus: derived from tag keywords in `tags` and `raw_threat_tag`.
    - Other sources: default to 'unknown'.

    Args:
        df: Input DataFrame containing threat data.

    Returns:
        pd.DataFrame: DataFrame with populated `severity` column.
    """
    if df.empty:
        df = df.copy()
        df["severity"] = []
        return df

    df = df.copy()
    severities = []

    for _, row in df.iterrows():
        source_val = str(row.get("source", "")).strip().lower()
        tags_lower = str(row.get("tags", "")).lower() + " " + str(row.get("raw_threat_tag", "")).lower()

        if source_val == "abuseipdb":
            tags_val = str(row.get("tags", ""))
            score = None
            if "confidence_" in tags_val:
                try:
                    score_str = tags_val.split("confidence_")[-1].split()[0]
                    score = int(score_str)
                except (ValueError, IndexError):
                    score = None

            if score is not None:
                if score >= 90:
                    sev = "high"
                elif score >= 50:
                    sev = "medium"
                else:
                    sev = "low"
            else:
                sev = "unknown"

        elif source_val == "urlhaus":
            # Extraction des tokens avec séparateurs: virgule, espace, tiret
            tokens = {t.strip() for t in re.split(r"[,\s\-]+", tags_lower) if t.strip()}

            # High: RATs, stealers, ransomware — compromission critique
            high_exact = {
                "rat", "remcos", "agenttesla", "formbook", "asyncrat",
                "qakbot", "xworm", "lokibot", "emotet", "njrat",
                "quasarrat", "quasar", "vidar", "redline", "lumma",
            }
            # Medium: botnets, droppers, loaders, trojans — menaces automatisées
            medium_exact = {
                "mirai", "mozi", "tsunami", "amadey", "gafgyt",
            }
            # Low: social engineering / nuisances / adware
            low_exact = {
                "clearfake", "phish", "spam", "adware",
            }

            if any(
                t in high_exact 
                or t.endswith("rat") 
                or "stealer" in t 
                or "ransomware" in t 
                for t in tokens
            ):
                sev = "high"
            elif any(
                t in medium_exact 
                or "botnet" in t 
                or "loader" in t 
                or "trojan" in t 
                or "dropper" in t 
                for t in tokens
            ):
                sev = "medium"
            elif any(t in low_exact or t.startswith("adware") for t in tokens):
                sev = "low"
            else:
                sev = "unknown"

        else:
            sev = "unknown"

        severities.append(sev)

    df["severity"] = severities
    return df


def sector_hint(df: pd.DataFrame) -> pd.DataFrame:
    """Add a `sector_hint` column to the DataFrame based on keyword matching on indicator_value and tags.
    Keywords:
        - ecommerce: wordpress, prestashop, woocommerce, shop
        - banking: bank, banque, paiement
        - government: .gov.ma, gouv
    Defaults to 'unknown' if no keywords match.

    Args:
        df: Input DataFrame containing threat data.

    Returns:
        pd.DataFrame: DataFrame with populated `sector_hint` column.
    """
    if df.empty:
        df = df.copy()
        df["sector_hint"] = []
        return df

    df = df.copy()
    sector_hints = []

    sector_map = {
        "ecommerce": ["wordpress", "prestashop", "woocommerce", "shop"],
        "banking": ["bank", "banque", "paiement"],
        "government": [".gov.ma", "gouv"],
    }

    for _, row in df.iterrows():
        indicator_str = str(row.get("indicator_value", "")).lower()
        tags_str = str(row.get("tags", "")).lower()
        combined_text = f"{indicator_str} {tags_str}"

        matched_sector = "unknown"
        for sector, keywords in sector_map.items():
            if any(kw in combined_text for kw in keywords):
                matched_sector = sector
                break

        sector_hints.append(matched_sector)

    df["sector_hint"] = sector_hints
    return df



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
    df_cat = categorize(df)
    return severity(df_cat)
