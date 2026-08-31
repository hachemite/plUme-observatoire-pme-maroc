"""Risk scoring engine for cybersecurity threat indicators.

Computes a normalized composite risk score (0.0 to 100.0) combining:
- Severity level (40% weight - potential business impact)
- Recurrence frequency (30% weight - campaign persistence)
- Cross-source confirmation (20% weight - multi-feed corroboration)
- Threat category taxonomy (10% weight - inherent attack vector risk)
"""

from typing import Any, Dict, Optional, Union
import numpy as np
import pandas as pd

# Weight allocations (sum = 1.0)
WEIGHT_SEVERITY = 0.40
WEIGHT_RECURRENCE = 0.30
WEIGHT_CROSS_SOURCE = 0.20
WEIGHT_CATEGORY = 0.10

# Severity weights (aligned with CVSS / business impact severity)
SEVERITY_WEIGHTS: Dict[str, float] = {
    "critical": 1.00,
    "high": 0.75,
    "medium": 0.50,
    "low": 0.25,
    "unknown": 0.10,
}

# Category weights (AUSIM taxonomy - ransomware and DDoS pose highest operational stoppage risk)
CATEGORY_WEIGHTS: Dict[str, float] = {
    "ransomware_malware": 1.00,
    "ddos_extortion": 0.80,
    "web_attack": 0.70,
    "phishing": 0.60,
    "unknown": 0.30,
}

# Benchmark maximum recurrence count observed in telemetry for normalization
MAX_RECURRENCE_BENCHMARK = 5.0


def compute_risk_score(
    row: Union[pd.Series, Dict[str, Any]],
    max_recurrence: float = MAX_RECURRENCE_BENCHMARK,
) -> float:
    """Compute composite threat risk score for an indicator record.

    Mathematical Rationale:
    ----------------------
    risk_score = 100 * [
        (W_sev * severity_weight) +
        (W_rec * normalized_recurrence) +
        (W_cross * cross_source_confirmed) +
        (W_cat * category_weight)
    ]

    Weights Rationale (Defensible in Academic / Industrial Viva):
    1. Severity (40%): Direct measure of potential damage / business disruption.
       A critical malware or botnet payload threatens core operations regardless of frequency.
    2. Recurrence (30%): Indicates sustained campaign persistence. Recurring infrastructure
       represents ongoing adversary investment and higher exposure probability for SMEs.
    3. Cross-Source Corroboration (20%): Verification across independent threat feeds
       (e.g., URLhaus distribution URLs + AbuseIPDB network abuse) eliminates false positives
       and confirms active multi-vector threat infrastructure.
    4. Category (10%): Threat taxonomy risk factor reflecting operational stoppage threat
       (Ransomware > DDoS > Web Attacks > Phishing).

    Args:
        row: Series or Dict with 'severity', 'category', 'occurrences' (or count), and 'cross_source_confirmed'.
        max_recurrence: Upper bound for recurrence count normalization (default: 5.0).

    Returns:
        float: Rounded composite risk score between 0.0 and 100.0.
    """
    # 1. Severity weight
    sev_raw = str(row.get("severity", "unknown")).strip().lower()
    sev_w = SEVERITY_WEIGHTS.get(sev_raw, SEVERITY_WEIGHTS["unknown"])

    # 2. Recurrence count normalization (capped at 1.0)
    occ_val = row.get("occurrences", row.get("count", 1))
    try:
        occ_float = float(occ_val) if occ_val is not None else 1.0
    except (ValueError, TypeError):
        occ_float = 1.0
    rec_norm = min(1.0, max(0.0, occ_float / max_recurrence)) if max_recurrence > 0 else 0.0

    # 3. Cross-source confirmation
    cross_val = row.get("cross_source_confirmed", False)
    cross_w = 1.0 if bool(cross_val) else 0.0

    # 4. Category weight
    cat_raw = str(row.get("category", "unknown")).strip().lower()
    cat_w = CATEGORY_WEIGHTS.get(cat_raw, CATEGORY_WEIGHTS["unknown"])

    # Composite weighted calculation
    score = (
        (WEIGHT_SEVERITY * sev_w)
        + (WEIGHT_RECURRENCE * rec_norm)
        + (WEIGHT_CROSS_SOURCE * cross_w)
        + (WEIGHT_CATEGORY * cat_w)
    )

    return round(float(score * 100.0), 1)


def score_indicators_dataframe(
    df: pd.DataFrame,
    max_recurrence: Optional[float] = None,
) -> pd.DataFrame:
    """Enrich an events or aggregated indicators DataFrame with risk scores.

    Args:
        df (pd.DataFrame): Input DataFrame.
        max_recurrence: Optional custom normalization upper bound. If None, computes from data.

    Returns:
        pd.DataFrame: DataFrame copy enriched with 'risk_score' column.
    """
    if df.empty:
        res = df.copy()
        res["risk_score"] = pd.Series(dtype=float)
        return res

    res = df.copy()
    
    # If occurrences column is absent, compute per-indicator counts
    if "occurrences" not in res.columns:
        if "indicator_value" in res.columns:
            counts = res["indicator_value"].map(res["indicator_value"].value_counts())
            res["occurrences"] = counts.fillna(1).astype(int)
        else:
            res["occurrences"] = 1

    benchmark = max_recurrence if max_recurrence is not None else float(res["occurrences"].max())
    if benchmark <= 0:
        benchmark = MAX_RECURRENCE_BENCHMARK

    res["risk_score"] = res.apply(
        lambda r: compute_risk_score(r, max_recurrence=benchmark),
        axis=1,
    )
    return res
