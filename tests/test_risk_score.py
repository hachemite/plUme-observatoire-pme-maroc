"""Unit tests for analytics/risk_score.py risk scoring engine."""

import pandas as pd
import pytest
from analytics.risk_score import (
    WEIGHT_CATEGORY,
    WEIGHT_CROSS_SOURCE,
    WEIGHT_RECURRENCE,
    WEIGHT_SEVERITY,
    compute_risk_score,
    score_indicators_dataframe,
)


def test_weights_sum_to_one():
    """Formula weights must sum precisely to 1.0."""
    total_weights = WEIGHT_SEVERITY + WEIGHT_RECURRENCE + WEIGHT_CROSS_SOURCE + WEIGHT_CATEGORY
    assert pytest.approx(total_weights, 1e-6) == 1.0


def test_high_severity_cross_source_recurrent_scores_highest():
    """High/critical, cross-source confirmed, recurrent threats score highest."""
    critical_threat = {
        "severity": "critical",
        "category": "ransomware_malware",
        "occurrences": 5,
        "cross_source_confirmed": True,
    }
    score_critical = compute_risk_score(critical_threat, max_recurrence=5.0)
    assert score_critical == 100.0  # (0.4*1.0 + 0.3*1.0 + 0.2*1.0 + 0.1*1.0) * 100


def test_low_severity_one_off_unconfirmed_scores_lowest():
    """Low/unknown severity, one-off, unconfirmed threats score lowest."""
    low_threat = {
        "severity": "low",
        "category": "unknown",
        "occurrences": 1,
        "cross_source_confirmed": False,
    }
    score_low = compute_risk_score(low_threat, max_recurrence=5.0)
    # (0.4*0.25 + 0.3*(1/5) + 0.2*0.0 + 0.1*0.3) * 100 = (0.10 + 0.06 + 0.0 + 0.03) * 100 = 19.0
    assert score_low == 19.0
    assert score_low < 30.0


def test_relative_ranking_consistency():
    """Threat with cross-source confirmation scores higher than identical threat without."""
    base_threat = {
        "severity": "high",
        "category": "ddos_extortion",
        "occurrences": 2,
        "cross_source_confirmed": False,
    }
    confirmed_threat = {
        "severity": "high",
        "category": "ddos_extortion",
        "occurrences": 2,
        "cross_source_confirmed": True,
    }
    score_base = compute_risk_score(base_threat, max_recurrence=5.0)
    score_confirmed = compute_risk_score(confirmed_threat, max_recurrence=5.0)
    assert score_confirmed > score_base
    assert score_confirmed - score_base == pytest.approx(20.0, 0.1)


def test_score_indicators_dataframe_empty():
    """Empty dataframe produces valid dataframe with risk_score column."""
    empty_df = pd.DataFrame()
    res = score_indicators_dataframe(empty_df)
    assert "risk_score" in res.columns
