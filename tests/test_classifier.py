"""Unit tests for analytics/classifier.py exploratory ML classifier."""

import pandas as pd
import pytest
from analytics.classifier import (
    FEATURE_COLUMNS,
    extract_indicator_features,
    train_category_classifier,
)


def test_extract_indicator_features_structure():
    """Feature extractor returns expected columns for URLs and IPs."""
    sample_df = pd.DataFrame([
        {
            "indicator_value": "http://192.168.1.1:8080/bin/malware.sh",
            "indicator_type": "url",
        },
        {
            "indicator_value": "45.148.10.157",
            "indicator_type": "ip",
        },
        {
            "indicator_value": "https://secure-login.bank-update.com/verify",
            "indicator_type": "url",
        },
    ])

    features = extract_indicator_features(sample_df)
    assert list(features.columns) == FEATURE_COLUMNS
    assert len(features) == 3

    # Row 0: URL with IP and port
    assert features.loc[0, "contains_raw_ip"] == 1
    assert features.loc[0, "has_port"] == 1
    assert features.loc[0, "is_type_url"] == 1

    # Row 1: Direct IP
    assert features.loc[1, "is_type_ip"] == 1
    assert features.loc[1, "contains_raw_ip"] == 1

    # Phishing domain with keywords and lifecycle fields
    assert features.loc[2, "suspicious_kw_count"] >= 2
    assert features.loc[2, "contains_raw_ip"] == 0
    assert "days_since_first_seen" in features.columns
    assert "times_seen_across_runs" in features.columns


def test_extract_indicator_features_empty():
    """Empty dataframe produces empty feature matrix with standard columns."""
    empty_df = pd.DataFrame()
    features = extract_indicator_features(empty_df)
    assert list(features.columns) == FEATURE_COLUMNS
    assert features.empty


def test_train_category_classifier_synthetic_fast():
    """Training on synthetic dataset completes rapidly and yields valid model artifacts."""
    synthetic_df = pd.DataFrame([
        # URLs -> ransomware_malware
        {"indicator_value": "http://192.168.1.50/arm4", "indicator_type": "url", "category": "ransomware_malware"},
        {"indicator_value": "http://192.168.1.50/arm5", "indicator_type": "url", "category": "ransomware_malware"},
        {"indicator_value": "http://10.0.0.1/payload.exe", "indicator_type": "url", "category": "ransomware_malware"},
        {"indicator_value": "http://10.0.0.2/bin.sh", "indicator_type": "url", "category": "ransomware_malware"},
        # IPs -> ddos_extortion
        {"indicator_value": "45.148.10.157", "indicator_type": "ip", "category": "ddos_extortion"},
        {"indicator_value": "45.148.10.147", "indicator_type": "ip", "category": "ddos_extortion"},
        {"indicator_value": "103.143.231.24", "indicator_type": "ip", "category": "ddos_extortion"},
        # Domains with login -> phishing
        {"indicator_value": "https://secure-login.portal.com/update", "indicator_type": "url", "category": "phishing"},
        {"indicator_value": "https://account-verify.service.net/login", "indicator_type": "url", "category": "phishing"},
    ])

    results = train_category_classifier(synthetic_df)
    assert results["model"] is not None
    assert results["baseline_model"] is not None
    assert results["rf_model"] is not None
    assert results["raw_accuracy"] > 0.0
    assert results["balanced_accuracy"] > 0.0
    assert not results["confusion_matrix"].empty
    assert isinstance(results["feature_importances_dt"], pd.Series)
    assert isinstance(results["feature_importances_rf"], pd.Series)
    assert len(results["feature_importances_dt"]) == len(FEATURE_COLUMNS)
    assert "Protocole d'Évaluation Rigoureux" in results["interpretation"]
