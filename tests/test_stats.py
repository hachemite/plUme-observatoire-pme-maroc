"""Tests for analytics/stats.py module."""

import pandas as pd
import pytest
from datetime import date
from analytics.stats import compute_daily_stats

def test_compute_daily_stats_returns_correct_columns():
    """Test 1: Vérifie que le DataFrame de sortie contient exactement les bonnes colonnes."""
    df_in = pd.DataFrame([
        {"date_added": "2026-07-27 10:00:00", "category": "phishing"}
    ])
    
    df_out = compute_daily_stats(df_in)
    
    assert list(df_out.columns) == ["date", "category", "count"]


def test_compute_daily_stats_exact_counts():
    """
    Test 2: Sur un DataFrame synthétique de 3 événements, 2 jours, 2 catégories,
    vérifie que l'agrégation et les totaux sont mathématiquement exacts.
    """
    df_in = pd.DataFrame([
        {"date_added": "2026-08-01 10:00:00", "category": "phishing"},
        {"date_added": "2026-08-01 15:30:00", "category": "phishing"},            # Même jour, même catégorie
        {"date_added": "2026-08-02 08:00:00", "category": "ransomware_malware"},  # Autre jour, autre catégorie
    ])

    df_out = compute_daily_stats(df_in)

    # Il doit y avoir exactement 2 lignes de groupement
    assert len(df_out) == 2

    # Vérification du jour 1 (1 août 2026) : 2 événements "phishing"
    day1_stats = df_out[(df_out["date"] == date(2026, 8, 1)) & (df_out["category"] == "phishing")]
    assert len(day1_stats) == 1
    assert day1_stats.iloc[0]["count"] == 2

    # Vérification du jour 2 (2 août 2026) : 1 événement "ransomware_malware"
    day2_stats = df_out[(df_out["date"] == date(2026, 8, 2)) & (df_out["category"] == "ransomware_malware")]
    assert len(day2_stats) == 1
    assert day2_stats.iloc[0]["count"] == 1


def test_compute_daily_stats_handles_empty_dataframe():
    """
    Test 3: Un DataFrame vide ne doit pas faire crasher l'application
    et doit renvoyer un DataFrame vide avec la bonne structure.
    """
    df_in = pd.DataFrame()
    df_out = compute_daily_stats(df_in)
    
    assert isinstance(df_out, pd.DataFrame)
    assert df_out.empty
    assert list(df_out.columns) == ["date", "category", "count"]