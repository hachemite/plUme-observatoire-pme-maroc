"""Unit tests for time-series rolling z-score anomaly detection module."""

import numpy as np
import pandas as pd
import pytest

from analytics.anomaly import compute_rolling_zscore, detect_weekly_volume_anomalies


def test_compute_rolling_zscore_empty_series():
    """Empty series returns an empty DataFrame with expected column structure."""
    empty_series = pd.Series(dtype=float)
    df = compute_rolling_zscore(empty_series)
    assert df.empty
    assert list(df.columns) == ["volume", "rolling_mean", "rolling_std", "z_score", "is_anomaly"]


def test_compute_rolling_zscore_expected_columns():
    """Valid numerical series produces non-empty DataFrame with all metric columns."""
    s = pd.Series([100.0, 105.0, 98.0, 102.0, 500.0])
    df = compute_rolling_zscore(s, window=3, threshold=2.0)
    assert len(df) == 5
    assert "z_score" in df.columns
    assert "is_anomaly" in df.columns
    assert "rolling_mean" in df.columns
    assert "rolling_std" in df.columns


def test_compute_rolling_zscore_detects_outlier():
    """An extreme outlier beyond 2 standard deviations is flagged as anomaly."""
    # Baseline around 100 with negligible variation, followed by a massive spike (10,000)
    s = pd.Series([100.0, 100.0, 100.0, 100.0, 10000.0])
    df = compute_rolling_zscore(s, window=4, threshold=2.0, use_trailing_baseline=True)
    # The 5th point (index 4) against the prior 4 points has mean 100, std 0 -> test with slight noise
    s_noise = pd.Series([100.0, 102.0, 98.0, 101.0, 1000.0])
    df_noise = compute_rolling_zscore(s_noise, window=4, threshold=2.0, use_trailing_baseline=True)
    assert df_noise.loc[4, "is_anomaly"] == True
    assert df_noise.loc[4, "z_score"] > 2.0


def test_detect_weekly_volume_anomalies():
    """Weekly DataFrame is enriched with anomaly fields."""
    weekly_df = pd.DataFrame({
        "week_num": [27, 28, 29, 30, 31, 32, 33],
        "volume": [3655, 3800, 3193, 3418, 3581, 4628, 4483],
    })
    enriched = detect_weekly_volume_anomalies(weekly_df, volume_col="volume", window=4)
    assert "z_score" in enriched.columns
    assert "is_anomaly" in enriched.columns
    assert len(enriched) == 7
