"""Time-series anomaly detection algorithms for threat intelligence volume monitoring.

Provides rolling z-score and statistical anomaly detection over weekly and daily
threat telemetry series.
"""

from typing import Optional
import numpy as np
import pandas as pd


def compute_rolling_zscore(
    series: pd.Series,
    window: int = 4,
    threshold: float = 2.0,
    min_periods: int = 2,
    use_trailing_baseline: bool = False,
) -> pd.DataFrame:
    """Compute rolling z-score anomaly scores over a time series.

    For each point x_t, calculates:
        z_t = (x_t - rolling_mean) / rolling_std

    Args:
        series (pd.Series): Numerical time series (e.g. weekly event volumes).
        window (int): Trailing window size for rolling calculations (default: 4).
        threshold (float): Standard deviation threshold for anomaly flagging (default: 2.0).
        min_periods (int): Minimum non-null observations required (default: 2).
        use_trailing_baseline (bool): If True, computes mean and std over the prior window
            excluding current point (via shift(1)). If False, uses trailing window inclusive.

    Returns:
        pd.DataFrame: DataFrame containing original values, rolling_mean, rolling_std,
            z_score, and is_anomaly boolean flag.
    """
    if series.empty:
        return pd.DataFrame(
            columns=["volume", "rolling_mean", "rolling_std", "z_score", "is_anomaly"]
        )

    s = series.astype(float)
    if use_trailing_baseline:
        ref_s = s.shift(1)
        r_mean = ref_s.rolling(window=window, min_periods=min_periods).mean()
        r_std = ref_s.rolling(window=window, min_periods=min_periods).std()
    else:
        r_mean = s.rolling(window=window, min_periods=min_periods).mean()
        r_std = s.rolling(window=window, min_periods=min_periods).std()

    # Avoid division by zero: replace 0 std with NaN
    safe_std = r_std.replace(0, np.nan)
    z_score = (s - r_mean) / safe_std

    is_anomaly = z_score.abs() > threshold

    return pd.DataFrame(
        {
            "volume": s,
            "rolling_mean": r_mean,
            "rolling_std": r_std,
            "z_score": z_score,
            "is_anomaly": is_anomaly.fillna(False),
        },
        index=series.index,
    )


def detect_weekly_volume_anomalies(
    weekly_df: pd.DataFrame,
    volume_col: str = "volume",
    window: int = 4,
    threshold: float = 2.0,
) -> pd.DataFrame:
    """Detect anomalies in weekly aggregated volumes.

    Args:
        weekly_df (pd.DataFrame): DataFrame containing weekly volumes.
        volume_col (str): Column name representing weekly counts.
        window (int): Rolling window in weeks.
        threshold (float): Z-score anomaly cutoff threshold.

    Returns:
        pd.DataFrame: Weekly DataFrame enriched with z_score and is_anomaly.
    """
    if weekly_df.empty or volume_col not in weekly_df.columns:
        return weekly_df.copy()

    res = compute_rolling_zscore(
        weekly_df[volume_col],
        window=window,
        threshold=threshold,
    )

    enriched = weekly_df.copy()
    enriched["rolling_mean"] = res["rolling_mean"]
    enriched["rolling_std"] = res["rolling_std"]
    enriched["z_score"] = res["z_score"]
    enriched["is_anomaly"] = res["is_anomaly"]
    return enriched
