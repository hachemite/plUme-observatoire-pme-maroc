"""Unit tests for reporting/recommendations.py module."""

import pandas as pd
import pytest
from reporting.recommendations import (
    DEFAULT_RECOMMENDATION,
    TAG_RECOMMENDATIONS,
    extract_top_tags_from_dataframe,
    get_recommendations_for_tags,
)


def test_get_recommendations_mirai_gafgyt():
    """Mirai and Gafgyt tags return router/IoT firmware update recommendations."""
    recos = get_recommendations_for_tags(["mirai", "gafgyt"])
    assert len(recos) == 2
    assert any("firmware" in r for r in recos)
    assert any("VLAN" in r for r in recos)


def test_get_recommendations_ransomware():
    """Ransomware tags return backup and offline storage recommendations."""
    recos = get_recommendations_for_tags(["lockbit", "ransomware"])
    assert any("sauvegardes hors-ligne" in r for r in recos)


def test_get_recommendations_unknown_tag_fallback():
    """Unknown or empty tags return default baseline cyber hygiene recommendation."""
    recos = get_recommendations_for_tags(["unknown_custom_tag_xyz"])
    assert len(recos) == 1
    assert recos[0] == DEFAULT_RECOMMENDATION


def test_extract_top_tags_from_dataframe():
    """Top tags are accurately extracted from a DataFrame."""
    df = pd.DataFrame({
        "tags": ["mirai, elf", "mozi; mirai", "elf", None, "lockbit"]
    })
    top_tags = extract_top_tags_from_dataframe(df, top_n=3)
    assert "mirai" in top_tags
    assert "elf" in top_tags
