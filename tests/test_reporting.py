"""Tests for reporting/rapport_pilote.py module."""

from pathlib import Path
import tempfile
import pytest
from reporting.rapport_pilote import generate_pilot_report


def test_generate_pilot_report_creates_file():
    """Test that generate_pilot_report successfully writes the markdown file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_output = Path(tmpdir) / "test_report.md"
        result_path = generate_pilot_report(output_path=tmp_output)
        
        assert result_path.exists()
        assert result_path.is_file()
        
        content = result_path.read_text(encoding="utf-8")
        assert "# Observatoire PME — Cybermenaces : Rapport Pilote" in content
        assert "## 1. Résumé" in content
        assert "## 2. Volume et tendance" in content
        assert "## 3. Répartition par source, catégorie et secteur" in content
        assert "## 4. Top 10 des indicateurs récurrents" in content
        assert "## 5. Distribution par sévérité" in content
        assert "## 6. Recommandations PME" in content
        assert "## 7. Observations" in content
        assert "## 8. Méthodologie et limites" in content
        assert "28 656" in content
        assert "urlhaus" in content
        assert "abuseipdb" in content
