# Pull Request : Jalon Alt 5 — Corrélation Multi-Sources & Score de Risque Composite

## Résumé des Modifications
- **Corrélation Inter-Flux ([`analytics/correlate.py`](file:///c:/Users/squal/Pictures/stage%20pfa/cmrpi/observatoire-pme-maroc/analytics/correlate.py))** : Extraction et matching des adresses IP / hôtes entre URLhaus et AbuseIPDB, ajout du champ `cross_source_confirmed: bool`.
- **Formule de Risque Pondérée ([`analytics/risk_score.py`](file:///c:/Users/squal/Pictures/stage%20pfa/cmrpi/observatoire-pme-maroc/analytics/risk_score.py))** : Score composite ($40\%$ Sévérité, $30\%$ Récurrence normalisée, $20\%$ Corroboration croisée, $10\%$ Catégorie).
- **Ré-ordonnancement du Top 10** : Priorisation des indicateurs confirmés multi-sources (`91.92.40.5` et `94.154.43.146`).
- **Tests Unitaires** : Ajout de `tests/test_correlate.py` et `tests/test_risk_score.py`.

## Validation
- `pytest tests/test_correlate.py tests/test_risk_score.py -v` $\rightarrow$ 100% Validé (9 tests).
