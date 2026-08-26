# Pull Request : Jalon Alt 4 — Détection d'Anomalies Z-Score & Recommandations PME

## Résumé des Modifications
- **Algorithme d'Anomalies ([`analytics/anomaly.py`](file:///c:/Users/squal/Pictures/stage%20pfa/cmrpi/observatoire-pme-maroc/analytics/anomaly.py))** : Implémentation du Z-score roulant sur fenêtre glissante $W=3$ semaines avec seuil statistique $|Z| \ge 2.0$.
- **Recommandations PME ([`analytics/recommendations.py`](file:///c:/Users/squal/Pictures/stage%20pfa/cmrpi/observatoire-pme-maroc/analytics/recommendations.py))** : Matrice de mapping déterministe associant les tags de menaces dominants (Mirai, Gafgyt, Ransomware) à des actions de remédiation directes pour les PME.
- **Rapports & UI** : Intégration dans le générateur de rapport Markdown ([`reporting/rapport_pilote.py`](file:///c:/Users/squal/Pictures/stage%20pfa/cmrpi/observatoire-pme-maroc/reporting/rapport_pilote.py)) et affichage de bannières d'alerte dans Streamlit ([`app.py`](file:///c:/Users/squal/Pictures/stage%20pfa/cmrpi/observatoire-pme-maroc/app.py)).
- **Tests Unitaires** : Ajout de `tests/test_anomaly.py` et `tests/test_recommendations.py`.

## Validation
- `pytest tests/test_anomaly.py tests/test_recommendations.py -v` $\rightarrow$ 100% Validé (8 tests).
