# Pull Request : Jalon Alt 7 — Protocole Rigoureux Machine Learning & Analyse de Colinéarité

## Résumé des Modifications
- **Refonte de l'Évaluation ([`analytics/classifier.py`](file:///c:/Users/squal/Pictures/stage%20pfa/cmrpi/observatoire-pme-maroc/analytics/classifier.py))** : Remplacement des métriques de resubstitution par une évaluation sur jeu de test tenu à l'écart (80/20 stratifié, $N_{\text{test}} = 5\ 729$).
- **Traitement de l'Imbalance** : Exclusion documentée des classes ultra-minoritaires (`phishing` n=6, `web_attack` n=8) et recentrage sur la tâche binaire.
- **Benchmark Baseline** : Preuve de la séparabilité linéaire par équivalence de la Régression Logistique (Macro F1 = 0.9858).
- **Analyse Mathématique DT vs RF** : Explication de la divergence d'importance par le sous-échantillonnage de variables colinéaires ($r = +0.7494$).
- **Tests Unitaires** : Ajout de `tests/test_classifier.py`.

## Validation
- `pytest tests/test_classifier.py -v` $\rightarrow$ 100% Validé (3 tests).
