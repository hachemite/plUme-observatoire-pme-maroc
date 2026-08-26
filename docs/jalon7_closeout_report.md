# Rapport de Clôture : Jalon Alt 7 (Protocole Rigoureux ML & Analyse Colinéarité)

## 1. Synthèse des Livrables
- **Classifieur Révisé ([`analytics/classifier.py`](file:///c:/Users/squal/Pictures/stage%20pfa/cmrpi/observatoire-pme-maroc/analytics/classifier.py))** : Évaluation sur jeu de test indépendant (80/20, $N_{\text{test}} = 5\ 729$).
- **Benchmark Comparatif** : Régression Logistique (Baseline) vs Arbre de Décision vs Forêt Aléatoire.
- **Rationnel DT vs RF** : Explication de la sélection gloutonne vs sous-échantillonnage de variables colinéaires ($r = +0.7494$).
- **Tests Unitaires** : `tests/test_classifier.py` (3 tests).

## 2. Métriques sur Jeu de Test tenu à l'écart
- **Exactitude Test** : 99.86%
- **Exactitude Équilibrée** : 97.30%
- **Macro F1-Score** : 0.9858
- **Matrice de Confusion** : 140 vrais DDoS (8 faux négatifs) / 5 581 vrais Malwares (0 faux positif).
