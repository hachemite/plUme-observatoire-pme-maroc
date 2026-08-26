# Explication Détaillée : Jalon Alt 7 (Protocole Rigoureux Machine Learning & Analyse de Colinéarité)

## 1. Objectifs du Jalon
1. Remplacer les métriques de resubstitution par un protocole rigoureux d'évaluation sur jeu de test indépendant (80/20 stratifié).
2. Traiter le déséquilibre extrême des classes et documenter l'exclusion des catégories ultra-minoritaires.
3. Intégrer une baseline linéaire (Régression Logistique) et expliquer mathématiquement la divergence d'importance des variables entre l'Arbre de Décision et la Forêt Aléatoire.

## 2. Protocole d'Évaluation Rigoureux ([`analytics/classifier.py`](file:///c:/Users/squal/Pictures/stage%20pfa/cmrpi/observatoire-pme-maroc/analytics/classifier.py))
- **Exclusion documentée** : `phishing` (n=6) et `web_attack` (n=8) sont exclues de l'apprentissage supervisé en raison d'un effectif insuffisant pour une validation croisée à 3 plis ($k=3$).
- **Tâche binaire** : `ransomware_malware` (27 942) vs `ddos_extortion` (700).
- **Split Stratifié** : 80% train ($N=22\ 913$), 20% test ($N=5\ 729$).

### Résultats sur Jeu de Test tenu à l'écart :
- **Test Accuracy** : **99.86%**
- **Test Balanced Accuracy** : **97.30%** (compense le déséquilibre de classes)
- **Test Macro F1-Score** : **0.9858**
- **Matrice de Confusion (Test)** : 140 vrais DDoS, 8 faux Malwares / 5 581 vrais Malwares, 0 faux DDoS.

## 3. Équivalence de la Baseline Linéaire
La Régression Logistique avec régularisation L2 ($C=0.01$) atteint exactement les mêmes performances ($F1 = 0.9858$) que l'Arbre de Décision et la Forêt Aléatoire. Cela démontre que les indicateurs issus des deux flux sont **linéairement séparables** dans l'espace des caractéristiques lexicales.

## 4. Explication Mathématique de la Divergence DT vs RF
- **Arbre de Décision** : Attribue **98.71%** d'importance à `is_type_ip` car l'algorithme glouton (*greedy search*) choisit la variable apportant le gain d'information maximal au nœud racine, masquant les autres variables.
- **Forêt Aléatoire** : À chaque split, seul un sous-ensemble aléatoire de variables ($m = \sqrt{p}$) est disponible. Les arbres sont forcés d'utiliser les variables hautement colinéaires :
  - `is_type_url` : **28.98%**
  - `url_length` : **27.75%**
  - `is_type_ip` : **21.72%**
  - `digit_ratio` : **16.89%**

### Corrélations Linéaires Calculées :
$$r(\text{contains\_raw\_ip}, \text{digit\_ratio}) = \mathbf{+0.7494}$$
$$r(\text{contains\_raw\_ip}, \text{url\_length}) = \mathbf{-0.5730}$$
$$r(\text{url\_length}, \text{digit\_ratio}) = \mathbf{-0.4954}$$
