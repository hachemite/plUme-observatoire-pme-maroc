# ADR 0007: Protocole Rigoureux d'Évaluation Machine Learning et Analyse de Colinéarité

## Statut
Accepté (Jalon Alt 7)

## Contexte
Les métriques de ré-échantillonnage brut (resubstitution sans split) présentaient des scores artificiellement gonflés. De plus, les classes ultra-minoritaires (`phishing` n=6, `web_attack` n=8) ne permettaient pas une validation croisée statistiquement fiable.

## Décision
1. **Périmètre du Problème** : Exclusion documentée des classes ultra-minoritaires et recentrage sur la tâche binaire `ransomware_malware` vs `ddos_extortion` (28 642 échantillons).
2. **Jeu de Test Tenu à l'Écart (80/20 Stratifié)** :
   - $N_{\text{train}} = 22\ 913$, $N_{\text{test}} = 5\ 729$.
   - Évaluation exclusive sur le jeu de test : Test Accuracy = 99.86%, Test Balanced Accuracy = 97.30%, Test Macro F1 = 0.9858.
3. **Modèle de Référence (Baseline)** :
   - Régression Logistique linéaire (baseline) = Arbre de Décision = Forêt Aléatoire.
   - Démontre la **séparabilité linéaire** des flux basée sur la structure lexicale.
4. **Explication Mathématique de la Divergence DT vs RF** :
   - L'Arbre de Décision sélectionne de manière gloutonne (*greedy*) `is_type_ip` (98.71%).
   - La Forêt Aléatoire applique un sous-échantillonnage aléatoire des variables ($m=\sqrt{p}$), forçant l'utilisation des variables colinéaires (`is_type_url`: 28.98%, `url_length`: 27.75%, `is_type_ip`: 21.72%, `digit_ratio`: 16.89%).
   - Matrice de corrélations directes calculées :
     * $r(\text{contains\_raw\_ip}, \text{digit\_ratio}) = +0.7494$
     * $r(\text{contains\_raw\_ip}, \text{url\_length}) = -0.5730$
     * $r(\text{url\_length}, \text{digit\_ratio}) = -0.4954$

## Conséquences
Une méthodologie scientifique inattaquable en soutenance académique.
