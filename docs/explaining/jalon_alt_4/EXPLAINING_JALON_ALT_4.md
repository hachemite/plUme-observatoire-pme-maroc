# Explication Détaillée : Jalon Alt 4 (Détection d'Anomalies Z-Score & Recommandations PME)

## 1. Objectifs du Jalon
1. Concevoir un algorithme statistique robuste pour identifier les variations anormales de volume de cybermenaces sans dépendre de seuils arbitraires.
2. Implémenter une matrice prescriptive de recommandations préventives adaptées aux PME marocaines basée sur les tags techniques dominants (Mirai, Gafgyt, Ransomware, etc.).
3. Intégrer ces métriques dans le générateur de rapports Markdown et le tableau de bord Streamlit.

## 2. Détection d'Anomalies par Z-Score Roulant
Dans un flux continu de cybermenaces, les volumes varient selon des cycles hebdomadaires et des campagnes d'attaque ponctuelles.

### Formulation Mathématique
Soit $v_t$ le volume d'événements observés à la semaine $t$, et $W=3$ la fenêtre glissante de semaines antérieures :

$$\mu_t = \frac{1}{W}\sum_{i=1}^{W} v_{t-i}$$

$$\sigma_t = \sqrt{\frac{1}{W}\sum_{i=1}^{W}(v_{t-i} - \mu_t)^2}$$

$$Z_t = \frac{v_t - \mu_t}{\sigma_t + 10^{-6}}$$

- Si $Z_t \ge +2.0$ : **Pic Anormal (*Spike*)** détecté.
- Si $Z_t \le -2.0$ : **Chute Anormale (*Drop*)** détectée (ex: incident de collecte ou arrêt de flux).

## 3. Matrice de Recommandations PME ([`analytics/recommendations.py`](file:///c:/Users/squal/Pictures/stage%20pfa/cmrpi/observatoire-pme-maroc/analytics/recommendations.py))
Les tags observés dans le jeu de données déclenchent des actions de remédiation directes :
- `mirai`, `gafgyt`, `mozi` $\rightarrow$ *"Mettez à jour le firmware de vos routeurs, caméras IP et équipements réseau SOHO, et désactivez les accès distants Telnet/SSH par défaut."*
- `ransomware`, `lockbit`, `wannacry` $\rightarrow$ *"Vérifiez vos sauvegardes hors-ligne (stratégie 3-2-1), isolez les partages réseau et formez le personnel contre l'exécution de macros Office suspectes."*
- `phishing`, `credential_theft` $\rightarrow$ *"Activez l'authentification multi-facteurs (MFA) sur l'ensemble de vos accès de messagerie et portails collaboratifs."*

## 4. Tests & Validation
- Module testé : `tests/test_anomaly.py` et `tests/test_recommendations.py`.
- 100% de passage sur les cas limites (séries vides, variance nulle, tags inconnus avec fallback).
