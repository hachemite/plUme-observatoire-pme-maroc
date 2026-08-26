# Explication Détaillée : Jalon Alt 5 (Corrélation Multi-Sources & Score de Risque)

## 1. Objectifs du Jalon
1. Établir une corrélation croisée entre les URLs malveillantes URLhaus et les adresses IP signalées par AbuseIPDB.
2. Développer une fonction de score de risque pondérée et justifiable en soutenance académique.
3. Ré-ordonner les indicateurs prioritaires (Top 10) selon ce score multidimensionnel.

## 2. Corrélation Multi-Sources ([`analytics/correlate.py`](file:///c:/Users/squal/Pictures/stage%20pfa/cmrpi/observatoire-pme-maroc/analytics/correlate.py))
- **Défi** : URLhaus fournit des URLs (`http://91.92.40.5:8080/bin.sh`), tandis qu'AbuseIPDB fournit des adresses IP pures (`91.92.40.5`).
- **Solution** : Extraction normalisée de l'hôte/IP avec parsing regex et comparaison inter-sources.
- **Résultat** : Détection des adresses IP corroborées simultanément (`cross_source_confirmed = True`), notamment `91.92.40.5` et `94.154.43.146`.

## 3. Formule du Score de Risque Composite ([`analytics/risk_score.py`](file:///c:/Users/squal/Pictures/stage%20pfa/cmrpi/observatoire-pme-maroc/analytics/risk_score.py))

$$\text{Risk Score} = (w_{\text{severity}} \times 0.40) + (w_{\text{recurrence}} \times 0.30) + (w_{\text{correlation}} \times 0.20) + (w_{\text{category}} \times 0.10)$$

| Composante | Poids | Rationale de Soutenance |
| :--- | :---: | :--- |
| **Sévérité** | **40%** | La criticité technique de la charge utile (ex: exécution de code distant vs simple scan) est le facteur de dangerosité immédiat le plus élevé. |
| **Récurrence** | **30%** | Un attaquant ou une infrastructure active sur plusieurs jours traduit une persistance hostile accrue. |
| **Corroboration Multi-Sources** | **20%** | La présence sur deux flux indépendants élimine le risque de faux positif et confirme une menace globale. |
| **Catégorie de Menace** | **10%** | Priorisation des attaques à impact destructeur direct (Ransomware > DDoS > Phishing). |

## 4. Impact sur le Classement
Le Top 10 ne repose plus sur le seul volume d'occurrences. Les adresses `91.92.40.5` et `94.154.43.146` (score 64.0) grimpent aux rangs #2 et #3 en raison de leur double confirmation URLhaus + AbuseIPDB.
