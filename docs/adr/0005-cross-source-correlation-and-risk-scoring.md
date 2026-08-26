# ADR 0005: Corrélation Croisée Multi-Sources et Score de Risque Composite

## Statut
Accepté (Jalon Alt 5)

## Contexte
Le classement des indicateurs de compromission (IoCs) par simple nombre d'occurrences brutes crée un biais en faveur des adresses IP d'analyse récurrentes et sous-estime les URLs malveillantes critiques à faible occurrence ou corroborées sur plusieurs flux indépendants.

## Décision
1. **Extraction Normalisée** : Dérivation des adresses IP / hôtes sous-jacents depuis les URLs URLhaus via regex IPv4 et parsing urllib.
2. **Jointure Inter-Sources** : Détection des IoCs observés simultanément dans URLhaus et AbuseIPDB (`cross_source_confirmed: bool`).
3. **Formule de Risque Composite** :
   $$\text{Risk} = (w_{\text{sev}} \times 0.4) + (w_{\text{rec}} \times 0.3) + (w_{\text{cross}} \times 0.2) + (w_{\text{cat}} \times 0.1)$$
   - $w_{\text{sev}}$ : Sévérité (Critical: 100, High: 75, Medium: 50, Low: 25, Unknown: 10).
   - $w_{\text{rec}}$ : Normalisation min-max des occurrences historiques.
   - $w_{\text{cross}}$ : Bonus de corroboration (100 si présent sur $\ge 2$ sources, sinon 0).
   - $w_{\text{cat}}$ : Criticité taxonomique (Ransomware: 100, DDoS: 80, Phishing: 70, Web Attack: 60).

## Conséquences
- **Impact sur le classement** : Des IoCs doublement corroborés comme `91.92.40.5` et `94.154.43.146` montent aux rangs #2 et #3 de priorité d'alerte, reflétant une menace réelle confirmée.
