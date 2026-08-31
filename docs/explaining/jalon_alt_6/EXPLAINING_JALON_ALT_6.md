# Explication Détaillée : Jalon Alt 6 (Géolocalisation GeoIP Hors-Ligne & Focus ASN Maroc)

## 1. Objectifs du Jalon
1. Intégrer un enrichissement géographique hors-ligne ultra-rapide basé sur MaxMind GeoLite2 sans dépendre d'APIs tierces limitées en quota.
2. Établir une rigueur statistique stricte en distinguant les dénominateurs (totalité du dataset vs sous-ensemble d'IPs résolubles).
3. Effectuer l'attribution par opérateur télécom marocain (ASN BGP/AFRINIC) et contre-vérifier par sondage sur les registres publics.

## 2. Distinction des Deux Dénominateurs
Une erreur fréquente dans les rapports CTI consiste à déclarer un pourcentage de pays sans préciser s'il s'applique au total global ou aux seules adresses IP analysables :

- **Dénominateur Global** : 28 656 événements (100.00%).
- **Événements avec IP résolue** : 14 453 événements (50.44%).
- **Événements avec domaine FQDN / URL non résolue** : 14 203 événements (49.56%).
- **Infrastructures hébergées au Maroc (`MA`)** :
  - **0.66%** du dataset complet (188 événements sur 28 656).
  - **1.30%** du sous-ensemble des adresses IP résolues (188 événements sur 14 453).

## 3. Attribution par Opérateur Marocain (ASN BGP)
Sur les 188 événements localisés au Maroc (108 adresses IP uniques) :
- **Maroc Telecom / IAM (`AS6713`)** : 185 événements (98.41%, 106 adresses IP uniques, majoritairement réparties sur les plages d'accès résidentiel/professionnel ADSL/FTTH `105.184.0.0/14`).
- **Wana Corporate / Inwi (`AS36903`)** : 3 événements (1.59%, 2 adresses IP uniques).
- **Orange Maroc (`AS36925`)** : 0 événement dans le jeu de données actuel.

## 4. Vérification Croisée Publique (AFRINIC WHOIS / RDAP)
Pour prouver l'exactitude de l'attribution statique, 4 adresses IP représentatives ont été vérifiées en direct auprès du registre officiel AFRINIC RDAP et de Hurricane Electric BGP (`bgp.he.net`) :
1. `105.186.237.86` $\rightarrow$ Plage `105.186.0.0/16` $\rightarrow$ **Confirmé AS6713 (Maroc Telecom)**.
2. `105.184.124.53` $\rightarrow$ Plage `105.184.0.0/16` $\rightarrow$ **Confirmé AS6713 (Maroc Telecom)**.
3. `105.187.33.138` $\rightarrow$ Plage `105.187.0.0/16` $\rightarrow$ **Confirmé AS6713 (Maroc Telecom)**.
4. `197.153.57.103` $\rightarrow$ Plage `197.153.0.0/17` $\rightarrow$ **Confirmé AS36903 (Wana / Inwi)**.

*Résultat* : 100% de concordance, 0 divergence.
