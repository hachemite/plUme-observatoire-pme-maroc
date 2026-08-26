# ADR 0006: Géolocalisation Hors-Ligne MaxMind GeoLite2 et Attribution ASN BGP

## Statut
Accepté (Jalon Alt 6)

## Contexte
Interroger une API tierce en ligne (ex: `ip-api.com`) pour 28 000+ adresses IP violerait les limites de taux (rate-limits), ralentirait la chaîne de traitement et introduirait une dépendance externe fragile en production.

## Décision
1. **Lookup Hors-Ligne** : Utilisation de plages CIDR GeoLite2-Country et ASN en mémoire pour une résolution sous la milliseconde.
2. **Rigueur Méthodologique sur les Dénominateurs** :
   - Totalité du dataset : 28 656 événements (100.00%).
   - Événements avec adresses IP résolues : 14 453 (50.44%).
   - Noms de domaine FQDN / URLs non résolus : 14 203 (49.56%).
   - Infrastructures au Maroc (`MA`) : 188 événements (**0.66% du volume total**, **1.30% des IPs résolues**).
3. **Attribution par Opérateur Télécom (ASN BGP/AFRINIC)** :
   - **Maroc Telecom (`AS6713`)** : 185 événements (98.41%, 106 IPs uniques, blocs ADSL/FTTH `105.184.0.0/14`).
   - **Wana Corporate / Inwi (`AS36903`)** : 3 événements (1.59%, 2 IPs uniques).
   - **Orange Maroc (`AS36925`)** : 0 événement.
4. **Vérification Croisée** : 4 adresses IP testées et certifiées conformes sur le registre officiel WHOIS AFRINIC / BGP Hurricane Electric (`bgp.he.net`).

## Conséquences
Traitement haute performance sans dépendance réseau, métriques défendables et rigoureuses.
