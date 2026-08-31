# Rapport de Clôture : Jalon Alt 6 (GeoIP MaxMind & Focus Opérateurs Maroc)

## 1. Synthèse des Livrables
- **Module GeoIP ([`analytics/geoip.py`](file:///c:/Users/squal/Pictures/stage%20pfa/cmrpi/observatoire-pme-maroc/analytics/geoip.py))** : Résolution locale hors-ligne via MaxMind GeoLite2.
- **Rapport de Télécoms Marocaines** :
  - Maroc Telecom (`AS6713`) : 185 événements (98.41%).
  - Wana Corporate Inwi (`AS36903`) : 3 événements (1.59%).
  - Orange Maroc (`AS36925`) : 0 événement.
- **Vérification Publique RDAP/AFRINIC** : 4 adresses échantillonnées certifiées conformes.
- **Tests Unitaires** : `tests/test_geoip.py` (4 tests).

## 2. Métriques Vérifiées
- Total événements : 28 656.
- Événements avec adresses IP résolues : 14 453 (50.44%).
- Infrastructures au Maroc : 188 événements (**0.66% du total**, **1.30% des IPs résolues**).
