# Pull Request : Jalon Alt 6 — Géolocalisation Hors-Ligne GeoIP & Focus National ASN

## Résumé des Modifications
- **Module GeoIP ([`analytics/geoip.py`](file:///c:/Users/squal/Pictures/stage%20pfa/cmrpi/observatoire-pme-maroc/analytics/geoip.py))** : Enrichissement géographique hors-ligne haute performance via base MaxMind GeoLite2.
- **Rigueur des Dénominateurs** : Distinction formelle entre volume total (28 656) et sous-ensemble résoluble (14 453 IPs).
- **Attribution ASN BGP Maroc** : Décomposition par opérateur (98.41% Maroc Telecom AS6713, 1.59% Inwi AS36903).
- **Contre-Vérification Publique** : 4 adresses IP vérifiées sans divergence auprès de WHOIS AFRINIC RDAP / BGP Hurricane Electric.
- **Tests Unitaires** : Ajout de `tests/test_geoip.py`.

## Validation
- `pytest tests/test_geoip.py -v` $\rightarrow$ 100% Validé (4 tests).
