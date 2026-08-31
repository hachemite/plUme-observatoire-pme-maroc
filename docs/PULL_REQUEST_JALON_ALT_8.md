# Pull Request : Jalon Alt 8 — Store Opérationnel SQLite, Cycle de Vie des IoCs, Cron CI & Docker

## Résumé des Modifications
- **Store SQLite ([`storage/repository.py`](file:///c:/Users/squal/Pictures/stage%20pfa/cmrpi/observatoire-pme-maroc/storage/repository.py))** : Schéma relationnel 3 tables (`indicators`, `collection_runs`, `events`) avec UPSERT automatique préservant `first_seen` et incrémentant `times_seen`.
- **Script de Migration ([`scripts/migrate_csv_to_sqlite.py`](file:///c:/Users/squal/Pictures/stage%20pfa/cmrpi/observatoire-pme-maroc/scripts/migrate_csv_to_sqlite.py))** : Migration sans perte des 28 656 événements historiques vers 28 620 entités IoCs uniques.
- **Features Temporelles ML** : Ajout de `days_since_first_seen` et `times_seen_across_runs` dans `analytics/classifier.py`.
- **Section 14 Dashboard ([`app.py`](file:///c:/Users/squal/Pictures/stage%20pfa/cmrpi/observatoire-pme-maroc/app.py))** : Analyse interactive du cycle de vie des IoCs (Nouveaux, Récurrents, Inactifs).
- **Automatisation CI & Docker** :
  - `.github/workflows/collect.yml` : Collecte quotidienne programmée par cron à 06:00 UTC avec auto-commit sécurisé (`[skip ci]`).
  - `Dockerfile` & `.dockerignore` : Déploiement conteneurisé en une seule commande (`docker run -p 8501:8501 observatoire`).
- **Tests Unitaires** : Ajout de `tests/test_repository_sqlite.py`.

## Validation
- `pytest -v` $\rightarrow$ 100% Validé (**41 / 41 tests**).
