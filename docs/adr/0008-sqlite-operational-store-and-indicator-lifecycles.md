# ADR 0008: Store Opérationnel SQLite, Suivi de Cycle de Vie et Automatisation CI

## Statut
Accepté (Jalon Alt 8)

## Contexte
Le stockage CSV append-only limitait le suivi de la récurrence des IoCs à un comptage de lignes dupliquées au sein d'un même fichier, sans distinction fine entre première détection (`first_seen`), dernière observation (`last_seen`) et nombre de runs de collecte (`times_seen`).

## Décision
1. **Migration vers SQLite (`data/db.sqlite3`)** :
   - Table `indicators` : Stocke l'entité IoC avec sa date de première apparition, sa dernière observation et le compteur `times_seen`.
   - Table `collection_runs` : Trace chaque cycle d'exécution avec son horodatage et son volume d'événements ingérés.
   - Table `events` : Conserve l'historique brut des événements.
2. **Mécanisme d'UPSERT** :
   - `INSERT ... ON CONFLICT(indicator_value) DO UPDATE SET last_seen = excluded.last_seen, times_seen = indicators.times_seen + 1`.
3. **Features Temporelles ML** :
   - Ajout de `days_since_first_seen` et `times_seen_across_runs` dans `analytics/classifier.py`.
   - Constat documenté : la persistance temporelle n'ajoute pas de gain de séparabilité ($F1_{\text{macro}}$ inchangé) car la nature de la menace est intrinsèquement liée à la structure lexicale (URL vs IP).
4. **Automatisation CI & Conteneurisation** :
   - Workflow `.github/workflows/collect.yml` programmé quotidiennement à 06:00 UTC avec auto-commit sécurisé (`[skip ci]`).
   - `Dockerfile` mono-étape optimisé (`python:3.11-slim`) avec `HEALTHCHECK` intégré et commande d'exécution documentée.

## Conséquences
Architecture opérationnelle de niveau production avec suivi d'état des menaces et pipeline entièrement automatisé.
