# Explication Détaillée : Jalon Alt 8 (Store SQLite, Cycle de Vie des IoCs, Cron CI & Docker)

## 1. Objectifs du Jalon
1. Migrer la persistance opérationnelle de CSV append-only vers SQLite (`data/db.sqlite3`) avec suivi fin du cycle de vie des indicateurs (`first_seen`, `last_seen`, `times_seen`).
2. Ajouter des variables d'apprentissage temporelles dans le classifieur ML et évaluer leur impact prédictif.
3. Créer une nouvelle section d'analyse de cycle de vie dans le tableau de bord Streamlit.
4. Mettre en place un workflow d'automatisation GitHub Actions quotidien (`.github/workflows/collect.yml`) et conteneuriser le projet via Docker (`Dockerfile`).

## 2. Architecture de Stockage SQLite ([`storage/repository.py`](file:///c:/Users/squal/Pictures/stage%20pfa/cmrpi/observatoire-pme-maroc/storage/repository.py))
- **Table `indicators`** : Maintient l'état persistant de chaque IoC unique.
  - `first_seen` : Date de la première observation (invariant).
  - `last_seen` : Date de la plus récente observation (mise à jour lors d'un nouveau run).
  - `times_seen` : Compteur de récurrence incrémenté lors des collectes successives via `INSERT ... ON CONFLICT DO UPDATE`.
- **Table `collection_runs`** : Enregistre chaque exécution du pipeline avec son horodatage et son volume d'ingestion.
- **Table `events`** : Conserve l'historique complet des 28 656 événements bruts.

## 3. Évaluation des Features Temporelles dans le Classifieur ML
Deux variables ont été ajoutées :
- `days_since_first_seen` : $\text{last\_seen} - \text{first\_seen}$ en jours.
- `times_seen_across_runs` : Compteur `times_seen`.

### Constat Scientifique
L'importance attribuée par les modèles d'arbres à ces variables est quasi-nulle (`0.00%` sur DT, $7.5 \times 10^{-12}$ sur RF), et le $F1_{\text{macro}}$ reste identique à la baseline lexicale.
*Rationnel défendable* : La distinction entre flux de malwares et flux de DDoS/extorsion repose sur la nature syntaxique de l'indicateur (URL vs IP) et non sur son ancienneté dans la base.

## 4. Tableau de Bord : Section 14 (Cycle de Vie des Indicateurs)
- **Indicateurs Nouveaux** : 28 585 (99.88%) vus une seule fois.
- **Indicateurs Récurrents** : 35 (0.12%) persistants sur plusieurs jours (`45.148.10.157` vu 5 fois, `45.148.10.147` vu 4 fois).
- **Seuil d'inactivité paramétrable** : Slider interactif pour isoler les menaces obsolètes (> 14 jours).

## 5. Automatisation CI & Conteneurisation
1. **GitHub Actions ([`.github/workflows/collect.yml`](file:///c:/Users/squal/Pictures/stage%20pfa/cmrpi/observatoire-pme-maroc/.github/workflows/collect.yml))** :
   - Cron programmé quotidiennement à 06:00 UTC.
   - Exécution de `run_daily_collection.py` avec `ABUSEIPDB_API_KEY`.
   - Auto-commit sécurisé avec `[skip ci]` pour éviter les boucles d'exécution.
2. **Conteneur Docker ([`Dockerfile`](file:///c:/Users/squal/Pictures/stage%20pfa/cmrpi/observatoire-pme-maroc/Dockerfile))** :
   - Image légère basée sur `python:3.11-slim` avec `HEALTHCHECK` intégré.
   - Commande d'exécution unique :
     ```bash
     docker build -t observatoire . && docker run -p 8501:8501 observatoire
     ```
