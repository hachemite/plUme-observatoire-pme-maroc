<p align="center">
  <img src="assets/logo.png" alt="Plume logo" width="150">
</p>

<h1 align="center">Plume</h1>

<p align="center">
  <strong>Observatoire data-driven des cybermenaces visant les PME marocaines</strong><br>
  Moroccan SME Cyber Threat Intelligence Observatory
</p>

<p align="center">
  <a href="https://plume-observatoire-pme-maroc-pvficuynff6xbxltobwrza.streamlit.app/"><strong>Ouvrir le dashboard live</strong></a>
  ·
  <a href="https://github.com/hachemite/plUme-observatoire-pme-maroc">Dépôt GitHub</a>
  ·
  <a href="docs/jalon_actualisation_report.md">Rapport d'actualisation</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/release-v2.0--prod-db7c26" alt="Release v2.0 production">
  <img src="https://img.shields.io/badge/python-3.10%2B-3776AB" alt="Python 3.10+">
  <a href="https://github.com/hachemite/plUme-observatoire-pme-maroc/actions/workflows/test.yml"><img src="https://github.com/hachemite/plUme-observatoire-pme-maroc/actions/workflows/test.yml/badge.svg" alt="CI tests"></a>
  <img src="https://img.shields.io/badge/tests-41%20passed-brightgreen" alt="41 tests passed">
  <img src="https://img.shields.io/badge/license-MIT-2ea44f" alt="MIT license">
</p>

> **Voir le signal avant l'éruption.**
> Plume transforme des flux publics de Cyber Threat Intelligence (CTI) en indicateurs,
> tendances, priorités et rapports compréhensibles pour les PME marocaines.

## Dashboard public

**Accès direct : [plume-observatoire-pme-maroc-pvficuynff6xbxltobwrza.streamlit.app](https://plume-observatoire-pme-maroc-pvficuynff6xbxltobwrza.streamlit.app/)**

Le dashboard Streamlit est déployé publiquement et alimenté par les données versionnées
du dépôt. La collecte et la synchronisation sont planifiées quotidiennement à **06:00 UTC**
(**07:00 au Maroc, UTC+1**) par GitHub Actions. Cette architecture permet au service de
rester accessible en continu sans dépendre d'une machine locale, sous réserve de la
disponibilité de Streamlit Community Cloud et de GitHub Actions. Elle ne constitue pas
une garantie contractuelle de disponibilité ni un système de détection temps réel.

Le dashboard propose notamment :

- des KPI exécutifs sur le volume, la sévérité, les sources et la période couverte ;
- des filtres par date, catégorie, statut, source et niveau de sévérité ;
- une taxonomie contextualisée PME : phishing, ransomware/malware, attaques web et DDoS ;
- des tendances temporelles et une détection statistique d'anomalies ;
- un score de risque composite et une priorisation des indicateurs ;
- des enrichissements GeoIP/ASN et un focus sur les infrastructures marocaines ;
- une analyse de cycle de vie des IoC : première observation, récurrence et obsolescence ;
- l'export CSV des résultats filtrés.

## 1. Objectif et périmètre

Plume est un **observatoire analytique CTI**, développé dans le cadre du stage PFA 2026
au **CMRPI / Espace Maroc Cyberconfiance (EMC)**. Il agrège des signaux publics,
les normalise, les valide, les enrichit et les restitue sous forme de statistiques et
de rapports.

### Ce que Plume apporte

1. **Corrélation multi-sources** entre URLhaus, AbuseIPDB et les enrichissements
   disponibles.
2. **Contextualisation marocaine** par taxonomie AUSIM/CMRPI, secteurs ciblés et
   attribution GeoIP/ASN.
3. **Historique exploitable** pour mesurer les tendances et la récurrence des IoC.
4. **Priorisation pour les non-experts** grâce à la sévérité, aux anomalies et au
   score de risque.
5. **Traçabilité d'exploitation** avec historique des collectes, stockage SQLite et
   rapports Markdown automatisés.

### Limites importantes

Plume n'est ni un SOC, ni un EDR, ni un système de surveillance réseau temps réel.
Les flux sont publics et leur couverture dépend de leurs fournisseurs. Les résultats
doivent être interprétés comme des signaux CTI destinés à l'analyse et à la
priorisation, pas comme une preuve autonome de compromission.

## 2. État de la release

La base de production documentée dans le rapport d'actualisation correspond à la
release **v2.0-Prod** (jalon alt 8), consolidant :

| Domaine | Livraison |
| --- | --- |
| Ingestion | Collecteurs URLhaus et AbuseIPDB, validation et déduplication |
| Traitement | Schémas Pydantic, taxonomie AUSIM/CMRPI et enrichissement des événements |
| Analytics | Statistiques, anomalies Z-score, corrélation, score de risque et ML |
| Géographie | Résolution GeoIP hors ligne et attribution ASN |
| Persistance | CSV historique et store SQLite (`indicators`, `collection_runs`, `events`) |
| Exploitation | Dashboard Streamlit, rapports CTI et export CSV |
| Automatisation | CI de tests et collecte quotidienne GitHub Actions |
| Déploiement | Image Docker `python:3.11-slim` avec healthcheck Streamlit |
| Qualité | **41/41 tests Pytest passés** |

### Indicateurs du dataset actuellement versionné

Ces chiffres sont une photographie du fichier `data/threat_events.csv` au
**16 octobre 2026** ; ils évolueront avec les collectes quotidiennes.

| Indicateur | Valeur |
| --- | ---: |
| Événements | **74 206** |
| Période couverte | **27/06/2026 – 16/10/2026** |
| URLhaus | **73 302** |
| AbuseIPDB | **904** |
| Ransomware / malware | **73 064** |
| DDoS / extorsion | **1 089** |
| Attaques web | **42** |
| Phishing | **11** |

Les métriques détaillées et les résultats scientifiques sont conservés dans
[`docs/jalon_actualisation_report.md`](docs/jalon_actualisation_report.md).

## 3. Architecture

```text
Sources publiques
  URLhaus + AbuseIPDB
          │
          ▼
collectors/          ingestion et normalisation
          │
          ▼
processing/          validation Pydantic + taxonomie
          │
          ├──► storage/       CSV + SQLite + cycle de vie des IoC
          ├──► analytics/     statistiques, anomalies, risque, GeoIP, ML
          └──► reporting/     rapports CTI Markdown
                              │
                              ▼
                         app.py / Streamlit
```

| Répertoire | Responsabilité |
| --- | --- |
| [`collectors/`](collectors/) | Collecte URLhaus, AbuseIPDB, PhishTank, NVD et DGSSI |
| [`processing/`](processing/) | Validation, normalisation et classification taxonomique |
| [`storage/`](storage/) | Persistance, déduplication et suivi du cycle de vie |
| [`analytics/`](analytics/) | Statistiques, anomalies, corrélation, risque, GeoIP et ML |
| [`reporting/`](reporting/) | Génération des rapports et recommandations |
| [`data/`](data/) | Dataset historique et statistiques quotidiennes |
| [`scripts/`](scripts/) | Migration, orchestration et utilitaires |
| [`tests/`](tests/) | Suite Pytest couvrant les composants critiques |
| [`app.py`](app.py) | Interface interactive Streamlit |
| [`.github/workflows/`](.github/workflows/) | Tests CI et collecte quotidienne |

## 4. Installation locale

### Prérequis

- Python **3.10 ou supérieur** ;
- Git ;
- Docker (optionnel) ;
- une clé AbuseIPDB uniquement pour activer cette source avec authentification.

### Windows PowerShell

```powershell
git clone https://github.com/hachemite/plUme-observatoire-pme-maroc.git
Set-Location observatoire-pme-maroc

py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt

# Configuration optionnelle
Copy-Item .env.example .env
# Éditer .env et renseigner ABUSEIPDB_API_KEY si nécessaire
```

### Linux / macOS

```bash
git clone https://github.com/hachemite/plUme-observatoire-pme-maroc.git
cd observatoire-pme-maroc

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
```

Ne versionnez jamais `.env` ni une clé API. Le fichier `.env` est explicitement ignoré
par Git.

## 5. Lancer le dashboard

```bash
streamlit run app.py
```

Ouvrir ensuite [http://localhost:8501](http://localhost:8501). Le contrôle de santé
du conteneur est disponible à `http://localhost:8501/_stcore/health`.

### Docker

```bash
docker build -t plume-observatoire .
docker run --rm -p 8501:8501 plume-observatoire
```

Le `Dockerfile` utilise une image Python slim, expose le port `8501` et inclut un
healthcheck adapté à un déploiement conteneurisé.

## 6. Collecte, stockage et rapports

### Exécution du pipeline quotidien

```bash
python run_daily_collection.py
```

Le pipeline collecte les sources configurées, valide les événements, met à jour le
dataset historique et les statistiques quotidiennes. En production, le workflow
[`collect.yml`](.github/workflows/collect.yml) l'exécute automatiquement chaque jour.
Un lancement manuel est également disponible dans l'onglet **Actions** de GitHub.

### Commandes utiles

```bash
# Recalculer les statistiques
python analytics/stats.py

# Générer un rapport CTI Markdown
python reporting/rapport_pilote.py

# Migrer ou reconstruire le store SQLite depuis l'historique CSV
python scripts/migrate_csv_to_sqlite.py
```

### Configuration AbuseIPDB

```dotenv
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
```

URLhaus reste exploitable sans clé. Si AbuseIPDB n'est pas configuré, le pipeline
doit conserver un comportement explicite et documenté en mode dégradé.

## 7. Tests et qualité

La suite vérifie la validation des données, la taxonomie, les repositories CSV/SQLite,
les statistiques, les recommandations, la corrélation, le risque, GeoIP, le
classifieur et le reporting.

```bash
# Suite complète
python -m pytest -v

# Sous-ensemble du stockage et de la validation
python -m pytest tests/test_validate.py tests/test_repository.py tests/test_repository_sqlite.py -v

# Compilation syntaxique
python -m compileall -q app.py analytics collectors processing reporting scripts tests
```

La CI teste Python **3.10, 3.11 et 3.12** sur chaque push et pull request.

## 8. Exploitation “toujours disponible”

Pour maintenir le service dans un état opérationnel :

1. conserver le déploiement Streamlit Cloud relié à `main` ;
2. laisser le workflow de collecte planifié actif ;
3. vérifier le badge CI avant chaque publication ;
4. surveiller les exécutions GitHub Actions et les commits de données ;
5. tester périodiquement `/_stcore/health` et ouvrir le dashboard public ;
6. ne jamais stocker de secret dans le dépôt ou dans les fichiers de données.

La disponibilité réelle reste dépendante des quotas, mises en veille éventuelles et
incidents de la plateforme Streamlit Community Cloud. Pour une garantie 24/7 stricte,
déployer la même image Docker sur une plateforme avec SLA et supervision explicite.

## 9. Publication et packaging

Plume est une **application de données déployable**, pas une bibliothèque Python :
un package PyPI n'apporterait donc pas de valeur à ce stade. Le livrable publiable
est constitué de l'application Streamlit, du dataset versionné, du workflow CI/CD et
de l'image Docker reproductible.

Avant une publication :

```bash
python -m pytest -q
docker build -t plume-observatoire:release .
docker run --rm -d --name plume-check -p 8501:8501 plume-observatoire:release
curl http://localhost:8501/_stcore/health
docker stop plume-check
```

Pour une release Git, créer un tag annoté uniquement après validation CI :

```bash
git tag -a v2.0.0 -m "Plume v2.0 production baseline"
git push origin v2.0.0
```

Le tag doit toujours correspondre à un commit validé et documenté. Les données
continueront ensuite à évoluer via les commits quotidiens `[skip ci]`.

## 10. Références et gouvernance

- [Rapport global d'actualisation](docs/jalon_actualisation_report.md)
- [Rapport de clôture du jalon 8](docs/jalon8_closeout_report.md)
- [Politique de sécurité](SECURITY.md)
- [Licence MIT](LICENSE)

Développé dans le cadre du stage PFA 2026 au **CMRPI / EMC**, avec une approche
orientée data engineering, reproductibilité et valorisation de la CTI pour les PME
marocaines.
