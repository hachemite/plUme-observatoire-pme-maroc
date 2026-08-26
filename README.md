# Plume — Observatoire des Cybermenaces pour PME Marocaines / Moroccan SME CTI Observatory

> *"Voir le signal avant l'éruption."* / *"See the signal before the eruption."*

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![CI Tests](https://github.com/hachemite/plUme-observatoire-pme-maroc/actions/workflows/test.yml/badge.svg)](https://github.com/hachemite/plUme-observatoire-pme-maroc/actions/workflows/test.yml)
[![Tests](https://img.shields.io/badge/tests-14%20passed-brightgreen.svg)](#6-exécution-des-tests-unitaires--running-tests)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## 🌐 Navigation
- 🇫🇷 [Français](#-français)
  - [1. Présentation du Projet](#1-présentation-du-projet)
  - [2. Architecture & Structure](#2-architecture--structure-du-projet)
  - [3. Installation & Configuration](#3-installation--configuration)
  - [4. Lancement du Dashboard (Streamlit)](#4-lancement-du-dashboard-interactif-streamlit)
  - [5. Exécution des Pipelines & Rapports](#5-exécution-des-collecteurs-pipelines--rapports)
  - [6. Exécution des Tests](#6-exécution-des-tests-unitaires)
- 🇬🇧 [English](#-english)
  - [1. Project Overview](#1-project-overview)
  - [2. Architecture & Structure](#2-architecture--project-structure)
  - [3. Setup & Installation](#3-setup--installation)
  - [4. Launching the Dashboard (Streamlit)](#4-launching-the-interactive-dashboard-streamlit)
  - [5. Running Pipelines & Reports](#5-running-collectors-pipelines--reports)
  - [6. Running Tests](#6-running-unit-tests)
- 📊 [Qualité des Données / Data Metrics](#-qualité-des-données--data-quality-metrics)

---

## 🇫🇷 Français

### 1. Présentation du Projet
**Plume** est un observatoire data-driven des cybermenaces visant les PME marocaines, développé dans le cadre d'un stage PFA au **CMRPI / EMC** (Juillet–Août 2026).

Le projet collecte périodiquement des indicateurs de menace (IoCs) depuis des flux publics (**URLhaus**, **AbuseIPDB**), les valide avec des schémas Pydantic stricts, les catégorise selon la taxonomie du guide **AUSIM / CMRPI** (*Phishing*, *Ransomware / Malware*, *Attaques Web*, *DDoS*), et persiste les événements dédupliqués dans une couche de stockage (`storage/repository.py`).

### 2. Architecture & Structure du Projet
```text
observatoire-pme-maroc/
├── collectors/          # Ingestion des flux cyber (urlhaus.py, abuseipdb.py)
├── processing/          # Validation Pydantic (validate.py) & Taxonomie (taxonomy.py)
├── storage/             # Couche d'abstraction repository (repository.py)
├── analytics/           # Statistiques & agrégations (stats.py)
├── reporting/           # Générateur de rapports CTI (rapport_pilote.py)
├── reports/             # Rapports générés en Markdown
├── notebooks/           # Notebooks d'exploration & scripts (notebookv1.py)
├── scripts/             # Orchestration & utilitaires (run_daily_collection.py, build_notebook.py)
├── tests/               # Tests unitaires Pytest (test_reporting, test_repository, test_taxonomy, etc.)
├── data/                # Données persistées (threat_events.csv, daily_stats.csv)
├── app.py               # Dashboard interactif Streamlit
└── requirements.txt     # Dépendances Python
```

### 3. Installation & Configuration

#### Prérequis
- **Python 3.10+**
- **Git**

#### Étapes d'installation
```bash
# 1. Cloner le dépôt
git clone <repository_url>
cd observatoire-pme-maroc

# 2. Créer et activer l'environnement virtuel
python -m venv venv

# Sur Windows (PowerShell) :
.\venv\Scripts\activate.ps1

# Sur Linux / macOS :
source venv/bin/activate

# 3. Installer les dépendances
pip install -r requirements.txt

# 4. Configurer les variables d'environnement (Optionnel pour AbuseIPDB)
cp .env.example .env
# Éditer le fichier .env si vous disposez d'une clé API AbuseIPDB
```

### 4. Lancement du Dashboard Interactif (Streamlit)

Pour explorer visuellement les indicateurs de menace, les ventilations taxonomiques et les alertes PME :

```bash
# Lancer l'application Streamlit
streamlit run app.py
```

L'application s'ouvrira automatiquement dans votre navigateur à l'adresse **`http://localhost:8501`**.

**Fonctionnalités du Dashboard :**
- 📈 **KPIs globaux** : Volume d'événements, IoCs critiques, répartition par source et dates couvertes.
- 🎯 **Filtres interactifs** : Période temporelle, catégories de menaces, niveaux de sévérité et sources.
- 🇲🇦 **Focus PME Marocaines** : Détection des ciblages sectoriels (Bancaire, Gouvernemental `.gov.ma`, E-commerce).
- 📊 **Visualisations dynamiques** : Évolution temporelle, répartition taxonomique, et tags fréquents.
- 📥 **Export des données** : Téléchargement direct des événements filtrés au format CSV.

---

### 5. Exécution des Collecteurs, Pipelines & Rapports

#### Collecte quotidienne automatisée
```bash
# Lancer le pipeline complet quotidien (URLhaus + AbuseIPDB + calcul des statistiques)
python scripts/run_daily_collection.py
```
> **Note** : Ce script orchestre l'exécution successive de `collectors/urlhaus.py` et `collectors/abuseipdb.py` en sous-processus isolés, puis déclenche automatiquement l'agrégation statistique dans `data/daily_stats.csv` via `analytics/stats.py`.

#### Automatisation sous Windows (Planificateur de tâches / Task Scheduler)
Pour planifier l'exécution quotidienne automatique chaque matin à 09:00 :
```powershell
schtasks /create /tn "PlumeDailyCollection" /tr "\"$(Get-Command python).Source\" \"C:\chemin\vers\repo\scripts\run_daily_collection.py\"" /sc daily /st 09:00
```
*(Note : adapter le chemin absolu vers votre dépôt local).*

#### Génération de rapports CTI (Markdown)
```bash
# Générer le rapport pilote Markdown basé sur les données actuelles
python reporting/rapport_pilote.py
```
*(Le rapport sera automatiquement sauvegardé dans le dossier `reports/rapport_pilote_YYYY-MM-DD.md`).*

#### Exécutions individuelles & utilitaires
```bash
# Exécuter le collecteur URLhaus seul (Flux principal)
python collectors/urlhaus.py

# Exécuter le collecteur AbuseIPDB seul (Flux secondaire)
python collectors/abuseipdb.py

# Recalculer les statistiques quotidiennes seules
python analytics/stats.py

# Générer le notebook d'exploration
python scripts/build_notebook.py
```

---

### 6. Exécution des Tests Unitaires

Le projet utilise **pytest** pour garantir la fiabilité des composants de validation, de taxonomie, de stockage, de reporting et d'agrégation statistique.

```bash
# Lancer tous les tests unitaires en mode verbeux (14 tests)
python -m pytest -v

# Lancer un fichier de test spécifique
python -m pytest tests/test_reporting.py -v
python -m pytest tests/test_repository.py -v
python -m pytest tests/test_taxonomy.py -v
python -m pytest tests/test_validate.py -v
python -m pytest tests/test_stats.py -v
```

---

## 🇬🇧 English

### 1. Project Overview
**Plume** is a data-driven Cyber Threat Intelligence (CTI) observatory focused on Moroccan SMEs, developed during a PFA internship at **CMRPI / EMC** (Summer 2026).

The project periodically ingests threat indicators (IoCs) from public threat feeds (**URLhaus**, **AbuseIPDB**), validates them with strict Pydantic schemas, categorizes them against the **AUSIM / CMRPI** taxonomy (*Phishing*, *Ransomware / Malware*, *Web Attacks*, *DDoS*), and persists deduplicated threat events via a repository abstraction layer (`storage/repository.py`).

### 2. Architecture & Project Structure
- **`collectors/`**: Data ingestion modules (`urlhaus.py`, `abuseipdb.py`).
- **`processing/`**: Data validation (`validate.py`) and taxonomy enrichment (`taxonomy.py`).
- **`storage/`**: Load-bearing repository abstraction (`repository.py`) managing CSV read/write and deduplication.
- **`analytics/`**: Aggregations and statistical metrics (`stats.py`).
- **`reporting/`**: Sectoral intelligence report generator (`rapport_pilote.py`).
- **`reports/`**: Generated Markdown reports.
- **`scripts/`**: Orchestration and utility scripts (`run_daily_collection.py`, `build_notebook.py`).
- **`data/`**: Ingested threat events and daily statistics (`threat_events.csv`, `daily_stats.csv`).
- **`tests/`**: Unit test suite powered by `pytest`.
- **`app.py`**: Interactive Streamlit dashboard.
- **`requirements.txt`**: Python dependencies.

### 3. Setup & Installation

#### Prerequisites
- **Python 3.10+**
- **Git**

#### Setup Steps
```bash
# 1. Clone repository
git clone <repository_url>
cd observatoire-pme-maroc

# 2. Create and activate virtual environment
python -m venv venv

# On Windows (PowerShell):
.\venv\Scripts\activate.ps1

# On Linux / macOS:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set up environment configuration (Optional for AbuseIPDB)
cp .env.example .env
```

### 4. Launching the Interactive Dashboard (Streamlit)

To launch the web interface and explore cyber threat telemetry:

```bash
# Launch Streamlit dashboard
streamlit run app.py
```

Access the dashboard at **`http://localhost:8501`**.

**Dashboard Features:**
- 📈 **Executive KPIs**: Real-time total events, critical IoCs, data completeness, and source splits.
- 🎯 **Multi-criteria Filtering**: Filter by date range, taxonomy category, severity level, and data feed.
- 🇲🇦 **Moroccan SME Intelligence**: Automated identification of targets (.gov.ma, Moroccan banking, local e-commerce).
- 📊 **Dynamic Visualizations**: Temporal timeline, categorical breakdowns, and top indicator tags.
- 📥 **Data Export**: Filter and export datasets directly to CSV.

---

### 5. Running Collectors, Pipelines & Reports

#### Daily automated collection
```bash
# Run full daily pipeline (URLhaus + AbuseIPDB + automated statistical aggregation)
python scripts/run_daily_collection.py
```
> **Note**: This orchestrator runs `collectors/urlhaus.py` and `collectors/abuseipdb.py` as isolated subprocesses, then automatically triggers `analytics/stats.py` to refresh `data/daily_stats.csv`.

#### Windows Task Scheduler Automation
To schedule an automated daily run at 09:00:
```powershell
schtasks /create /tn "PlumeDailyCollection" /tr "\"$(Get-Command python).Source\" \"C:\path\to\repo\scripts\run_daily_collection.py\"" /sc daily /st 09:00
```
*(Note: adjust the absolute path to match your local repository).*

#### Generating CTI Intelligence Reports (Markdown)
```bash
# Generate the automated pilot report in Markdown
python reporting/rapport_pilote.py
```
*(Saved to `reports/rapport_pilote_YYYY-MM-DD.md`).*

#### Standalone & utility executions
```bash
# Execute URLhaus collector standalone (Primary feed)
python collectors/urlhaus.py

# Execute AbuseIPDB collector standalone (Secondary feed)
python collectors/abuseipdb.py

# Recompute daily aggregated statistics standalone
python analytics/stats.py

# Generate exploratory notebook script
python scripts/build_notebook.py
```

---

### 6. Running Unit Tests

The test suite ensures data validation, taxonomy mapping, repository storage, reporting, and statistical aggregation integrity.

```bash
# Run all unit tests (14 tests)
python -m pytest -v

# Run specific test modules
python -m pytest tests/test_reporting.py -v
python -m pytest tests/test_repository.py -v
python -m pytest tests/test_taxonomy.py -v
python -m pytest tests/test_validate.py -v
python -m pytest tests/test_stats.py -v
```

---

## 📊 Qualité des Données / Data Quality Metrics

| Métrique / Metric | Valeur / Value | Description |
| :--- | :--- | :--- |
| **Événements collectés** | 26,793 | Total des événements validés et dédupliqués dans `data/threat_events.csv`. |
| **Complétude du schéma core** | 100% | 9 champs obligatoires (`event_id`, `source`, `date_added`, `indicator_type`, `indicator_value`, `raw_threat_tag`, `status`, `category`, `severity`). |
| **Champ `tags`** | 90.62% | Renseigné pour 24,279 événements (absent pour 2,514 enregistrements URLhaus sans étiquette d'origine). |
| **Géolocalisation (`country_code`)** | 1.87% | Renseigné pour 500 événements (fourni par AbuseIPDB uniquement). |
| **Inférence sectorielle (`sector_hint`)** | 0.24% | Renseigné pour 63 événements identifiant un secteur cible spécifique (`banking`, `.gov.ma`, `ecommerce`). |

---

## 📜 Licence & Crédits
Développé dans le cadre du stage PFA au **CMRPI / EMC** (2026).