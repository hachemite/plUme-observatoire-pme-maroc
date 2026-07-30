# Plume — Observatoire des Cybermenaces pour PME Marocaines / Moroccan SME CTI Observatory

> *"Voir le signal avant l'éruption."* / *"See the signal before the eruption."*

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-9%20passed-brightgreen.svg)](#5-exécution-des-tests-unitaires--running-tests)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## 🌐 Navigation
- 🇫🇷 [Français](#-français)
  - [1. Présentation du Projet](#1-présentation-du-projet)
  - [2. Architecture & Structure](#2-architecture--structure-du-projet)
  - [3. Installation & Configuration](#3-installation--configuration)
  - [4. Exécution des Pipelines](#4-exécution-des-collecteurs--pipelines)
  - [5. Exécution des Tests](#5-exécution-des-tests-unitaires)
- 🇬🇧 [English](#-english)
  - [1. Project Overview](#1-project-overview)
  - [2. Architecture & Structure](#2-architecture--project-structure)
  - [3. Setup & Installation](#3-setup--installation)
  - [4. Running Pipelines](#4-running-collectors--pipelines)
  - [5. Running Tests](#5-running-unit-tests)
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
├── reporting/           # Rapports sectoriels (rapport_pilote.py)
├── notebooks/           # Notebooks d'exploration & scripts (notebookv1.py)
├── scripts/             # Scripts utilitaires (build_notebook.py)
├── tests/               # Tests unitaires Pytest (test_repository, test_taxonomy, etc.)
├── data/                # Stockage des données (threat_events.csv)
├── app.py               # Application Streamlit
└── requirements.txt     # Dépendances Python
```

### 3. Installation & Configuration

#### Prérequis
- **Python 3.10+**
- **Git**

#### Étapes d'installation
```bash
# 1. Cloner le dépôt
git clone https://github.com/hachemite/plUme-observatoire-pme-maroc.git
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

### 4. Exécution des Collecteurs & Pipelines

```bash
# Exécuter le collecteur URLhaus (Flux principal)
python collectors/urlhaus.py

# Exécuter le collecteur AbuseIPDB (Flux secondaire)
python collectors/abuseipdb.py

# Générer le notebook d'exploration
python scripts/build_notebook.py
```

### 5. Exécution des Tests Unitaires

Le projet utilise **pytest** pour garantir la fiabilité des composants de validation, de taxonomie et de stockage.

```bash
# Lancer tous les tests unitaires en mode verbeux
python -m pytest -v

# Lancer un fichier de test spécifique
python -m pytest tests/test_repository.py -v
python -m pytest tests/test_taxonomy.py -v
python -m pytest tests/test_validate.py -v
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
- **`reporting/`**: Sectoral report generator (`rapport_pilote.py`).
- **`tests/`**: Unit test suite powered by `pytest`.
- **`app.py`**: Interactive Streamlit dashboard.

### 3. Setup & Installation

#### Prerequisites
- **Python 3.10+**
- **Git**

#### Setup Steps
```bash
# 1. Clone repository
git clone https://github.com/hachemite/plUme-observatoire-pme-maroc.git
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

### 4. Running Collectors & Pipelines

```bash
# Execute URLhaus collector (Primary feed)
python collectors/urlhaus.py

# Execute AbuseIPDB collector (Secondary feed)
python collectors/abuseipdb.py

# Generate exploratory notebook script
python scripts/build_notebook.py
```

### 5. Running Unit Tests

The test suite ensures data validation, taxonomy mapping, and repository storage integrity.

```bash
# Run all unit tests
python -m pytest -v

# Run specific test modules
python -m pytest tests/test_repository.py -v
python -m pytest tests/test_taxonomy.py -v
python -m pytest tests/test_validate.py -v
```

---

## 📊 Qualité des Données / Data Quality Metrics

| Métrique / Metric | Valeur / Value | Description |
| :--- | :--- | :--- |
| **Événements collectés** | 15,697+ | Total des événements validés et dédupliqués. |
| **Complétude du schéma core** | 100% | 9 champs obligatoires (`event_id`, `source`, `date_added`, `indicator_type`, `indicator_value`, `raw_threat_tag`, `status`, `category`, `severity`). |
| **Champ `tags`** | 92.81% | Optionnel dans le schéma ; absent pour 1,129 enregistrements sans étiquettes source. |
| **Géolocalisation (`country_code`)** | 1.3% | Fourni par AbuseIPDB uniquement (URLhaus ne géolocalise pas les IoCs). |
| **Inférence sectorielle (`sector_hint`)** | 0.3% | Basé sur la détection de mots-clés génériques (`banking`, `.gov.ma`, etc.). |

---

## 📜 Licence & Crédits
Développé dans le cadre du stage PFA au **CMRPI / EMC** (2026).
