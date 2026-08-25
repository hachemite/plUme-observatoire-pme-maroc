# Rapport de Clôture — Jalon 3 (Observatoire Cyber PME Maroc)

**Date**: 25 août 2026  
**Projet**: Observatoire des Menaces Cyber pour PME Marocaines (`observatoire-pme-maroc`)  
**Statut**: Validé & Conforme (Prêt pour Revue Encadrant & Clôture Jalon 3)

---

## 1. Objectifs du Jalon 3 et Livrables Attendus

Conformément à la fiche de cadrage du stage PFA (**CMRPI / EMC**) et aux critères du document `AGENT.md` :

* **Livrable 1 : Dashboard interactif Streamlit (`app.py`)** :
  * Restitution visuelle de l'ensemble de la télémétrie des menaces collectées (26 793 événements sur 53 jours d'observation).
  * KPIs exécutifs en temps réel (Volume d'événements, IoCs critiques, répartition par source, taux de complétude du schéma).
  * Filtrage multi-critères : période temporelle dynamique, catégorie AUSIM, sévérité, statut actif/inactif, et recherche textuelle d'IoC.
  * Section dédiée « Focus PME Marocaines » identifiant les ciblages sectoriels (bancaire, gouvernemental `.gov.ma`, e-commerce).
  * Graphiques temporels interactifs avec bascule quotidien/hebdomadaire.
  * Explorateur d'événements paginé avec badges de sévérité et bouton d'export CSV complet.

* **Livrable 2 : Générateur de rapports CTI pilotes (`reporting/rapport_pilote.py`)** :
  * Production automatique d'un rapport exécutif synthétique au format Markdown (`reports/rapport_pilote_YYYY-MM-DD.md`).
  * Analyse des volumes hebdomadaires (S27 à S33) avec pente de régression (+164.7 événements/semaine) et top 10 des IoCs récurrents.

* **Livrable 3 : Qualité & Tests Unitaires (`tests/`)** :
  * 14 tests unitaires `pytest` couvrant la validation, la taxonomie, le stockage, les statistiques et la génération de rapports (100% de réussite).

---

## 2. Architecture Technique Déployée

```mermaid
flowchart TD
    subgraph INGESTION["1. Ingestion & Validation (Jalons 1 & 2)"]
        URLHAUS["URLhaus (CSV Feed)"]
        ABUSE["AbuseIPDB (API v2 / Fallback)"]
        VAL["processing/validate.py<br/>(Schémas Pydantic)"]
        TAX["processing/taxonomy.py<br/>(Taxonomie AUSIM/CMRPI)"]
    end

    subgraph STORAGE["2. Couche Stockage Abstraite"]
        REPO["storage/repository.py"]
        CSV_RAW[("data/threat_events.csv<br/>(26 793 événements)")]
        CSV_STATS[("data/daily_stats.csv<br/>(53 jours agrégés)")]
    end

    subgraph PRESENTATION["3. Restitution & Visualisation (Jalon 3)"]
        APP["app.py<br/>(Dashboard Streamlit)"]
        TOKENS["theme_tokens.py<br/>(Palette Onyx / Ocre)"]
        ASSETS["assets/<br/>(Logos & Icônes HiDPI)"]
    end

    subgraph REPORTING["4. Reporting Exécutif (Jalon 3)"]
        REP_GEN["reporting/rapport_pilote.py"]
        MD_OUT[("reports/rapport_pilote_*.md<br/>(Rapports Markdown)")]
    end

    URLHAUS --> VAL
    ABUSE --> VAL
    VAL --> TAX
    TAX --> REPO
    REPO <--> CSV_RAW
    CSV_RAW --> CSV_STATS

    CSV_RAW -->|@st.cache_data| APP
    TOKENS --> APP
    ASSETS --> APP

    CSV_RAW --> REP_GEN
    REP_GEN --> MD_OUT
```

---

## 3. Métriques de Données & Qualité de l'Observatoire

| Indicateur | Valeur Observée | Description / Interprétation |
| :--- | :--- | :--- |
| **Total événements validés** | 26 793 | Volume cumulé sur 53 jours (du 27/06/2026 au 18/08/2026). |
| **Complétude du schéma core** | 100.0% | 9 colonnes obligatoires renseignées sans aucune valeur nulle. |
| **Catégorie dominante** | `ransomware_malware` (90.62%) | Liée à la prépondérance du flux URLhaus (distribution de malwares). |
| **Sévérité High / Critical** | 3.52% | Adresses IP malveillantes associées à des attaques DDoS et botnets actifs. |
| **Inférences PME marocaines** | 63 événements | Détection de ciblages explicites (banques marocaines, `.gov.ma`, plateformes e-commerce locales). |

---

## 4. Bilan des Tests Unitaires

* **Suite de tests** : 14 tests exécutés sous `pytest` (`14 passed in 6.35s`).
* **Couverture** :
  - `test_validate.py` : Conformité des schémas Pydantic et rejet des lignes corrompues.
  - `test_taxonomy.py` : Mappage des catégories AUSIM/CMRPI et règles de sévérité.
  - `test_repository.py` : Déduplication à l'écriture et résilience aux fichiers absents.
  - `test_stats.py` : Calculs de séries temporelles sans double comptage.
  - `test_reporting.py` : Génération complète et validation structurelle du rapport Markdown.

---

## 5. Conclusion & Clôture du Jalon 3

Tous les objectifs de la fiche de cadrage pour le Jalon 3 sont intégralement atteints et validés. Le projet `observatoire-pme-maroc` dispose désormais d'un pipeline complet opérationnel, allant de la collecte et classification automatique des cybermenaces jusqu'à leur restitution décisionnelle interactive et documentaire.
