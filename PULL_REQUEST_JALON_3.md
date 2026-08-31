# Pull Request : Jalon 3 — Dashboard Streamlit & Rapports CTI

## Description
Cette Pull Request finalise le **Jalon 3** du projet `observatoire-pme-maroc` développé dans le cadre du stage PFA au **CMRPI / EMC**.

Elle introduit l'application web interactive Streamlit (`app.py`), le module de génération automatique de rapports d'intelligence (`reporting/rapport_pilote.py`), les tokens et assets de design néo-squeuomorphique, la documentation bilingue mise à jour et la suite complète de 14 tests unitaires.

---

## 🎯 Livrables Implémentés

### 1. Dashboard Web Interactif (`app.py`)
- **Design System Néo-squeuomorphique** : Thème sombre inspiré de Spotify (palette Onyx `#121212`, accents Ocre `#db7c26`, bordures subtiles et cartes à profondeur).
- **Chargement optimisé & cache** : Ingestion ultra-rapide des 26 793 événements avec `@st.cache_data` et parsing ISO 8601 UTC.
- **Filtrage multi-critères** : Sélecteur de date dynamique, multiselects (catégories AUSIM, sévérité, statut, sources) et recherche d'IoC en temps réel.
- **KPIs Exécutifs** : Cartes métriques stylisées (`streamlit-extras` avec fallback sécurisé).
- **Visualisations analytiques** : Évolution temporelle quotidienne/hebdomadaire et graphiques de distribution catégorielle.
- **Focus PME Marocaines** : Détection des ciblages sectoriels locaux (`.gov.ma`, banques, e-commerce) et géolocalisation.
- **Table d'événements & Export** : Grille exploratoire avec badges de sévérité et téléchargement direct du dataset filtré en CSV.

### 2. Module de Reporting Automatisé (`reporting/rapport_pilote.py`)
- Moteur d'agrégation produisant des synthèses exécutives CTI au format Markdown dans `reports/rapport_pilote_YYYY-MM-DD.md`.
- Analyse des volumes hebdomadaires (S27 à S33), pente de régression (+164.7 événements/semaine), répartition taxonomique et top 10 des IoCs récurrents.

### 3. Design Tokens & Assets (`theme_tokens.py`, `assets/`, `static/`)
- Centralisation des constantes chromatiques et libellés bilingues.
- Assets de marque anti-aliasés en haute définition (512x512, favicons, SVG vectoriel) et polices Poppins embarquées.

### 4. Tests Unitaires & Documentation (`tests/`, `README.md`, `AGENT.md`)
- 14 tests unitaires `pytest` validant 100% des modules (validation, taxonomie, stockage, statistiques, reporting).
- Documentation complète en Français et Anglais décrivant l'installation, le lancement du dashboard et la production de rapports.

---

## 🧪 Validation & Tests
```bash
pytest -v
# 14 passed in 6.35s (100% pass rate)
```

Closes #3
