# Rapport de Clôture — Jalon 1 (Observatoire Cyber PME Maroc)

**Date**: 28 juillet 2026  
**Projet**: Observatoire des Menaces Cyber pour PME Marocaines (`observatoire-pme-maroc`)  
**Statut**: Validé & Conforme  

---

## 1. Sécurité et Gestion des Secrets (Étape 1)
- **Fichier `.env.example`** : Contient uniquement le placeholder factice `ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here`.
- **Fichier `.env` (production/local)** : Confirmé présent dans `.gitignore` (ligne 14).
- **Historique Git (`git log --all --full-history -- .env`)** : Résultat vierge. Le fichier `.env` réel n'a jamais été commité.
- **Audit des clés d'API** : Aucune clé réelle présente dans l'historique git.

---

## 2. Régénération des Données et Schéma à 12 Colonnes (Étape 2)
Exécution successive des deux collecteurs automatisés :
1. `python collectors/urlhaus.py`
2. `python collectors/abuseipdb.py`

### Résultat de la Structure du Schéma (`data/threat_events.csv`)
Header des 12 colonnes standardisées :
```csv
event_id,source,date_added,indicator_type,indicator_value,raw_threat_tag,tags,country_code,status,category,severity,sector_hint
```

### Volumétrie et Déduplication
- **Événements initiaux** : 14 974 lignes
- **Après passage URLhaus** : 15 597 lignes
- **Après passage AbuseIPDB** : 15 697 lignes
- **Mécanisme de déduplication** : Garanti par la clé canonique `(indicator_value, source, date_added)` dans `storage/repository.py`. Aucune duplication observée.

---

## 3. Nettoyage du Code Mort (Étape 3)
- Suppression dans `processing/validate.py` des structures obsolètes non utilisées :
  - `URLhausRow`
  - `ThreatEventSchema`
  - `validate_urlhaus_dataframe()`
- Validation d'absence de références via `grep`.
- Passage des tests unitaires post-nettoyage.

---

## 4. Validation de la Suite de Tests (Étape 4)
Exécution de `python -m pytest -v` (9/9 tests validés avec succès) :

```text
tests/test_repository.py::test_save_events_creates_file_with_correct_header PASSED
tests/test_repository.py::test_save_events_deduplication PASSED
tests/test_repository.py::test_load_events_on_missing_file PASSED
tests/test_taxonomy.py::test_row_with_phishing_tag_categorizes_as_phishing PASSED
tests/test_taxonomy.py::test_urlhaus_row_no_keyword_match_defaults_to_ransomware_malware PASSED
tests/test_taxonomy.py::test_abuseipdb_row_no_keyword_match_defaults_to_ddos_extortion PASSED
tests/test_validate.py::test_well_formed_row_passes_validation PASSED
tests/test_validate.py::test_row_missing_indicator_value_is_dropped PASSED
tests/test_validate.py::test_validate_rows_on_empty_dataframe PASSED
```

---

## 5. Régénération du Notebook et Métriques de Qualité (Étape 5)
Re-génération de `notebooks/exploration.ipynb` via `scripts/build_notebook.py`.

### Métriques des données
- **Dimensions (`df.shape`)** : `(15697, 12)`
- **Qualité des données et complétude du schéma** :
  Sur les 15 697 événements collectés, les 9 champs du schéma de validation `ThreatEvent` (`event_id`, `source`, `date_added`, `indicator_type`, `indicator_value`, `raw_threat_tag`, `status`, `category`, `severity`) affichent 100% de complétude. Le champ `tags`, optionnel dans le schéma (`tags: str = ""`), est absent pour 1 129 événements (7,19%), reflétant des enregistrements URLhaus fournis sans étiquette source.

  Les deux champs d'enrichissement ajoutés lors du Jalon 1 sont techniquement complets (aucune valeur NaN après remplissage par défaut) mais peu informatifs à ce stade : `country_code`, alimenté uniquement par AbuseIPDB (URLhaus ne fournit pas de géolocalisation IP), n'est renseigné que pour 200 événements sur 15 697 (1,3%) ; `sector_hint`, basé sur une inférence par mots-clés génériques, n'identifie un secteur autre que "unknown" que pour 49 événements (0,3%). Ces deux limites sont attendues à ce stade du projet et seront adressées en priorité lors des jalons suivants.

- **Répartition des catégories (`df['category'].value_counts()`)** :
  - `ransomware_malware`: 15 480
  - `ddos_extortion`: 210
  - `phishing`: 4
  - `web_attack`: 3

---

## 6. Mise à jour de la Documentation (Étape 6)
Sections ajoutées au `README.md` :
1. Précision sur la qualité des données et l'analyse détaillée des 9 champs du schéma de validation `ThreatEvent` ainsi que du comportement des champs d'enrichissement `country_code` et `sector_hint`.
2. Clarté sur la portée du Jalon 1 (sources globales URLhaus / AbuseIPDB, provenance des IP attaquantes vs victimes, inférence sectorielle générique) et l'arrivée des signaux spécifiques marocains (DGSSI) au Jalon 2+.
