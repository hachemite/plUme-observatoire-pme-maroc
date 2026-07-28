# Plume — Observatoire des Cybermenaces pour PME Marocaines

Plume est un observatoire data-driven des cybermenaces visant les PME marocaines, développé dans le cadre d'un stage PFA au CMRPI/EMC (été 2026).

Le projet collecte périodiquement des indicateurs de menace depuis des sources publiques (URLhaus, AbuseIPDB), les catégorise selon la taxonomie du guide AUSIM/CMRPI (phishing, ransomware, attaques web, DDoS), et en dégage des tendances via un tableau de bord Streamlit et un rapport sectoriel.

> *"Voir le signal avant l'éruption."*

## Qualité des données et complétude du schéma
Sur les 15 697 événements collectés, les 9 champs du schéma de validation `ThreatEvent` (`event_id`, `source`, `date_added`, `indicator_type`, `indicator_value`, `raw_threat_tag`, `status`, `category`, `severity`) affichent 100% de complétude. Le champ `tags`, optionnel dans le schéma (`tags: str = ""`), est absent pour 1 129 événements (7,19%), reflétant des enregistrements URLhaus fournis sans étiquette source.

Les deux champs d'enrichissement ajoutés lors du Jalon 1 sont techniquement complets (aucune valeur NaN après remplissage par défaut) mais peu informatifs à ce stade : `country_code`, alimenté uniquement par AbuseIPDB (URLhaus ne fournit pas de géolocalisation IP), n'est renseigné que pour 200 événements sur 15 697 (1,3%) ; `sector_hint`, basé sur une inférence par mots-clés génériques, n'identifie un secteur autre que "unknown" que pour 49 événements (0,3%). Ces deux limites sont attendues à ce stade du projet et seront adressées en priorité lors des jalons suivants.

## Périmètre du Jalon 1 et portée régionale (Maroc)
Les flux de données intégrés au Jalon 1 (**URLhaus** et **AbuseIPDB**) constituent des sources d'intelligence cyber globales. Le champ `country_code` issu d'AbuseIPDB identifie le pays d'origine de l'adresse IP attaquante (l'émetteur de l'hostilité) et non celui de la cible ou de la victime. Par ailleurs, la catégorisation sectorielle (`sector_hint`) repose sur des règles d'inférence par mots-clés génériques (`banking`, `ecommerce`, `.gov.ma`). Le ciblage direct des menaces spécifiques à l'écosystème des PME marocaines sera renforcé lors des jalons ultérieurs avec l'intégration des flux nationaux (notamment les avis et bulletins de la DGSSI).