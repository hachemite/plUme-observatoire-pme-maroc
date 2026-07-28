# Plume — Observatoire des Cybermenaces pour PME Marocaines

Plume est un observatoire data-driven des cybermenaces visant les PME marocaines, développé dans le cadre d'un stage PFA au CMRPI/EMC (été 2026).

Le projet collecte périodiquement des indicateurs de menace depuis des sources publiques (URLhaus, AbuseIPDB), les catégorise selon la taxonomie du guide AUSIM/CMRPI (phishing, ransomware, attaques web, DDoS), et en dégage des tendances via un tableau de bord Streamlit et un rapport sectoriel.

> *"Voir le signal avant l'éruption."*

## Qualité des données et complétude du schéma
L'ensemble des 11 champs obligatoires du schéma `ThreatEvent` (`event_id`, `source`, `date_added`, `indicator_type`, `indicator_value`, `raw_threat_tag`, `country_code`, `status`, `category`, `severity`, `sector_hint`) affichent un taux de complétude de 100% (0 valeur nulle). Le champ `tags`, configuré comme optionnel dans le schéma Pydantic (`tags: str = ""`), présente 1 129 valeurs manquantes sur 15 697 événements collectés (soit un taux de complétude de 92,81% et un taux d'absence de 7,19%), reflétant directement les enregistrements bruts URLhaus fournis sans étiquette source.

## Périmètre du Jalon 1 et portée régionale (Maroc)
Les flux de données intégrés au Jalon 1 (**URLhaus** et **AbuseIPDB**) constituent des sources d'intelligence cyber globales. Le champ `country_code` issu d'AbuseIPDB identifie le pays d'origine de l'adresse IP attaquante (l'émetteur de l'hostilité) et non celui de la cible ou de la victime. Par ailleurs, la catégorisation sectorielle (`sector_hint`) repose sur des règles d'inférence par mots-clés génériques (`banking`, `ecommerce`, `.gov.ma`). Le ciblage direct des menaces spécifiques à l'écosystème des PME marocaines sera renforcé lors des jalons ultérieurs avec l'intégration des flux nationaux (notamment les avis et bulletins de la DGSSI).