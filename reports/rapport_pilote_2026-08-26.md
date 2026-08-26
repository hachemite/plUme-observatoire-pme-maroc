# Observatoire PME — Cybermenaces : Rapport Pilote
**Date de génération** : 2026-08-26  
**Période couverte** : 27 juin 2026 → 18 août 2026 (53 jours)

## 1. Résumé
- Total événements : 28 656
- Période couverte : 27/06/2026 → 18/08/2026 (53 jours)
- Source principale : urlhaus (97.56%)
- Catégorie principale : ransomware_malware (97.37%)
- Tendance globale : hausse (+22.65% sur les 7 semaines complètes)

## 2. Volume et tendance
| Semaine | Fin de semaine | Volume | Évolution (%) |
| :--- | :--- | :--- | :--- |
| S26 (semaine partielle) | 2026-06-28 | 778 | *(Semaine partielle)* |
| S27 | 2026-07-05 | 3 655 | *(1ère semaine complète)* |
| S28 | 2026-07-12 | 3 800 | +3.97% |
| S29 | 2026-07-19 | 3 193 | -15.97% |
| S30 | 2026-07-26 | 3 418 | +7.05% |
| S31 | 2026-08-02 | 3 581 | +4.77% |
| S32 | 2026-08-09 | 4 628 | +29.24% |
| S33 | 2026-08-16 | 4 483 | -3.13% |
| S34 (semaine partielle) | 2026-08-23 | 1 120 | *(Semaine partielle)* |

Sur les 7 semaines complètes (S27–S33), le volume hebdomadaire est passé de 3 655 à 4 483 événements (+22.65%), avec un pic à 4 628 en semaine 32.
La pente de régression linéaire sur les semaines complètes est positive (+164.7 événements/semaine).
Détection d'anomalie (z-score glissant sur 4 semaines, seuil 2σ) : le pic de la semaine S32 obtient un z-score de +1.45 (n'est pas marqué comme anomalie statistique extrême, restant sous le seuil critique de 2.0 écarts-types).

## 3. Répartition par source, catégorie et secteur
### Par source
| Source | Volume | Part (%) |
| :--- | :--- | :--- |
| `urlhaus` | 27 956 | 97.56% |
| `abuseipdb` | 700 | 2.44% |

### Par catégorie
| Catégorie | Volume | Part (%) |
| :--- | :--- | :--- |
| `ransomware_malware` | 27 903 | 97.37% |
| `ddos_extortion` | 739 | 2.58% |
| `web_attack` | 8 | 0.03% |
| `phishing` | 6 | 0.02% |

### Par secteur ciblé
Le champ sector_hint est renseigné pour seulement 0.22% des événements (ecommerce: 57, banking: 6, government: 0) — les flux techniques bruts ne comportent pas de ciblage sectoriel explicite ; cette dimension n'est pas exploitable dans ce rapport pilote.

## 4. Top 10 des indicateurs récurrents
| Indicateur (IoC) | Type | Catégorie | Sévérité | Source | Occurrences |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `45.148.10.157` | ip | `ddos_extortion` | `high` | `abuseipdb` | 5 |
| `45.148.10.147` | ip | `ddos_extortion` | `high` | `abuseipdb` | 4 |
| `45.148.10.152` | ip | `ddos_extortion` | `high` | `abuseipdb` | 3 |
| `102.210.148.92` | ip | `ddos_extortion` | `high` | `abuseipdb` | 2 |
| `103.143.231.24` | ip | `ddos_extortion` | `high` | `abuseipdb` | 2 |
| `103.155.47.50` | ip | `ddos_extortion` | `high` | `abuseipdb` | 2 |
| `103.204.167.40` | ip | `ddos_extortion` | `high` | `abuseipdb` | 2 |
| `104.28.222.16` | ip | `ddos_extortion` | `high` | `abuseipdb` | 2 |
| `107.189.28.96` | ip | `ddos_extortion` | `high` | `abuseipdb` | 2 |
| `173.249.52.138` | ip | `ddos_extortion` | `high` | `abuseipdb` | 2 |

Les indicateurs récurrents proviennent exclusivement d'AbuseIPDB (IP signalées à plusieurs reprises) ; les URLs URLhaus sont quasi-uniques et n'apparaissent pas dans ce classement.

## 5. Distribution par sévérité
| Sévérité | Libellé | Volume | Part (%) |
| :--- | :--- | :--- | :--- |
| `unknown` | Non classifié (Unknown) | 13 558 | 47.31% |
| `medium` | Moyen (Medium) | 13 001 | 45.37% |
| `high` | Élevé (High) | 1 341 | 4.68% |
| `low` | Faible (Low) | 756 | 2.64% |
| `critical` | Critique (Critical) | 0 | 0.00% |

Aucun événement n'est classé 'critical' dans le jeu de données actuel — la taxonomie place les menaces les plus sévères observées (adresses IP AbuseIPDB liées au DDoS/extorsion) au niveau 'high'.

## 6. Observations
- La source URLhaus représente 97.56% des événements collectés contre 2.44% pour AbuseIPDB, reflétant la composition du flux plutôt qu'un paysage de menaces équilibré. [Interprétation à compléter]
- La catégorie ransomware_malware domine à 97.37%, ce qui découle directement de la nature du flux URLhaus (URLs de distribution de malware). [Interprétation à compléter]
- [Placeholder libre — observation additionnelle à rédiger manuellement après lecture du rapport]

## 7. Méthodologie et limites
- **Sources** : 2 sources (URLhaus, AbuseIPDB).
- **Fenêtre temporelle** : 53 jours (du 27/06/2026 au 18/08/2026).
- **Qualité de collecte** : 0 ligne avec date invalide (qualité de collecte confirmée).
- **Limites sectorielles** : Champ sector_hint non exploitable (99.78% unknown).
- **Sévérité** : Niveau 'critical' absent du jeu de données actuel.
- **Mode de collecte AbuseIPDB** : Clé API AbuseIPDB active (collecte en ligne via API v2).
