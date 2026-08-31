# ADR 0003: Architecture du Dashboard Streamlit et Génération de Rapports CTI

## Statut
Accepté

## Contexte
Le Jalon 3 exige la livraison de l'interface utilisateur interactive (Streamlit) pour la restitution des indicateurs de cybermenaces aux PME marocaines, ainsi qu'un module de reporting automatisé capable de produire un rapport exécutif synthétique en Markdown.

Le volume de données à manipuler dépasse 26 000 enregistrements dédupliqués. L'interface devait concilier fluidité de navigation, rendu haute définition (HiDPI / Retina), résilience aux dépendances optionnelles (`streamlit-extras`), et conformité avec les contraintes matérielles du navigateur sans surcharger le DOM.

## Décisions

### 1. Stratégie de chargement et de filtrage des données dans `app.py`
- **Cache en mémoire** : Utilisation du décorateur natif `@st.cache_data(ttl=3600)` pour la fonction `get_data()`. Le parsing datetime ISO 8601 UTC est effectué une seule fois lors du chargement initial.
- **Filtrage vectorisé à passe unique** : Application d'un masque booléen global combinant période temporelle, recherche d'IoC, catégories, sources, types et statuts. L'indexation pandas s'exécute en 2 à 4 ms sur 26 793 lignes.

### 2. Dégradation gracieuse des dépendances visuelles (`streamlit_extras`)
- Pour éviter les erreurs `ModuleNotFoundError` en environnement d'exécution minimaliste, l'import de `style_metric_cards` est encapsulé dans un bloc `try / except ImportError` fournissant une fonction neutre (*no-op fallback*). Le style CSS centralisé néo-squeuomorphique prend le relais automatiquement.

### 3. Gestion du DOM et export CSV complet
- **Affichage exploratoire plafonné** : La table interactive (`st.dataframe`) affiche les 500 événements les plus récents (`full_export_df.head(500)`) afin d'éviter la dégradation des performances de rendu dans le navigateur.
- **Export sans troncature** : Le bouton `st.download_button` opère sur l'intégralité du DataFrame filtré (`full_export_df.to_csv(index=False)`), permettant aux analystes d'extraire la totalité des enregistrements correspondants (jusqu'à 26 793 lignes).

### 4. Module de reporting CTI isolé (`reporting/rapport_pilote.py`)
- Implémentation d'une fonction pure `generate_pilot_report(output_path)` réutilisable en CLI autonome ou via planificateur de tâches, calculant les tendances hebdomadaires (S27 à S33), la régression linéaire (+164.7 événements/semaine) et le top 10 des IoCs récurrents.

## Conséquences
- Temps de réponse interactif immédiat sur les filtres de navigation.
- Tolérance aux pannes et résilience en mode dégradé (sans `streamlit-extras` ou sans clé AbuseIPDB).
- Garantie d'export complet des données sans perte ni troncature pour les besoins d'investigation des PME.
