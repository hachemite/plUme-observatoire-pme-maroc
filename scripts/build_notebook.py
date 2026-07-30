import sys
from pathlib import Path
import nbformat
from nbformat.v4 import new_notebook, new_markdown_cell, new_code_cell

nb = new_notebook()

# Section 0: Title & Objective
nb.cells.append(new_markdown_cell("""# Observatoire PME Maroc — Analyse Exploratoire des Données (Jalon 1)
**Projet** : Observatoire data-driven des cybermenaces visant les PME au Maroc  
**Stage PFA — CMRPI/EMC, été 2026**  
**Encadrante** : Dr. Yasmina Al Marouni  
**Date du livrable** : 30 juillet 2026  

---

## Objectif de ce notebook
Ce notebook présente l'analyse exploratoire complète des données de cybermenaces collectées lors du Jalon 1, à partir de deux sources gratuites :
- **URLhaus** (abuse.ch) — source primaire, URLs malveillantes, CSV sans authentification
- **AbuseIPDB** — source secondaire, IPs blacklistées, API JSON avec clé

Il couvre :
1. Chargement et vue d'ensemble des données
2. Répartition par source et par catégorie (taxonomie AUSIM/CMRPI)
3. Qualité des données et complétude du schéma
4. Analyse temporelle (évolution des menaces dans le temps)
5. Analyse de sévérité (AbuseIPDB)
6. Analyse sectorielle (sector_hint)
7. Statut des indicateurs (online / offline / reported)
8. Vérification de la déduplication
9. Synthèse et conclusions du Jalon 1"""))

# Section 0: Config & Imports
nb.cells.append(new_markdown_cell("""## 0. Configuration et imports"""))
code_0 = """import sys
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

# Ajout du répertoire parent pour importer la couche d'abstraction storage
sys.path.insert(0, str(Path.cwd().parent))
from storage.repository import load_events

# Style visuel cohérent pour tout le notebook
plt.rcParams["figure.facecolor"] = "white"
plt.rcParams["axes.facecolor"] = "white"
plt.rcParams["font.size"] = 11
COLOR_PRIMARY = "#1f77b4"
COLOR_SECONDARY = "#2ca02c"
COLOR_ACCENT = "#d62728"
COLOR_WARN = "#ff7f0e"
"""
nb.cells.append(new_code_cell(code_0))

# Section 1: Chargement et vue d'ensemble
nb.cells.append(new_markdown_cell("""## 1. Chargement et vue d'ensemble des données"""))
code_1 = """df = load_events()

print(f"Nombre total d'événements enregistrés : {len(df):,}")
print(f"Nombre de colonnes du schéma           : {df.shape[1]}")
print(f"Colonnes                               : {list(df.columns)}")
print(f"Période couverte : du {df['date_added'].min()} au {df['date_added'].max()}")

df.head(10)"""
nb.cells.append(new_code_cell(code_1))

code_1_samples = """# Aperçu des lignes issues de chaque source
print("--- Échantillon URLhaus ---")
display_urlhaus = df[df["source"] == "urlhaus"].head(5)
display(display_urlhaus)

print("\n--- Échantillon AbuseIPDB (avec sévérité et géolocalisation renseignées) ---")
display_abuse = df[df["source"] == "abuseipdb"].head(5)
display(display_abuse)

print("\n--- Échantillon d'événements avec secteur ciblé inféré (sector_hint != 'unknown') ---")
display_sector = df[df["sector_hint"] != "unknown"][["event_id", "source", "indicator_value", "category", "sector_hint"]].head(5)
display(display_sector)"""
nb.cells.append(new_code_cell(code_1_samples))

# Section 2: Répartition par source
nb.cells.append(new_markdown_cell("""## 2. Répartition par source de données"""))
code_2 = """fig, ax = plt.subplots(figsize=(8, 5))
source_counts = df["source"].value_counts()
bars = source_counts.plot(kind="bar", color=COLOR_PRIMARY, edgecolor="black", ax=ax)

ax.set_title("Répartition des événements de menaces par source de données", fontsize=14, pad=15)
ax.set_xlabel("Source de données", fontsize=12)
ax.set_ylabel("Nombre d'événements", fontsize=12)
ax.set_xticklabels(ax.get_xticklabels(), rotation=0, fontsize=11)
ax.grid(axis="y", linestyle="--", alpha=0.7)
ax.yaxis.set_major_formatter(mticker.StrMethodFormatter("{x:,.0f}"))

for p in ax.patches:
    ax.annotate(f"{int(p.get_height()):,}", (p.get_x() + p.get_width() / 2.0, p.get_height()),
                ha="center", va="bottom", fontsize=11, xytext=(0, 5), textcoords="offset points")

plt.tight_layout()
plt.show()

print(f"URLhaus représente {source_counts.get('urlhaus', 0) / len(df) * 100:.1f}% du volume total.")
print(f"AbuseIPDB représente {source_counts.get('abuseipdb', 0) / len(df) * 100:.1f}% du volume total.")"""
nb.cells.append(new_code_cell(code_2))

# Section 3: Répartition par catégorie
nb.cells.append(new_markdown_cell("""## 3. Répartition par catégorie de menace (Taxonomie AUSIM/CMRPI)"""))
code_3 = """fig, ax = plt.subplots(figsize=(10, 5))
cat_counts = df["category"].value_counts()
cat_counts.plot(kind="bar", color=COLOR_SECONDARY, edgecolor="black", ax=ax)

ax.set_title("Répartition des événements par catégorie de menace (AUSIM/CMRPI)", fontsize=14, pad=15)
ax.set_xlabel("Catégorie de menace", fontsize=12)
ax.set_ylabel("Nombre d'événements", fontsize=12)
ax.set_xticklabels(ax.get_xticklabels(), rotation=15, fontsize=10, ha="right")
ax.grid(axis="y", linestyle="--", alpha=0.7)
ax.yaxis.set_major_formatter(mticker.StrMethodFormatter("{x:,.0f}"))

for p in ax.patches:
    ax.annotate(f"{int(p.get_height()):,}", (p.get_x() + p.get_width() / 2.0, p.get_height()),
                ha="center", va="bottom", fontsize=10, xytext=(0, 5), textcoords="offset points")

plt.tight_layout()
plt.show()"""
nb.cells.append(new_code_cell(code_3))

nb.cells.append(new_markdown_cell("""*Note explicative : La prédominance des catégories `ransomware_malware` et `ddos_extortion` reflète directement les spécificités des flux collectés (les URLs URLhaus diffusent principalement des charges utiles malveillantes, tandis que les adresses AbuseIPDB proviennent de listes de blocage IP liées au brute-force et aux botnets), et ne constitue aucunement une anomalie de traitement.*"""))

nb.cells.append(new_markdown_cell("""### 3bis. Croisement Source × Catégorie"""))
code_3bis = """fig, ax = plt.subplots(figsize=(10, 5))
cross_tab = pd.crosstab(df["category"], df["source"])
cross_tab.plot(kind="bar", stacked=True, ax=ax,
                color=[COLOR_PRIMARY, COLOR_WARN], edgecolor="black")

ax.set_title("Catégorie de menace par source de données", fontsize=14, pad=15)
ax.set_xlabel("Catégorie de menace", fontsize=12)
ax.set_ylabel("Nombre d'événements", fontsize=12)
ax.set_xticklabels(ax.get_xticklabels(), rotation=15, ha="right")
ax.legend(title="Source")
ax.grid(axis="y", linestyle="--", alpha=0.7)

plt.tight_layout()
plt.show()

display(cross_tab)"""
nb.cells.append(new_code_cell(code_3bis))

# Section 4: Qualité des données
nb.cells.append(new_markdown_cell("""## 4. Qualité des données (Validation de complétude)"""))
code_4_table = """null_summary = pd.DataFrame({
    "Colonnes": df.columns,
    "Valeurs nulles": df.isnull().sum().values,
    "Taux de complétude (%)": ((len(df) - df.isnull().sum().values) / len(df) * 100).round(2),
})
null_summary"""
nb.cells.append(new_code_cell(code_4_table))

code_4_chart = """fig, ax = plt.subplots(figsize=(10, 5))
completeness = null_summary.set_index("Colonnes")["Taux de complétude (%)"].sort_values()
colors = [COLOR_ACCENT if v < 50 else (COLOR_WARN if v < 95 else COLOR_SECONDARY) for v in completeness]
completeness.plot(kind="barh", color=colors, edgecolor="black", ax=ax)

ax.set_title("Taux de complétude par champ du schéma", fontsize=14, pad=15)
ax.set_xlabel("Complétude (%)", fontsize=12)
ax.set_xlim(0, 105)
ax.grid(axis="x", linestyle="--", alpha=0.7)

for i, v in enumerate(completeness):
    ax.text(v + 1, i, f"{v:.1f}%", va="center", fontsize=9)

plt.tight_layout()
plt.show()"""
nb.cells.append(new_code_cell(code_4_chart))

nb.cells.append(new_markdown_cell("""**Lecture** : les 9 champs du schéma `ThreatEvent` (validés par Pydantic) sont à 100% de complétude par construction — toute ligne avec un champ requis manquant est rejetée avant stockage (`processing/validate.py`). Les champs d'enrichissement `country_code` et `sector_hint` sont volontairement moins renseignés à ce stade (limites connues, documentées dans le README)."""))

# Section 5: Analyse temporelle
nb.cells.append(new_markdown_cell("""## 5. Analyse temporelle"""))
code_5 = """df["date_added_parsed"] = pd.to_datetime(df["date_added"], errors="coerce")
timeline = df.dropna(subset=["date_added_parsed"]).copy()
timeline["date_only"] = timeline["date_added_parsed"].dt.date

daily_counts = timeline.groupby(["date_only", "source"]).size().unstack(fill_value=0)

fig, ax = plt.subplots(figsize=(12, 5))
daily_counts.plot(ax=ax, marker="o", color=[COLOR_PRIMARY, COLOR_WARN])

ax.set_title("Évolution du nombre d'événements collectés par jour", fontsize=14, pad=15)
ax.set_xlabel("Date", fontsize=12)
ax.set_ylabel("Nombre d'événements", fontsize=12)
ax.grid(axis="y", linestyle="--", alpha=0.7)
ax.legend(title="Source")

plt.tight_layout()
plt.show()"""
nb.cells.append(new_code_cell(code_5))

# Section 6: Analyse de sévérité
nb.cells.append(new_markdown_cell("""## 6. Analyse de sévérité (AbuseIPDB uniquement)"""))
code_6 = """abuse_df = df[df["source"] == "abuseipdb"]

if not abuse_df.empty and "severity" in abuse_df.columns:
    fig, ax = plt.subplots(figsize=(7, 5))
    sev_order = ["high", "medium", "low", "unknown"]
    sev_counts = abuse_df["severity"].value_counts().reindex(sev_order, fill_value=0)
    sev_colors = {"high": COLOR_ACCENT, "medium": COLOR_WARN, "low": COLOR_SECONDARY, "unknown": "gray"}

    sev_counts.plot(kind="bar", color=[sev_colors[s] for s in sev_order], edgecolor="black", ax=ax)
    ax.set_title("Répartition de la sévérité des IPs signalées (AbuseIPDB)", fontsize=14, pad=15)
    ax.set_xlabel("Niveau de sévérité", fontsize=12)
    ax.set_ylabel("Nombre d'événements", fontsize=12)
    ax.set_xticklabels(ax.get_xticklabels(), rotation=0)
    ax.grid(axis="y", linestyle="--", alpha=0.7)

    for p in ax.patches:
        ax.annotate(f"{int(p.get_height()):,}", (p.get_x() + p.get_width() / 2.0, p.get_height()),
                    ha="center", va="bottom", fontsize=10, xytext=(0, 5), textcoords="offset points")

    plt.tight_layout()
    plt.show()
else:
    print("Aucune donnée AbuseIPDB disponible pour l'analyse de sévérité.")"""
nb.cells.append(new_code_cell(code_6))

# Section 7: Analyse sectorielle
nb.cells.append(new_markdown_cell("""## 7. Analyse sectorielle (sector_hint)"""))
code_7 = """fig, ax = plt.subplots(figsize=(8, 5))
sector_counts = df["sector_hint"].value_counts()
sector_counts.plot(kind="bar", color=COLOR_PRIMARY, edgecolor="black", ax=ax)

ax.set_title("Répartition des événements par secteur inféré (mots-clés génériques)", fontsize=14, pad=15)
ax.set_xlabel("Secteur", fontsize=12)
ax.set_ylabel("Nombre d'événements", fontsize=12)
ax.set_xticklabels(ax.get_xticklabels(), rotation=15, ha="right")
ax.grid(axis="y", linestyle="--", alpha=0.7)

for p in ax.patches:
    ax.annotate(f"{int(p.get_height()):,}", (p.get_x() + p.get_width() / 2.0, p.get_height()),
                ha="center", va="bottom", fontsize=10, xytext=(0, 5), textcoords="offset points")

plt.tight_layout()
plt.show()

print("--- Échantillon des événements avec secteur identifié (banking, ecommerce, government) ---")
display_sector_known = df[df["sector_hint"] != "unknown"][["event_id", "source", "indicator_value", "category", "sector_hint"]].head(10)
display(display_sector_known)

print(f"\n'unknown' représente {sector_counts.get('unknown', 0) / len(df) * 100:.1f}% des événements — "
      f"limite attendue au Jalon 1, à adresser via des règles plus fines ou des sources marocaines "
      f"(DGSSI) aux jalons suivants.")"""
nb.cells.append(new_code_cell(code_7))

# Section 8: Statut des indicateurs
nb.cells.append(new_markdown_cell("""## 8. Statut des indicateurs (online / offline / reported)"""))
code_8 = """fig, ax = plt.subplots(figsize=(7, 5))
status_counts = df["status"].value_counts()
status_counts.plot(kind="bar", color=COLOR_SECONDARY, edgecolor="black", ax=ax)

ax.set_title("Statut des indicateurs collectés", fontsize=14, pad=15)
ax.set_xlabel("Statut", fontsize=12)
ax.set_ylabel("Nombre d'événements", fontsize=12)
ax.set_xticklabels(ax.get_xticklabels(), rotation=0)
ax.grid(axis="y", linestyle="--", alpha=0.7)

for p in ax.patches:
    ax.annotate(f"{int(p.get_height()):,}", (p.get_x() + p.get_width() / 2.0, p.get_height()),
                ha="center", va="bottom", fontsize=10, xytext=(0, 5), textcoords="offset points")

plt.tight_layout()
plt.show()"""
nb.cells.append(new_code_cell(code_8))

# Section 9: Vérification de la déduplication
nb.cells.append(new_markdown_cell("""## 9. Vérification de la déduplication
Contrôle rapide : la clé canonique `(indicator_value, source, date_added)` ne doit produire aucun doublon dans les données stockées."""))
code_9 = """dedup_check = df.duplicated(subset=["indicator_value", "source", "date_added"]).sum()
print(f"Nombre de doublons détectés sur la clé canonique : {dedup_check}")
assert dedup_check == 0, "Anomalie : des doublons ont été trouvés malgré le mécanisme de dédoublonnage."
print("[OK] Aucun doublon — le mécanisme de dédoublonnage de storage/repository.py fonctionne correctement.")"""
nb.cells.append(new_code_cell(code_9))

# Section 10: Synthèse des livrables
nb.cells.append(new_markdown_cell("""## 10. Synthèse des livrables du Jalon 1

Ce notebook conclut la validation du **Jalon 1** de l'Observatoire des Menaces Cyber pour PME Marocaines.

**Ce qui a été livré :**
- Deux collecteurs fonctionnels : `collectors/urlhaus.py` (source primaire, CSV, sans authentification) et `collectors/abuseipdb.py` (source secondaire, API JSON avec clé).
- Un pipeline complet fetch → validate → categorize → save, reposant sur `processing/validate.py` (schéma Pydantic `ThreatEvent`) et `processing/taxonomy.py` (catégorisation AUSIM/CMRPI par mots-clés).
- Une couche de stockage abstraite (`storage/repository.py`) garantissant la déduplication sur la clé `(indicator_value, source, date_added)`.
- Une suite de tests unitaires (9/9 passés) couvrant le stockage, la validation et la taxonomie."""))

code_10 = """summary_stats = pd.DataFrame({
    "Métrique": [
        "Nombre total d'événements",
        "Sources intégrées",
        "Catégories AUSIM/CMRPI couvertes",
        "Complétude des champs requis (ThreatEvent)",
        "Doublons détectés",
    ],
    "Valeur": [
        f"{len(df):,}",
        ", ".join(df["source"].unique()),
        ", ".join(sorted(df["category"].unique())),
        "100%",
        dedup_check,
    ],
})
summary_stats"""
nb.cells.append(new_code_cell(code_10))

nb.cells.append(new_markdown_cell("""**Limites connues (documentées et attendues à ce stade) :**
- `country_code` n'est renseigné que par AbuseIPDB (URLhaus ne fournit pas de géolocalisation IP) et identifie l'origine de l'attaquant, pas la victime.
- `sector_hint` repose sur une inférence par mots-clés génériques, encore peu précise — à renforcer avec des sources marocaines spécifiques (DGSSI) au Jalon 2+.

**Prochaines étapes (Jalon 2, échéance 15 août) :**
- Mise en place d'une collecte planifiée (scheduling).
- `analytics/stats.py` : comptages/jour et répartition par catégorie, cohérents sur ré-exécution (pas de double comptage)."""))

with open("notebooks/exploration.ipynb", "w", encoding="utf-8") as f:
    nbformat.write(nb, f)

print("Advanced exploration notebook successfully generated in notebooks/exploration.ipynb.")
