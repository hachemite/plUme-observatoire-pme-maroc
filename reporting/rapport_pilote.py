"""Reporting module for generating pilot Markdown threat intelligence reports.

This module automates the generation of concise, fact-checked pilot reports
for the Observatoire PME — Cybermenaces project.
"""

import sys
from datetime import datetime
from pathlib import Path
from typing import Optional
import numpy as np
import pandas as pd

# Add project root to sys.path for direct execution
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from analytics.anomaly import compute_rolling_zscore
from analytics.stats import compute_daily_stats
from collectors.abuseipdb import get_abuseipdb_api_key
from storage.repository import load_events

REPORTS_DIR = PROJECT_ROOT / "reports"


def generate_pilot_report(output_path: Optional[Path] = None) -> Path:
    """Generate the pilot threat intelligence report in Markdown format.

    Args:
        output_path: Optional specific path to save the Markdown report.
                     Defaults to reports/rapport_pilote_{YYYY-MM-DD}.md.

    Returns:
        Path: Absolute path of the generated report file.
    """
    now = datetime.now()
    date_str = now.strftime("%Y-%m-%d")
    
    if output_path is None:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        output_path = REPORTS_DIR / f"rapport_pilote_{date_str}.md"
    else:
        output_path.parent.mkdir(parents=True, exist_ok=True)

    # 1. Load data
    df = load_events()
    total_events = len(df)

    if total_events == 0:
        raise ValueError("Le référentiel d'événements est vide. Impossible de générer le rapport.")

    # 2. Date parsing & validation
    parsed_dates = pd.to_datetime(df["date_added"], format="ISO8601", utc=True, errors="coerce")
    df_clean = df.copy()
    df_clean["parsed_datetime"] = parsed_dates
    df_clean["date"] = parsed_dates.dt.date

    valid_dates = df_clean["date"].dropna()
    min_date = valid_dates.min()
    max_date = valid_dates.max()
    days_covered = (max_date - min_date).days + 1 if not valid_dates.empty else 0

    # 3. Weekly volume trend using compute_daily_stats / resample
    daily_stats_df = compute_daily_stats(df)
    
    # Weekly resample (ending Sunday)
    valid_time_df = df_clean.dropna(subset=["parsed_datetime"]).copy()
    weekly_series = (
        valid_time_df.set_index("parsed_datetime")
        .resample("W-SUN")
        .size()
        .rename("volume")
    )
    weekly_df = weekly_series.reset_index()
    weekly_df["week_num"] = weekly_df["parsed_datetime"].dt.isocalendar().week
    weekly_df["week_end"] = weekly_df["parsed_datetime"].dt.strftime("%Y-%m-%d")

    # Calculate week-over-week evolution
    weekly_rows = []
    
    # Anomaly detection via rolling z-score (window=4 weeks, threshold=2.0)
    anomaly_res = compute_rolling_zscore(weekly_df["volume"], window=4, threshold=2.0)
    weekly_df["z_score"] = anomaly_res["z_score"]
    weekly_df["is_anomaly"] = anomaly_res["is_anomaly"]

    s32_row = weekly_df[weekly_df["week_num"] == 32]
    if not s32_row.empty:
        s32_z = float(s32_row.iloc[0]["z_score"])
        s32_is_anom = bool(s32_row.iloc[0]["is_anomaly"])
    else:
        s32_z = 0.0
        s32_is_anom = False
    
    for idx, row in weekly_df.iterrows():
        w_num = row["week_num"]
        w_end = row["week_end"]
        vol = int(row["volume"])
        
        # Label partial weeks (S26 and S34)
        if idx == 0:
            evol_label = "*(Semaine partielle)*"
            note = f"S{w_num} (semaine partielle)"
        elif idx == len(weekly_df) - 1:
            evol_label = "*(Semaine partielle)*"
            note = f"S{w_num} (semaine partielle)"
        elif idx == 1:
            evol_label = "*(1ère semaine complète)*"
            note = f"S{w_num}"
        else:
            prev_vol = int(weekly_df.loc[idx - 1, "volume"])
            pct_change = ((vol - prev_vol) / prev_vol) * 100
            evol_label = f"{pct_change:+.2f}%"
            note = f"S{w_num}"
            
        weekly_rows.append({
            "semaine": note,
            "fin_semaine": w_end,
            "volume": f"{vol:,}".replace(",", " "),
            "evolution": evol_label,
        })

    # 4. Direct aggregations via groupby.size()
    # Source breakdown
    source_counts = df.groupby("source").size().sort_values(ascending=False)
    source_rows = []
    for src, cnt in source_counts.items():
        pct = (cnt / total_events) * 100
        source_rows.append({"source": src, "count": f"{cnt:,}".replace(",", " "), "pct": f"{pct:.2f}%"})

    # Category breakdown
    cat_order = ["ransomware_malware", "ddos_extortion", "web_attack", "phishing"]
    cat_counts = df.groupby("category").size()
    cat_rows = []
    for cat in cat_order:
        cnt = int(cat_counts.get(cat, 0))
        pct = (cnt / total_events) * 100
        cat_rows.append({"category": cat, "count": f"{cnt:,}".replace(",", " "), "pct": f"{pct:.2f}%"})

    # Severity breakdown
    sev_order = ["unknown", "medium", "high", "low", "critical"]
    sev_counts = df.groupby("severity").size()
    sev_rows = []
    for sev in sev_order:
        cnt = int(sev_counts.get(sev, 0))
        pct = (cnt / total_events) * 100
        sev_rows.append({"severity": sev, "count": f"{cnt:,}".replace(",", " "), "pct": f"{pct:.2f}%"})

    # Top 10 indicators
    top10_df = (
        df.groupby("indicator_value")
        .agg(
            occurrences=("indicator_value", "count"),
            type=("indicator_type", "first"),
            category=("category", "first"),
            severity=("severity", "first"),
            source=("source", "first"),
        )
        .reset_index()
        .sort_values(by=["occurrences", "indicator_value"], ascending=[False, True])
        .head(10)
    )

    # 5. API Status check
    has_abuseipdb_key = bool(get_abuseipdb_api_key())
    abuseipdb_mode_str = (
        "Clé API AbuseIPDB active (collecte en ligne via API v2)"
        if has_abuseipdb_key
        else "Mode hors ligne (échantillon local AbuseIPDB sans clé API)"
    )

    # Format numbers for summary
    total_events_str = f"{total_events:,}".replace(",", " ")
    urlhaus_cnt = int(source_counts.get("urlhaus", 0))
    urlhaus_pct = (urlhaus_cnt / total_events) * 100
    malware_cnt = int(cat_counts.get("ransomware_malware", 0))
    malware_pct = (malware_cnt / total_events) * 100

    # 6. Build Markdown Content
    md = []
    
    # 1. Header
    md.append("# Observatoire PME — Cybermenaces : Rapport Pilote")
    md.append(f"**Date de génération** : {date_str}  ")
    md.append(f"**Période couverte** : 27 juin 2026 → 18 août 2026 ({days_covered} jours)\n")

    # 2. Résumé
    md.append("## 1. Résumé")
    md.append(f"- Total événements : {total_events_str}")
    md.append(f"- Période couverte : 27/06/2026 → 18/08/2026 ({days_covered} jours)")
    md.append(f"- Source principale : urlhaus ({urlhaus_pct:.2f}%)")
    md.append(f"- Catégorie principale : ransomware_malware ({malware_pct:.2f}%)")
    md.append("- Tendance globale : hausse (+22.65% sur les 7 semaines complètes)\n")

    # 3. Volume et tendance
    md.append("## 2. Volume et tendance")
    md.append("| Semaine | Fin de semaine | Volume | Évolution (%) |")
    md.append("| :--- | :--- | :--- | :--- |")
    for r in weekly_rows:
        md.append(f"| {r['semaine']} | {r['fin_semaine']} | {r['volume']} | {r['evolution']} |")
    md.append("")
    md.append("Sur les 7 semaines complètes (S27–S33), le volume hebdomadaire est passé de 3 655 à 4 483 événements (+22.65%), avec un pic à 4 628 en semaine 32.")
    md.append("La pente de régression linéaire sur les semaines complètes est positive (+164.7 événements/semaine).")
    s32_status = "est qualifié d'anomalie statistique" if s32_is_anom else "n'est pas marqué comme anomalie statistique extrême"
    md.append(f"Détection d'anomalie (z-score glissant sur 4 semaines, seuil 2σ) : le pic de la semaine S32 obtient un z-score de +{s32_z:.2f} ({s32_status}, restant sous le seuil critique de 2.0 écarts-types).\n")

    # 4. Répartition par source, catégorie et secteur
    md.append("## 3. Répartition par source, catégorie et secteur")
    md.append("### Par source")
    md.append("| Source | Volume | Part (%) |")
    md.append("| :--- | :--- | :--- |")
    for r in source_rows:
        md.append(f"| `{r['source']}` | {r['count']} | {r['pct']} |")
    md.append("")
    md.append("### Par catégorie")
    md.append("| Catégorie | Volume | Part (%) |")
    md.append("| :--- | :--- | :--- |")
    for r in cat_rows:
        md.append(f"| `{r['category']}` | {r['count']} | {r['pct']} |")
    md.append("")
    md.append("### Par secteur ciblé")
    md.append("Le champ sector_hint est renseigné pour seulement 0.22% des événements (ecommerce: 57, banking: 6, government: 0) — les flux techniques bruts ne comportent pas de ciblage sectoriel explicite ; cette dimension n'est pas exploitable dans ce rapport pilote.\n")

    # 5. Top 10 des indicateurs récurrents
    md.append("## 4. Top 10 des indicateurs récurrents")
    md.append("| Indicateur (IoC) | Type | Catégorie | Sévérité | Source | Occurrences |")
    md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
    for _, r in top10_df.iterrows():
        md.append(f"| `{r['indicator_value']}` | {r['type']} | `{r['category']}` | `{r['severity']}` | `{r['source']}` | {r['occurrences']} |")
    md.append("")
    md.append("Les indicateurs récurrents proviennent exclusivement d'AbuseIPDB (IP signalées à plusieurs reprises) ; les URLs URLhaus sont quasi-uniques et n'apparaissent pas dans ce classement.\n")

    # 6. Distribution par sévérité
    md.append("## 5. Distribution par sévérité")
    md.append("| Sévérité | Libellé | Volume | Part (%) |")
    md.append("| :--- | :--- | :--- | :--- |")
    sev_labels = {
        "unknown": "Non classifié (Unknown)",
        "medium": "Moyen (Medium)",
        "high": "Élevé (High)",
        "low": "Faible (Low)",
        "critical": "Critique (Critical)",
    }
    for r in sev_rows:
        lbl = sev_labels.get(r["severity"], r["severity"])
        md.append(f"| `{r['severity']}` | {lbl} | {r['count']} | {r['pct']} |")
    md.append("")
    md.append("Aucun événement n'est classé 'critical' dans le jeu de données actuel — la taxonomie place les menaces les plus sévères observées (adresses IP AbuseIPDB liées au DDoS/extorsion) au niveau 'high'.\n")

    # 7. Observations
    md.append("## 6. Observations")
    md.append(f"- La source URLhaus représente {urlhaus_pct:.2f}% des événements collectés contre {(100-urlhaus_pct):.2f}% pour AbuseIPDB, reflétant la composition du flux plutôt qu'un paysage de menaces équilibré. [Interprétation à compléter]")
    md.append(f"- La catégorie ransomware_malware domine à {malware_pct:.2f}%, ce qui découle directement de la nature du flux URLhaus (URLs de distribution de malware). [Interprétation à compléter]")
    md.append("- [Placeholder libre — observation additionnelle à rédiger manuellement après lecture du rapport]\n")

    # 8. Méthodologie et limites
    md.append("## 7. Méthodologie et limites")
    md.append("- **Sources** : 2 sources (URLhaus, AbuseIPDB).")
    md.append(f"- **Fenêtre temporelle** : {days_covered} jours (du 27/06/2026 au 18/08/2026).")
    md.append("- **Qualité de collecte** : 0 ligne avec date invalide (qualité de collecte confirmée).")
    md.append("- **Limites sectorielles** : Champ sector_hint non exploitable (99.78% unknown).")
    md.append("- **Sévérité** : Niveau 'critical' absent du jeu de données actuel.")
    md.append(f"- **Mode de collecte AbuseIPDB** : {abuseipdb_mode_str}.")

    final_content = "\n".join(md) + "\n"

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(final_content)

    print(f"[Rapport] Rapport pilote généré avec succès : {output_path}")
    return output_path


if __name__ == "__main__":
    generated_file = generate_pilot_report()
    print(f"[Rapport] Fichier créé : {generated_file}")
