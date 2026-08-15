"""Analytics module for computing summary statistics and threat distributions."""

import sys
from pathlib import Path
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from storage.repository import load_events

STATS_FILE = PROJECT_ROOT / "data" / "daily_stats.csv"

def compute_daily_stats(df: pd.DataFrame) -> pd.DataFrame:
    """
    Fonction pure : calcule le nombre d'événements par jour et par catégorie.
    Gère les DataFrames vides sans crasher.
    """
    if df.empty:
        return pd.DataFrame(columns=["date", "category", "count"])

    df = df.copy()
    
    # Conversion robuste des dates avec gestion des fuseaux horaires mixtes (+00:00 vs sans offset)
    parsed_dates = pd.to_datetime(df["date_added"], format="ISO8601", utc=True, errors="coerce")
    
    # Alerte explicite si des lignes contiennent des dates invalides
    invalid_mask = parsed_dates.isna()
    if invalid_mask.any():
        dropped_count = invalid_mask.sum()
        sources = df.loc[invalid_mask, "source"].value_counts().to_dict() if "source" in df.columns else "inconnu"
        print(f"[Stats] AVERTISSEMENT : {dropped_count} lignes ignorées (dates non reconnues). Sources : {sources}")
    
    df["date_added"] = parsed_dates
    df = df.dropna(subset=["date_added"]).copy()

    # Si le DataFrame est vide après nettoyage des dates invalides
    if df.empty:
        return pd.DataFrame(columns=["date", "category", "count"])

    df["date"] = df["date_added"].dt.date
    
    # Agrégation : format long (date, category, count)
    stats_df = df.groupby(["date", "category"]).size().reset_index(name="count")
    stats_df = stats_df.sort_values(by=["date", "category"])
    
    return stats_df

def generate_daily_stats() -> None:
    """
    Orchestrateur : charge les données, appelle le calcul, et sauvegarde le CSV.
    """
    print("[Stats] Chargement des événements...")
    df = load_events()
    
    if df.empty:
        print("[Stats] AVERTISSEMENT : Le DataFrame d'entrée est vide. Aucune donnée à analyser ce jour.")
        print("[Stats] Sortie propre. Aucun fichier stats n'a été écrasé.")
        return

    print(f"[Stats] {len(df)} événements chargés. Calcul des statistiques...")
    
    # Appel de la fonction pure
    stats_df = compute_daily_stats(df)
    
    if stats_df.empty:
        print("[Stats] Aucun événement valide trouvé après parsing des dates.")
        return

    # Écriture du fichier CSV (écrasement complet)
    STATS_FILE.parent.mkdir(parents=True, exist_ok=True)
    stats_df.to_csv(STATS_FILE, index=False)
    print(f"[Stats] Fichier généré et écrasé : {STATS_FILE.name}")
    
    total_events = stats_df["count"].sum()
    days_covered = stats_df["date"].nunique()
    
    print("\n" + "=" * 50)
    print("=== RÉSUMÉ DES STATISTIQUES (JALON 2) ===")
    print(f"Événements totaux agrégés : {total_events}")
    print(f"Nombre de jours couverts  : {days_covered}")
    print("=" * 50)
    print("\nLes 5 dernières lignes de daily_stats.csv :")
    print(stats_df.tail(5).to_string(index=False))
    print("\n[Stats] Exécution terminée avec succès.")

if __name__ == "__main__":
    generate_daily_stats()