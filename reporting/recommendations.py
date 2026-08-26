"""Prescriptive cyber hygiene recommendations engine for Moroccan SMEs.

Maps observed threat indicator tags and malware families to actionable,
concrete defensive recommendations. Pure dictionary lookup without external dependencies.
"""

from typing import Iterable, List, Optional, Set
import pandas as pd

# Mapping of threat tags / families / patterns to actionable SME recommendations
TAG_RECOMMENDATIONS = {
    # Botnets / IoT / DDoS
    "mirai": "Mettez à jour le firmware de vos routeurs, caméras IP et équipements connectés (IoT).",
    "gafgyt": "Mettez à jour le firmware de vos routeurs et isolez vos équipements réseau sur un VLAN dédié.",
    "mozi": "Désactivez les services d'administration distants non sécurisés (Telnet/SSH) exposés sur Internet.",
    "confidence_100": "Bloquez les adresses IP malveillantes récurrentes au niveau de votre pare-feu périmétrique.",
    "botnet": "Surveillez les connexions sortantes suspectes vers des serveurs de commande et contrôle (C2).",
    "botnetdomain": "Filtrez les requêtes DNS sortantes vers les domaines de botnets identifiés.",
    
    # Ransomware & Infostealers
    "ransomware": "Vérifiez l'intégrité et l'étanchéité de vos sauvegardes hors-ligne (règle 3-2-1).",
    "lockbit": "Vérifiez vos sauvegardes hors-ligne et appliquez l'authentification multi-facteurs (MFA) sur les accès distants.",
    "amadey": "Restreignez l'exécution de scripts non autorisés (PowerShell, macros) sur les postes utilisateurs.",
    "clearfake": "Sensibilisez vos collaborateurs contre les fausses invites de mise à jour de navigateurs web.",
    "stealer": "Renouvelez les identifiants compromis et déployez un gestionnaire de mots de passe d'entreprise.",
    
    # Generic malware & downloads
    "malware_download": "Évitez les téléchargements depuis des sources non vérifiées et filtrez les extensions exécutables.",
    "elf": "Sécurisez vos serveurs et appliances Linux (mises à jour de sécurité et gestion stricte des clés SSH).",
    "exe": "Installez et maintenez à jour une solution de protection Endpoint (Antivirus/EDR) sur tous les postes.",
    "phishing": "Formez les collaborateurs à la détection des e-mails frauduleux et vérifiez l'authenticité des expéditeurs.",
}

DEFAULT_RECOMMENDATION = (
    "Maintenez l'ensemble de vos systèmes d'exploitation et logiciels à jour et appliquez le principe de moindre privilège."
)


def get_recommendations_for_tags(tags: Iterable[str]) -> List[str]:
    """Retrieve unique defensive recommendations matching a collection of threat tags.

    Args:
        tags (Iterable[str]): List or set of threat tag strings (e.g. ['mirai', 'mozi']).

    Returns:
        List[str]: Deduplicated list of prescriptive recommendations for SMEs.
    """
    matched: Set[str] = set()
    recommendations: List[str] = []

    for tag in tags:
        if not tag or not isinstance(tag, str):
            continue
        tag_clean = tag.strip().lower()
        for key, reco in TAG_RECOMMENDATIONS.items():
            if key in tag_clean:
                if reco not in matched:
                    matched.add(reco)
                    recommendations.append(reco)

    if not recommendations:
        recommendations.append(DEFAULT_RECOMMENDATION)

    return recommendations


def extract_top_tags_from_dataframe(df: pd.DataFrame, top_n: int = 10) -> List[str]:
    """Extract the most frequent threat tags from an events DataFrame.

    Args:
        df (pd.DataFrame): Threat events DataFrame containing a 'tags' column.
        top_n (int): Maximum number of top tags to return.

    Returns:
        List[str]: List of top tag strings.
    """
    if df.empty or "tags" not in df.columns:
        return []

    tags_series = (
        df["tags"]
        .dropna()
        .astype(str)
        .str.split("[,;|]")
        .explode()
        .str.strip()
        .str.lower()
    )
    valid_tags = tags_series[tags_series != ""]
    if valid_tags.empty:
        return []
    return valid_tags.value_counts().head(top_n).index.tolist()
