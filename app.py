"""Observatoire PME — Cybermenaces Dashboard Application.

Streamlit application for threat intelligence visualization and SME monitoring.
"""

import base64
from datetime import date
from pathlib import Path
import pandas as pd
import streamlit as st

try:
    from streamlit_extras.metric_cards import style_metric_cards
except ImportError:
    def style_metric_cards(*args, **kwargs):
        """Fallback no-op when streamlit_extras is not installed."""
        pass

from analytics.stats import compute_daily_stats, load_events
from collectors.abuseipdb import get_abuseipdb_api_key
from theme_tokens import COLORS, SEVERITY_COLORS, SEVERITY_LABELS

# 1. Page configuration & brand assets
st.set_page_config(
    page_title="Observatoire PME — Cybermenaces",
    page_icon="assets/favicon.png",
    layout="wide",
)


def _get_logo_base64() -> str:
    """Load logo as base64 string for inline HTML rendering."""
    logo_file = Path(__file__).parent / "assets" / "logo.png"
    if logo_file.exists():
        return base64.b64encode(logo_file.read_bytes()).decode("utf-8")
    return ""


LOGO_B64 = _get_logo_base64()


# 2. Centralized Neo-skeuomorphic theme CSS injection
def inject_theme_css():
    """Inject centralized CSS for border glow, card depth, and neo-skeuomorphic buttons."""
    st.markdown(
        """
        <style>
        [data-testid="stSidebar"] .sidebar-brand-text {
            display: block;
        }
        /* When Streamlit collapses the sidebar, it sets aria-expanded="false" on the sidebar's control — this rule hides the text and centers the icon when that happens */
        [data-testid="stSidebarCollapsedControl"] ~ * .sidebar-brand-text,
        section[data-testid="stSidebar"][aria-expanded="false"] .sidebar-brand-text {
            display: none;
        }
        [data-testid="stVerticalBlockBorderWrapper"] {
            border: 1px solid rgba(255,255,255,0.08) !important;
            box-shadow: 0 1px 0 rgba(255,255,255,0.06) inset,
                        0 4px 12px rgba(0,0,0,0.4);
            border-radius: 0.75rem;
        }
        button[kind="primary"] {
            background: linear-gradient(180deg, #e8913f 0%, #db7c26 60%, #a85f1c 100%);
            border: 1px solid rgba(255,255,255,0.14);
            box-shadow: 0 1px 0 rgba(255,255,255,0.2) inset,
                        0 2px 6px rgba(0,0,0,0.35);
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


inject_theme_css()


# 3. Cached data loading
@st.cache_data(ttl=3600)
def get_data() -> pd.DataFrame:
    """Load and preprocess threat events from the storage layer with caching.

    Returns:
        pd.DataFrame: Threat events with parsed datetime and date columns.
    """
    df = load_events()
    if not df.empty and "date_added" in df.columns:
        parsed_dates = pd.to_datetime(
            df["date_added"], format="ISO8601", utc=True, errors="coerce"
        )
        df = df.copy()
        df["parsed_datetime"] = parsed_dates
        df["date"] = parsed_dates.dt.date
    else:
        df["parsed_datetime"] = pd.Series(dtype="datetime64[ns, UTC]")
        df["date"] = pd.Series(dtype="object")
    return df


df_raw = get_data()

# 4. Sidebar setup & filter controls
if LOGO_B64:
    sidebar_brand_html = (
        f'<div style="display:flex;align-items:center;gap:10px;padding:4px 0 10px 0;">'
        f'<img src="data:image/png;base64,{LOGO_B64}" width="28" height="28" style="object-fit:contain;vertical-align:middle;" />'
        f'<span class="sidebar-brand-text" style="font-weight:600;font-size:1.2rem;letter-spacing:-0.02em;">plUme</span>'
        f'</div>'
    )
else:
    sidebar_brand_html = (
        '<div style="display:flex;align-items:center;gap:8px;padding:8px 0;">'
        '<span style="font-size:1.5rem;">🛡️</span>'
        '<span class="sidebar-brand-text" style="font-weight:600;">plUme</span>'
        '</div>'
    )

st.sidebar.markdown(
    sidebar_brand_html,
    unsafe_allow_html=True,
)

st.sidebar.markdown("### :material/tune: Filtres")

# Text search filter for indicator_value (IP / domain / URL)
search_query = st.sidebar.text_input(
    "Recherche IoC (IP, domaine, URL)",
    placeholder="Ex: 182.122, .online, mozi...",
)

# Date range extraction
valid_dates = df_raw["date"].dropna()
if not valid_dates.empty:
    min_date = valid_dates.min()
    max_date = valid_dates.max()
else:
    min_date = date.today()
    max_date = date.today()

selected_dates = st.sidebar.date_input(
    "Période d'analyse",
    value=(min_date, max_date),
    min_value=min_date,
    max_value=max_date,
    format="YYYY-MM-DD",
)

# Robust date selection handling
if isinstance(selected_dates, (tuple, list)):
    if len(selected_dates) == 2:
        start_date, end_date = selected_dates
    elif len(selected_dates) == 1:
        start_date = end_date = selected_dates[0]
    else:
        start_date, end_date = min_date, max_date
else:
    start_date = end_date = selected_dates

# Source multiselect
available_sources = sorted(df_raw["source"].dropna().unique().tolist())
selected_sources = st.sidebar.multiselect(
    "Source",
    options=available_sources,
    default=available_sources,
)

# Category multiselect
available_categories = sorted(df_raw["category"].dropna().unique().tolist())
selected_categories = st.sidebar.multiselect(
    "Catégorie",
    options=available_categories,
    default=available_categories,
)

# Indicator type multiselect
available_indicator_types = sorted(df_raw["indicator_type"].dropna().unique().tolist())
selected_indicator_types = st.sidebar.multiselect(
    "Type d'indicateur",
    options=available_indicator_types,
    default=available_indicator_types,
)

# Status multiselect (default: active threats only, e.g. 'online')
available_statuses = sorted(df_raw["status"].dropna().unique().tolist())
default_statuses = [s for s in available_statuses if s in ["online", "active"]]
if not default_statuses:
    default_statuses = available_statuses

selected_statuses = st.sidebar.multiselect(
    "Statut de l'indicateur",
    options=available_statuses,
    default=default_statuses,
    help="Par défaut filtré sur les menaces actives ('online'). Cochez 'offline' pour inclure l'historique.",
)

# Sector hint multiselect (PME Maroc targeting)
available_sectors = sorted(df_raw["sector_hint"].dropna().unique().tolist())
selected_sectors = st.sidebar.multiselect(
    "Secteur ciblé (PME)",
    options=available_sectors,
    default=available_sectors,
    help="Indication du secteur d'activité ciblé dans le contexte des PME marocaines.",
)

# Refresh button
if st.sidebar.button("Actualiser", icon=":material/refresh:", type="primary"):
    st.cache_data.clear()
    st.rerun()

# Sidebar footer metadata & API key status
latest_date_str = max_date.strftime("%Y-%m-%d") if isinstance(max_date, date) else str(max_date)
st.sidebar.caption(f":material/schedule: Dernière mise à jour : {latest_date_str}")

if get_abuseipdb_api_key():
    st.sidebar.success("AbuseIPDB : clé API active", icon=":material/check_circle:")
else:
    st.sidebar.warning("AbuseIPDB : mode hors ligne (aucune clé API)", icon=":material/cloud_off:")

# 5. Single-step filtering
filter_mask = (
    (df_raw["date"] >= start_date)
    & (df_raw["date"] <= end_date)
    & (df_raw["source"].isin(selected_sources))
    & (df_raw["category"].isin(selected_categories))
    & (df_raw["indicator_type"].isin(selected_indicator_types))
    & (df_raw["status"].isin(selected_statuses))
    & (df_raw["sector_hint"].isin(selected_sectors))
)

if search_query.strip():
    filter_mask &= df_raw["indicator_value"].str.contains(
        search_query.strip(), case=False, regex=False, na=False
    )

filtered_df = df_raw[filter_mask].copy()
