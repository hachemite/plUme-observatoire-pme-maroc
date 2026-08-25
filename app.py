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
