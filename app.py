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

from analytics.correlate import tag_cross_source_confirmed
from analytics.risk_score import score_indicators_dataframe
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
        pd.DataFrame: Threat events with parsed datetime, cross-source confirmation, and risk scores.
    """
    df = load_events()
    if not df.empty and "date_added" in df.columns:
        parsed_dates = pd.to_datetime(
            df["date_added"], format="ISO8601", utc=True, errors="coerce"
        )
        df = df.copy()
        df["parsed_datetime"] = parsed_dates
        df["date"] = parsed_dates.dt.date
        df = tag_cross_source_confirmed(df)
        df = score_indicators_dataframe(df)
    else:
        df["parsed_datetime"] = pd.Series(dtype="datetime64[ns, UTC]")
        df["date"] = pd.Series(dtype="object")
        df["cross_source_confirmed"] = pd.Series(dtype=bool)
        df["risk_score"] = pd.Series(dtype=float)
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

# 6. Main content brand header
header_col1, header_col2 = st.columns([1, 14])
with header_col1:
    if (Path(__file__).parent / "assets" / "logo.png").exists():
        st.image("assets/logo.png", width=56)
    else:
        st.markdown("### :material/shield_person:")
with header_col2:
    st.markdown("## plUme")
    st.caption("Observatoire de veille cyber pour les PME marocaines")
st.divider()

# 7. KPI Metrics Row
col1, col2, col3, col4 = st.columns(4)

total_unfiltered = len(df_raw)
total_filtered = len(filtered_df)

with col1:
    if total_unfiltered > 0:
        ratio = (total_filtered / total_unfiltered) * 100
        delta_str = f"{ratio:.1f}% du total"
    else:
        delta_str = None

    st.metric(
        label="Total Événements",
        value=f"{total_filtered:,}".replace(",", " "),
        delta=delta_str,
        delta_color="off" if total_filtered == total_unfiltered else "normal",
    )

with col2:
    days_count = filtered_df["date"].nunique() if not filtered_df.empty else 0
    st.metric(
        label="Jours Couverts",
        value=f"{days_count} j",
    )

with col3:
    if not filtered_df.empty and not filtered_df["category"].empty:
        top_cat = filtered_df["category"].value_counts().index[0]
    else:
        top_cat = "N/A"

    st.metric(
        label="Catégorie Principale",
        value=top_cat,
    )

with col4:
    if not filtered_df.empty and not filtered_df["source"].empty:
        top_src = filtered_df["source"].value_counts().index[0]
    else:
        top_src = "N/A"

    st.metric(
        label="Source Principale",
        value=top_src,
    )

# Neo-skeuomorphic style injection for KPI cards
style_metric_cards(
    background_color=COLORS["graphite"],
    border_color=COLORS["border_glow"],
    border_left_color=COLORS["ochre_500"],
    box_shadow=True,
)

st.divider()

# 8. Section: Volume Evolution Line Chart (with Daily / Weekly toggle in container)
with st.container(border=True):
    vol_head_col, vol_toggle_col = st.columns([3, 1])

    with vol_head_col:
        st.subheader(":material/trending_up: Évolution du volume")

    with vol_toggle_col:
        granularity = st.radio(
            "Granularité",
            options=["Quotidienne", "Hebdomadaire"],
            horizontal=True,
            label_visibility="collapsed",
        )

    if not filtered_df.empty:
        if granularity == "Hebdomadaire":
            valid_time_df = filtered_df.dropna(subset=["parsed_datetime"]).copy()
            if not valid_time_df.empty:
                weekly_volume = (
                    valid_time_df.set_index("parsed_datetime")
                    .resample("W-SUN")
                    .size()
                    .rename("Événements")
                )
                weekly_volume.index = weekly_volume.index.strftime("%Y-%m-%d")
                st.line_chart(
                    weekly_volume,
                    x_label="Semaine (finissant le)",
                    y_label="Nombre d'événements",
                )
            else:
                st.info("Aucune donnée temporelle valide pour l'agrégation hebdomadaire.", icon=":material/info:")
        else:
            stats_df = compute_daily_stats(filtered_df)
            if not stats_df.empty:
                daily_volume = stats_df.groupby("date")["count"].sum()
                st.line_chart(
                    daily_volume,
                    x_label="Date",
                    y_label="Nombre d'événements",
                )
            else:
                st.info("Aucune statistique journalière calculable pour les données sélectionnées.", icon=":material/info:")
    else:
        st.info("Aucun événement à afficher pour les filtres sélectionnés.", icon=":material/info:")

# 9. Section: Threat Breakdowns & Top Offenders (in container)
with st.container(border=True):
    st.subheader(":material/analytics: Répartition des menaces")
    chart_col1, chart_col2, chart_col3 = st.columns(3)

    with chart_col1:
        st.markdown("#### :material/source: Par source")
        if not filtered_df.empty and "source" in filtered_df.columns:
            source_counts = filtered_df["source"].value_counts()
            st.bar_chart(source_counts, x_label="Source", y_label="Événements")
        else:
            st.info("Aucune donnée de source disponible.")

    with chart_col2:
        st.markdown("#### :material/category: Par catégorie")
        if not filtered_df.empty and "category" in filtered_df.columns:
            category_counts = filtered_df["category"].value_counts()
            st.bar_chart(category_counts, x_label="Catégorie", y_label="Événements")
        else:
            st.info("Aucune donnée de catégorie disponible.")

    with chart_col3:
        st.markdown("#### :material/domain: Par secteur ciblé (PME)")
        if not filtered_df.empty and "sector_hint" in filtered_df.columns:
            sector_counts = filtered_df["sector_hint"].value_counts()
            st.bar_chart(sector_counts, x_label="Secteur", y_label="Événements")
        else:
            st.info("Aucune donnée sectorielle disponible.")

    st.markdown("#### :material/priority_high: Top 10 des indicateurs prioritaires (par score de risque)")
    st.caption("Indicateurs classés selon le score composite de risque (gravité, récurrence, corrélation multi-sources et catégorie).")

    if not filtered_df.empty and "indicator_value" in filtered_df.columns:
        top_offenders = (
            filtered_df.groupby("indicator_value")
            .agg(
                risk_score=("risk_score", "max"),
                occurrences=("indicator_value", "count"),
                type=("indicator_type", "first"),
                category=("category", "first"),
                severity=("severity", "first"),
                cross_source_confirmed=("cross_source_confirmed", "max"),
            )
            .reset_index()
            .sort_values(by=["risk_score", "occurrences", "indicator_value"], ascending=[False, False, True])
            .head(10)
        )

        top_config = {
            "risk_score": st.column_config.NumberColumn(
                "Score de risque",
                help="Score composite (0-100) : 40% Sévérité, 30% Récurrence, 20% Corrélation multi-sources, 10% Catégorie.",
                format="%.1f",
            ),
            "indicator_value": st.column_config.TextColumn(
                "Indicateur (IoC)",
                help="Valeur technique observable dans les flux.",
            ),
            "type": st.column_config.TextColumn(
                "Type",
                help="Type d'IoC (IP, URL).",
            ),
            "category": st.column_config.TextColumn(
                "Catégorie",
                help="Classification de menace AUSIM/CMRPI.",
            ),
            "severity": st.column_config.TextColumn(
                "Sévérité",
                help="Niveau de criticité évalué.",
            ),
            "cross_source_confirmed": st.column_config.CheckboxColumn(
                "Corroboré",
                help="Indique si l'indicateur est corroboré simultanément sur URLhaus et AbuseIPDB.",
            ),
            "occurrences": st.column_config.ProgressColumn(
                "Occurrences",
                help="Nombre total d'apparitions de cet indicateur.",
                format="%d",
                min_value=0,
                max_value=int(top_offenders["occurrences"].max()) if not top_offenders.empty else 10,
            ),
        }

        # Apply severity and risk styling
        def style_risk_score(val):
            try:
                num = float(val)
            except (ValueError, TypeError):
                return ""
            if num >= 65.0:
                color = SEVERITY_COLORS.get("high", "#c2452e")
            elif num >= 50.0:
                color = SEVERITY_COLORS.get("medium", "#e08d2e")
            elif num >= 25.0:
                color = SEVERITY_COLORS.get("low", "#f4c542")
            else:
                color = COLORS.get("cool_steel", "#a0a0a0")
            return f"background-color: {color}22; color: {color}; font-weight: 700; border-radius: 4px;"

        styled_top = (
            top_offenders.style
            .map(style_risk_score, subset=["risk_score"])
        )

        st.dataframe(
            styled_top,
            column_config=top_config,
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("Aucun indicateur disponible pour identifier les récurrences.")

# 10. Section: Severity Distribution View (in container)
with st.container(border=True):
    st.subheader(":material/warning: Distribution par sévérité")

    if not filtered_df.empty and "severity" in filtered_df.columns:
        severity_counts = filtered_df["severity"].value_counts()

        severity_order = ["low", "medium", "high", "critical", "unknown"]
        active_severities = [s for s in severity_order if s in severity_counts.index or s in ["low", "medium", "high", "critical"]]

        sev_cols = st.columns(len(active_severities))
        for idx, sev_key in enumerate(active_severities):
            count = int(severity_counts.get(sev_key, 0))
            pct = (count / total_filtered * 100) if total_filtered > 0 else 0.0
            color = SEVERITY_COLORS.get(sev_key, COLORS["cool_steel"])
            label = SEVERITY_LABELS.get(sev_key, sev_key.capitalize())

            with sev_cols[idx]:
                st.markdown(
                    f"""
                    <div style="
                        background-color: {COLORS['graphite']};
                        border: 1px solid rgba(255, 255, 255, 0.08);
                        border-left: 5px solid {color};
                        border-radius: 0.75rem;
                        padding: 14px 16px;
                        margin-bottom: 12px;
                        box-shadow: 0 1px 0 rgba(255,255,255,0.06) inset, 0 4px 12px rgba(0,0,0,0.4);
                    ">
                        <div style="font-size: 0.8rem; color: {COLORS['cool_steel']}; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">
                            {label}
                        </div>
                        <div style="font-size: 1.6rem; font-weight: 700; color: {COLORS['white']}; margin-top: 4px;">
                            {count:,}
                        </div>
                        <div style="font-size: 0.85rem; color: {color}; font-weight: 600; margin-top: 2px;">
                            {pct:.1f}% des menaces
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
    else:
        st.info("Aucune donnée de sévérité disponible pour cette sélection.")

# 11. Section: Detailed Events Data Explorer (in container)
with st.container(border=True):
    st.subheader(":material/table_rows: Événements détaillés")

    if not filtered_df.empty:
        sorted_df = filtered_df.sort_values(by="parsed_datetime", ascending=False)

        standard_columns = [
            "risk_score",
            "event_id",
            "source",
            "date_added",
            "indicator_type",
            "indicator_value",
            "raw_threat_tag",
            "tags",
            "country_code",
            "status",
            "category",
            "severity",
            "cross_source_confirmed",
            "sector_hint",
        ]
        display_cols = [c for c in standard_columns if c in sorted_df.columns]
        full_export_df = sorted_df[display_cols]

        total_count = len(full_export_df)
        capped_df = full_export_df.head(500)

        # Caption & Export Button Bar
        col_cap, col_exp = st.columns([3, 1])
        with col_cap:
            st.caption(f"{total_count:,} événements au total, 500 les plus récents affichés".replace(",", " "))

        with col_exp:
            csv_bytes = full_export_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="Télécharger (CSV)",
                data=csv_bytes,
                file_name="evenements_cybermenaces_filtres.csv",
                mime="text/csv",
                icon=":material/download:",
                type="primary",
            )

        col_config = {
            "risk_score": st.column_config.NumberColumn(
                "Score de risque",
                help="Score composite (0-100) : 40% Sévérité, 30% Récurrence, 20% Corrélation multi-sources, 10% Catégorie.",
                format="%.1f",
            ),
            "event_id": st.column_config.TextColumn(
                "ID Événement",
                help="Identifiant unique de l'événement de menace.",
            ),
            "source": st.column_config.TextColumn(
                "Source",
                help="Flux de renseignement d'origine : URLhaus ou AbuseIPDB.",
            ),
            "date_added": st.column_config.TextColumn(
                "Date d'ajout",
                help="Horodatage UTC de la détection et enregistrement de l'indicateur.",
            ),
            "indicator_type": st.column_config.TextColumn(
                "Type d'IoC",
                help="Type d'indicateur de compromission (ex: url, ip).",
            ),
            "indicator_value": st.column_config.TextColumn(
                "Indicateur (IoC)",
                help="Valeur technique observable (URL suspecte, IP malveillante).",
            ),
            "raw_threat_tag": st.column_config.TextColumn(
                "Tag brut",
                help="Tag ou étiquette technique issue de la source primaire.",
            ),
            "tags": st.column_config.TextColumn(
                "Tags",
                help="Mots-clés décrivant le comportement ou la charge malveillante.",
            ),
            "country_code": st.column_config.TextColumn(
                "Pays",
                help="Code pays géographique associé à l'hôte.",
            ),
            "status": st.column_config.TextColumn(
                "Statut",
                help="État de disponibilité de l'indicateur au moment de la collecte.",
            ),
            "category": st.column_config.TextColumn(
                "Catégorie",
                help="Taxonomie AUSIM/CMRPI : ransomware_malware, phishing, ddos_extortion, web_attack.",
            ),
            "severity": st.column_config.TextColumn(
                "Sévérité",
                help="Niveau de criticité évalué : low, medium, high, critical, unknown.",
            ),
            "cross_source_confirmed": st.column_config.CheckboxColumn(
                "Corroboré",
                help="Indique si l'indicateur est corroboré simultanément sur URLhaus et AbuseIPDB.",
            ),
            "sector_hint": st.column_config.TextColumn(
                "Secteur ciblé",
                help="Indication sectorielle pour les PME marocaines.",
            ),
        }

        # 11. Style dataframe with colored tags using pandas Styler
        def style_severity(val):
            colors = {
                "low": SEVERITY_COLORS.get("low", "#f4c542"),
                "medium": SEVERITY_COLORS.get("medium", "#e08d2e"),
                "high": SEVERITY_COLORS.get("high", "#c2452e"),
                "critical": SEVERITY_COLORS.get("critical", "#8b1e1e"),
            }
            color = colors.get(str(val).lower(), COLORS.get("cool_steel", "#a0a0a0"))
            return f"background-color: {color}22; color: {color}; font-weight: 600; border-radius: 4px;"

        def style_category(val):
            cat_colors = {
                "ransomware_malware": COLORS.get("ochre_500", "#db7c26"),
                "ddos_extortion": COLORS.get("ochre_700", "#a85f1c"),
                "phishing": COLORS.get("ochre_300", "#f0b374"),
                "web_attack": COLORS.get("cool_steel", "#a0a0a0"),
            }
            color = cat_colors.get(str(val).lower(), COLORS.get("cool_steel", "#a0a0a0"))
            return f"background-color: {color}22; color: {color}; font-weight: 600; border-radius: 4px;"

        def style_risk_score(val):
            try:
                num = float(val)
            except (ValueError, TypeError):
                return ""
            if num >= 65.0:
                color = SEVERITY_COLORS.get("high", "#c2452e")
            elif num >= 50.0:
                color = SEVERITY_COLORS.get("medium", "#e08d2e")
            elif num >= 25.0:
                color = SEVERITY_COLORS.get("low", "#f4c542")
            else:
                color = COLORS.get("cool_steel", "#a0a0a0")
            return f"background-color: {color}22; color: {color}; font-weight: 700; border-radius: 4px;"

        styled_df = (
            capped_df.style
            .map(style_severity, subset=["severity"])
            .map(style_category, subset=["category"])
            .map(style_risk_score, subset=["risk_score"])
        )

        st.dataframe(
            styled_df,
            column_config=col_config,
            use_container_width=True,
            hide_index=True,
        )

        st.caption("ℹ️ **Méthodologie du score de risque** : Le score (0 à 100) pondère la sévérité d'impact (40%), la récurrence de l'indicateur (30%), la corroboration croisée multi-sources (20%) et la dangerosité de la catégorie de menace (10%).")

        # 12. Detail drill-down expander with native st.badge indicators
        with st.expander("Voir un événement en détail"):
            indicator_options = full_export_df["indicator_value"].dropna().unique().tolist()
            if indicator_options:
                selected_indicator = st.selectbox(
                    "Sélectionner un indicateur pour inspecter ses détails :",
                    options=indicator_options,
                    index=0,
                )
                if selected_indicator:
                    matching_event = full_export_df[full_export_df["indicator_value"] == selected_indicator]
                    if not matching_event.empty:
                        row = matching_event.iloc[0]

                        # Native st.badge indicators
                        b_col1, b_col2, b_col3, b_col4 = st.columns(4)
                        with b_col1:
                            sev_val = str(row.get("severity", "unknown")).lower()
                            sev_color = "red" if sev_val == "critical" else "orange" if sev_val in ("high", "medium") else "yellow" if sev_val == "low" else "gray"
                            st.markdown("**Sévérité :**")
                            st.badge(str(row.get("severity", "unknown")).capitalize(), color=sev_color, icon=":material/warning:")

                        with b_col2:
                            cat_val = str(row.get("category", "unknown"))
                            cat_color = "orange" if "ransomware" in cat_val else "yellow" if "phishing" in cat_val else "blue"
                            st.markdown("**Catégorie :**")
                            st.badge(cat_val, color=cat_color, icon=":material/category:")

                        with b_col3:
                            status_val = str(row.get("status", "unknown")).lower()
                            status_color = "green" if status_val == "online" else "gray"
                            st.markdown("**Statut :**")
                            st.badge(status_val.capitalize(), color=status_color, icon=":material/wifi:" if status_val == "online" else ":material/wifi_off:")

                        with b_col4:
                            st.markdown("**Source :**")
                            st.badge(str(row.get("source", "unknown")), color="primary", icon=":material/source:")

                        st.divider()
                        st.json(row.to_dict())
            else:
                st.info("Aucun indicateur disponible dans le jeu de données filtré.")
    else:
        st.info("Aucun événement détaillé disponible pour cette sélection.")
