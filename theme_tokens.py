"""Theme tokens and color palette definitions for Observatoire PME dashboard."""

COLORS = {
    "onyx": "#121212",
    "graphite": "#2a2a2a",
    "white": "#ffffff",
    "cool_steel": "#a0a0a0",
    # Ochre ramp — for depth, gradients, hover states
    "ochre_100": "#fde8d4",  # lightest tint — text on dark orange fills
    "ochre_300": "#f0b374",
    "ochre_500": "#db7c26",  # base — original ochre
    "ochre_700": "#a85f1c",  # darker — pressed/active states
    "ochre_900": "#6b3c10",  # deepest — gradient shadow end
    # Border/glow — the Spotify "white fade" separator
    "border_glow": "rgba(255, 255, 255, 0.08)",
    "border_glow_strong": "rgba(255, 255, 255, 0.14)",
}

SEVERITY_COLORS = {
    "low": "#f4c542",
    "medium": "#e08d2e",
    "high": "#c2452e",
    "critical": "#8b1e1e",
    "unknown": "#a0a0a0",
}

SEVERITY_LABELS = {
    "low": "Faible (Low)",
    "medium": "Moyen (Medium)",
    "high": "Élevé (High)",
    "critical": "Critique (Critical)",
    "unknown": "Non classifié (Unknown)",
}
