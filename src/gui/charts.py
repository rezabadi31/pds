"""src/gui/charts.py
Dark Minimal Plotly Visualizations for Rox Platform
Color Palette:
- Background: #101827 / #060912
- Text: #F4F7FB / #8E9BAD
- Accents: Cyan #22D3EE, Blue #1687FF, Green #21D98B, Red #FF5577
"""

from typing import Dict, Any, List, Optional
import pandas as pd
import numpy as np

try:
    import plotly.graph_objects as go
    import plotly.express as px
    HAS_PLOTLY = True
except ImportError:
    HAS_PLOTLY = False

from config import THEME

CLASS_COLORS = {
    "benign": "#21D98B",           # Green
    "brute_force": "#FFB547",       # Amber
    "path_traversal": "#FF5577",    # Red
    "xss": "#1687FF",               # Blue
    "command_injection": "#EC4899", # Pink
    "sqli": "#22D3EE",              # Cyan
}


def apply_dark_layout(fig, title: str = "", height: int = 340):
    """Applies modern dark minimal styling to a Plotly figure."""
    if not HAS_PLOTLY or fig is None:
        return fig

    fig.update_layout(
        title={
            "text": f"<b>{title}</b>" if title else "",
            "font": {"size": 13, "color": THEME["text_primary"], "family": "Inter, sans-serif"},
            "x": 0.02,
            "xanchor": "left",
        },
        paper_bgcolor=THEME["card_bg"],
        plot_bgcolor="#0A0F1D",
        margin={"l": 40, "r": 20, "t": 45 if title else 20, "b": 35},
        height=height,
        font={"family": "Inter, sans-serif", "color": THEME["text_secondary"], "size": 11},
        xaxis={
            "showgrid": True,
            "gridcolor": "rgba(120, 180, 255, 0.07)",
            "linecolor": "rgba(120, 180, 255, 0.12)",
            "zeroline": False,
            "tickfont": {"size": 10, "color": THEME["text_secondary"]},
        },
        yaxis={
            "showgrid": True,
            "gridcolor": "rgba(120, 180, 255, 0.07)",
            "linecolor": "rgba(120, 180, 255, 0.12)",
            "zeroline": False,
            "tickfont": {"size": 10, "color": THEME["text_secondary"]},
        },
        legend={
            "bgcolor": "rgba(16, 24, 39, 0.8)",
            "bordercolor": "rgba(120, 180, 255, 0.12)",
            "borderwidth": 1,
            "font": {"size": 10, "color": THEME["text_primary"]},
        },
        hoverlabel={
            "bgcolor": "#151E2E",
            "font_size": 11,
            "font_family": "Inter, sans-serif",
            "font_color": "#F4F7FB",
            "bordercolor": THEME["accent_cyan"],
        },
    )
    return fig


def plot_traffic_classification_donut(label_counts: Dict[str, int]):
    """Renders a sleek donut chart of traffic classifications."""
    if not HAS_PLOTLY or not label_counts:
        return None

    labels = list(label_counts.keys())
    values = [label_counts[k] for k in labels]
    colors = [CLASS_COLORS.get(k.lower(), "#22D3EE") for k in labels]

    fig = go.Figure(
        data=[
            go.Pie(
                labels=[l.replace("_", " ").title() for l in labels],
                values=values,
                hole=0.55,
                marker=dict(colors=colors, line=dict(color="#060912", width=2)),
                textinfo="percent+label",
                textposition="outside",
                hoverinfo="label+value+percent",
            )
        ]
    )
    return apply_dark_layout(fig, "Traffic Classification Breakdown", height=320)


def plot_threat_distribution_bar(label_counts: Dict[str, int]):
    """Renders a horizontal bar chart of attack categories."""
    if not HAS_PLOTLY or not label_counts:
        return None

    non_benign = {k: v for k, v in label_counts.items() if k.lower() != "benign" and v > 0}
    if not non_benign:
        # If 100% benign
        labels = ["Benign"]
        values = [label_counts.get("benign", 1)]
        colors = ["#21D98B"]
    else:
        labels = [k.replace("_", " ").title() for k in non_benign.keys()]
        values = list(non_benign.values())
        colors = [CLASS_COLORS.get(k.lower(), "#22D3EE") for k in non_benign.keys()]

    fig = go.Figure(
        data=[
            go.Bar(
                x=values,
                y=labels,
                orientation="h",
                marker=dict(color=colors, line=dict(color="rgba(255,255,255,0.05)", width=1)),
                text=values,
                textposition="auto",
            )
        ]
    )
    fig.update_layout(yaxis=dict(autorange="reversed"))
    return apply_dark_layout(fig, "Threat Distribution (Incident Counts)", height=280)


def plot_feature_importance_bar(feature_importance_df: pd.DataFrame, top_n: int = 10):
    """Renders top N feature importances."""
    if not HAS_PLOTLY or feature_importance_df is None or feature_importance_df.empty:
        return None

    top_df = feature_importance_df.head(top_n).copy()
    top_df.sort_values(by="importance", ascending=True, inplace=True)

    fig = go.Figure(
        data=[
            go.Bar(
                x=top_df["importance"],
                y=top_df["feature"],
                orientation="h",
                marker=dict(
                    color=THEME["accent_cyan"],
                    line=dict(color="rgba(34, 211, 238, 0.4)", width=1)
                ),
                text=top_df["importance"].round(3),
                textposition="auto",
            )
        ]
    )
    return apply_dark_layout(fig, f"Top {top_n} Discriminative Features", height=320)


def plot_pipeline_stage_durations_dark():
    """Renders verified Practical 10 pipeline stage execution durations."""
    if not HAS_PLOTLY:
        return None

    stages = [
        {"Stage": "1. Ingestion / Load", "Duration": 20.58, "Pct": "18.9%"},
        {"Stage": "2. Structuring", "Duration": 23.22, "Pct": "21.4%"},
        {"Stage": "3. Preprocessing", "Duration": 9.48, "Pct": "8.7%"},
        {"Stage": "4. Attack Labeling", "Duration": 20.48, "Pct": "18.8%"},
        {"Stage": "5. Feature Eng.", "Duration": 4.96, "Pct": "4.6%"},
        {"Stage": "6. Serialization", "Duration": 29.98, "Pct": "27.6%"},
    ]
    df = pd.DataFrame(stages)

    fig = go.Figure(
        data=[
            go.Bar(
                x=df["Stage"],
                y=df["Duration"],
                marker=dict(
                    color=["#22D3EE", "#1687FF", "#21D98B", "#FF5577", "#FFB547", "#1687FF"],
                    line=dict(color="rgba(255,255,255,0.08)", width=1),
                ),
                text=[f"{v:.1f}s ({p})" for v, p in zip(df["Duration"], df["Pct"])],
                textposition="outside",
            )
        ]
    )
    fig.update_layout(yaxis_title="Seconds")
    return apply_dark_layout(fig, "Practical 10 Pipeline Stage Durations (108.67s Total)", height=300)
