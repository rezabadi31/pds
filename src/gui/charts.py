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


def plot_class_distribution_dark(log_scale: bool = True) -> Optional[Any]:
    """Plot the actual 6 ground-truth classes from Practical 04."""
    if not HAS_PLOTLY:
        return None
    data = [
        {"Class": "Benign", "Count": 1_487_823, "Pct": "99.708%"},
        {"Class": "Brute Force", "Count": 1_342, "Pct": "0.090%"},
        {"Class": "Path Traversal", "Count": 1_098, "Pct": "0.074%"},
        {"Class": "XSS", "Count": 954, "Pct": "0.064%"},
        {"Class": "Command Inj.", "Count": 805, "Pct": "0.054%"},
        {"Class": "SQLi", "Count": 160, "Pct": "0.011%"},
    ]
    df = pd.DataFrame(data)
    colors = ["#21D98B", "#FFB547", "#FF5577", "#1687FF", "#EC4899", "#22D3EE"]

    fig = go.Figure(
        data=[
            go.Bar(
                x=df["Class"],
                y=df["Count"],
                text=[f"{c:,}<br>({p})" for c, p in zip(df["Count"], df["Pct"])],
                textposition="auto",
                marker_color=colors,
                marker_line=dict(color="rgba(255,255,255,0.1)", width=1),
            )
        ]
    )
    if log_scale:
        fig.update_yaxes(type="log", title="Log10 Record Count")
    else:
        fig.update_yaxes(title="Record Count")
    fig.update_xaxes(title="Security Category")
    return apply_dark_layout(fig, "Original Dataset Class Distribution (1,492,182 Records)", height=370)


def plot_balancing_comparison_dark() -> Optional[Any]:
    """Plot distribution comparison across Original, RUS, ROS, and SMOTE from Practical 6."""
    if not HAS_PLOTLY:
        return None
    methods = ["Original Train", "Random Undersampling", "Random Oversampling", "SMOTE (Selected)"]
    data = {
        "benign": [1190258, 128, 10000, 10000],
        "brute_force": [1074, 128, 10000, 10000],
        "command_inj": [644, 128, 10000, 10000],
        "path_traversal": [878, 128, 10000, 10000],
        "sqli": [128, 128, 10000, 10000],
        "xss": [763, 128, 10000, 10000],
    }
    palette = ["#21D98B", "#FFB547", "#FF5577", "#1687FF", "#22D3EE", "#EC4899"]

    fig = go.Figure()
    for (cls_name, values), color in zip(data.items(), palette):
        fig.add_trace(go.Bar(name=cls_name, x=methods, y=values, marker_color=color))

    fig.update_layout(barmode="group")
    fig.update_yaxes(type="log", title="Log10 Samples per Class")
    return apply_dark_layout(fig, "Practical 06: Balancing Method Comparison (Training Fold)", height=380)


def plot_model_comparison_experiments_dark() -> Optional[Any]:
    """Plot Experiment A vs Experiment B model comparison from Practical 9."""
    if not HAS_PLOTLY:
        return None
    experiments = [
        "Exp A: LR (Natural)",
        "Exp A: RF (Natural)",
        "Exp B: LR (SMOTE)",
        "Exp B: RF (SMOTE)",
    ]
    accuracy = [0.9707, 0.9997, 0.9672, 0.9954]
    macro_recall = [0.9845, 0.9763, 0.9882, 0.9924]
    macro_f1 = [0.4518, 0.9526, 0.4281, 0.6918]
    weighted_f1 = [0.9829, 0.9997, 0.9810, 0.9965]

    fig = go.Figure()
    fig.add_trace(go.Bar(name="Accuracy", x=experiments, y=accuracy, marker_color="#22D3EE"))
    fig.add_trace(go.Bar(name="Macro Recall", x=experiments, y=macro_recall, marker_color="#21D98B"))
    fig.add_trace(go.Bar(name="Macro F1", x=experiments, y=macro_f1, marker_color="#FFB547"))
    fig.add_trace(go.Bar(name="Weighted F1", x=experiments, y=weighted_f1, marker_color="#1687FF"))

    fig.update_layout(barmode="group", yaxis_range=[0, 1.05])
    fig.update_yaxes(title="Score (0.0 to 1.0)")
    return apply_dark_layout(fig, "Practical 09: Classification Models Comparison", height=380)


def plot_feature_importance_dark(top_n: int = 12) -> Optional[Any]:
    """Plot top N Random Forest feature importances from Practical 9."""
    if not HAS_PLOTLY:
        return None
    features = [
        "contains_sql_keyword", "contains_script_tag", "contains_path_traversal",
        "payload_length", "ft_COUNT_requests", "ip_request_rank",
        "requests_per_ip", "payload_entropy", "user_agent_length",
        "failed_pattern_count", "letter_ratio", "requests_per_ip_10min"
    ][:top_n]
    importances = [
        0.0913, 0.0907, 0.0803, 0.0648, 0.0646, 0.0644,
        0.0514, 0.0395, 0.0379, 0.0344, 0.0342, 0.0296
    ][:top_n]

    features_rev = features[::-1]
    importances_rev = importances[::-1]

    fig = go.Figure(
        go.Bar(
            x=importances_rev,
            y=features_rev,
            orientation="h",
            marker=dict(
                color=importances_rev,
                colorscale=[[0, "#1687FF"], [1, "#22D3EE"]],
            ),
            text=[f"{v*100:.2f}%" for v in importances_rev],
            textposition="auto",
        )
    )
    fig.update_xaxes(title="Gini Feature Importance")
    return apply_dark_layout(fig, f"Top {top_n} Security Features (Random Forest)", height=420)


def plot_dataset_journey_flow_dark() -> Optional[Any]:
    """Plot dataset record progression through the entire project pipeline."""
    if not HAS_PLOTLY:
        return None
    stages = [
        "P01: Raw Lines", "P01: Extracted", "P02: Structured",
        "P03: Deduplicated", "P04: Labeled", "P05: Features",
        "P06: SMOTE Train", "P06: Test Set", "P07: Wrangled", "P10: Final Parquet"
    ]
    counts = [
        2_062_365, 2_062_361, 2_062_361, 1_492_182, 1_492_182,
        1_492_182, 60_000, 298_437, 59_497, 1_492_047
    ]
    colors = [
        "#1687FF", "#1687FF", "#22D3EE", "#21D98B", "#21D98B",
        "#1687FF", "#FFB547", "#22D3EE", "#FF5577", "#21D98B"
    ]

    fig = go.Figure(
        go.Bar(
            x=stages,
            y=counts,
            text=[f"{c:,}" for c in counts],
            textposition="auto",
            marker_color=colors,
        )
    )
    fig.update_yaxes(title="Record Volume")
    return apply_dark_layout(fig, "Pipeline Journey: Record Volume Across Practicals", height=360)

