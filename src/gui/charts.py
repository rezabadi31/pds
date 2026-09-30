"""src/gui/charts.py
Dark Cybersecurity Plotly Visualizations
Theme: Deep dark backgrounds (#151B26), neon cyan and purple accents, high contrast typography.
"""

import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from typing import Dict, Any, List

from config import THEME


def apply_dark_layout(fig: go.Figure, title: str = "", height: int = 400) -> go.Figure:
    """Applies modern dark cybersecurity styling to any Plotly figure."""
    fig.update_layout(
        title={
            "text": f"<b>{title}</b>" if title else "",
            "font": {"size": 14, "color": THEME["text_primary"], "family": "Inter, sans-serif"},
            "x": 0.02,
            "xanchor": "left",
        },
        paper_bgcolor=THEME["card_bg"],
        plot_bgcolor="#0D121C",
        margin={"l": 45, "r": 25, "t": 55 if title else 25, "b": 45},
        height=height,
        font={"family": "Inter, sans-serif", "color": THEME["text_secondary"], "size": 12},
        xaxis={
            "showgrid": True,
            "gridcolor": "rgba(255, 255, 255, 0.05)",
            "linecolor": "rgba(255, 255, 255, 0.1)",
            "zeroline": False,
            "tickfont": {"size": 11, "color": THEME["text_secondary"]},
        },
        yaxis={
            "showgrid": True,
            "gridcolor": "rgba(255, 255, 255, 0.05)",
            "linecolor": "rgba(255, 255, 255, 0.1)",
            "zeroline": False,
            "tickfont": {"size": 11, "color": THEME["text_secondary"]},
        },
        legend={
            "bgcolor": "rgba(21, 27, 38, 0.8)",
            "bordercolor": "rgba(255, 255, 255, 0.1)",
            "borderwidth": 1,
            "font": {"size": 11, "color": THEME["text_primary"]},
        },
        hoverlabel={
            "bgcolor": THEME["accent"],
            "font_size": 12,
            "font_family": "Inter, sans-serif",
            "font_color": "#FFFFFF",
        },
    )
    return fig


def plot_traffic_classification_donut(label_counts: Dict[str, int]) -> go.Figure:
    """Renders a sleek dark cyber donut chart of traffic classifications."""
    labels = list(label_counts.keys())
    values = list(label_counts.values())

    color_map = {
        "benign": "#39D98A",
        "brute_force": "#FFB547",
        "path_traversal": "#FF5C7A",
        "xss": "#9333EA",
        "command_injection": "#EC4899",
        "sqli": "#00D9FF",
    }
    colors = [color_map.get(k.lower(), "#6C63FF") for k in labels]

    fig = go.Figure(
        data=[
            go.Pie(
                labels=labels,
                values=values,
                hole=0.55,
                marker=dict(colors=colors, line=dict(color="#080B12", width=2)),
                textinfo="percent+label",
                textposition="outside",
                hoverinfo="label+value+percent",
            )
        ]
    )
    return apply_dark_layout(fig, "Traffic Classification Breakdown", height=350)


def plot_class_distribution_dark(log_scale: bool = True) -> go.Figure:
    """Plot the actual 6 ground-truth classes from the project."""
    data = [
        {"Class": "Benign", "Count": 1_487_823, "Pct": "99.708%"},
        {"Class": "Brute Force", "Count": 1_342, "Pct": "0.090%"},
        {"Class": "Path Traversal", "Count": 1_098, "Pct": "0.074%"},
        {"Class": "XSS", "Count": 954, "Pct": "0.064%"},
        {"Class": "Command Inj.", "Count": 805, "Pct": "0.054%"},
        {"Class": "SQLi", "Count": 160, "Pct": "0.011%"},
    ]
    df = pd.DataFrame(data)
    colors = ["#39D98A", "#FFB547", "#FF5C7A", "#9333EA", "#EC4899", "#00D9FF"]

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


def plot_balancing_comparison_dark() -> go.Figure:
    """Plot distribution comparison across Original, RUS, ROS, and SMOTE from Practical 6."""
    methods = ["Original Train", "Random Undersampling", "Random Oversampling", "SMOTE (Selected)"]
    data = {
        "benign": [1190258, 128, 10000, 10000],
        "brute_force": [1074, 128, 10000, 10000],
        "command_inj": [644, 128, 10000, 10000],
        "path_traversal": [878, 128, 10000, 10000],
        "sqli": [128, 128, 10000, 10000],
        "xss": [763, 128, 10000, 10000],
    }
    palette = ["#39D98A", "#FFB547", "#FF5C7A", "#6C63FF", "#00D9FF", "#9333EA"]

    fig = go.Figure()
    for (cls_name, values), color in zip(data.items(), palette):
        fig.add_trace(go.Bar(name=cls_name, x=methods, y=values, marker_color=color))

    fig.update_layout(barmode="group")
    fig.update_yaxes(type="log", title="Log10 Samples per Class")
    return apply_dark_layout(fig, "Practical 06: Balancing Method Comparison (Training Fold)", height=380)


def plot_model_comparison_experiments_dark() -> go.Figure:
    """Plot Experiment A vs Experiment B model comparison from Practical 9."""
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
    fig.add_trace(go.Bar(name="Accuracy", x=experiments, y=accuracy, marker_color="#00D9FF"))
    fig.add_trace(go.Bar(name="Macro Recall", x=experiments, y=macro_recall, marker_color="#39D98A"))
    fig.add_trace(go.Bar(name="Macro F1", x=experiments, y=macro_f1, marker_color="#FFB547"))
    fig.add_trace(go.Bar(name="Weighted F1", x=experiments, y=weighted_f1, marker_color="#6C63FF"))

    fig.update_layout(barmode="group", yaxis_range=[0, 1.05])
    fig.update_yaxes(title="Score (0.0 to 1.0)")
    return apply_dark_layout(fig, "Practical 09: Classification Models Comparison", height=380)


def plot_feature_importance_dark(top_n: int = 12) -> go.Figure:
    """Plot top N Random Forest feature importances from Practical 9."""
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
                colorscale=[[0, "#4D44E0"], [1, "#00D9FF"]],
            ),
            text=[f"{v*100:.2f}%" for v in importances_rev],
            textposition="auto",
        )
    )
    fig.update_xaxes(title="Gini Feature Importance")
    return apply_dark_layout(fig, f"Top {top_n} Security Features (Random Forest)", height=420)


def plot_pipeline_stage_durations_dark() -> go.Figure:
    """Plot Practical 10 pipeline stage execution durations."""
    stages = [
        "1. Load Stream", "2. Parse & Structure", "3. Preprocess & Clean",
        "4. Deterministic Label", "5. Feature Eng.", "6. Save & Serialize"
    ]
    durations = [20.57, 23.21, 9.48, 20.48, 4.96, 29.98]
    colors = ["#6C63FF", "#00D9FF", "#39D98A", "#FF5C7A", "#FFB547", "#3B82F6"]

    fig = go.Figure(
        go.Bar(
            x=stages,
            y=durations,
            text=[f"{d:.2f}s" for d in durations],
            textposition="auto",
            marker_color=colors,
        )
    )
    fig.update_yaxes(title="Execution Time (Seconds)")
    return apply_dark_layout(fig, "Practical 10: 7-Stage Pipeline Runtime Breakdown (108.67s Total)", height=340)


def plot_dataset_journey_flow_dark() -> go.Figure:
    """Plot dataset record progression through the entire project pipeline."""
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
        "#6C63FF", "#6C63FF", "#00D9FF", "#39D98A", "#39D98A",
        "#6C63FF", "#FFB547", "#00D9FF", "#FF5C7A", "#39D98A"
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
