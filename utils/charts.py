"""utils/charts.py
Interactive Plotly Charts with Academic Aesthetic
Matches the restrained, professional academic palette (Deep Navy, Slate Blue, Soft Blue).
"""

import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from typing import Dict, Any, List

from config import THEME


def apply_academic_layout(fig: go.Figure, title: str = "", height: int = 400) -> go.Figure:
    """Apply uniform academic theme styling to Plotly figures."""
    fig.update_layout(
        title={
            "text": f"<b>{title}</b>" if title else "",
            "font": {"size": 15, "color": THEME["text"], "family": "Inter, Roboto, sans-serif"},
            "x": 0.02,
            "xanchor": "left",
        },
        paper_bgcolor=THEME["card_bg"],
        plot_bgcolor="#FAFBFC",
        margin={"l": 50, "r": 30, "t": 60 if title else 25, "b": 50},
        height=height,
        font={"family": "Inter, Roboto, sans-serif", "color": THEME["text"], "size": 12},
        xaxis={
            "showgrid": True,
            "gridcolor": "#EDF2F7",
            "linecolor": THEME["border"],
            "zeroline": False,
            "tickfont": {"size": 11, "color": THEME["text_muted"]},
        },
        yaxis={
            "showgrid": True,
            "gridcolor": "#EDF2F7",
            "linecolor": THEME["border"],
            "zeroline": False,
            "tickfont": {"size": 11, "color": THEME["text_muted"]},
        },
        legend={
            "bgcolor": "rgba(255, 255, 255, 0.8)",
            "bordercolor": THEME["border"],
            "borderwidth": 1,
            "font": {"size": 11},
        },
        hoverlabel={
            "bgcolor": THEME["primary"],
            "font_size": 12,
            "font_family": "Inter, Roboto, sans-serif",
            "font_color": "#FFFFFF",
        },
    )
    return fig


def plot_class_distribution(log_scale: bool = True) -> go.Figure:
    """Plot the actual 6 ground-truth class distribution from Practical 4/6."""
    data = [
        {"Class": "Benign", "Count": 1_487_823, "Pct": "99.708%"},
        {"Class": "Brute Force", "Count": 1_342, "Pct": "0.090%"},
        {"Class": "Path Traversal", "Count": 1_098, "Pct": "0.074%"},
        {"Class": "XSS", "Count": 954, "Pct": "0.064%"},
        {"Class": "Command Inj.", "Count": 805, "Pct": "0.054%"},
        {"Class": "SQLi", "Count": 160, "Pct": "0.011%"},
    ]
    df = pd.DataFrame(data)
    
    colors = [THEME["secondary"], "#D97706", "#DC2626", "#9333EA", "#E11D48", "#2563EB"]
    
    fig = go.Figure(
        data=[
            go.Bar(
                x=df["Class"],
                y=df["Count"],
                text=[f"{c:,}<br>({p})" for c, p in zip(df["Count"], df["Pct"])],
                textposition="auto",
                marker_color=colors,
                marker_line={"color": "#FFFFFF", "width": 1.5},
                hoverinfo="x+y",
            )
        ]
    )
    
    if log_scale:
        fig.update_yaxes(type="log", title="Log10 Record Count")
    else:
        fig.update_yaxes(title="Record Count")
        
    fig.update_xaxes(title="Ground-Truth Security Category")
    return apply_academic_layout(fig, "Original Dataset Class Distribution (1,492,182 Records)", height=380)


def plot_balancing_comparison() -> go.Figure:
    """Plot distribution comparison across Original, RUS, ROS, and SMOTE from Practical 6."""
    methods = ["Original Train", "Random Undersampling", "Random Oversampling", "SMOTE (Selected)"]
    classes = ["benign", "brute_force", "command_inj", "path_traversal", "sqli", "xss"]
    
    # Actual values from Practical 6 balancing_comparison.csv
    data = {
        "benign": [1190258, 128, 10000, 10000],
        "brute_force": [1074, 128, 10000, 10000],
        "command_inj": [644, 128, 10000, 10000],
        "path_traversal": [878, 128, 10000, 10000],
        "sqli": [128, 128, 10000, 10000],
        "xss": [763, 128, 10000, 10000],
    }
    
    palette = ["#1E3A5F", "#D97706", "#DC2626", "#4F6D8A", "#2563EB", "#9333EA"]
    
    fig = go.Figure()
    for (cls_name, values), color in zip(data.items(), palette):
        fig.add_trace(
            go.Bar(
                name=cls_name,
                x=methods,
                y=values,
                marker_color=color,
            )
        )
        
    fig.update_layout(barmode="group")
    fig.update_yaxes(type="log", title="Log10 Samples per Class")
    return apply_academic_layout(fig, "Practical 6: Balancing Methodology Comparison (Training Fold)", height=400)


def plot_model_comparison_experiments() -> go.Figure:
    """Plot Experiment A vs Experiment B model comparison from Practical 9."""
    experiments = [
        "Exp A: LR (Natural)",
        "Exp A: RF (Natural)",
        "Exp B: LR (SMOTE Train)",
        "Exp B: RF (SMOTE Train)",
    ]
    accuracy = [0.9707, 0.9997, 0.9672, 0.9954]
    macro_recall = [0.9845, 0.9763, 0.9882, 0.9924]
    macro_f1 = [0.4518, 0.9526, 0.4281, 0.6918]
    weighted_f1 = [0.9829, 0.9997, 0.9810, 0.9965]
    
    fig = go.Figure()
    fig.add_trace(go.Bar(name="Accuracy", x=experiments, y=accuracy, marker_color="#1E3A5F"))
    fig.add_trace(go.Bar(name="Macro Recall", x=experiments, y=macro_recall, marker_color="#10B981"))
    fig.add_trace(go.Bar(name="Macro F1", x=experiments, y=macro_f1, marker_color="#F59E0B"))
    fig.add_trace(go.Bar(name="Weighted F1", x=experiments, y=weighted_f1, marker_color="#6C8EBF"))
    
    fig.update_layout(barmode="group", yaxis_range=[0, 1.05])
    fig.update_yaxes(title="Score (0.0 to 1.0)")
    return apply_academic_layout(fig, "Practical 9: Experiment A vs Experiment B Performance (Evaluated on Untouched Test Data)", height=400)


def plot_feature_importance(top_n: int = 15) -> go.Figure:
    """Plot top N Random Forest feature importances from Practical 9."""
    features = [
        "contains_sql_keyword", "contains_script_tag", "contains_path_traversal",
        "payload_length", "ft_COUNT_requests", "ip_request_rank",
        "requests_per_ip", "payload_entropy", "user_agent_length",
        "failed_pattern_count", "letter_ratio", "requests_per_ip_10min",
        "request_rate_5min", "requests_per_ip_1min", "special_char_count"
    ][:top_n]
    
    importances = [
        0.0913, 0.0907, 0.0803, 0.0648, 0.0646, 0.0644,
        0.0514, 0.0395, 0.0379, 0.0344, 0.0342, 0.0296,
        0.0272, 0.0264, 0.0248
    ][:top_n]
    
    # Reverse so top is at top of horizontal bar
    features_rev = features[::-1]
    importances_rev = importances[::-1]
    
    fig = go.Figure(
        go.Bar(
            x=importances_rev,
            y=features_rev,
            orientation="h",
            marker=dict(
                color=importances_rev,
                colorscale=[[0, "#6C8EBF"], [1, "#1E3A5F"]],
            ),
            text=[f"{v*100:.2f}%" for v in importances_rev],
            textposition="auto",
        )
    )
    fig.update_xaxes(title="Gini Feature Importance")
    return apply_academic_layout(fig, f"Top {top_n} Features (Random Forest Multi-Class Classifier)", height=450)


def plot_pipeline_stage_durations() -> go.Figure:
    """Plot Practical 10 pipeline stage execution durations."""
    stages = [
        "1. Load Stream",
        "2. Parse & Structure",
        "3. Preprocess & Clean",
        "4. Deterministic Label",
        "5. Feature Engineering",
        "6. Parquet / CSV Save"
    ]
    durations = [20.57, 23.21, 9.48, 20.48, 4.96, 29.98]
    
    fig = go.Figure(
        go.Bar(
            x=stages,
            y=durations,
            text=[f"{d:.2f}s" for d in durations],
            textposition="auto",
            marker_color=["#1E3A5F", "#2A4D69", "#3B6978", "#84A9AC", "#4F6D8A", "#10B981"],
        )
    )
    fig.update_yaxes(title="Execution Time (Seconds)")
    return apply_academic_layout(fig, "Practical 10: End-to-End Pipeline Stage Timing (Total: 108.67s)", height=360)


def plot_dataset_journey_flow() -> go.Figure:
    """Plot dataset record progression through the entire project pipeline."""
    stages = [
        "P1: Raw Lines",
        "P1: Extracted",
        "P2: Structured",
        "P3: Deduplicated",
        "P4: Labeled",
        "P5: Features",
        "P6: Balanced Train",
        "P6: Untouched Test",
        "P7: Wrangled",
        "P10: Final Parquet"
    ]
    counts = [
        2_062_365,
        2_062_361,
        2_062_361,
        1_492_182,
        1_492_182,
        1_492_182,
        60_000,
        298_437,
        59_497,
        1_492_047
    ]
    colors = [
        "#4F6D8A", "#4F6D8A", "#2A4D69", "#1E3A5F", "#1E3A5F",
        "#1E3A5F", "#10B981", "#6C8EBF", "#3B6978", "#1E3A5F"
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
    fig.update_yaxes(title="Record Count (Linear Scale)")
    return apply_academic_layout(fig, "Project Journey: Record Volume Across Practicals", height=380)
