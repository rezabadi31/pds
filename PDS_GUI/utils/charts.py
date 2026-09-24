"""charts.py
Interactive Plotly and Visualization Utilities for PDS_GUI
Generates presentation-grade interactive charts matching the white/blue/teal aesthetic.
"""

from typing import Dict, Any, Optional
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from config import THEME_COLORS


def plot_class_distribution(dist: Dict[str, int], log_scale: bool = True) -> go.Figure:
    """Creates an interactive bar chart of the 6 traffic classes."""
    labels = list(dist.keys())
    counts = list(dist.values())
    total = sum(counts)
    percentages = [(c / total) * 100 for c in counts]

    colors = ["#2563eb", "#d97706", "#dc2626", "#9333ea", "#0d9488", "#0284c7"][:len(labels)]

    fig = go.Figure(
        data=[
            go.Bar(
                x=labels,
                y=counts,
                text=[f"{c:,}<br>({p:.2f}%)" for c, p in zip(counts, percentages)],
                textposition="outside",
                marker=dict(color=colors, line=dict(color="#1e293b", width=1.5)),
                hovertemplate="<b>Class</b>: %{x}<br><b>Count</b>: %{y:,}<br><b>Share</b>: %{text}<extra></extra>",
            )
        ]
    )

    fig.update_layout(
        title=dict(
            text="Cybersecurity Traffic Category Distribution",
            font=dict(size=16, color="#0f172a", family="Inter, sans-serif"),
        ),
        xaxis=dict(title="Traffic Category", tickfont=dict(size=12, color="#334155")),
        yaxis=dict(
            title="Record Count (Log Scale)" if log_scale else "Record Count",
            type="log" if log_scale else "linear",
            tickfont=dict(size=12, color="#334155"),
            gridcolor="#e2e8f0",
        ),
        paper_bgcolor="#ffffff",
        plot_bgcolor="#f8fafc",
        height=450,
        margin=dict(l=40, r=40, t=60, b=40),
    )
    return fig


def plot_model_comparison_chart(comp_df: pd.DataFrame) -> go.Figure:
    """Creates a side-by-side grouped bar chart comparing Accuracy and Macro F1."""
    fig = go.Figure()

    models = comp_df["Model"].tolist()
    accuracies = [round(a * 100, 2) for a in comp_df["Accuracy"]]
    macro_f1s = [round(f * 100, 2) for f in comp_df["Macro F1"]]
    macro_recalls = [round(r * 100, 2) for r in comp_df["Macro Recall"]]

    fig.add_trace(
        go.Bar(
            name="Accuracy (%)",
            x=models,
            y=accuracies,
            marker_color="#2563eb",
            text=[f"{v:.2f}%" for v in accuracies],
            textposition="auto",
        )
    )
    fig.add_trace(
        go.Bar(
            name="Macro F1 (%)",
            x=models,
            y=macro_f1s,
            marker_color="#0d9488",
            text=[f"{v:.2f}%" for v in macro_f1s],
            textposition="auto",
        )
    )
    fig.add_trace(
        go.Bar(
            name="Macro Recall (%)",
            x=models,
            y=macro_recalls,
            marker_color="#f59e0b",
            text=[f"{v:.2f}%" for v in macro_recalls],
            textposition="auto",
        )
    )

    fig.update_layout(
        barmode="group",
        title=dict(
            text="Model Performance Evaluation (Accuracy vs. Macro F1 & Recall)",
            font=dict(size=16, color="#0f172a"),
        ),
        xaxis=dict(title="Model Architecture"),
        yaxis=dict(title="Score (%)", range=[0, 115], gridcolor="#e2e8f0"),
        paper_bgcolor="#ffffff",
        plot_bgcolor="#f8fafc",
        height=420,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        margin=dict(l=40, r=40, t=70, b=40),
    )
    return fig


def plot_feature_importance_chart(fi_df: pd.DataFrame, top_n: int = 15) -> go.Figure:
    """Creates a horizontal bar chart of the top Gini feature importances."""
    top = fi_df.head(top_n).sort_values(by="Importance", ascending=True)

    fig = go.Figure(
        go.Bar(
            x=top["Importance"],
            y=top["Feature"],
            orientation="h",
            marker=dict(
                color=top["Importance"],
                colorscale="Blues",
                line=dict(color="#1e3a8a", width=1),
            ),
            text=[f"{val:.4f}" for val in top["Importance"]],
            textposition="outside",
            hovertemplate="<b>%{y}</b><br>Importance: %{x:.6f}<extra></extra>",
        )
    )

    fig.update_layout(
        title=dict(
            text=f"Top {top_n} Discriminative Features (Random Forest Gini Importance)",
            font=dict(size=16, color="#0f172a"),
        ),
        xaxis=dict(title="Gini Feature Importance", gridcolor="#e2e8f0"),
        yaxis=dict(title="", tickfont=dict(size=11)),
        paper_bgcolor="#ffffff",
        plot_bgcolor="#f8fafc",
        height=500,
        margin=dict(l=150, r=40, t=60, b=40),
    )
    return fig


def plot_balancing_comparison_chart() -> go.Figure:
    """Creates a before vs after balancing comparison chart for Practical 6."""
    categories = ["benign", "brute_force", "path_traversal", "xss", "command_injection", "sqli"]
    before_counts = [1_190_258, 1_074, 878, 763, 644, 128]
    after_counts = [10_000, 10_000, 10_000, 10_000, 10_000, 10_000]

    fig = go.Figure()
    fig.add_trace(
        go.Bar(
            name="Before Balancing (Train Partition)",
            x=categories,
            y=before_counts,
            marker_color="#ef4444",
            text=[f"{c:,}" for c in before_counts],
            textposition="outside",
        )
    )
    fig.add_trace(
        go.Bar(
            name="After SMOTE / Balancing (Train Partition)",
            x=categories,
            y=after_counts,
            marker_color="#10b981",
            text=[f"{c:,}" for c in after_counts],
            textposition="outside",
        )
    )

    fig.update_layout(
        barmode="group",
        title=dict(
            text="Training Class Distribution: Before vs After SMOTE Balancing (Log Scale)",
            font=dict(size=16, color="#0f172a"),
        ),
        xaxis=dict(title="Traffic Category"),
        yaxis=dict(title="Record Count (Log Scale)", type="log", gridcolor="#e2e8f0"),
        paper_bgcolor="#ffffff",
        plot_bgcolor="#f8fafc",
        height=450,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        margin=dict(l=40, r=40, t=70, b=40),
    )
    return fig
