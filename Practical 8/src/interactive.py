"""interactive.py
Interactive Plotly Visualizations & Comprehensive Local Dashboard
Generates standalone interactive HTML visualizations and outputs/interactive/eda_dashboard.html.
All files run 100% locally without cloud dependencies.
"""

from typing import List, Dict, Any
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from pathlib import Path

from src.config import (
    INTERACTIVE_DIR,
    INTERACTIVE_01_REQUESTS_PER_HOUR,
    INTERACTIVE_02_TOP10_IPS,
    INTERACTIVE_03_ATTACK_OVER_TIME,
    INTERACTIVE_04_STATUS_CODES,
    INTERACTIVE_07_ATTACK_CATEGORIES,
    INTERACTIVE_EDA_DASHBOARD,
)


def generate_interactive_visualizations(
    hourly_df: pd.DataFrame,
    top10_df: pd.DataFrame,
    temporal_attacks_df: pd.DataFrame,
    df: pd.DataFrame,
) -> List[str]:
    """Generates standalone interactive Plotly figures and the master EDA dashboard."""
    INTERACTIVE_DIR.mkdir(parents=True, exist_ok=True)
    generated_files = []

    # 1. Interactive 01: Requests per Hour
    if not hourly_df.empty:
        fig1 = go.Figure()
        fig1.add_trace(go.Scatter(x=hourly_df["timestamp_hour"], y=hourly_df["total_requests"],
                                  mode="lines+markers", name="Total Requests", line=dict(color="#1f77b4", width=2)))
        if "benign_requests" in hourly_df.columns:
            fig1.add_trace(go.Scatter(x=hourly_df["timestamp_hour"], y=hourly_df["benign_requests"],
                                      mode="lines", name="Benign Requests", line=dict(color="#2ca02c", width=1.5, dash="dash")))
        if "attack_requests" in hourly_df.columns:
            fig1.add_trace(go.Scatter(x=hourly_df["timestamp_hour"], y=hourly_df["attack_requests"],
                                      mode="lines", name="Attack Requests", line=dict(color="#d62728", width=1.5, dash="dot")))

        fig1.update_layout(
            title="Interactive Requests per Hour",
            xaxis_title="Hourly Interval",
            yaxis_title="Request Volume",
            hovermode="x unified",
            template="plotly_white",
        )
        fig1.write_html(str(INTERACTIVE_01_REQUESTS_PER_HOUR))
        generated_files.append("01_requests_per_hour.html")

    # 2. Interactive 02: Top 10 Attacking IPs
    if not top10_df.empty:
        fig2 = px.bar(
            top10_df,
            x="attack_requests",
            y="client_ip",
            orientation="h",
            title="Top 10 Attacking IPs by Request Count",
            labels={"attack_requests": "Number of Attack Requests", "client_ip": "Client IP Address"},
            color="attack_requests",
            color_continuous_scale="Reds",
            template="plotly_white",
        )
        fig2.update_layout(yaxis=dict(autorange="reversed"))
        fig2.write_html(str(INTERACTIVE_02_TOP10_IPS))
        generated_files.append("02_top10_attacking_ips.html")

    # 3. Interactive 03: Attack Categories over Time
    if not temporal_attacks_df.empty and "date" in temporal_attacks_df.columns:
        cat_cols = [c for c in temporal_attacks_df.columns if c != "date"]
        fig3 = go.Figure()
        for cat in cat_cols:
            fig3.add_trace(go.Scatter(
                x=temporal_attacks_df["date"],
                y=temporal_attacks_df[cat],
                mode="lines+markers",
                name=cat,
            ))
        fig3.update_layout(
            title="Attack Categories over Time",
            xaxis_title="Date",
            yaxis_title="Attack Request Count",
            hovermode="x unified",
            template="plotly_white",
        )
        fig3.write_html(str(INTERACTIVE_03_ATTACK_OVER_TIME))
        generated_files.append("03_attack_categories_over_time.html")

    # 4. Interactive 04: Status Code Distribution
    if "status_code" in df.columns:
        status_counts = df["status_code"].astype(str).value_counts().reset_index()
        status_counts.columns = ["status_code", "count"]
        fig4 = px.bar(
            status_counts,
            x="status_code",
            y="count",
            title="HTTP Status Code Distribution",
            labels={"status_code": "HTTP Status Code", "count": "Request Count"},
            color="count",
            color_continuous_scale="Blues",
            template="plotly_white",
        )
        fig4.write_html(str(INTERACTIVE_04_STATUS_CODES))
        generated_files.append("04_status_code_distribution.html")

    # 5. Interactive 07: Attack Category Distribution
    if "label" in df.columns:
        label_counts = df["label"].value_counts().reset_index()
        label_counts.columns = ["label", "count"]
        fig7 = px.bar(
            label_counts,
            x="label",
            y="count",
            title="Traffic Category & Attack Label Distribution",
            labels={"label": "Classification Label", "count": "Record Count"},
            color="label",
            template="plotly_white",
        )
        fig7.write_html(str(INTERACTIVE_07_ATTACK_CATEGORIES))
        generated_files.append("07_attack_category_distribution.html")

    # 6. Comprehensive Interactive EDA Dashboard (Part 13)
    # 6-panel interactive multi-plot dashboard
    fig_dash = make_subplots(
        rows=3, cols=2,
        subplot_titles=(
            "1. Requests over Time (Hourly)",
            "2. Attack Categories over Time (Daily)",
            "3. Top Attacking IPs",
            "4. HTTP Status Code Distribution",
            "5. Traffic Classification Breakdown",
            "6. HTTP Request Method Distribution",
        ),
        vertical_spacing=0.10,
        horizontal_spacing=0.10,
    )

    # Panel 1: Requests over Time
    if not hourly_df.empty:
        fig_dash.add_trace(
            go.Scatter(x=hourly_df["timestamp_hour"], y=hourly_df["total_requests"], name="Total Reqs", line=dict(color="#1f77b4")),
            row=1, col=1
        )
        if "attack_requests" in hourly_df.columns:
            fig_dash.add_trace(
                go.Scatter(x=hourly_df["timestamp_hour"], y=hourly_df["attack_requests"], name="Attack Reqs", line=dict(color="#d62728", dash="dot")),
                row=1, col=1
            )

    # Panel 2: Attack Categories over Time
    if not temporal_attacks_df.empty and "date" in temporal_attacks_df.columns:
        cat_cols = [c for c in temporal_attacks_df.columns if c != "date"]
        for cat in cat_cols[:4]:  # Top 4 for clean dashboard presentation
            fig_dash.add_trace(
                go.Scatter(x=temporal_attacks_df["date"], y=temporal_attacks_df[cat], name=cat),
                row=1, col=2
            )

    # Panel 3: Top Attacking IPs
    if not top10_df.empty:
        fig_dash.add_trace(
            go.Bar(x=top10_df["attack_requests"].head(8), y=top10_df["client_ip"].head(8), orientation="h", name="Top IPs", marker=dict(color="#d62728")),
            row=2, col=1
        )

    # Panel 4: Status Codes
    if "status_code" in df.columns:
        sc_counts = df["status_code"].astype(str).value_counts()
        fig_dash.add_trace(
            go.Bar(x=sc_counts.index, y=sc_counts.values, name="Status Codes", marker=dict(color="#ff7f0e")),
            row=2, col=2
        )

    # Panel 5: Attack Categories
    if "label" in df.columns:
        lbl_counts = df["label"].value_counts()
        fig_dash.add_trace(
            go.Bar(x=lbl_counts.index, y=lbl_counts.values, name="Class Labels", marker=dict(color="#2ca02c")),
            row=3, col=1
        )

    # Panel 6: Request Types
    if "request_type" in df.columns:
        rt_counts = df["request_type"].value_counts().head(8)
        fig_dash.add_trace(
            go.Bar(x=rt_counts.index.astype(str), y=rt_counts.values, name="HTTP Methods", marker=dict(color="#9467bd")),
            row=3, col=2
        )

    fig_dash.update_layout(
        title_text="<b>Practical 8 — Comprehensive Exploratory Data Analysis Dashboard</b>",
        height=1100,
        showlegend=False,
        template="plotly_white",
    )
    fig_dash.write_html(str(INTERACTIVE_EDA_DASHBOARD))
    generated_files.append("eda_dashboard.html")

    return generated_files
