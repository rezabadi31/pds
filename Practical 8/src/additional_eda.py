"""additional_eda.py
Part 11: Statistical Feature Distributions (URL, Payload, Requests/IP, Inter-request Time)
Part 12: Correlation Heatmap of Meaningful Numeric Security Features
Renders high-resolution Seaborn diagnostic figures.
"""

from typing import List, Dict, Any
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path

from src.config import (
    PLOT_11_URL_LENGTH_DIST,
    PLOT_12_PAYLOAD_LENGTH_DIST,
    PLOT_13_REQUESTS_PER_IP_DIST,
    PLOT_14_INTER_REQUEST_TIME_DIST,
    PLOT_15_CORRELATION_HEATMAP,
    CANDIDATE_CORRELATION_FEATURES,
)


def set_plotting_style():
    sns.set_theme(style="whitegrid", font="sans-serif")
    plt.rcParams["font.size"] = 10
    plt.rcParams["axes.titlesize"] = 13
    plt.rcParams["axes.labelsize"] = 11


def plot_feature_distributions(df: pd.DataFrame) -> List[str]:
    """Part 11: Renders distributions for available security attributes."""
    set_plotting_style()
    generated_plots = []

    # 11. URL Length Distribution
    if "url_length" in df.columns:
        fig, ax = plt.subplots(figsize=(9, 5), dpi=300)
        sns.histplot(df["url_length"], kde=True, color="#1f77b4", bins=40, ax=ax, edgecolor="black", alpha=0.6)
        ax.set_title("Distribution of URL Length", fontweight="bold", pad=12)
        ax.set_xlabel("URL Character Length", fontweight="bold")
        ax.set_ylabel("Frequency", fontweight="bold")
        plt.tight_layout()
        PLOT_11_URL_LENGTH_DIST.parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(PLOT_11_URL_LENGTH_DIST)
        plt.close()
        generated_plots.append("11_url_length_distribution.png")

    # 12. Payload Length Distribution
    if "payload_length" in df.columns:
        fig, ax = plt.subplots(figsize=(9, 5), dpi=300)
        sns.histplot(df["payload_length"], kde=True, color="#d62728", bins=40, ax=ax, edgecolor="black", alpha=0.6)
        ax.set_title("Distribution of Request Payload Length", fontweight="bold", pad=12)
        ax.set_xlabel("Payload Character Length", fontweight="bold")
        ax.set_ylabel("Frequency", fontweight="bold")
        plt.tight_layout()
        PLOT_12_PAYLOAD_LENGTH_DIST.parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(PLOT_12_PAYLOAD_LENGTH_DIST)
        plt.close()
        generated_plots.append("12_payload_length_distribution.png")

    # 13. Requests Per IP Distribution
    if "requests_per_ip" in df.columns:
        fig, ax = plt.subplots(figsize=(9, 5), dpi=300)
        # Log scale if wide variation
        data = df["requests_per_ip"].dropna()
        sns.histplot(data, kde=True, color="#2ca02c", bins=40, log_scale=True, ax=ax, edgecolor="black", alpha=0.6)
        ax.set_title("Distribution of Requests per Client IP (Log Scale)", fontweight="bold", pad=12)
        ax.set_xlabel("Requests per Client IP (Log Scale)", fontweight="bold")
        ax.set_ylabel("Frequency", fontweight="bold")
        plt.tight_layout()
        PLOT_13_REQUESTS_PER_IP_DIST.parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(PLOT_13_REQUESTS_PER_IP_DIST)
        plt.close()
        generated_plots.append("13_requests_per_ip_distribution.png")

    # 14. Inter-Request Time Distribution
    time_col = "time_since_previous_request" if "time_since_previous_request" in df.columns else (
        "mean_inter_request_time_ip" if "mean_inter_request_time_ip" in df.columns else None
    )
    if time_col:
        fig, ax = plt.subplots(figsize=(9, 5), dpi=300)
        valid_times = df[time_col].dropna()
        valid_times = valid_times[valid_times >= 0]
        sns.histplot(valid_times, kde=True, color="#9467bd", bins=40, ax=ax, edgecolor="black", alpha=0.6)
        ax.set_title(f"Inter-Request Time Distribution ({time_col})", fontweight="bold", pad=12)
        ax.set_xlabel("Inter-Request Interval (Seconds)", fontweight="bold")
        ax.set_ylabel("Frequency", fontweight="bold")
        plt.tight_layout()
        PLOT_14_INTER_REQUEST_TIME_DIST.parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(PLOT_14_INTER_REQUEST_TIME_DIST)
        plt.close()
        generated_plots.append("14_inter_request_time_distribution.png")

    return generated_plots


def plot_15_feature_correlation_heatmap(df: pd.DataFrame) -> bool:
    """Part 12: Calculates correlation matrix and plots Seaborn heatmap."""
    set_plotting_style()

    # Identify existing numeric features from candidate list
    available_features = [c for c in CANDIDATE_CORRELATION_FEATURES if c in df.columns]

    # Add other numeric columns if candidate list has few
    if len(available_features) < 5:
        num_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        num_cols = [c for c in num_cols if c not in ["label", "label_reason"]]
        available_features = num_cols[:12]

    if len(available_features) < 2:
        print("Insufficient numeric features for correlation heatmap.")
        return False

    # Compute Pearson correlation matrix
    corr_df = df[available_features].corr().round(2)

    fig, ax = plt.subplots(figsize=(11, 9), dpi=300)
    sns.heatmap(
        corr_df,
        annot=True,
        fmt=".2f",
        cmap="coolwarm",
        vmin=-1,
        vmax=1,
        center=0,
        linewidths=0.5,
        cbar_kws={"label": "Pearson Correlation Coefficient"},
        ax=ax,
    )

    ax.set_title("Numeric Security Feature Correlation Heatmap", fontweight="bold", pad=15)
    plt.xticks(rotation=45, ha="right", fontsize=9)
    plt.yticks(rotation=0, fontsize=9)
    plt.tight_layout()

    PLOT_15_CORRELATION_HEATMAP.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(PLOT_15_CORRELATION_HEATMAP)
    plt.close()

    return True
