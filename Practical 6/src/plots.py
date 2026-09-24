"""plots.py
Part 12: Publication-Grade Visualizations for Dataset Balancing
Generates clean comparative bar charts displaying distribution before and after balancing.
"""

from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from src.config import PLOTS_DIR


def generate_balancing_plots(
    under_counts: dict,
    over_counts: dict,
    smote_counts: dict,
    comp_df: pd.DataFrame,
):
    """Generates the required diagnostic bar charts for Practical 6."""
    print("\n" + "=" * 60)
    print("PART 12 — GENERATING BALANCING VISUALIZATIONS")
    print("=" * 60)

    # 1. Random Undersampling Distribution Plot
    fig, ax = plt.subplots(figsize=(8.5, 5), dpi=300)
    labels = list(under_counts.keys())
    values = list(under_counts.values())
    colors = ["#2563eb", "#d97706", "#dc2626", "#9333ea", "#059669", "#e11d48"][:len(labels)]

    bars = ax.bar(labels, values, color=colors, edgecolor="#1e293b", width=0.5)
    ax.set_title("Random Undersampling Class Distribution (Equalized to Minority Count)", fontsize=11, fontweight="bold")
    ax.set_xlabel("Traffic Category", fontsize=10)
    ax.set_ylabel("Record Count", fontsize=10)
    ax.grid(True, linestyle="--", alpha=0.5, axis="y")

    for bar, val in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 2,
            f"{val:,}",
            ha="center",
            va="bottom",
            fontsize=9,
            fontweight="semibold",
        )
    plt.tight_layout()
    p_under = PLOTS_DIR / "undersampling_distribution.png"
    plt.savefig(p_under)
    plt.close()
    print(f"  -> Saved: {p_under.name}")

    # 2. Random Oversampling Distribution Plot
    fig, ax = plt.subplots(figsize=(8.5, 5), dpi=300)
    labels = list(over_counts.keys())
    values = list(over_counts.values())
    bars = ax.bar(labels, values, color=colors, edgecolor="#1e293b", width=0.5)
    ax.set_title("Random Oversampling Class Distribution (Duplicates Resampled)", fontsize=11, fontweight="bold")
    ax.set_xlabel("Traffic Category", fontsize=10)
    ax.set_ylabel("Record Count", fontsize=10)
    ax.grid(True, linestyle="--", alpha=0.5, axis="y")

    for bar, val in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() * 0.9,
            f"{val:,}",
            ha="center",
            va="top",
            fontsize=9,
            fontweight="semibold",
            color="white",
        )
    plt.tight_layout()
    p_over = PLOTS_DIR / "random_oversampling_distribution.png"
    plt.savefig(p_over)
    plt.close()
    print(f"  -> Saved: {p_over.name}")

    # 3. SMOTE Distribution Plot
    fig, ax = plt.subplots(figsize=(8.5, 5), dpi=300)
    labels = list(smote_counts.keys())
    values = list(smote_counts.values())
    bars = ax.bar(labels, values, color=colors, edgecolor="#1e293b", width=0.5)
    ax.set_title("SMOTE Synthetic Class Distribution (k-NN Manifold Interpolation)", fontsize=11, fontweight="bold")
    ax.set_xlabel("Traffic Category", fontsize=10)
    ax.set_ylabel("Record Count", fontsize=10)
    ax.grid(True, linestyle="--", alpha=0.5, axis="y")

    for bar, val in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() * 0.9,
            f"{val:,}",
            ha="center",
            va="top",
            fontsize=9,
            fontweight="semibold",
            color="white",
        )
    plt.tight_layout()
    p_smote = PLOTS_DIR / "smote_distribution.png"
    plt.savefig(p_smote)
    plt.close()
    print(f"  -> Saved: {p_smote.name}")

    # 4. Final Balanced Dataset Distribution Plot
    fig, ax = plt.subplots(figsize=(8.5, 5), dpi=300)
    bars = ax.bar(labels, values, color="#059669", edgecolor="#064e3b", width=0.5)
    ax.set_title("Final Balanced Training Dataset Distribution (Selected: SMOTE)", fontsize=11, fontweight="bold")
    ax.set_xlabel("Traffic Category", fontsize=10)
    ax.set_ylabel("Record Count", fontsize=10)
    ax.grid(True, linestyle="--", alpha=0.5, axis="y")

    for bar, val in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() * 0.9,
            f"{val:,}",
            ha="center",
            va="top",
            fontsize=9,
            fontweight="semibold",
            color="white",
        )
    plt.tight_layout()
    p_final = PLOTS_DIR / "final_balanced_distribution.png"
    plt.savefig(p_final)
    plt.close()
    print(f"  -> Saved: {p_final.name}")

    # 5. Balancing Methods Comparison Chart (Log Scale)
    fig, ax = plt.subplots(figsize=(10, 6), dpi=300)
    methods = comp_df["Method"].tolist()
    total_counts = comp_df["Total Records"].tolist()
    palette = ["#64748b", "#0284c7", "#d97706", "#059669"]

    bars = ax.bar(methods, total_counts, color=palette, edgecolor="#1e293b", width=0.5)
    ax.set_yscale("log")
    ax.set_title("Comparison of Total Training Records Across Balancing Methods (Log Scale)", fontsize=12, fontweight="bold", pad=12)
    ax.set_xlabel("Balancing Strategy", fontsize=10, labelpad=8)
    ax.set_ylabel("Total Training Records (Log Scale)", fontsize=10, labelpad=8)
    ax.grid(True, linestyle="--", alpha=0.5, axis="y")

    for bar, val in zip(bars, total_counts):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() * 1.25,
            f"{val:,}",
            ha="center",
            va="bottom",
            fontsize=9,
            fontweight="semibold",
        )

    plt.tight_layout()
    p_comp = PLOTS_DIR / "balancing_methods_comparison.png"
    plt.savefig(p_comp)
    plt.close()
    print(f"  -> Saved: {p_comp.name}")
