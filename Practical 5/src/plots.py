"""plots.py
Diagnostic Visualizations for Practical 5 Feature Engineering
Generates the 7 required publication-grade plots.
"""

from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from src.config import PLOTS_DIR


def generate_all_plots(
    full_df: pd.DataFrame,
    imp_df: pd.DataFrame,
    ua_stats: dict,
    tsfresh_features: list,
):
    """Generates and saves the 7 required publication-grade diagnostic plots."""
    print("\n" + "=" * 60)
    print("GENERATING PUBLICATION-GRADE VISUALIZATIONS")
    print("=" * 60)

    # 1. requests_per_ip distribution (Log scale)
    fig, ax = plt.subplots(figsize=(8, 5), dpi=300)
    reqs_per_ip = full_df.groupby("client_ip")["requests_per_ip"].first()
    ax.hist(reqs_per_ip, bins=50, color="#2563eb", edgecolor="#1e293b", log=True)
    ax.set_title("1. Distribution of Request Counts per Client IP (Log Scale)", fontsize=11, fontweight="bold")
    ax.set_xlabel("Total Requests from IP", fontsize=10)
    ax.set_ylabel("Number of Unique IPs (Log Count)", fontsize=10)
    ax.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    p1 = PLOTS_DIR / "1_requests_per_ip_distribution.png"
    plt.savefig(p1)
    plt.close()
    print(f"  -> Saved: {p1.name}")

    # 2. inter-request-time distribution
    fig, ax = plt.subplots(figsize=(8, 5), dpi=300)
    valid_inter = full_df["time_since_previous_request"].dropna()
    clipped_inter = np.clip(valid_inter, 0, 300)
    ax.hist(clipped_inter, bins=60, color="#059669", edgecolor="#064e3b")
    ax.set_title("2. Distribution of Inter-Request Arrival Times (Capped at 300s)", fontsize=11, fontweight="bold")
    ax.set_xlabel("Time Since Previous Request (Seconds)", fontsize=10)
    ax.set_ylabel("Frequency", fontsize=10)
    ax.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    p2 = PLOTS_DIR / "2_inter_request_time_distribution.png"
    plt.savefig(p2)
    plt.close()
    print(f"  -> Saved: {p2.name}")

    # 3. URL entropy distribution
    fig, ax = plt.subplots(figsize=(8, 5), dpi=300)
    ax.hist(full_df["url_entropy"], bins=40, color="#d97706", edgecolor="#78350f")
    ax.set_title("3. Distribution of URL Shannon Entropy (Bits)", fontsize=11, fontweight="bold")
    ax.set_xlabel("Shannon Entropy H(X)", fontsize=10)
    ax.set_ylabel("Request Frequency", fontsize=10)
    ax.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    p3 = PLOTS_DIR / "3_url_entropy_distribution.png"
    plt.savefig(p3)
    plt.close()
    print(f"  -> Saved: {p3.name}")

    # 4. bot / scanner / browser distribution
    fig, ax = plt.subplots(figsize=(8, 5), dpi=300)
    ua_dist = ua_stats.get("ua_distribution", {})
    categories = list(ua_dist.keys())
    counts = list(ua_dist.values())
    colors = ["#2563eb", "#d97706", "#dc2626", "#9333ea", "#64748b"][:len(categories)]

    bars = ax.bar(categories, counts, color=colors, edgecolor="#1e293b", width=0.55)
    ax.set_yscale("log")
    ax.set_title("4. User-Agent Taxonomy Distribution (Log Scale)", fontsize=11, fontweight="bold")
    ax.set_xlabel("Client Category", fontsize=10)
    ax.set_ylabel("Request Frequency (Log Scale)", fontsize=10)
    ax.grid(True, linestyle="--", alpha=0.5, axis="y")

    total_records = len(full_df)
    for bar, cnt in zip(bars, counts):
        pct = (cnt / total_records) * 100
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() * 1.25,
            f"{cnt:,}\n({pct:.2f}%)",
            ha="center",
            va="bottom",
            fontsize=8.5,
            fontweight="semibold",
        )
    plt.tight_layout()
    p4 = PLOTS_DIR / "4_bot_scanner_browser_distribution.png"
    plt.savefig(p4)
    plt.close()
    print(f"  -> Saved: {p4.name}")

    # 5. Top 20 feature importance
    fig, ax = plt.subplots(figsize=(10, 7), dpi=300)
    top_20 = imp_df.head(20).iloc[::-1]
    ax.barh(top_20["feature"], top_20["importance"], color="#0284c7", edgecolor="#0c4a6e", height=0.65)
    ax.set_title("5. Top 20 Engineered Features by Discriminative Importance", fontsize=11, fontweight="bold")
    ax.set_xlabel("Relative Importance (Random Forest Validation)", fontsize=10)
    ax.grid(True, linestyle="--", alpha=0.5, axis="x")
    plt.tight_layout()
    p5 = PLOTS_DIR / "5_top20_feature_importance.png"
    plt.savefig(p5)
    plt.close()
    print(f"  -> Saved: {p5.name}")

    # 6. tsfresh feature distribution
    fig, ax = plt.subplots(figsize=(8, 5), dpi=300)
    ts_feature = "tsfresh_mean" if "tsfresh_mean" in full_df.columns else (tsfresh_features[0] if tsfresh_features else None)
    if ts_feature and ts_feature in full_df.columns:
        ax.hist(full_df[ts_feature], bins=40, color="#ec4899", edgecolor="#831843")
        ax.set_title(f"6. Automated Time-Series Feature Distribution ({ts_feature})", fontsize=11, fontweight="bold")
        ax.set_xlabel(ts_feature, fontsize=10)
        ax.set_ylabel("Record Count", fontsize=10)
    else:
        ax.text(0.5, 0.5, "tsfresh features active", ha="center", va="center")
    ax.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    p6 = PLOTS_DIR / "6_tsfresh_feature_distribution.png"
    plt.savefig(p6)
    plt.close()
    print(f"  -> Saved: {p6.name}")

    # 7. Anomaly score distribution
    fig, ax = plt.subplots(figsize=(8, 5), dpi=300)
    ax.hist(full_df["anomaly_score"], bins=50, color="#7c3aed", edgecolor="#4c1d95")
    ax.axvline(0.0, color="#ef4444", linestyle="--", linewidth=1.5, label="Decision Boundary (Score = 0.0)")
    ax.set_title("7. Unsupervised Isolation Forest Anomaly Score Distribution", fontsize=11, fontweight="bold")
    ax.set_xlabel("Anomaly Score (Lower = More Anomalous)", fontsize=10)
    ax.set_ylabel("Record Count", fontsize=10)
    ax.legend(frameon=True)
    ax.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    p7 = PLOTS_DIR / "7_anomaly_score_distribution.png"
    plt.savefig(p7)
    plt.close()
    print(f"  -> Saved: {p7.name}")
