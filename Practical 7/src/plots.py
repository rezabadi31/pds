"""plots.py
Part 12: Visualizations
Generates 7 clean, informative diagnostic and aggregate plots using matplotlib.
All figures are saved to outputs/plots/ at high resolution (300 DPI).
"""

from typing import Dict, Any
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path
from src.config import PLOTS_DIR


def generate_all_visualizations(
    df: pd.DataFrame,
    ip_freq_df: pd.DataFrame,
    hourly_df: pd.DataFrame,
    daily_df: pd.DataFrame,
    req_pivot_df: pd.DataFrame,
    bot_stats: Dict[str, Any],
    internal_stats: Dict[str, Any],
) -> None:
    """Generates the 7 required aggregate analysis figures (Part 12)."""
    print("\n" + "=" * 60)
    print("PART 12 — VISUALIZATIONS")
    print("=" * 60)

    PLOTS_DIR.mkdir(parents=True, exist_ok=True)
    plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")

    # -------------------------------------------------------------
    # 1. Top 20 IPs by Attack Frequency
    # -------------------------------------------------------------
    plot_1_path = PLOTS_DIR / "1_top_attack_ips.png"
    if not ip_freq_df.empty:
        top20 = ip_freq_df.head(20).copy()
        top20 = top20.sort_values(by="attack_requests", ascending=True)

        fig, ax = plt.subplots(figsize=(10, 7), dpi=300)
        bars = ax.barh(top20["client_ip"], top20["attack_requests"], color="#d9534f", edgecolor="black", alpha=0.85)

        for bar in bars:
            w = bar.get_width()
            ax.text(w + max(top20["attack_requests"]) * 0.01, bar.get_y() + bar.get_height() / 2, f"{int(w):,}",
                    va="center", ha="left", fontsize=9, fontweight="bold", color="#333333")

        ax.set_title("Top 20 Client IPs by Attack Request Volume", fontsize=14, fontweight="bold", pad=15)
        ax.set_xlabel("Number of Attack Requests", fontsize=11, fontweight="bold")
        ax.set_ylabel("Client IP Address", fontsize=11, fontweight="bold")
        ax.set_xlim(0, max(top20["attack_requests"]) * 1.15)
        plt.tight_layout()
        plt.savefig(plot_1_path)
        plt.close()
        print(f"Generated: {plot_1_path.name}")

    # -------------------------------------------------------------
    # 2. Hourly Total Traffic
    # -------------------------------------------------------------
    plot_2_path = PLOTS_DIR / "2_hourly_traffic.png"
    if not hourly_df.empty:
        fig, ax = plt.subplots(figsize=(12, 6), dpi=300)
        x_vals = range(len(hourly_df))
        ax.plot(x_vals, hourly_df["total_requests"], label="Total Requests", color="#0275d8", linewidth=2.0)
        ax.plot(x_vals, hourly_df["benign_requests"], label="Benign Traffic", color="#5cb85c", linewidth=1.5, linestyle="--")
        ax.plot(x_vals, hourly_df["attack_requests"], label="Attack Traffic", color="#d9534f", linewidth=1.5, linestyle="-.")

        step = max(1, len(hourly_df) // 10)
        ax.set_xticks(list(x_vals)[::step])
        ax.set_xticklabels(hourly_df["timestamp_hour"].iloc[::step], rotation=35, ha="right", fontsize=9)

        ax.set_title("Hourly Cybersecurity Traffic Aggregation", fontsize=14, fontweight="bold", pad=15)
        ax.set_xlabel("Hourly Time Interval", fontsize=11, fontweight="bold")
        ax.set_ylabel("Request Count", fontsize=11, fontweight="bold")
        ax.legend(loc="upper right", frameon=True)
        plt.tight_layout()
        plt.savefig(plot_2_path)
        plt.close()
        print(f"Generated: {plot_2_path.name}")

    # -------------------------------------------------------------
    # 3. Daily Attack Traffic
    # -------------------------------------------------------------
    plot_3_path = PLOTS_DIR / "3_daily_attack_traffic.png"
    if not daily_df.empty:
        fig, ax1 = plt.subplots(figsize=(11, 6), dpi=300)
        x_vals = range(len(daily_df))

        bars = ax1.bar(x_vals, daily_df["attack_requests"], color="#f0ad4e", edgecolor="black", alpha=0.85, label="Attack Requests")
        ax1.set_ylabel("Attack Request Volume", fontsize=11, fontweight="bold", color="#b27300")
        ax1.set_xlabel("Observation Date", fontsize=11, fontweight="bold")

        step = max(1, len(daily_df) // 8)
        ax1.set_xticks(list(x_vals)[::step])
        ax1.set_xticklabels(daily_df["date"].iloc[::step], rotation=30, ha="right", fontsize=9)

        # Secondary axis for attack rate
        ax2 = ax1.twinx()
        ax2.plot(x_vals, daily_df["attack_rate"] * 100, color="#d9534f", linewidth=2.5, marker="o", label="Attack Rate (%)")
        ax2.set_ylabel("Attack Rate (%)", fontsize=11, fontweight="bold", color="#d9534f")
        ax2.grid(False)

        ax1.set_title("Daily Attack Traffic Volume and Attack Rate", fontsize=14, fontweight="bold", pad=15)
        plt.tight_layout()
        plt.savefig(plot_3_path)
        plt.close()
        print(f"Generated: {plot_3_path.name}")

    # -------------------------------------------------------------
    # 4. Attack Type Distribution
    # -------------------------------------------------------------
    plot_4_path = PLOTS_DIR / "4_attack_type_distribution.png"
    if "label" in df.columns:
        counts = df["label"].value_counts()
        fig, ax = plt.subplots(figsize=(10, 6), dpi=300)
        colors = ["#5cb85c", "#0275d8", "#f0ad4e", "#d9534f", "#6f42c1", "#20c997"][:len(counts)]
        bars = ax.bar(counts.index, counts.values, color=colors, edgecolor="black", alpha=0.85)

        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2, h + max(counts.values) * 0.015, f"{int(h):,}",
                    ha="center", va="bottom", fontsize=10, fontweight="bold")

        ax.set_title("Class & Attack Type Distribution in Balanced Dataset", fontsize=14, fontweight="bold", pad=15)
        ax.set_xlabel("Traffic Category / Label", fontsize=11, fontweight="bold")
        ax.set_ylabel("Record Count", fontsize=11, fontweight="bold")
        ax.set_ylim(0, max(counts.values) * 1.15)
        plt.xticks(rotation=20, ha="right", fontsize=10)
        plt.tight_layout()
        plt.savefig(plot_4_path)
        plt.close()
        print(f"Generated: {plot_4_path.name}")

    # -------------------------------------------------------------
    # 5. Request Type × Label Heatmap
    # -------------------------------------------------------------
    plot_5_path = PLOTS_DIR / "5_request_type_label_heatmap.png"
    if not req_pivot_df.empty:
        pivot_data = req_pivot_df.set_index("request_type")
        fig, ax = plt.subplots(figsize=(9, 6), dpi=300)
        im = ax.imshow(pivot_data.values, cmap="YlOrRd", aspect="auto")

        cbar = ax.figure.colorbar(im, ax=ax)
        cbar.ax.set_ylabel("Request Count", rotation=-90, va="bottom", fontsize=10, fontweight="bold")

        ax.set_xticks(np.arange(pivot_data.shape[1]))
        ax.set_yticks(np.arange(pivot_data.shape[0]))
        ax.set_xticklabels(pivot_data.columns, rotation=30, ha="right", fontsize=9)
        ax.set_yticklabels(pivot_data.index, fontsize=10)

        # Annotate text
        max_val = pivot_data.values.max()
        for i in range(pivot_data.shape[0]):
            for j in range(pivot_data.shape[1]):
                val = pivot_data.values[i, j]
                color = "white" if val > max_val * 0.5 else "black"
                ax.text(j, i, f"{int(val):,}", ha="center", va="center", color=color, fontsize=9, fontweight="bold")

        ax.set_title("Request Type × Label Aggregation Heatmap", fontsize=14, fontweight="bold", pad=15)
        ax.set_xlabel("Traffic Label", fontsize=11, fontweight="bold")
        ax.set_ylabel("HTTP Request Type", fontsize=11, fontweight="bold")
        plt.tight_layout()
        plt.savefig(plot_5_path)
        plt.close()
        print(f"Generated: {plot_5_path.name}")

    # -------------------------------------------------------------
    # 6. Bot vs Non-Bot Traffic
    # -------------------------------------------------------------
    plot_6_path = PLOTS_DIR / "6_bot_vs_nonbot.png"
    if bot_stats:
        bot_cnt = bot_stats.get("bot_records", 0)
        non_bot_cnt = bot_stats.get("non_bot_records", 0)

        fig, (ax_pie, ax_bar) = plt.subplots(1, 2, figsize=(12, 5), dpi=300)

        # Pie chart
        labels = ["Non-Bot Traffic", "Likely Bot Traffic"]
        sizes = [non_bot_cnt, bot_cnt]
        colors = ["#0275d8", "#d9534f"]
        ax_pie.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=140, colors=colors,
                   wedgeprops={"edgecolor": "black", "linewidth": 1})
        ax_pie.set_title("Bot vs Non-Bot Traffic Share", fontsize=12, fontweight="bold")

        # Bar chart
        bars = ax_bar.bar(labels, sizes, color=colors, edgecolor="black", alpha=0.85, width=0.5)
        for bar in bars:
            h = bar.get_height()
            ax_bar.text(bar.get_x() + bar.get_width() / 2, h + max(sizes) * 0.02, f"{int(h):,}",
                        ha="center", va="bottom", fontsize=10, fontweight="bold")
        ax_bar.set_ylabel("Record Count", fontsize=10, fontweight="bold")
        ax_bar.set_title("Traffic Volume Comparison", fontsize=12, fontweight="bold")
        ax_bar.set_ylim(0, max(sizes) * 1.15)

        plt.suptitle("Bot Telemetry Identification Analysis", fontsize=14, fontweight="bold", y=1.02)
        plt.tight_layout()
        plt.savefig(plot_6_path)
        plt.close()
        print(f"Generated: {plot_6_path.name}")

    # -------------------------------------------------------------
    # 7. Internal vs External IP Traffic
    # -------------------------------------------------------------
    plot_7_path = PLOTS_DIR / "7_internal_vs_external.png"
    if internal_stats:
        internal_cnt = internal_stats.get("internal_records", 0)
        external_cnt = internal_stats.get("external_records", 0)

        fig, (ax_pie, ax_bar) = plt.subplots(1, 2, figsize=(12, 5), dpi=300)

        labels = ["External / Public IPs", "Internal / RFC1918 IPs"]
        sizes = [external_cnt, internal_cnt]
        colors = ["#5cb85c", "#f0ad4e"]
        ax_pie.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=140, colors=colors,
                   wedgeprops={"edgecolor": "black", "linewidth": 1})
        ax_pie.set_title("IP Classification Share", fontsize=12, fontweight="bold")

        bars = ax_bar.bar(labels, sizes, color=colors, edgecolor="black", alpha=0.85, width=0.5)
        for bar in bars:
            h = bar.get_height()
            ax_bar.text(bar.get_x() + bar.get_width() / 2, h + max(sizes) * 0.02, f"{int(h):,}",
                        ha="center", va="bottom", fontsize=10, fontweight="bold")
        ax_bar.set_ylabel("Record Count", fontsize=10, fontweight="bold")
        ax_bar.set_title("Record Distribution", fontsize=12, fontweight="bold")
        ax_bar.set_ylim(0, max(sizes) * 1.15)

        plt.suptitle("Internal vs External IPv4 Traffic Analysis", fontsize=14, fontweight="bold", y=1.02)
        plt.tight_layout()
        plt.savefig(plot_7_path)
        plt.close()
        print(f"Generated: {plot_7_path.name}")

    print("All 7 visualizations generated successfully.")
