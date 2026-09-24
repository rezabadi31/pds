"""visualizer.py
Parts 2 through 10: Static Data Visualizations (Matplotlib & Seaborn)
Renders high-resolution publication-quality PNG charts and exports data tables.
"""

from typing import Dict, Any, Tuple
import ipaddress
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path

from src.config import (
    TOP10_ATTACKING_IPS_CSV,
    ATTACK_CATEGORIES_OVER_TIME_CSV,
    STATUS_CODE_GROUPS_CSV,
    IP_VS_REQUEST_TYPE_CSV,
    OUTPUTS_DATA_DIR,
    PLOT_01_REQUESTS_PER_HOUR,
    PLOT_02_TOP10_ATTACKING_IPS,
    PLOT_03_ATTACK_CATEGORIES_OVER_TIME,
    PLOT_04_STATUS_CODE_DIST,
    PLOT_05_STATUS_CODE_GROUPS,
    PLOT_06_IP_VS_REQUEST_HEATMAP,
    PLOT_07_ATTACK_CATEGORY_DIST,
    PLOT_08_REQUEST_TYPE_DIST,
    PLOT_09_BOT_VS_NONBOT,
    PLOT_10_INTERNAL_VS_EXTERNAL,
    P7_HOURLY_TRAFFIC_CSV,
)


def set_plotting_style():
    """Configures clean aesthetic plotting defaults."""
    sns.set_theme(style="whitegrid", font="sans-serif")
    plt.rcParams["font.size"] = 10
    plt.rcParams["axes.titlesize"] = 13
    plt.rcParams["axes.labelsize"] = 11
    plt.rcParams["xtick.labelsize"] = 9
    plt.rcParams["ytick.labelsize"] = 9


def plot_01_requests_per_hour(df: pd.DataFrame) -> Tuple[pd.DataFrame, bool]:
    """Part 2: Creates an hourly time-series showing total, benign, attack requests."""
    set_plotting_style()

    # Prefer pre-computed Practical 7 hourly traffic if available, else compute dynamically
    if P7_HOURLY_TRAFFIC_CSV.exists():
        hourly_df = pd.read_csv(P7_HOURLY_TRAFFIC_CSV)
    elif "timestamp" in df.columns and df["timestamp"].notnull().any():
        ts_valid = df[df["timestamp"].notnull()].copy()
        ts_valid["hourly_bucket"] = ts_valid["timestamp"].dt.floor("h")
        grouped = ts_valid.groupby("hourly_bucket")
        hourly_df = pd.DataFrame({
            "timestamp_hour": grouped.size().index.strftime("%Y-%m-%d %H:00:00"),
            "total_requests": grouped.size().values,
            "benign_requests": grouped.apply(lambda g: (g["label"] == "benign").sum(), include_groups=False).values,
            "attack_requests": grouped.apply(lambda g: (g["label"] != "benign").sum(), include_groups=False).values,
        })
    else:
        print("[timestamp] unavailable — skipping requests per hour plot.")
        return pd.DataFrame(), False

    fig, ax = plt.subplots(figsize=(12, 6), dpi=300)
    x = range(len(hourly_df))

    ax.plot(x, hourly_df["total_requests"], label="Total Requests", color="#1f77b4", linewidth=2.0)
    if "benign_requests" in hourly_df.columns:
        ax.plot(x, hourly_df["benign_requests"], label="Benign Requests", color="#2ca02c", linewidth=1.5, linestyle="--")
    if "attack_requests" in hourly_df.columns:
        ax.plot(x, hourly_df["attack_requests"], label="Attack Requests", color="#d62728", linewidth=1.5, linestyle="-.")

    # Spacing for x-axis ticks
    step = max(1, len(hourly_df) // 10)
    ax.set_xticks(list(x)[::step])
    ax.set_xticklabels(hourly_df["timestamp_hour"].iloc[::step], rotation=35, ha="right")

    ax.set_title("Requests per Hour", fontweight="bold", pad=12)
    ax.set_xlabel("Hour", fontweight="bold")
    ax.set_ylabel("Number of Requests", fontweight="bold")
    ax.legend(loc="upper right", frameon=True)
    plt.tight_layout()

    PLOT_01_REQUESTS_PER_HOUR.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(PLOT_01_REQUESTS_PER_HOUR)
    plt.close()

    return hourly_df, True


def plot_02_top10_attacking_ips(df: pd.DataFrame) -> Tuple[pd.DataFrame, bool]:
    """Part 3: Horizontal bar chart of top 10 attacking client IPs."""
    set_plotting_style()

    if "client_ip" not in df.columns or "label" not in df.columns:
        print("[client_ip] or [label] unavailable — skipping top 10 IPs.")
        return pd.DataFrame(), False

    # Filter attack traffic
    attack_df = df[df["label"] != "benign"]
    ip_counts = attack_df["client_ip"].value_counts().reset_index()
    ip_counts.columns = ["client_ip", "attack_requests"]

    top10_df = ip_counts.head(10).copy()

    # Save data table to both data/ and outputs/data/
    TOP10_ATTACKING_IPS_CSV.parent.mkdir(parents=True, exist_ok=True)
    OUTPUTS_DATA_DIR.mkdir(parents=True, exist_ok=True)
    top10_df.to_csv(TOP10_ATTACKING_IPS_CSV, index=False)
    top10_df.to_csv(OUTPUTS_DATA_DIR / "top10_attacking_ips.csv", index=False)

    # Plot horizontal bar chart (sorted ascending for top-to-bottom descending display)
    plot_df = top10_df.sort_values(by="attack_requests", ascending=True)

    fig, ax = plt.subplots(figsize=(10, 6), dpi=300)
    bars = ax.barh(plot_df["client_ip"], plot_df["attack_requests"], color="#d62728", edgecolor="black", alpha=0.85)

    max_reqs = max(plot_df["attack_requests"]) if not plot_df.empty else 1
    for bar in bars:
        w = bar.get_width()
        ax.text(w + max_reqs * 0.015, bar.get_y() + bar.get_height() / 2, f"{int(w):,}",
                va="center", ha="left", fontsize=9, fontweight="bold", color="#333333")

    ax.set_title("Top 10 Attacking IPs", fontweight="bold", pad=12)
    ax.set_xlabel("Number of Attack Requests", fontweight="bold")
    ax.set_ylabel("Client IP", fontweight="bold")
    ax.set_xlim(0, max_reqs * 1.15)
    plt.tight_layout()

    PLOT_02_TOP10_ATTACKING_IPS.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(PLOT_02_TOP10_ATTACKING_IPS)
    plt.close()

    return top10_df, True


def plot_03_attack_categories_over_time(df: pd.DataFrame) -> Tuple[pd.DataFrame, bool]:
    """Part 4: Multi-line / stacked temporal visualization of distinct attack categories."""
    set_plotting_style()

    if "timestamp" not in df.columns or "label" not in df.columns:
        print("[timestamp] or [label] unavailable — skipping attack categories over time.")
        return pd.DataFrame(), False

    # Exclude benign traffic
    attack_mask = (df["label"] != "benign") & df["timestamp"].notnull()
    attack_telemetry = df[attack_mask].copy()

    if attack_telemetry.empty:
        print("No attack traffic found — skipping temporal attack breakdown.")
        return pd.DataFrame(), False

    # Group daily by date
    attack_telemetry["date"] = attack_telemetry["timestamp"].dt.strftime("%Y-%m-%d")
    temporal_crosstab = pd.crosstab(attack_telemetry["date"], attack_telemetry["label"])

    # Export underlying table
    ATTACK_CATEGORIES_OVER_TIME_CSV.parent.mkdir(parents=True, exist_ok=True)
    temporal_crosstab.reset_index().to_csv(ATTACK_CATEGORIES_OVER_TIME_CSV, index=False)
    temporal_crosstab.reset_index().to_csv(OUTPUTS_DATA_DIR / "attack_categories_over_time.csv", index=False)

    # Plot multi-line chart
    fig, ax = plt.subplots(figsize=(12, 6), dpi=300)
    x = range(len(temporal_crosstab))

    palette = sns.color_palette("tab10", n_colors=temporal_crosstab.shape[1])
    for idx, col in enumerate(temporal_crosstab.columns):
        ax.plot(x, temporal_crosstab[col], label=col, color=palette[idx], linewidth=1.8, marker="o", markersize=3)

    step = max(1, len(temporal_crosstab) // 10)
    ax.set_xticks(list(x)[::step])
    ax.set_xticklabels(temporal_crosstab.index[::step], rotation=35, ha="right")

    ax.set_title("Attack Categories over Time", fontweight="bold", pad=12)
    ax.set_xlabel("Observation Date", fontweight="bold")
    ax.set_ylabel("Attack Request Count", fontweight="bold")
    ax.legend(title="Attack Category", loc="upper right", frameon=True)
    plt.tight_layout()

    PLOT_03_ATTACK_CATEGORIES_OVER_TIME.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(PLOT_03_ATTACK_CATEGORIES_OVER_TIME)
    plt.close()

    return temporal_crosstab.reset_index(), True


def plot_04_05_status_code_distribution(df: pd.DataFrame) -> Tuple[pd.DataFrame, bool]:
    """Part 5: HTTP status code distribution and 2xx/3xx/4xx/5xx group breakdowns."""
    set_plotting_style()

    if "status_code" not in df.columns:
        print("Status code unavailable — status-code visualization skipped.")
        return pd.DataFrame(), False

    # Extract status codes as clean integers
    status_series = pd.to_numeric(df["status_code"], errors="coerce").fillna(0).astype(int)
    code_counts = status_series.value_counts().sort_index()

    # Plot 04: Exact Status Code Distribution
    fig, ax = plt.subplots(figsize=(10, 5), dpi=300)
    x_labels = [str(c) for c in code_counts.index]
    bars = ax.bar(x_labels, code_counts.values, color="#1f77b4", edgecolor="black", alpha=0.85, width=0.4)

    for bar in bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h + max(code_counts.values) * 0.02, f"{int(h):,}",
                ha="center", va="bottom", fontsize=9, fontweight="bold")

    ax.set_title("HTTP Status Code Distribution", fontweight="bold", pad=12)
    ax.set_xlabel("Status Code", fontweight="bold")
    ax.set_ylabel("Request Count", fontweight="bold")
    ax.set_ylim(0, max(code_counts.values) * 1.15)
    plt.tight_layout()

    PLOT_04_STATUS_CODE_DIST.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(PLOT_04_STATUS_CODE_DIST)
    plt.close()

    # Group into 2xx, 3xx, 4xx, 5xx
    def categorize_code(code: int) -> str:
        if 200 <= code < 300:
            return "2xx Success"
        elif 300 <= code < 400:
            return "3xx Redirection"
        elif 400 <= code < 500:
            return "4xx Client Error"
        elif 500 <= code < 600:
            return "5xx Server Error"
        else:
            return "Other / Honeypot Default (0)"

    group_series = status_series.map(categorize_code)
    group_counts = group_series.value_counts().reset_index()
    group_counts.columns = ["status_group", "request_count"]
    group_counts["percentage"] = (group_counts["request_count"] / len(df) * 100).round(2)

    # Save table to data/status_code_groups.csv and outputs/data/
    STATUS_CODE_GROUPS_CSV.parent.mkdir(parents=True, exist_ok=True)
    group_counts.to_csv(STATUS_CODE_GROUPS_CSV, index=False)
    group_counts.to_csv(OUTPUTS_DATA_DIR / "status_code_groups.csv", index=False)

    # Plot 05: Status Code Group Distribution
    fig, ax = plt.subplots(figsize=(9, 5), dpi=300)
    bars = ax.bar(group_counts["status_group"], group_counts["request_count"], color="#ff7f0e", edgecolor="black", alpha=0.85, width=0.5)

    for bar in bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h + max(group_counts["request_count"]) * 0.02, f"{int(h):,}",
                ha="center", va="bottom", fontsize=9, fontweight="bold")

    ax.set_title("HTTP Status Code Group Distribution", fontweight="bold", pad=12)
    ax.set_xlabel("Status Code Group", fontweight="bold")
    ax.set_ylabel("Request Count", fontweight="bold")
    ax.set_ylim(0, max(group_counts["request_count"]) * 1.15)
    plt.xticks(rotation=15, ha="right")
    plt.tight_layout()

    PLOT_05_STATUS_CODE_GROUPS.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(PLOT_05_STATUS_CODE_GROUPS)
    plt.close()

    return group_counts, True


def plot_06_ip_vs_request_type_heatmap(df: pd.DataFrame) -> Tuple[pd.DataFrame, bool]:
    """Part 6: Heatmap of client_ip vs request_type for top 20 IPs by total traffic."""
    set_plotting_style()

    if "client_ip" not in df.columns or "request_type" not in df.columns:
        print("[client_ip] or [request_type] unavailable — skipping IP vs request type heatmap.")
        return pd.DataFrame(), False

    # Select top 20 IPs by total request volume to preserve visual readability
    top_20_ips = df["client_ip"].value_counts().head(20).index
    filtered_df = df[df["client_ip"].isin(top_20_ips)]

    # Crosstab matrix: Rows = client_ip, Columns = request_type
    crosstab_df = pd.crosstab(filtered_df["client_ip"], filtered_df["request_type"])
    crosstab_df = crosstab_df.loc[top_20_ips]  # Preserve top-to-bottom descending order

    # Export underlying table
    IP_VS_REQUEST_TYPE_CSV.parent.mkdir(parents=True, exist_ok=True)
    crosstab_df.reset_index().to_csv(IP_VS_REQUEST_TYPE_CSV, index=False)
    crosstab_df.reset_index().to_csv(OUTPUTS_DATA_DIR / "ip_vs_request_type.csv", index=False)

    # Plot Seaborn heatmap
    fig, ax = plt.subplots(figsize=(10, 8), dpi=300)
    sns.heatmap(crosstab_df, annot=True, fmt=",d", cmap="YlOrRd", cbar_kws={"label": "Request Count"}, ax=ax, linewidths=0.5)

    ax.set_title("IP vs Request Type Heatmap (Top 20 IPs by Volume)", fontweight="bold", pad=12)
    ax.set_xlabel("HTTP Request Type", fontweight="bold")
    ax.set_ylabel("Client IP Address", fontweight="bold")
    plt.tight_layout()

    PLOT_06_IP_VS_REQUEST_HEATMAP.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(PLOT_06_IP_VS_REQUEST_HEATMAP)
    plt.close()

    return crosstab_df.reset_index(), True


def plot_07_attack_category_distribution(df: pd.DataFrame) -> Tuple[pd.Series, bool]:
    """Part 7: Categorical distribution of benign and all attack classes."""
    set_plotting_style()

    if "label" not in df.columns:
        print("[label] unavailable — skipping attack category distribution.")
        return pd.Series(dtype=int), False

    label_counts = df["label"].value_counts()

    fig, ax = plt.subplots(figsize=(10, 6), dpi=300)
    palette = sns.color_palette("muted", n_colors=len(label_counts))
    bars = ax.bar(label_counts.index, label_counts.values, color=palette, edgecolor="black", alpha=0.85)

    for bar in bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h + max(label_counts.values) * 0.02, f"{int(h):,}",
                ha="center", va="bottom", fontsize=10, fontweight="bold")

    ax.set_title("Attack Category & Traffic Class Distribution", fontweight="bold", pad=12)
    ax.set_xlabel("Traffic Category / Class Label", fontweight="bold")
    ax.set_ylabel("Request Count", fontweight="bold")
    ax.set_ylim(0, max(label_counts.values) * 1.15)
    plt.xticks(rotation=20, ha="right")
    plt.tight_layout()

    PLOT_07_ATTACK_CATEGORY_DIST.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(PLOT_07_ATTACK_CATEGORY_DIST)
    plt.close()

    return label_counts, True


def plot_08_request_type_distribution(df: pd.DataFrame) -> Tuple[pd.Series, bool]:
    """Part 8: Frequency distribution of HTTP request types."""
    set_plotting_style()

    if "request_type" not in df.columns:
        print("[request_type] unavailable — skipping request type distribution.")
        return pd.Series(dtype=int), False

    req_counts = df["request_type"].value_counts().head(15)

    fig, ax = plt.subplots(figsize=(8, 5), dpi=300)
    bars = ax.bar(req_counts.index.astype(str), req_counts.values, color="#9467bd", edgecolor="black", alpha=0.85, width=0.4)

    for bar in bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h + max(req_counts.values) * 0.02, f"{int(h):,}",
                ha="center", va="bottom", fontsize=10, fontweight="bold")

    ax.set_title("HTTP Request Type Distribution", fontweight="bold", pad=12)
    ax.set_xlabel("HTTP Request Method", fontweight="bold")
    ax.set_ylabel("Request Count", fontweight="bold")
    ax.set_ylim(0, max(req_counts.values) * 1.15)
    plt.tight_layout()

    PLOT_08_REQUEST_TYPE_DIST.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(PLOT_08_REQUEST_TYPE_DIST)
    plt.close()

    return req_counts, True


def plot_09_bot_vs_nonbot(df: pd.DataFrame) -> Tuple[Dict[str, Any], bool]:
    """Part 9: Bot vs non-bot comparative exploration."""
    set_plotting_style()

    # Identify bot status
    if "is_bot" in df.columns:
        is_bot = df["is_bot"].astype(bool)
    elif "user_agent" in df.columns:
        bot_keywords = ["bot", "crawler", "spider", "slurp", "wget", "curl", "python-requests", "scrapy", "scanner"]
        ua_clean = df["user_agent"].fillna("").astype(str).str.lower()
        is_bot = ua_clean.str.contains("|".join(bot_keywords), regex=True)
    else:
        is_bot = pd.Series(False, index=df.index)

    bot_records = int(is_bot.sum())
    non_bot_records = int((~is_bot).sum())

    # Attack counts within bot vs non-bot
    if "label" in df.columns:
        bot_attacks = int((is_bot & (df["label"] != "benign")).sum())
        non_bot_attacks = int(((~is_bot) & (df["label"] != "benign")).sum())
    else:
        bot_attacks = 0
        non_bot_attacks = 0

    bot_attack_pct = round(bot_attacks / bot_records * 100, 2) if bot_records > 0 else 0.0
    non_bot_attack_pct = round(non_bot_attacks / non_bot_records * 100, 2) if non_bot_records > 0 else 0.0

    fig, (ax_vol, ax_atk) = plt.subplots(1, 2, figsize=(11, 5), dpi=300)

    categories = ["Non-Bot", "Likely Bot"]
    vols = [non_bot_records, bot_records]
    pcts = [non_bot_attack_pct, bot_attack_pct]
    colors = ["#1f77b4", "#d62728"]

    # Volume comparison
    bars1 = ax_vol.bar(categories, vols, color=colors, edgecolor="black", alpha=0.85, width=0.5)
    for bar in bars1:
        h = bar.get_height()
        ax_vol.text(bar.get_x() + bar.get_width() / 2, h + max(vols) * 0.02, f"{int(h):,}",
                    ha="center", va="bottom", fontsize=9, fontweight="bold")
    ax_vol.set_title("Traffic Volume (Bot vs Non-Bot)", fontweight="bold")
    ax_vol.set_ylabel("Request Count", fontweight="bold")
    ax_vol.set_ylim(0, max(vols) * 1.15)

    # Attack percentage comparison
    bars2 = ax_atk.bar(categories, pcts, color=colors, edgecolor="black", alpha=0.85, width=0.5)
    for bar in bars2:
        h = bar.get_height()
        ax_atk.text(bar.get_x() + bar.get_width() / 2, h + 2, f"{h:.1f}%",
                    ha="center", va="bottom", fontsize=9, fontweight="bold")
    ax_atk.set_title("Attack Rate (%) (Bot vs Non-Bot)", fontweight="bold")
    ax_atk.set_ylabel("Attack Rate (%)", fontweight="bold")
    ax_atk.set_ylim(0, 115)

    plt.suptitle("Bot vs Non-Bot Behavioral Exploration", fontweight="bold", y=1.02)
    plt.tight_layout()

    PLOT_09_BOT_VS_NONBOT.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(PLOT_09_BOT_VS_NONBOT)
    plt.close()

    stats = {
        "bot_records": bot_records,
        "non_bot_records": non_bot_records,
        "bot_attacks": bot_attacks,
        "non_bot_attacks": non_bot_attacks,
        "bot_attack_pct": bot_attack_pct,
        "non_bot_attack_pct": non_bot_attack_pct,
    }
    return stats, True


def plot_10_internal_vs_external(df: pd.DataFrame) -> Tuple[Dict[str, Any], bool]:
    """Part 10: Internal vs external IP traffic distribution."""
    set_plotting_style()

    def is_internal(ip: str) -> bool:
        if not isinstance(ip, str) or not ip.strip():
            return False
        try:
            obj = ipaddress.ip_address(ip.strip())
            return obj.is_private or obj.is_loopback
        except ValueError:
            return False

    if "client_ip" in df.columns:
        is_int = df["client_ip"].map(is_internal)
    else:
        is_int = pd.Series(False, index=df.index)

    internal_count = int(is_int.sum())
    external_count = int((~is_int).sum())
    total = len(df)
    internal_pct = round(internal_count / total * 100, 2) if total > 0 else 0.0
    external_pct = round(external_count / total * 100, 2) if total > 0 else 0.0

    fig, ax = plt.subplots(figsize=(8, 5), dpi=300)
    labels = ["External / Public IPs", "Internal / RFC1918 IPs"]
    counts = [external_count, internal_count]
    colors = ["#2ca02c", "#ff7f0e"]

    bars = ax.bar(labels, counts, color=colors, edgecolor="black", alpha=0.85, width=0.5)
    for bar in bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h + max(counts) * 0.02, f"{int(h):,} ({h/total*100:.1f}%)",
                ha="center", va="bottom", fontsize=10, fontweight="bold")

    ax.set_title("Internal vs External IP Traffic Distribution", fontweight="bold", pad=12)
    ax.set_xlabel("IP Classification", fontweight="bold")
    ax.set_ylabel("Request Count", fontweight="bold")
    ax.set_ylim(0, max(counts) * 1.15)
    plt.tight_layout()

    PLOT_10_INTERNAL_VS_EXTERNAL.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(PLOT_10_INTERNAL_VS_EXTERNAL)
    plt.close()

    stats = {
        "internal_count": internal_count,
        "external_count": external_count,
        "internal_pct": internal_pct,
        "external_pct": external_pct,
    }
    return stats, True
