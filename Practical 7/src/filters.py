"""filters.py
Part 8: Bot Filtering via User-Agent Analysis
Part 9: Internal IP Filtering via Python's standard ipaddress library
Part 10: Combined Filtering for Clean Telemetry Wrangling
Part 11: Re-execution of Key Aggregations on Filtered Telemetry

Analytical Rules:
- Filtering is for aggregated comparative analysis; does NOT imply discarded records are irrelevant.
- Bot user-agent is NOT automatically malicious.
- Internal IP is NOT automatically benign.
- Original Practical 6 dataset is NEVER modified.
"""

from typing import Tuple, Dict, Any
import ipaddress
import pandas as pd
from pathlib import Path

from src.config import (
    BOT_KEYWORDS,
    BOT_FILTERED_CSV,
    BOT_TRAFFIC_SUMMARY_CSV,
    EXTERNAL_IP_CSV,
    INTERNAL_EXTERNAL_SUMMARY_CSV,
    WRANGLED_FILTERED_CSV,
    FILTERED_IP_FREQ_CSV,
    FILTERED_HOURLY_CSV,
    FILTERED_DAILY_CSV,
    FILTERED_REQUEST_PIVOT_CSV,
    FILTERED_STATUS_PIVOT_CSV,
)
from src.ip_analyzer import analyze_ip_attack_frequency
from src.time_series import resample_hourly_traffic, resample_daily_traffic
from src.pivots import create_request_type_pivot, create_status_code_pivot


def filter_bots(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, Dict[str, Any]]:
    """Detects likely bots using explicit user-agent keywords (Part 8)."""
    print("\n" + "=" * 60)
    print("PART 8 — BOT FILTERING")
    print("=" * 60)

    if "user_agent" not in df.columns:
        print("[user_agent] unavailable — bot analysis skipped.")
        return df.copy(), pd.DataFrame(), {}

    # Case-insensitive keyword matching
    ua_series = df["user_agent"].fillna("").astype(str).str.lower()
    bot_pattern = "|".join(BOT_KEYWORDS)
    is_bot = ua_series.str.contains(bot_pattern, regex=True)

    bot_records = int(is_bot.sum())
    non_bot_records = int((~is_bot).sum())
    total_records = len(df)
    bot_percentage = round((bot_records / total_records) * 100, 2) if total_records > 0 else 0.0

    print(f"Bot records:        {bot_records:,}")
    print(f"Non-bot records:    {non_bot_records:,}")
    print(f"Bot percentage:     {bot_percentage}%")

    # Exclude bots for bot_filtered_dataset.csv
    bot_filtered_df = df[~is_bot].copy()
    BOT_FILTERED_CSV.parent.mkdir(parents=True, exist_ok=True)
    bot_filtered_df.to_csv(BOT_FILTERED_CSV, index=False)
    print(f"Saved bot-filtered dataset to: {BOT_FILTERED_CSV.name}")

    # Bot traffic summary by label
    bot_traffic_df = df[is_bot]
    if not bot_traffic_df.empty and "label" in bot_traffic_df.columns:
        bot_counts = bot_traffic_df["label"].value_counts().reset_index()
        bot_counts.columns = ["label", "request_count"]
        bot_counts["percentage"] = (bot_counts["request_count"] / bot_records * 100).round(2)
    else:
        bot_counts = pd.DataFrame(columns=["label", "request_count", "percentage"])

    bot_counts.to_csv(BOT_TRAFFIC_SUMMARY_CSV, index=False)
    print(f"Saved bot traffic summary to: {BOT_TRAFFIC_SUMMARY_CSV.name}")

    stats = {
        "bot_records": bot_records,
        "non_bot_records": non_bot_records,
        "bot_percentage": bot_percentage,
    }

    return bot_filtered_df, bot_counts, stats


def is_ip_internal(ip_str: str) -> bool:
    """Classifies an IP string as private/internal (RFC 1918) or loopback."""
    if not isinstance(ip_str, str) or not ip_str.strip():
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return ip_obj.is_private or ip_obj.is_loopback
    except ValueError:
        return False


def filter_internal_ips(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, Dict[str, Any]]:
    """Identifies and filters private/internal and loopback IPs using ipaddress (Part 9)."""
    print("\n" + "=" * 60)
    print("PART 9 — INTERNAL IP FILTERING")
    print("=" * 60)

    if "client_ip" not in df.columns:
        print("[client_ip] unavailable — internal IP filtering skipped.")
        return df.copy(), pd.DataFrame(), {}

    # Apply vector / map
    is_internal = df["client_ip"].map(is_ip_internal)

    internal_records = int(is_internal.sum())
    external_records = int((~is_internal).sum())
    total_records = len(df)
    internal_percentage = round((internal_records / total_records) * 100, 2) if total_records > 0 else 0.0

    print(f"Internal IP records:    {internal_records:,}")
    print(f"External IP records:    {external_records:,}")
    print(f"Internal IP percentage: {internal_percentage}%")

    # Exclude internal IPs for external_ip_dataset.csv
    external_ip_df = df[~is_internal].copy()
    EXTERNAL_IP_CSV.parent.mkdir(parents=True, exist_ok=True)
    external_ip_df.to_csv(EXTERNAL_IP_CSV, index=False)
    print(f"Saved external-only IP dataset to: {EXTERNAL_IP_CSV.name}")

    # Internal vs External summary
    summary_data = [
        {"ip_classification": "Internal / Private / Loopback", "record_count": internal_records, "percentage": internal_percentage},
        {"ip_classification": "External / Public", "record_count": external_records, "percentage": round(100.0 - internal_percentage, 2)},
    ]
    summary_df = pd.DataFrame(summary_data)
    summary_df.to_csv(INTERNAL_EXTERNAL_SUMMARY_CSV, index=False)
    print(f"Saved internal/external summary to: {INTERNAL_EXTERNAL_SUMMARY_CSV.name}")

    stats = {
        "internal_records": internal_records,
        "external_records": external_records,
        "internal_percentage": internal_percentage,
    }

    return external_ip_df, summary_df, stats


def perform_combined_filtering(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Creates final aggregated analysis dataset excluding bots and internal IPs (Part 10)."""
    print("\n" + "=" * 60)
    print("PART 10 — COMBINED FILTERING")
    print("=" * 60)

    original_records = len(df)

    # Bot mask
    if "user_agent" in df.columns:
        ua_series = df["user_agent"].fillna("").astype(str).str.lower()
        bot_pattern = "|".join(BOT_KEYWORDS)
        is_bot = ua_series.str.contains(bot_pattern, regex=True)
    else:
        is_bot = pd.Series(False, index=df.index)

    # Internal IP mask
    if "client_ip" in df.columns:
        is_internal = df["client_ip"].map(is_ip_internal)
    else:
        is_internal = pd.Series(False, index=df.index)

    # Records after individual stages
    after_bot_filtering = int((~is_bot).sum())
    after_internal_filtering = int((~is_internal).sum())

    # Combined exclusion mask
    clean_mask = (~is_bot) & (~is_internal)
    wrangled_filtered_df = df[clean_mask].copy()
    final_records = len(wrangled_filtered_df)

    print(f"Original records:            {original_records:,}")
    print(f"After bot filtering:         {after_bot_filtering:,}")
    print(f"After internal-IP filtering: {after_internal_filtering:,}")
    print(f"Final records:               {final_records:,}")

    # Export to data/processed/wrangled_filtered_dataset.csv
    WRANGLED_FILTERED_CSV.parent.mkdir(parents=True, exist_ok=True)
    wrangled_filtered_df.to_csv(WRANGLED_FILTERED_CSV, index=False)
    print(f"\nSaved wrangled filtered dataset to: {WRANGLED_FILTERED_CSV.name}")

    stats = {
        "original_records": original_records,
        "after_bot_filtering": after_bot_filtering,
        "after_internal_filtering": after_internal_filtering,
        "final_records": final_records,
    }

    return wrangled_filtered_df, stats


def repeat_aggregations_on_filtered(filtered_df: pd.DataFrame) -> None:
    """Regenerates key aggregations on the wrangled filtered telemetry (Part 11)."""
    print("\n" + "=" * 60)
    print("PART 11 — REPEAT KEY AGGREGATIONS ON FILTERED DATA")
    print("=" * 60)

    if filtered_df.empty:
        print("Filtered dataset is empty — skipping filtered aggregations.")
        return

    # 1. Filtered IP attack frequency
    temp_top = FILTERED_IP_FREQ_CSV.parent / "top_attack_ips.csv"
    analyze_ip_attack_frequency(filtered_df, export_path=FILTERED_IP_FREQ_CSV, top_export_path=temp_top)

    # 2. Filtered Hourly traffic
    resample_hourly_traffic(filtered_df, export_path=FILTERED_HOURLY_CSV)

    # 3. Filtered Daily traffic
    temp_daily_attacks = FILTERED_DAILY_CSV.parent / "daily_attack_types.csv"
    resample_daily_traffic(filtered_df, export_daily_path=FILTERED_DAILY_CSV, export_attack_path=temp_daily_attacks)

    # 4. Filtered Request type × label pivot
    temp_pct = FILTERED_REQUEST_PIVOT_CSV.parent / "request_type_label_percentage.csv"
    create_request_type_pivot(filtered_df, export_pivot_path=FILTERED_REQUEST_PIVOT_CSV, export_pct_path=temp_pct)

    # 5. Filtered Status code × label pivot
    create_status_code_pivot(filtered_df, export_path=FILTERED_STATUS_PIVOT_CSV)

    print("\nAll filtered aggregations successfully exported under: outputs/aggregated/filtered/")
