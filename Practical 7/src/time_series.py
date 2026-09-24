"""time_series.py
Part 4: Hourly Time-Series Resampling
Part 5: Daily Time-Series Resampling & Daily Attack-Type Breakdown
Does not modify original data. Uses pandas resampling/grouping.
"""

from typing import Tuple, Dict, Any, Optional
import pandas as pd
from pathlib import Path
from src.config import (
    HOURLY_TRAFFIC_CSV,
    DAILY_TRAFFIC_CSV,
    DAILY_ATTACK_TYPES_CSV,
)


def resample_hourly_traffic(
    df: pd.DataFrame,
    export_path: Path = HOURLY_TRAFFIC_CSV,
) -> pd.DataFrame:
    """Aggregates traffic hourly using timestamp as the time index."""
    print("\n" + "=" * 60)
    print("PART 4 — HOURLY TIME-SERIES RESAMPLING")
    print("=" * 60)

    if "timestamp" not in df.columns or df["timestamp"].isnull().all():
        print("[timestamp] unavailable — hourly analysis skipped.")
        return pd.DataFrame()

    # Work on a copy with valid timestamps
    valid_ts_mask = df["timestamp"].notnull()
    ts_df = df[valid_ts_mask].copy()

    # Helper flags
    is_attack = (ts_df["label"] != "benign").astype(int)
    is_benign = (ts_df["label"] == "benign").astype(int)

    has_status = "status_code" in ts_df.columns
    if has_status:
        # Convert status_code to numeric safely
        status_num = pd.to_numeric(ts_df["status_code"], errors="coerce").fillna(0).astype(int)
        is_4xx = ((status_num >= 400) & (status_num < 500)).astype(int)
        is_5xx = ((status_num >= 500) & (status_num < 600)).astype(int)

    # Floor timestamp to hour
    ts_df["timestamp_hour"] = ts_df["timestamp"].dt.floor("h")

    # Group by hourly period
    grouped = ts_df.groupby("timestamp_hour")
    total_reqs = grouped.size().rename("total_requests")
    benign_reqs = grouped.apply(lambda g: (g["label"] == "benign").sum(), include_groups=False).rename("benign_requests")
    attack_reqs = grouped.apply(lambda g: (g["label"] != "benign").sum(), include_groups=False).rename("attack_requests")

    if "client_ip" in ts_df.columns:
        unique_ips = grouped["client_ip"].nunique().rename("unique_ips")
    else:
        unique_ips = pd.Series(0, index=total_reqs.index, name="unique_ips")

    series_list = [total_reqs, benign_reqs, attack_reqs, unique_ips]

    if has_status:
        reqs_4xx = grouped.apply(lambda g: ((pd.to_numeric(g["status_code"], errors="coerce") >= 400) & (pd.to_numeric(g["status_code"], errors="coerce") < 500)).sum(), include_groups=False).rename("4xx_requests")
        reqs_5xx = grouped.apply(lambda g: ((pd.to_numeric(g["status_code"], errors="coerce") >= 500) & (pd.to_numeric(g["status_code"], errors="coerce") < 600)).sum(), include_groups=False).rename("5xx_requests")
        series_list.extend([reqs_4xx, reqs_5xx])

    hourly_df = pd.concat(series_list, axis=1).reset_index()

    # Format timestamp_hour string
    hourly_df["timestamp_hour"] = hourly_df["timestamp_hour"].dt.strftime("%Y-%m-%d %H:00:00")

    export_path.parent.mkdir(parents=True, exist_ok=True)
    hourly_df.to_csv(export_path, index=False)
    print(f"Exported Hourly Traffic ({len(hourly_df):,} hourly intervals) to: {export_path.name}")
    print("\nHourly Traffic Sample:")
    print(hourly_df.head(3))

    return hourly_df


def resample_daily_traffic(
    df: pd.DataFrame,
    export_daily_path: Path = DAILY_TRAFFIC_CSV,
    export_attack_path: Path = DAILY_ATTACK_TYPES_CSV,
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Aggregates traffic daily and breaks down daily attack types."""
    print("\n" + "=" * 60)
    print("PART 5 — DAILY TIME-SERIES RESAMPLING")
    print("=" * 60)

    if "timestamp" not in df.columns or df["timestamp"].isnull().all():
        print("[timestamp] unavailable — daily analysis skipped.")
        return pd.DataFrame(), pd.DataFrame()

    valid_ts_mask = df["timestamp"].notnull()
    ts_df = df[valid_ts_mask].copy()

    # Extract date
    ts_df["date"] = ts_df["timestamp"].dt.strftime("%Y-%m-%d")

    # Group by date
    grouped = ts_df.groupby("date")
    total_reqs = grouped.size().rename("total_requests")
    benign_reqs = grouped.apply(lambda g: (g["label"] == "benign").sum(), include_groups=False).rename("benign_requests")
    attack_reqs = grouped.apply(lambda g: (g["label"] != "benign").sum(), include_groups=False).rename("attack_requests")

    if "client_ip" in ts_df.columns:
        unique_ips = grouped["client_ip"].nunique().rename("unique_ips")
    else:
        unique_ips = pd.Series(0, index=total_reqs.index, name="unique_ips")

    daily_df = pd.concat([total_reqs, benign_reqs, attack_reqs, unique_ips], axis=1).reset_index()
    daily_df["attack_rate"] = (daily_df["attack_requests"] / daily_df["total_requests"]).round(4)

    export_daily_path.parent.mkdir(parents=True, exist_ok=True)
    daily_df.to_csv(export_daily_path, index=False)
    print(f"Exported Daily Traffic ({len(daily_df):,} days) to: {export_daily_path.name}")
    print("\nDaily Traffic Sample:")
    print(daily_df.head(3))

    # Daily attack types crosstab
    daily_attacks = pd.crosstab(ts_df["date"], ts_df["label"]).reset_index()
    export_attack_path.parent.mkdir(parents=True, exist_ok=True)
    daily_attacks.to_csv(export_attack_path, index=False)
    print(f"Exported Daily Attack Types Matrix to: {export_attack_path.name}")

    return daily_df, daily_attacks
