"""ip_features.py
Part A (1 & 2): Client IP Traffic, Rolling Time Windows, and Inter-Arrival Dynamics
Extracts behavioral frequency, bursts, and inter-request timing without target leakage.
"""

from typing import Tuple
import numpy as np
import pandas as pd


def extract_ip_traffic_features(
    df: pd.DataFrame, ts_dt: pd.Series
) -> Tuple[pd.DataFrame, dict]:
    """Calculates client IP aggregate volumes, time windows, and inter-request intervals.
    
    Preserves exact original record-level alignment.
    """
    stats = {}
    n_rows = len(df)

    # 1. Total Requests Per IP and IP Request Rank
    ip_counts = df["client_ip"].value_counts()
    df["requests_per_ip"] = df["client_ip"].map(ip_counts).astype(int)
    
    # Dense rank: 1 = IP with highest total requests
    ip_ranks = ip_counts.rank(ascending=False, method="dense").astype(int)
    df["ip_request_rank"] = df["client_ip"].map(ip_ranks).astype(int)

    # 2. Inter-Request Time Calculation (Part A - 2)
    # Prepare sorted working frame by (client_ip, ts_dt)
    work_df = pd.DataFrame({
        "client_ip": df["client_ip"],
        "ts_dt": ts_dt,
        "orig_idx": df.index,
    })
    work_df.sort_values(by=["client_ip", "ts_dt"], inplace=True)

    # Compute time difference in seconds per IP
    ip_shift = work_df["client_ip"].shift(1)
    same_ip_mask = work_df["client_ip"] == ip_shift
    time_diff = work_df["ts_dt"].diff().dt.total_seconds()
    # First request of each IP has NaN for time_since_previous_request
    time_diff.loc[~same_ip_mask] = np.nan
    work_df["time_since_previous_request"] = time_diff

    # 3. Time-Window Request Densities (1min, 5min, 10min) using vectorized searchsorted
    t_sec = (work_df["ts_dt"].astype(np.int64) // 10**9).values
    ips = work_df["client_ip"].values

    # Locate contiguous IP group boundaries
    change_idx = np.where(ips[:-1] != ips[1:])[0] + 1
    group_starts = np.concatenate(([0], change_idx))
    group_ends = np.concatenate((change_idx, [n_rows]))

    counts_1m = np.zeros(n_rows, dtype=np.int32)
    counts_5m = np.zeros(n_rows, dtype=np.int32)
    counts_10m = np.zeros(n_rows, dtype=np.int32)

    for start, end in zip(group_starts, group_ends):
        times = t_sec[start:end]
        n_grp = len(times)
        idx_arr = np.arange(n_grp)

        left_1m = np.searchsorted(times, times - 60, side="left")
        counts_1m[start:end] = idx_arr - left_1m + 1

        left_5m = np.searchsorted(times, times - 300, side="left")
        counts_5m[start:end] = idx_arr - left_5m + 1

        left_10m = np.searchsorted(times, times - 600, side="left")
        counts_10m[start:end] = idx_arr - left_10m + 1

    work_df["requests_per_ip_1min"] = counts_1m
    work_df["requests_per_ip_5min"] = counts_5m
    work_df["requests_per_ip_10min"] = counts_10m

    # Re-align back to original dataframe order
    work_df.sort_values(by="orig_idx", inplace=True)
    df["time_since_previous_request"] = work_df["time_since_previous_request"].values
    df["requests_per_ip_1min"] = work_df["requests_per_ip_1min"].values
    df["requests_per_ip_5min"] = work_df["requests_per_ip_5min"].values
    df["requests_per_ip_10min"] = work_df["requests_per_ip_10min"].values

    # 4. Aggregates: Mean, Median, Min, and Max inter-request time per IP
    inter_stats = df.groupby("client_ip")["time_since_previous_request"].agg(
        mean_inter_request_time_ip="mean",
        median_inter_request_time_ip="median",
        min_inter_request_time_ip="min",
        max_inter_request_time_ip="max",
    )
    global_median_inter = df["time_since_previous_request"].median()
    if np.isnan(global_median_inter):
        global_median_inter = 60.0

    df["mean_inter_request_time_ip"] = (
        df["client_ip"].map(inter_stats["mean_inter_request_time_ip"]).fillna(global_median_inter)
    )
    df["median_inter_request_time_ip"] = (
        df["client_ip"].map(inter_stats["median_inter_request_time_ip"]).fillna(global_median_inter)
    )
    df["min_inter_request_time_ip"] = (
        df["client_ip"].map(inter_stats["min_inter_request_time_ip"]).fillna(global_median_inter)
    )
    df["max_inter_request_time_ip"] = (
        df["client_ip"].map(inter_stats["max_inter_request_time_ip"]).fillna(global_median_inter)
    )

    # Rapid request flag: time_since_previous_request <= 1.0s
    df["rapid_request_flag"] = (
        (df["time_since_previous_request"].notna()) & (df["time_since_previous_request"] <= 1.0)
    ).astype(int)

    # 5. IP Diversity Features
    url_col = "normalized_resource" if "normalized_resource" in df.columns else ("resource_requested" if "resource_requested" in df.columns else None)
    if url_col:
        unique_urls = df.groupby("client_ip")[url_col].nunique()
        df["unique_urls_per_ip"] = df["client_ip"].map(unique_urls).astype(int)
    else:
        df["unique_urls_per_ip"] = 1

    if "client_port" in df.columns:
        unique_ports = df.groupby("client_ip")["client_port"].nunique()
        df["unique_ports_per_ip"] = df["client_ip"].map(unique_ports).astype(int)
    else:
        df["unique_ports_per_ip"] = 1

    if "user_agent" in df.columns:
        unique_uas = df.groupby("client_ip")["user_agent"].nunique()
        df["unique_user_agents_per_ip"] = df["client_ip"].map(unique_uas).astype(int)
    else:
        df["unique_user_agents_per_ip"] = 1

    stats["rapid_requests_count"] = int(df["rapid_request_flag"].sum())
    stats["rapid_requests_pct"] = (stats["rapid_requests_count"] / n_rows) * 100
    stats["max_requests_single_ip"] = int(ip_counts.max())
    stats["top_ip"] = str(ip_counts.index[0])

    return df, stats
