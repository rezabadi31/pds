"""status_features.py
Feature 3: HTTP Status Code Frequency & Error Ratio Profiling
Extracts client-level response code distributions and error thresholds.
"""

from typing import Tuple, Dict, Any
import numpy as np
import pandas as pd
from src.config import HIGH_404_RATIO_THRESH, HIGH_404_COUNT_THRESH


def extract_status_code_features(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Evaluates status-code availability and computes per-IP error distributions.
    
    If status_code is available, computes 404, 403, and 500 aggregates and flags.
    If unavailable or constant zero, documents the schema state without fabricating data.
    """
    stats: Dict[str, Any] = {
        "status_code_available": False,
        "status_col_name": None,
        "unique_status_codes": [],
        "documented_note": "",
    }

    # Identify status code column
    possible_names = ["status_code", "status", "http_status", "response_status"]
    status_col = None
    for name in possible_names:
        if name in df.columns:
            status_col = name
            break

    if status_col is None:
        stats["status_code_available"] = False
        stats["documented_note"] = (
            "Status-code frequency feature could not be computed because no "
            "status-code field is available in the input schema."
        )
        # Create sentinel zero columns for schema consistency
        df["status_404_count_ip"] = 0
        df["status_403_count_ip"] = 0
        df["status_500_count_ip"] = 0
        df["status_404_ratio_ip"] = 0.0
        df["status_403_ratio_ip"] = 0.0
        df["error_status_ratio_ip"] = 0.0
        df["high_404_activity_flag"] = 0
        return df, stats

    stats["status_code_available"] = True
    stats["status_col_name"] = status_col
    val_counts = df[status_col].value_counts()
    stats["unique_status_codes"] = [int(x) for x in val_counts.index]

    # Convert status to integer safely
    s_series = pd.to_numeric(df[status_col], errors="coerce").fillna(0).astype(int)

    # Calculate per-IP occurrences
    # If the column has non-zero values:
    total_req_per_ip = df["requests_per_ip"]

    c404 = (s_series == 404).astype(int)
    c403 = (s_series == 403).astype(int)
    c500 = ((s_series >= 500) & (s_series < 600)).astype(int)
    c_err = ((s_series >= 400) & (s_series < 600)).astype(int)

    ip_404_counts = df.groupby("client_ip")[c404.name if c404.name else "client_ip"].transform("sum") if c404.sum() > 0 else 0
    # Vectorized computation
    if c404.sum() > 0:
        sum_404_map = c404.groupby(df["client_ip"]).sum()
        df["status_404_count_ip"] = df["client_ip"].map(sum_404_map).fillna(0).astype(int)
    else:
        df["status_404_count_ip"] = 0

    if c403.sum() > 0:
        sum_403_map = c403.groupby(df["client_ip"]).sum()
        df["status_403_count_ip"] = df["client_ip"].map(sum_403_map).fillna(0).astype(int)
    else:
        df["status_403_count_ip"] = 0

    if c500.sum() > 0:
        sum_500_map = c500.groupby(df["client_ip"]).sum()
        df["status_500_count_ip"] = df["client_ip"].map(sum_500_map).fillna(0).astype(int)
    else:
        df["status_500_count_ip"] = 0

    # Ratios
    df["status_404_ratio_ip"] = (df["status_404_count_ip"] / total_req_per_ip).fillna(0.0).round(4)
    df["status_403_ratio_ip"] = (df["status_403_count_ip"] / total_req_per_ip).fillna(0.0).round(4)

    if c_err.sum() > 0:
        sum_err_map = c_err.groupby(df["client_ip"]).sum()
        err_counts = df["client_ip"].map(sum_err_map).fillna(0).astype(int)
        df["error_status_ratio_ip"] = (err_counts / total_req_per_ip).fillna(0.0).round(4)
    else:
        df["error_status_ratio_ip"] = 0.0

    # High 404 flag: ratio >= 0.50 OR count >= 20
    df["high_404_activity_flag"] = (
        (df["status_404_ratio_ip"] >= HIGH_404_RATIO_THRESH)
        | (df["status_404_count_ip"] >= HIGH_404_COUNT_THRESH)
    ).astype(int)

    if len(stats["unique_status_codes"]) == 1 and stats["unique_status_codes"][0] == 0:
        stats["documented_note"] = (
            f"Field '{status_col}' exists in input schema but contains constant value 0 for all "
            f"{len(df):,} records (typical for honeypot packet capture telemetry where server HTTP response "
            "headers were not emitted or captured). Status features were computed faithfully without fabricating "
            "synthetic response codes."
        )
    else:
        stats["documented_note"] = (
            f"Computed status code features from column '{status_col}' across {len(stats['unique_status_codes'])} "
            "distinct status codes."
        )

    return df, stats
