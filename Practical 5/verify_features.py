#!/usr/bin/env python3
r"""verify_features.py
Practical 5: Quality & Validation Suite for Feature-Engineered Telemetry
========================================================================
Location: D:\Pds Practicals\Practical 5\verify_features.py

Performs comprehensive automated verification on Practical 5 outputs:
1. Input dataset loaded
2. Requests-per-IP feature
3. Time-between-requests feature
4. User-agent features
5. URL entropy feature
6. URL-derived features
7. Featuretools features
8. tsfresh features
9. No target leakage
10. No infinite values
11. Final feature dataset readable
"""

import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pandas as pd
from src.config import (
    FEATURE_ENGINEERED_CSV,
    ML_READY_CSV,
    FEATURETOOLS_CSV,
    TSFRESH_CSV,
    PRACTICAL4_CSV,
    PRACTICAL3_CSV,
)


def run_verification() -> bool:
    print("=" * 60)
    print("PRACTICAL 5 — FEATURE ENGINEERING VERIFICATION")
    print("=" * 60)
    print()

    # Determine original record count
    orig_path = PRACTICAL4_CSV if PRACTICAL4_CSV.exists() else PRACTICAL3_CSV
    if not orig_path.exists():
        print(f"[FAIL] Neither Practical 4 nor Practical 3 input files found.")
        return False

    orig_df_sample = pd.read_csv(orig_path, usecols=["client_ip"])
    orig_records = len(orig_df_sample)
    del orig_df_sample

    checks = []

    # 1. Input dataset loaded
    test_1 = "Input dataset loaded"
    checks.append((test_1, True))
    print(f"[PASS] {test_1}")

    # Load final feature engineered dataset
    if not FEATURE_ENGINEERED_CSV.exists():
        print(f"[FAIL] Final feature dataset not found at: {FEATURE_ENGINEERED_CSV}")
        return False

    df_final = pd.read_csv(FEATURE_ENGINEERED_CSV, low_memory=False)
    final_records = len(df_final)

    # 2. Requests-per-IP feature
    test_2 = "Requests-per-IP feature"
    ip_req_present = "requests_per_ip" in df_final.columns and "requests_per_ip_1min" in df_final.columns
    checks.append((test_2, ip_req_present))
    print(f"[{'PASS' if ip_req_present else 'FAIL'}] {test_2}")

    # 3. Time-between-requests feature
    test_3 = "Time-between-requests feature"
    time_req_present = (
        "time_since_previous_request" in df_final.columns
        and "mean_inter_request_time_ip" in df_final.columns
        and "rapid_request_flag" in df_final.columns
    )
    checks.append((test_3, time_req_present))
    print(f"[{'PASS' if time_req_present else 'FAIL'}] {test_3}")

    # 4. User-agent features
    test_4 = "User-agent features"
    ua_present = "user_agent_type" in df_final.columns and "is_bot" in df_final.columns and "is_scanner" in df_final.columns
    checks.append((test_4, ua_present))
    print(f"[{'PASS' if ua_present else 'FAIL'}] {test_4}")

    # 5. URL entropy feature
    test_5 = "URL entropy feature"
    entropy_present = "url_entropy" in df_final.columns and df_final["url_entropy"].min() >= 0.0
    checks.append((test_5, entropy_present))
    print(f"[{'PASS' if entropy_present else 'FAIL'}] {test_5}")

    # 6. URL-derived features
    test_6 = "URL-derived features"
    url_derived_present = (
        "url_length" in df_final.columns
        and "path_depth" in df_final.columns
        and ("query_parameter_count" in df_final.columns or "number_of_query_parameters" in df_final.columns)
        and "special_character_count" in df_final.columns
    )
    checks.append((test_6, url_derived_present))
    print(f"[{'PASS' if url_derived_present else 'FAIL'}] {test_6}")

    # 7. Featuretools features
    test_7 = "Featuretools features"
    ft_cols = [c for c in df_final.columns if c.startswith("ft_")]
    ft_present = len(ft_cols) > 0 and FEATURETOOLS_CSV.exists()
    checks.append((test_7, ft_present))
    print(f"[{'PASS' if ft_present else 'FAIL'}] {test_7}")

    # 8. tsfresh features
    test_8 = "tsfresh features"
    ts_cols = [c for c in df_final.columns if c.startswith("tsfresh_")]
    ts_present = len(ts_cols) > 0 and TSFRESH_CSV.exists()
    checks.append((test_8, ts_present))
    print(f"[{'PASS' if ts_present else 'FAIL'}] {test_8}")

    # 9. No target leakage
    test_9 = "No target leakage"
    if ML_READY_CSV.exists():
        df_ml = pd.read_csv(ML_READY_CSV, nrows=10)
        has_leakage = any(c in df_ml.columns for c in ["label", "label_reason", "target"])
        leak_pass = not has_leakage
    else:
        leak_pass = False
    checks.append((test_9, leak_pass))
    print(f"[{'PASS' if leak_pass else 'FAIL'}] {test_9}")

    # 10. No infinite values
    test_10 = "No infinite values"
    if ML_READY_CSV.exists():
        # Check ml matrix for inifinities or NaNs
        df_ml_full = pd.read_csv(ML_READY_CSV)
        has_inf = np.isinf(df_ml_full.values).any()
        has_nan = df_ml_full.isna().any().any()
        no_inf_pass = (not has_inf) and (not has_nan)
    else:
        no_inf_pass = False
    checks.append((test_10, no_inf_pass))
    print(f"[{'PASS' if no_inf_pass else 'FAIL'}] {test_10}")

    # 11. Final feature dataset readable
    test_11 = "Final feature dataset readable"
    readable_pass = (final_records == orig_records) and len(df_final.columns) > 20
    checks.append((test_11, readable_pass))
    print(f"[{'PASS' if readable_pass else 'FAIL'}] {test_11}")

    # Categorize features
    domain_cols = [
        c for c in df_final.columns
        if not c.startswith("ft_")
        and not c.startswith("tsfresh_")
        and c not in [
            "category_type", "payload", "timestamp", "client_ip", "client_port",
            "user_agent", "accept_language", "proxy_ip", "request_type", "status_code",
            "resource_requested", "bytes_sent", "referrer", "normalized_resource",
            "label", "label_reason", "ts_activity_signal", "anomaly_score", "anomaly_flag"
        ]
    ]

    total_final_features = len(df_ml_full.columns) if ML_READY_CSV.exists() else len(df_final.columns)

    print()
    print("-" * 60)
    print()
    print(f"Domain features:        {len(domain_cols)}")
    print(f"Featuretools features:  {len(ft_cols)}")
    print(f"tsfresh features:       {len(ts_cols)}")
    print(f"Total final features:   {total_final_features}")
    print()
    print(f"Original records:       {orig_records:,}")
    print(f"Final records:          {final_records:,}")
    print()
    print("=" * 60)
    print()

    all_passed = all(status for _, status in checks)
    print(f"STATUS: {'SUCCESS' if all_passed else 'FAILED'}")
    print()
    print("=" * 60)

    return all_passed


if __name__ == "__main__":
    success = run_verification()
    sys.exit(0 if success else 1)
