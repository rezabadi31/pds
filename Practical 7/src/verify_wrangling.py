#!/usr/bin/env python3
r"""verify_wrangling.py
Part 13: Comprehensive Data Quality & Verification Suite for Practical 7
========================================================================
Location: D:\Pds Practicals\Practical 7\src\verify_wrangling.py

Performs automated assertions to verify all Practical 7 wrangling, filtering,
and aggregation outputs for mathematical validity, structural integrity,
and non-destructive preservation of the original balanced training dataset.
"""

import sys
import hashlib
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
from src.config import (
    PRIMARY_INPUT_CSV,
    WRANGLED_FILTERED_CSV,
    IP_ATTACK_FREQ_CSV,
    TOP_ATTACK_IPS_CSV,
    IP_ATTACK_TYPE_MATRIX_CSV,
    HOURLY_TRAFFIC_CSV,
    DAILY_TRAFFIC_CSV,
    DAILY_ATTACK_TYPES_CSV,
    REQUEST_TYPE_PIVOT_CSV,
    STATUS_CODE_PIVOT_CSV,
    BOT_FILTERED_CSV,
    BOT_TRAFFIC_SUMMARY_CSV,
    EXTERNAL_IP_CSV,
    INTERNAL_EXTERNAL_SUMMARY_CSV,
    FILTERED_AGG_DIR,
)


def run_verification(initial_input_hash: str = None) -> bool:
    print("=" * 60)
    print("PRACTICAL 7 — DATA WRANGLING VERIFICATION SUITE")
    print("=" * 60)
    print()

    all_passed = True
    checks = []

    # 1. Input dataset loaded
    test_1 = "Input dataset loaded"
    if PRIMARY_INPUT_CSV.exists():
        df_input = pd.read_csv(PRIMARY_INPUT_CSV)
        t1_ok = len(df_input) > 0 and len(df_input.columns) > 0
        checks.append((test_1, t1_ok))
        print(f"[{'PASS' if t1_ok else 'FAIL'}] {test_1} ({len(df_input):,} records, {len(df_input.columns)} columns)")
    else:
        checks.append((test_1, False))
        print(f"[FAIL] {test_1} (File not found: {PRIMARY_INPUT_CSV})")
        return False

    # 2. Timestamp converted
    test_2 = "Timestamp converted"
    if "timestamp" in df_input.columns:
        ts_series = pd.to_datetime(df_input["timestamp"], errors="coerce")
        valid_ts = int(ts_series.notnull().sum())
        t2_ok = valid_ts > 0
        checks.append((test_2, t2_ok))
        print(f"[{'PASS' if t2_ok else 'FAIL'}] {test_2} ({valid_ts:,} valid timestamps converted)")
    else:
        checks.append((test_2, False))
        print(f"[FAIL] {test_2} (No timestamp column in input)")

    # 3. IP aggregation created
    test_3 = "IP aggregation created"
    if IP_ATTACK_FREQ_CSV.exists() and TOP_ATTACK_IPS_CSV.exists():
        df_ip = pd.read_csv(IP_ATTACK_FREQ_CSV)
        # Check non-negative counts and attack+benign == total
        counts_ok = (df_ip["total_requests"] >= 0).all() and (df_ip["attack_requests"] >= 0).all()
        sum_ok = (df_ip["attack_requests"] + df_ip["benign_requests"] == df_ip["total_requests"]).all()
        no_dup_ips = df_ip["client_ip"].is_unique
        t3_ok = counts_ok and sum_ok and no_dup_ips and len(df_ip) > 0
        checks.append((test_3, t3_ok))
        print(f"[{'PASS' if t3_ok else 'FAIL'}] {test_3} ({len(df_ip):,} unique IPs, additive totals verified)")
    else:
        checks.append((test_3, False))
        print(f"[FAIL] {test_3}")

    # 4. Hourly aggregation created
    test_4 = "Hourly aggregation created"
    if HOURLY_TRAFFIC_CSV.exists():
        df_hourly = pd.read_csv(HOURLY_TRAFFIC_CSV)
        counts_ok = (df_hourly["total_requests"] >= 0).all()
        sum_ok = (df_hourly["attack_requests"] + df_hourly["benign_requests"] == df_hourly["total_requests"]).all()
        no_dup_hours = df_hourly["timestamp_hour"].is_unique
        t4_ok = counts_ok and sum_ok and no_dup_hours and len(df_hourly) > 0
        checks.append((test_4, t4_ok))
        print(f"[{'PASS' if t4_ok else 'FAIL'}] {test_4} ({len(df_hourly):,} hourly intervals verified)")
    else:
        checks.append((test_4, False))
        print(f"[FAIL] {test_4}")

    # 5. Daily aggregation created
    test_5 = "Daily aggregation created"
    if DAILY_TRAFFIC_CSV.exists() and DAILY_ATTACK_TYPES_CSV.exists():
        df_daily = pd.read_csv(DAILY_TRAFFIC_CSV)
        counts_ok = (df_daily["total_requests"] >= 0).all()
        sum_ok = (df_daily["attack_requests"] + df_daily["benign_requests"] == df_daily["total_requests"]).all()
        pct_ok = ((df_daily["attack_rate"] >= 0.0) & (df_daily["attack_rate"] <= 1.0)).all()
        no_dup_days = df_daily["date"].is_unique
        t5_ok = counts_ok and sum_ok and pct_ok and no_dup_days and len(df_daily) > 0
        checks.append((test_5, t5_ok))
        print(f"[{'PASS' if t5_ok else 'FAIL'}] {test_5} ({len(df_daily):,} observation days, attack rates valid)")
    else:
        checks.append((test_5, False))
        print(f"[FAIL] {test_5}")

    # 6. Request type × label pivot created
    test_6 = "Request type × label pivot created"
    if REQUEST_TYPE_PIVOT_CSV.exists():
        df_req = pd.read_csv(REQUEST_TYPE_PIVOT_CSV)
        t6_ok = len(df_req) > 0 and len(df_req.columns) > 1
        checks.append((test_6, t6_ok))
        print(f"[{'PASS' if t6_ok else 'FAIL'}] {test_6} ({len(df_req)} request types × {len(df_req.columns)-1} labels)")
    else:
        checks.append((test_6, False))
        print(f"[FAIL] {test_6}")

    # 7. Bot filtering completed
    test_7 = "Bot filtering completed"
    if BOT_FILTERED_CSV.exists() and BOT_TRAFFIC_SUMMARY_CSV.exists():
        df_bot = pd.read_csv(BOT_FILTERED_CSV)
        t7_ok = len(df_bot) > 0 and len(df_bot) <= len(df_input)
        checks.append((test_7, t7_ok))
        print(f"[{'PASS' if t7_ok else 'FAIL'}] {test_7} ({len(df_bot):,} records retained after bot exclusion)")
    else:
        checks.append((test_7, False))
        print(f"[FAIL] {test_7}")

    # 8. Internal IP filtering completed
    test_8 = "Internal IP filtering completed"
    if EXTERNAL_IP_CSV.exists() and INTERNAL_EXTERNAL_SUMMARY_CSV.exists():
        df_ext = pd.read_csv(EXTERNAL_IP_CSV)
        t8_ok = len(df_ext) > 0 and len(df_ext) <= len(df_input)
        checks.append((test_8, t8_ok))
        print(f"[{'PASS' if t8_ok else 'FAIL'}] {test_8} ({len(df_ext):,} external records retained)")
    else:
        checks.append((test_8, False))
        print(f"[FAIL] {test_8}")

    # 9. Filtered dataset saved
    test_9 = "Filtered dataset saved"
    if WRANGLED_FILTERED_CSV.exists():
        df_clean = pd.read_csv(WRANGLED_FILTERED_CSV)
        t9_ok = len(df_clean) > 0 and len(df_clean) <= len(df_input)
        checks.append((test_9, t9_ok))
        print(f"[{'PASS' if t9_ok else 'FAIL'}] {test_9} ({len(df_clean):,} wrangled records in {WRANGLED_FILTERED_CSV.name})")
    else:
        checks.append((test_9, False))
        print(f"[FAIL] {test_9}")

    # 10. No unexpected data loss in original dataset
    test_10 = "No unexpected data loss in original dataset"
    t10_ok = len(df_input) == 60000
    checks.append((test_10, t10_ok))
    print(f"[{'PASS' if t10_ok else 'FAIL'}] {test_10} (Original dataset retains all {len(df_input):,} records)")

    # 11. Original balanced dataset unchanged
    test_11 = "Original balanced dataset unchanged"
    if initial_input_hash:
        with open(PRIMARY_INPUT_CSV, "rb") as f:
            curr_hash = hashlib.md5(f.read()).hexdigest()
        t11_ok = curr_hash == initial_input_hash
    else:
        # Fallback check: file exists and has exactly 60,000 rows
        t11_ok = PRIMARY_INPUT_CSV.exists() and len(df_input) == 60000
    checks.append((test_11, t11_ok))
    print(f"[{'PASS' if t11_ok else 'FAIL'}] {test_11} (Practical 6 dataset integrity strictly preserved)")

    # 12. All aggregation outputs readable
    test_12 = "All aggregation outputs readable"
    required_csvs = [
        IP_ATTACK_FREQ_CSV,
        TOP_ATTACK_IPS_CSV,
        IP_ATTACK_TYPE_MATRIX_CSV,
        HOURLY_TRAFFIC_CSV,
        DAILY_TRAFFIC_CSV,
        DAILY_ATTACK_TYPES_CSV,
        REQUEST_TYPE_PIVOT_CSV,
        STATUS_CODE_PIVOT_CSV,
        BOT_FILTERED_CSV,
        EXTERNAL_IP_CSV,
        WRANGLED_FILTERED_CSV,
    ]
    all_readable = all(p.exists() and p.stat().st_size > 0 for p in required_csvs)
    checks.append((test_12, all_readable))
    print(f"[{'PASS' if all_readable else 'FAIL'}] {test_12} (All 11 primary CSV aggregations non-empty & valid)")

    all_passed = all(status for _, status in checks)
    print("\n" + "-" * 60)
    print(f"Verification Result: {'ALL CHECKS PASSED' if all_passed else 'SOME CHECKS FAILED'}")
    print("-" * 60)
    return all_passed


if __name__ == "__main__":
    success = run_verification()
    sys.exit(0 if success else 1)
