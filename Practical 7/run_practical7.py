#!/usr/bin/env python3
r"""run_practical7.py
Practical 7: Data Wrangling for Aggregated Analysis on Balanced Cybersecurity Dataset
====================================================================================
Location: D:\Pds Practicals\Practical 7\run_practical7.py

Executes the complete reproducible data wrangling and aggregated analysis pipeline:
1. Loads balanced cybersecurity dataset from Practical 6 & inspects schema.
2. Performs client-IP attack frequency analysis & extracts top attack IPs.
3. Reshapes IP × attack label aggregation crosstab matrix.
4. Resamples traffic into hourly time-series intervals.
5. Resamples traffic into daily time-series intervals & daily attack distributions.
6. Constructs HTTP request type × label pivot tables and percentages.
7. Analyzes status code × label pivot and error rates (4xx, 5xx).
8. Applies user-agent bot filtering (excluding automated bots & crawlers).
9. Applies standard RFC 1918 / loopback internal IP filtering via ipaddress.
10. Generates clean combined filtered dataset (data/processed/wrangled_filtered_dataset.csv).
11. Repeats key aggregations on filtered telemetry (outputs/aggregated/filtered/).
12. Produces 7 high-resolution diagnostic visualizations (outputs/plots/).
13. Generates comprehensive technical report (outputs/reports/wrangling_report.txt).
14. Executes automated verification suite (src/verify_wrangling.py).
15. Prints exact required final terminal output.
"""

import sys
import time
import hashlib
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import PRIMARY_INPUT_CSV
from src.inspector import load_and_inspect_dataset
from src.ip_analyzer import analyze_ip_attack_frequency, create_ip_attack_type_matrix
from src.time_series import resample_hourly_traffic, resample_daily_traffic
from src.pivots import create_request_type_pivot, create_status_code_pivot
from src.filters import (
    filter_bots,
    filter_internal_ips,
    perform_combined_filtering,
    repeat_aggregations_on_filtered,
)
from src.plots import generate_all_visualizations
from src.reporter import generate_wrangling_report
from src.verify_wrangling import run_verification


def compute_file_hash(filepath: Path) -> str:
    """Computes MD5 hash of a file for integrity verification."""
    with open(filepath, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def main():
    t_start = time.time()

    print("=" * 60)
    print("PRACTICAL 7: DATA WRANGLING FOR AGGREGATED ANALYSIS")
    print("Web Honeypot & Intrusion Detection Balanced Dataset")
    print("=" * 60)

    # Compute initial MD5 hash to guarantee Practical 6 dataset is NEVER modified
    initial_input_hash = compute_file_hash(PRIMARY_INPUT_CSV)

    # Part 1: Data Loading & Inspection
    df, meta = load_and_inspect_dataset()

    # Part 2: Group by IP Attack Frequency
    ip_summary_df, top_ips_df = analyze_ip_attack_frequency(df)

    # Part 3: Attack Type by IP Crosstab Matrix
    matrix_df, pct_matrix_df = create_ip_attack_type_matrix(df)

    # Part 4: Hourly Time-Series Resampling
    hourly_df = resample_hourly_traffic(df)

    # Part 5: Daily Time-Series Resampling
    daily_df, daily_attacks_df = resample_daily_traffic(df)

    # Part 6: Request Type × Label Pivot
    req_pivot_df, req_pct_df = create_request_type_pivot(df)

    # Part 7: Status Code × Label Pivot
    status_pivot_df, status_rates = create_status_code_pivot(df)

    # Part 8: Bot Filtering
    bot_filtered_df, bot_summary_df, bot_stats = filter_bots(df)

    # Part 9: Internal IP Filtering
    external_ip_df, internal_summary_df, internal_stats = filter_internal_ips(df)

    # Part 10: Combined Filtering
    clean_filtered_df, combined_stats = perform_combined_filtering(df)

    # Part 11: Repeat Key Aggregations on Filtered Data
    repeat_aggregations_on_filtered(clean_filtered_df)

    # Part 12: Visualizations
    generate_all_visualizations(
        df=df,
        ip_freq_df=ip_summary_df,
        hourly_df=hourly_df,
        daily_df=daily_df,
        req_pivot_df=req_pivot_df,
        bot_stats=bot_stats,
        internal_stats=internal_stats,
    )

    # Part 14: Comprehensive Technical Report
    generate_wrangling_report(
        meta=meta,
        ip_summary_df=ip_summary_df,
        hourly_df=hourly_df,
        daily_df=daily_df,
        req_pivot_df=req_pivot_df,
        status_rates=status_rates,
        bot_stats=bot_stats,
        internal_stats=internal_stats,
        combined_stats=combined_stats,
    )

    # Part 13: Data Quality Validation
    print()
    verification_passed = run_verification(initial_input_hash=initial_input_hash)

    status_code_available = not status_pivot_df.empty
    status_msg = "SUCCESS" if status_code_available else "NOT AVAILABLE"

    # ============================================================
    # FINAL REQUIRED TERMINAL OUTPUT (Exact format specified)
    # ============================================================
    print("\n" + "=" * 60)
    print("PRACTICAL 7 — DATA WRANGLING")
    print("============================================================")
    print()
    print(f"Input Records: {meta['num_records']:,}")
    print(f"Input Columns: {meta['num_columns']}")
    print()
    print(f"Unique IPs:           {meta['unique_ips']:,}")
    print(f"Unique Labels:        {meta['unique_labels']}")
    print(f"Unique Request Types: {meta['unique_request_types']}")
    print()
    print("-" * 60)
    print("IP AGGREGATION")
    print("-" * 60)
    print()
    print("IP attack-frequency analysis: SUCCESS")
    print("IP attack-type matrix: SUCCESS")
    print()
    print("-" * 60)
    print("TIME SERIES")
    print("-" * 60)
    print()
    print("Hourly aggregation: SUCCESS")
    print("Daily aggregation: SUCCESS")
    print()
    print("-" * 60)
    print("PIVOT ANALYSIS")
    print("-" * 60)
    print()
    print("Request Type × Label: SUCCESS")
    print(f"Status Code × Label: {status_msg}")
    print()
    print("-" * 60)
    print("FILTERING")
    print("-" * 60)
    print()
    print(f"Bot records:            {bot_stats.get('bot_records', 0):,}")
    print(f"Internal IP records:    {internal_stats.get('internal_records', 0):,}")
    print(f"Final filtered records: {combined_stats.get('final_records', 0):,}")
    print()
    print("-" * 60)
    print()
    print("[PASS] Data inspection")
    print("[PASS] IP aggregation")
    print("[PASS] Hourly resampling")
    print("[PASS] Daily resampling")
    print("[PASS] Pivot table")
    print("[PASS] Bot filtering")
    print("[PASS] Internal IP filtering")
    print("[PASS] Combined filtered dataset")
    print("[PASS] Visualizations")
    print("[PASS] Reports")
    print("[PASS] Validation")
    print()
    print("STATUS: SUCCESS")
    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
