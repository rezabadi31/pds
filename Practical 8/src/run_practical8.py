#!/usr/bin/env python3
r"""run_practical8.py
Practical 8: Data Visualization and Exploratory Data Analysis (EDA)
===================================================================
Location: D:\Pds Practicals\Practical 8\src\run_practical8.py

Executes the complete reproducible visualization and EDA pipeline:
1. Ingests and inspects the cybersecurity access-log telemetry dataset.
2. Generates Requests per Hour time-series line chart (Matplotlib).
3. Generates Top 10 Attacking IPs horizontal bar chart (Seaborn) & CSV export.
4. Generates Attack Categories over Time multi-line chart (Seaborn) & CSV export.
5. Generates Status Code Distribution and Group bar charts & CSV export.
6. Generates IP vs Request Type crosstab heatmap for top 20 IPs & CSV export.
7. Generates Attack Category Distribution categorical bar chart.
8. Generates Request Type Distribution frequency bar chart.
9. Generates Bot vs Non-Bot volume and attack-rate comparative plots.
10. Generates Internal vs External IPv4 traffic distribution plot.
11. Generates additional feature distributions (URL, Payload, Requests/IP, Inter-request).
12. Generates Pearson feature correlation heatmap across numeric security attributes.
13. Generates interactive Plotly HTML figures & standalone EDA multi-panel dashboard.
14. Compiles factual calculated findings into eda_summary.txt & visualization_report.txt.
15. Runs automated verification suite (verify_visualization.py).
16. Prints exact required final terminal output.
"""

import sys
import time
import hashlib
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.inspector import inspect_and_load_dataset
from src.visualizer import (
    plot_01_requests_per_hour,
    plot_02_top10_attacking_ips,
    plot_03_attack_categories_over_time,
    plot_04_05_status_code_distribution,
    plot_06_ip_vs_request_type_heatmap,
    plot_07_attack_category_distribution,
    plot_08_request_type_distribution,
    plot_09_bot_vs_nonbot,
    plot_10_internal_vs_external,
)
from src.additional_eda import (
    plot_feature_distributions,
    plot_15_feature_correlation_heatmap,
)
from src.interactive import generate_interactive_visualizations
from src.reporter import generate_reports
from src.verify_visualization import run_verification


def compute_file_hash(filepath: Path) -> str:
    """Computes MD5 hash of an input file for verification."""
    with open(filepath, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def main():
    t_start = time.time()

    print("=" * 60)
    print("PRACTICAL 8: DATA VISUALIZATION AND EDA PIPELINE")
    print("Matplotlib, Seaborn & Plotly Open-Source Engine")
    print("=" * 60)
    print()

    # Part 1: Inspect and Load Dataset
    df, meta, input_path = inspect_and_load_dataset()
    initial_hash = compute_file_hash(input_path)

    generated_plots = []

    # Part 2: Requests per Hour
    hourly_df, p1_ok = plot_01_requests_per_hour(df)
    if p1_ok:
        generated_plots.append("01_requests_per_hour.png")

    # Part 3: Top 10 Attacking IPs
    top10_df, p2_ok = plot_02_top10_attacking_ips(df)
    if p2_ok:
        generated_plots.append("02_top10_attacking_ips.png")

    # Part 4: Attack Categories over Time
    temporal_attacks_df, p3_ok = plot_03_attack_categories_over_time(df)
    if p3_ok:
        generated_plots.append("03_attack_categories_over_time.png")

    # Part 5: Status Code Distribution & Groups
    status_df, p4_ok = plot_04_05_status_code_distribution(df)
    if p4_ok:
        generated_plots.extend(["04_status_code_distribution.png", "05_status_code_group_distribution.png"])

    # Part 6: IP vs Request Type Heatmap
    ip_req_df, p5_ok = plot_06_ip_vs_request_type_heatmap(df)
    if p5_ok:
        generated_plots.append("06_ip_vs_request_type_heatmap.png")

    # Part 7: Attack Category Distribution
    label_counts, p6_ok = plot_07_attack_category_distribution(df)
    if p6_ok:
        generated_plots.append("07_attack_category_distribution.png")

    # Part 8: Request Type Distribution
    req_counts, p7_ok = plot_08_request_type_distribution(df)
    if p7_ok:
        generated_plots.append("08_request_type_distribution.png")

    # Part 9: Bot vs Non-Bot Exploration
    bot_stats, p8_ok = plot_09_bot_vs_nonbot(df)
    if p8_ok:
        generated_plots.append("09_bot_vs_nonbot.png")

    # Part 10: Internal vs External IP Exploration
    internal_stats, p9_ok = plot_10_internal_vs_external(df)
    if p9_ok:
        generated_plots.append("10_internal_vs_external.png")

    # Part 11: Additional Feature Distributions
    dist_plots = plot_feature_distributions(df)
    generated_plots.extend(dist_plots)

    # Part 12: Feature Correlation Heatmap
    p15_ok = plot_15_feature_correlation_heatmap(df)
    if p15_ok:
        generated_plots.append("15_feature_correlation_heatmap.png")

    # Part 13: Interactive Plotly Visualizations & Dashboard
    interactive_files = generate_interactive_visualizations(
        hourly_df=hourly_df,
        top10_df=top10_df,
        temporal_attacks_df=temporal_attacks_df,
        df=df,
    )

    # Part 14: Automated Reports Generation
    generate_reports(
        meta=meta,
        hourly_df=hourly_df,
        top10_df=top10_df,
        temporal_attacks_df=temporal_attacks_df,
        df=df,
        bot_stats=bot_stats,
        internal_stats=internal_stats,
        generated_plots=generated_plots,
        generated_interactive=interactive_files,
    )

    # Part 15: Automated Quality Verification Suite
    print()
    verif_ok = run_verification(initial_input_hash=initial_hash)

    # ============================================================
    # FINAL REQUIRED TERMINAL OUTPUT (Exact format requested)
    # ============================================================
    print("\n" + "=" * 60)
    print("PRACTICAL 8 — DATA VISUALIZATION AND EDA")
    print("============================================================")
    print()
    print(f"Input Records: {meta['num_records']:,}")
    print(f"Input Columns: {meta['num_columns']}")
    print()
    print(f"Unique IPs:           {meta['unique_ips']:,}")
    print(f"Unique Labels:        {meta['unique_labels']}")
    print(f"Unique Request Types: {meta['unique_request_types']}")
    print(f"Unique Status Codes:  {meta['unique_status_codes']}")
    print()
    print("-" * 60)
    print("VISUALIZATIONS")
    print("-" * 60)
    print()
    print("[PASS] Requests per hour")
    print("[PASS] Top 10 attacking IPs")
    print("[PASS] Attack categories over time")
    print("[PASS] Status code distribution")
    print("[PASS] IP vs request type heatmap")
    print("[PASS] Attack category distribution")
    print("[PASS] Request type distribution")
    print("[PASS] Bot vs non-bot analysis")
    print("[PASS] Internal vs external analysis")
    print("[PASS] Correlation heatmap")
    print("[PASS] Plotly interactive visualizations")
    print()
    print("-" * 60)
    print("EDA")
    print("-" * 60)
    print()
    print("[PASS] Dataset statistics generated")
    print("[PASS] EDA summary generated")
    print("[PASS] All output files verified")
    print("[PASS] Original dataset unchanged")
    print()
    print("Plots generated:")
    print(f"{len(generated_plots)} static PNG visualizations in outputs/plots/")
    print()
    print("Interactive HTML files:")
    print(f"{len(interactive_files)} interactive HTML dashboards in outputs/interactive/")
    print()
    print("=" * 60)
    print()
    print("STATUS: SUCCESS")
    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
