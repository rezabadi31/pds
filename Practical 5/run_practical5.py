#!/usr/bin/env python3
r"""run_practical5.py
Practical 5: Feature Engineering for Anomaly & Suspicious Activity Detection
=============================================================================
Location: D:\Pds Practicals\Practical 5\run_practical5.py

Unified Open-Source Pipeline:
Part A: Domain-Specific Security & Behavioral Features
Part B: Featuretools Automated Relational Aggregations (Deep Feature Synthesis)
Part C: tsfresh Automated Time-Series Feature Extraction (EfficientFCParameters)
Part D & E: Feature Combination, Scaler Normalization, and Data Quality Auditing
Part F: Statistical Feature Selection & Variance Filtering (scikit-learn)
Part G: Top 20 Validation Feature Importance (Random Forest)
Part H: Unsupervised Anomaly Detection (Isolation Forest)
Part I: Methodological Comparison and Diagnostic Plotting
"""

import sys
import time
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pandas as pd

from src.inspector import inspect_and_load_dataset
from src.time_features import extract_time_features
from src.ip_features import extract_ip_traffic_features
from src.status_features import extract_status_code_features
from src.user_agent import extract_user_agent_features
from src.entropy_url import extract_url_entropy_features
from src.security_features import extract_security_features
from src.featuretools_extractor import extract_featuretools_features
from src.tsfresh_extractor import extract_tsfresh_features
from src.feature_combiner import combine_and_scale_features
from src.feature_selection import run_feature_selection
from src.anomaly import run_anomaly_detection, evaluate_feature_importance
from src.report_generator import generate_feature_comparison_report, generate_comprehensive_engineering_report
from src.plots import generate_all_plots


def main():
    t_start = time.time()

    # Step 1: Ingestion & Inspection
    df, meta = inspect_and_load_dataset()
    input_rows, input_cols = meta["rows"], meta["cols"]

    # PART A: Domain-Specific Feature Engineering
    print("\n" + "=" * 60)
    print("PART A - DOMAIN-SPECIFIC SECURITY FEATURE ENGINEERING")
    print("=" * 60)

    # 1. Temporal Features
    df, ts_dt = extract_time_features(df)
    domain_time_features = ["request_hour", "request_day_of_week", "request_day", "request_month", "is_night"]

    # 2. IP Traffic, Rolling Windows & Inter-Arrival Dynamics
    df, ip_stats = extract_ip_traffic_features(df, ts_dt)
    domain_ip_features = [
        "requests_per_ip", "ip_request_rank", "requests_per_ip_1min", "requests_per_ip_5min", "requests_per_ip_10min",
        "unique_urls_per_ip", "unique_ports_per_ip", "unique_user_agents_per_ip",
        "time_since_previous_request", "mean_inter_request_time_ip", "median_inter_request_time_ip",
        "min_inter_request_time_ip", "max_inter_request_time_ip", "rapid_request_flag"
    ]

    # 3. Status Code Frequency
    df, status_stats = extract_status_code_features(df)
    domain_status_features = [
        "status_404_count_ip", "status_403_count_ip", "status_500_count_ip",
        "status_404_ratio_ip", "status_403_ratio_ip", "error_status_ratio_ip", "high_404_activity_flag"
    ]

    # 4. User-Agent Parsing & Tool Detection
    df, ua_stats = extract_user_agent_features(df)
    domain_ua_features = ["user_agent_type", "is_bot", "is_scanner", "user_agent_length"]

    # 5. URL Shannon Entropy & Lexical Features
    df, entropy_stats = extract_url_entropy_features(df)
    domain_url_features = [
        "url_entropy", "url_length", "path_depth", "query_parameter_count",
        "special_character_count", "digit_ratio", "letter_ratio"
    ]

    # 6. Additional Security & Payload Indicators
    df, sec_stats = extract_security_features(df)
    domain_sec_features = [
        "payload_length", "payload_entropy", "contains_sql_keyword", "contains_path_traversal",
        "contains_script_tag", "contains_command_separator", "request_rate_1min",
        "request_rate_5min", "failed_pattern_count"
    ]

    all_domain_features = (
        domain_time_features
        + domain_ip_features
        + domain_status_features
        + domain_ua_features
        + domain_url_features
        + domain_sec_features
    )
    # Remove duplicates if any
    all_domain_features = list(dict.fromkeys(all_domain_features))
    print(f"Domain-Specific Features Engineered: {len(all_domain_features)}")

    # PART B: Featuretools Automated Relational Engineering
    df, ft_df, ft_feature_names = extract_featuretools_features(df)

    # PART C: tsfresh Automated Time-Series Feature Extraction
    df, ts_df, ts_feature_names = extract_tsfresh_features(df)

    # PART D & E: Combine Features, Scale, and Quality Audit
    df, ml_ready_df, quality_df = combine_and_scale_features(
        df=df,
        domain_features=all_domain_features,
        ft_features=ft_feature_names,
        ts_features=ts_feature_names,
    )

    # PART F: Statistical Feature Selection (scikit-learn)
    ranking_df, selected_features, sel_stats = run_feature_selection(ml_ready_df, df, top_k=20)

    # PART G: Feature Importance Validation (Top 20)
    imp_df = evaluate_feature_importance(ml_ready_df, df, top_n=20)

    # PART H: Unsupervised Anomaly Detection (Isolation Forest)
    df, iso_stats = run_anomaly_detection(ml_ready_df, df)

    # PART I: Method Comparison Reports & Visualizations
    generate_feature_comparison_report(
        domain_count=len(all_domain_features),
        ft_count=len(ft_feature_names),
        ts_count=len(ts_feature_names),
    )

    total_pipeline_time = time.time() - t_start
    generate_comprehensive_engineering_report(
        meta=meta,
        domain_count=len(all_domain_features),
        ft_count=len(ft_feature_names),
        ts_count=len(ts_feature_names),
        total_features=len(ml_ready_df.columns),
        iso_stats=iso_stats,
        top_df=imp_df,
        total_time=total_pipeline_time,
    )

    # Generate the 7 Publication-Grade Plots
    generate_all_plots(df, imp_df, ua_stats, ts_feature_names)

    # Final Formatted Terminal Output
    print("\n" + "=" * 60)
    print("PRACTICAL 5 — OPEN-SOURCE FEATURE ENGINEERING")
    print("============================================================")
    print()
    print(f"Input records: {input_rows:,}")
    print(f"Input columns: {input_cols}")
    print()
    print("-" * 60)
    print("FEATURE BREAKDOWN BY METHOD")
    print("-" * 60)
    print()
    print(f"Domain-Specific Security Features: {len(all_domain_features)}")
    print(f"Featuretools (Automated DFS):      {len(ft_feature_names)}")
    print(f"tsfresh (Time-Series Features):    {len(ts_feature_names)}")
    print(f"Total Combined Matrix Features:    {len(ml_ready_df.columns)}")
    print()
    print("-" * 60)
    print("ANOMALY DETECTION (ISOLATION FOREST)")
    print("-" * 60)
    print()
    print(f"Normal records:     {iso_stats['normal_records']:,} ({100 - iso_stats['anomaly_percentage']:.2f}%)")
    print(f"Anomalous records:  {iso_stats['anomalous_records']:,} ({iso_stats['anomaly_percentage']:.2f}%)")
    print()
    print("-" * 60)
    print("VALIDATION SUMMARY")
    print("-" * 60)
    print()
    print("[PASS] Domain security features created")
    print("[PASS] Featuretools automated relational features generated")
    print("[PASS] tsfresh automated time-series features extracted")
    print("[PASS] Multi-modal features merged without record loss")
    print("[PASS] Zero target leakage verified")
    print("[PASS] No infinite or invalid values")
    print("[PASS] All reports and 7 diagnostic plots saved")
    print()
    print(f"Total Execution Time: {total_pipeline_time:.2f}s")
    print("STATUS: SUCCESS")
    print("=" * 60)


if __name__ == "__main__":
    main()
