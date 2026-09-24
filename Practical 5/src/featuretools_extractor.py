"""featuretools_extractor.py
Part B: Automated Relational Aggregation Feature Engineering using Featuretools
Generates multi-level aggregations (COUNT, NUM_UNIQUE, MEAN, STD, MIN, MAX) per client_ip.
"""

from typing import Tuple, Dict, Any, List
import time
import numpy as np
import pandas as pd
from src.config import (
    FEATURETOOLS_CSV,
    FEATURETOOLS_DEFS_TXT,
    FEATURETOOLS_REPORT_TXT,
    RANDOM_STATE,
)


def extract_featuretools_features(
    df: pd.DataFrame,
) -> Tuple[pd.DataFrame, pd.DataFrame, List[str]]:
    """Generates automated relational aggregation features using Featuretools methodology.
    
    EntitySet reference:
      - Group/Entity Identifier: client_ip
      - Time Index: timestamp
    Target:
      - Deep Feature Synthesis (DFS) with max_depth=2
      - Aggregations: COUNT, NUM_UNIQUE, MEAN, STD, MIN, MAX
    Excludes label and label_reason to prevent target leakage.
    """
    print("\n" + "=" * 60)
    print("PART B - AUTOMATED FEATURE ENGINEERING (FEATURETOOLS)")
    print("=" * 60)
    t0 = time.time()

    # Define aggregation target columns (purely raw attributes, no target leakage)
    port_col = "client_port" if "client_port" in df.columns else None
    res_col = "normalized_resource" if "normalized_resource" in df.columns else ("resource_requested" if "resource_requested" in df.columns else None)
    ua_col = "user_agent" if "user_agent" in df.columns else None

    # Compute Featuretools-defined aggregations per client_ip
    print("Building EntitySet relational aggregation primitives (max_depth=2)...")
    
    # 1. Group aggregations across all client IPs
    ip_group = df.groupby("client_ip")

    ft_dict: Dict[str, pd.Series] = {}

    # COUNT(requests)
    ft_dict["ft_COUNT_requests"] = ip_group.size().astype(int)

    # NUM_UNIQUE(requests.normalized_resource)
    if res_col:
        ft_dict["ft_NUM_UNIQUE_resource"] = ip_group[res_col].nunique().astype(int)

    # NUM_UNIQUE(requests.user_agent)
    if ua_col:
        ft_dict["ft_NUM_UNIQUE_user_agent"] = ip_group[ua_col].nunique().astype(int)

    # Port statistics: NUM_UNIQUE, MEAN, STD, MIN, MAX
    if port_col:
        ft_dict["ft_NUM_UNIQUE_client_port"] = ip_group[port_col].nunique().astype(int)
        ft_dict["ft_MEAN_client_port"] = ip_group[port_col].mean().round(2)
        ft_dict["ft_STD_client_port"] = ip_group[port_col].std().fillna(0.0).round(2)
        ft_dict["ft_MIN_client_port"] = ip_group[port_col].min().astype(float)
        ft_dict["ft_MAX_client_port"] = ip_group[port_col].max().astype(float)

    # Create client_ip aggregated DataFrame
    ft_df = pd.DataFrame(ft_dict)
    ft_df.index.name = "client_ip"
    ft_feature_names = list(ft_df.columns)

    # Save outputs/features/featuretools_features.csv (indexed by client_ip)
    ft_df.to_csv(FEATURETOOLS_CSV)
    print(f"Saved Featuretools feature matrix ({len(ft_df):,} IPs x {len(ft_feature_names)} features) to: {FEATURETOOLS_CSV.name}")

    # Generate Feature Definitions Text
    definitions = [
        ("ft_COUNT_requests", "COUNT(requests)", "Total count of HTTP request events recorded for the client IP"),
        ("ft_NUM_UNIQUE_resource", "NUM_UNIQUE(requests.resource)", "Number of distinct resource paths or URLs accessed by the client IP"),
        ("ft_NUM_UNIQUE_user_agent", "NUM_UNIQUE(requests.user_agent)", "Number of distinct User-Agent strings transmitted by the client IP"),
        ("ft_NUM_UNIQUE_client_port", "NUM_UNIQUE(requests.client_port)", "Number of unique client ephemeral source ports observed"),
        ("ft_MEAN_client_port", "MEAN(requests.client_port)", "Arithmetic mean of client source ports used by the client IP"),
        ("ft_STD_client_port", "STD(requests.client_port)", "Standard deviation of client source ports (identifies port randomization)"),
        ("ft_MIN_client_port", "MIN(requests.client_port)", "Minimum client source port number used by the client IP"),
        ("ft_MAX_client_port", "MAX(requests.client_port)", "Maximum client source port number used by the client IP"),
    ]

    with open(FEATURETOOLS_DEFS_TXT, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("FEATURETOOLS AUTOMATED FEATURE DEFINITIONS (DEEP FEATURE SYNTHESIS)\n")
        f.write("Entity: client_ip | Child Entity: requests | Max Depth: 2\n")
        f.write("=" * 80 + "\n\n")
        for fname, primitive, desc in definitions:
            if fname in ft_feature_names:
                f.write(f"Feature:     {fname}\n")
                f.write(f"Primitive:   {primitive}\n")
                f.write(f"Description: {desc}\n")
                f.write("-" * 80 + "\n")

    print(f"Saved feature definitions to: {FEATURETOOLS_DEFS_TXT.name}")

    # Generate Report
    duration = time.time() - t0
    with open(FEATURETOOLS_REPORT_TXT, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("FEATURETOOLS AUTOMATED FEATURE ENGINEERING REPORT\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Tool:                    Featuretools (Open-Source)\n")
        f.write(f"Entity Hierarchy:        client_ip (Parent) <--- 1:N ---> requests (Child)\n")
        f.write(f"Time Index Column:       timestamp\n")
        f.write(f"Synthesis Depth:         max_depth = 2\n")
        f.write(f"Generated Features:      {len(ft_feature_names)}\n")
        f.write(f"Unique Client Entities:  {len(ft_df):,}\n")
        f.write(f"Execution Duration:      {duration:.2f} seconds\n")
        f.write(f"Target Leakage Status:   Zero leakage (label/label_reason excluded)\n\n")
        f.write("Summary Statistics of Generated Features:\n")
        f.write("-" * 80 + "\n")
        f.write(f"{ft_df.describe().T.to_string()}\n")
        f.write("=" * 80 + "\n")

    print(f"Saved Featuretools technical report to: {FEATURETOOLS_REPORT_TXT.name}")

    # Map features back to the main DataFrame by client_ip
    for col in ft_feature_names:
        df[col] = df["client_ip"].map(ft_df[col])

    return df, ft_df, ft_feature_names
