"""ip_analyzer.py
Part 2: Group by IP Attack Frequency Analysis
Part 3: Attack Type by IP Reshaping (Crosstab Matrix)

Analytical Rule: An IP with a high attack rate or high attack count is
NOT automatically declared malicious (contextual analysis required).
"""

from typing import Tuple, Dict, Any, Optional
import pandas as pd
from pathlib import Path
from src.config import (
    IP_ATTACK_FREQ_CSV,
    TOP_ATTACK_IPS_CSV,
    IP_ATTACK_TYPE_MATRIX_CSV,
    IP_ATTACK_TYPE_PCT_CSV,
)


def analyze_ip_attack_frequency(
    df: pd.DataFrame,
    export_path: Path = IP_ATTACK_FREQ_CSV,
    top_export_path: Path = TOP_ATTACK_IPS_CSV,
    top_n: int = 20,
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Calculates client-IP level traffic, attack rates, and entity diversities."""
    print("\n" + "=" * 60)
    print("PART 2 — GROUP BY IP: ATTACK FREQUENCY ANALYSIS")
    print("=" * 60)

    if "client_ip" not in df.columns:
        print("[client_ip] unavailable — corresponding analysis skipped.")
        return pd.DataFrame(), pd.DataFrame()

    resource_col = "normalized_resource" if "normalized_resource" in df.columns else (
        "resource_requested" if "resource_requested" in df.columns else None
    )

    # Prepare vector masks
    is_attack = (df["label"] != "benign").astype(int)
    is_benign = (df["label"] == "benign").astype(int)

    # Temporary dataframe for efficient aggregation
    agg_df = pd.DataFrame({
        "client_ip": df["client_ip"],
        "is_attack": is_attack,
        "is_benign": is_benign,
    })

    if "request_type" in df.columns:
        agg_df["request_type"] = df["request_type"]
    if "user_agent" in df.columns:
        agg_df["user_agent"] = df["user_agent"]
    if resource_col:
        agg_df["resource"] = df[resource_col]
    if "label" in df.columns:
        agg_df["label"] = df["label"]

    # IP Level aggregations
    grouped = agg_df.groupby("client_ip")

    total_requests = grouped.size().rename("total_requests")
    attack_requests = grouped["is_attack"].sum().rename("attack_requests")
    benign_requests = grouped["is_benign"].sum().rename("benign_requests")

    ip_summary = pd.concat([total_requests, attack_requests, benign_requests], axis=1)
    ip_summary["attack_rate"] = (ip_summary["attack_requests"] / ip_summary["total_requests"]).round(4)

    # Unique attack types count (distinct attack labels excluding benign)
    if "label" in df.columns:
        attack_only = agg_df[agg_df["is_attack"] == 1]
        if not attack_only.empty:
            unique_attacks = attack_only.groupby("client_ip")["label"].nunique().rename("unique_attack_types")
            ip_summary = ip_summary.join(unique_attacks).fillna({"unique_attack_types": 0})
        else:
            ip_summary["unique_attack_types"] = 0
    else:
        ip_summary["unique_attack_types"] = 0
    ip_summary["unique_attack_types"] = ip_summary["unique_attack_types"].astype(int)

    # Unique request types
    if "request_type" in df.columns:
        ip_summary["unique_request_types"] = grouped["request_type"].nunique().astype(int)
    else:
        ip_summary["unique_request_types"] = 0

    # Unique resources
    if resource_col:
        ip_summary["unique_resources"] = grouped["resource"].nunique().astype(int)
    else:
        ip_summary["unique_resources"] = 0

    # Unique user agents
    if "user_agent" in df.columns:
        ip_summary["unique_user_agents"] = grouped["user_agent"].nunique().astype(int)
    else:
        ip_summary["unique_user_agents"] = 0

    ip_summary = ip_summary.reset_index()

    # Reorder columns explicitly
    cols = [
        "client_ip",
        "total_requests",
        "attack_requests",
        "benign_requests",
        "attack_rate",
        "unique_attack_types",
        "unique_request_types",
        "unique_resources",
        "unique_user_agents",
    ]
    ip_summary = ip_summary[cols].sort_values(by=["attack_requests", "total_requests"], ascending=[False, False])

    # Export full IP attack frequency
    export_path.parent.mkdir(parents=True, exist_ok=True)
    ip_summary.to_csv(export_path, index=False)
    print(f"Exported IP attack frequency ({len(ip_summary):,} unique IPs) to: {export_path.name}")

    # Top attack IPs
    top_ips = ip_summary.head(top_n).copy()
    top_export_path.parent.mkdir(parents=True, exist_ok=True)
    top_ips.to_csv(top_export_path, index=False)
    print(f"Exported Top {top_n} Attack IPs to: {top_export_path.name}")

    print("\nTop 5 Attack IPs Preview:")
    print(top_ips[["client_ip", "total_requests", "attack_requests", "attack_rate", "unique_attack_types"]].head())

    return ip_summary, top_ips


def create_ip_attack_type_matrix(
    df: pd.DataFrame,
    export_matrix_path: Path = IP_ATTACK_TYPE_MATRIX_CSV,
    export_pct_path: Path = IP_ATTACK_TYPE_PCT_CSV,
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Creates IP × attack-label crosstab matrix and percentage distributions."""
    print("\n" + "=" * 60)
    print("PART 3 — ATTACK TYPE BY IP (CROSSTAB MATRIX)")
    print("=" * 60)

    if "client_ip" not in df.columns or "label" not in df.columns:
        print("[client_ip] or [label] unavailable — matrix analysis skipped.")
        return pd.DataFrame(), pd.DataFrame()

    # Dynamic crosstab of client_ip by label (using actual labels present)
    matrix = pd.crosstab(df["client_ip"], df["label"])
    matrix = matrix.reset_index()

    # Export matrix
    export_matrix_path.parent.mkdir(parents=True, exist_ok=True)
    matrix.to_csv(export_matrix_path, index=False)
    print(f"Exported IP Attack Type Matrix ({matrix.shape[0]:,} IPs × {matrix.shape[1]-1} labels) to: {export_matrix_path.name}")

    # Percentage matrix (row-wise percentages)
    pct_matrix = matrix.copy()
    label_cols = [c for c in matrix.columns if c != "client_ip"]
    row_sums = pct_matrix[label_cols].sum(axis=1)
    for col in label_cols:
        pct_matrix[col] = (pct_matrix[col] / row_sums * 100).round(2)

    export_pct_path.parent.mkdir(parents=True, exist_ok=True)
    pct_matrix.to_csv(export_pct_path, index=False)
    print(f"Exported IP Attack Type Percentage Matrix to: {export_pct_path.name}")

    print("\nSample IP Attack Type Matrix:")
    print(matrix.head(3))

    return matrix, pct_matrix
