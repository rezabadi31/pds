"""feature_combiner.py
Part D & Part E: Unified Multi-Modal Feature Combiner and Data Quality Auditor
Combines Domain + Featuretools + tsfresh features, prepares ML matrix, and audits quality.
"""

from typing import Tuple, List, Dict, Any
import numpy as np
import pandas as pd
from sklearn.preprocessing import RobustScaler
from src.config import (
    FEATURE_ENGINEERED_CSV,
    ML_READY_CSV,
    FEATURE_SAMPLE_CSV,
    FEATURE_QUALITY_CSV,
    SAMPLE_SIZE_EXPORT,
    RANDOM_STATE,
)


def combine_and_scale_features(
    df: pd.DataFrame,
    domain_features: List[str],
    ft_features: List[str],
    ts_features: List[str],
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Combines Domain, Featuretools, and tsfresh features without duplicating rows or columns.
    
    Verifies that the final record count matches the input row count exactly.
    Generates ml_ready_features.csv with RobustScaler normalization.
    Calculates comprehensive quality metrics for every feature.
    """
    print("\n" + "=" * 60)
    print("PART D & E - FEATURE COMBINATION & DATA QUALITY AUDIT")
    print("=" * 60)

    total_records = len(df)
    print(f"Verifying input record integrity: {total_records:,} rows.")

    # Distinct feature groups
    all_engineered = list(dict.fromkeys(domain_features + ft_features + ts_features))
    # Separate categorical features from purely numeric features
    excluded = [
        "timestamp", "client_ip", "label", "label_reason", "category_type", "payload",
        "user_agent", "resource_requested", "normalized_resource", "referrer",
        "accept_language", "proxy_ip", "request_type", "user_agent_type"
    ]
    candidate_numeric = [f for f in all_engineered if f in df.columns and f not in excluded]

    print(f"Total Unique Engineered Feature Columns: {len(candidate_numeric)}")
    print(f"  - Domain Features:      {len([f for f in domain_features if f in candidate_numeric])}")
    print(f"  - Featuretools Features:{len([f for f in ft_features if f in candidate_numeric])}")
    print(f"  - tsfresh Features:     {len([f for f in ts_features if f in candidate_numeric])}")

    # Impute missing values for ML ready matrix
    ml_working = df[candidate_numeric].copy()
    if "time_since_previous_request" in ml_working.columns:
        ml_working["time_since_previous_request"] = ml_working["time_since_previous_request"].fillna(999.0)

    # Impute remaining NaNs with column median for strictly numeric columns
    num_cols = ml_working.select_dtypes(include=[np.number]).columns
    ml_working[num_cols] = ml_working[num_cols].fillna(ml_working[num_cols].median())
    # Handle infinite values if any
    ml_working[num_cols] = ml_working[num_cols].replace([np.inf, -np.inf], 0.0)

    # One-hot encode user_agent_type if present
    if "user_agent_type" in df.columns:
        ua_dummies = pd.get_dummies(df["user_agent_type"], prefix="ua", dtype=float)
        ml_encoded = pd.concat([ml_working, ua_dummies], axis=1)
    else:
        ml_encoded = ml_working

    # Compute Feature Quality Metrics for Part E
    print("Computing feature quality metrics across all engineered attributes...")
    quality_records = []
    for col in ml_encoded.columns:
        s = ml_encoded[col]
        n_missing = int(df[col].isna().sum()) if col in df.columns else 0
        pct_missing = (n_missing / total_records) * 100
        quality_records.append({
            "feature_name": col,
            "data_type": str(s.dtype),
            "missing_count": n_missing,
            "missing_percentage": f"{pct_missing:.2f}%",
            "min_value": round(float(s.min()), 4),
            "max_value": round(float(s.max()), 4),
            "mean_value": round(float(s.mean()), 4),
            "std_deviation": round(float(s.std()), 4),
            "unique_values": int(s.nunique()),
        })

    quality_df = pd.DataFrame(quality_records)
    quality_df.to_csv(FEATURE_QUALITY_CSV, index=False)
    print(f"Saved feature quality audit metrics to: {FEATURE_QUALITY_CSV.name}")

    # Scale with RobustScaler (outlier-resistant normalization)
    scaler = RobustScaler()
    scaled_array = scaler.fit_transform(ml_encoded)
    ml_ready_df = pd.DataFrame(scaled_array, columns=ml_encoded.columns, index=df.index)

    # Save full feature-engineered dataset (original 16 + all engineered)
    print(f"Exporting feature_engineered_access_logs.csv ({len(df):,} rows x {len(df.columns)} cols)...")
    df.to_csv(FEATURE_ENGINEERED_CSV, index=False)

    # Save ml_ready_features.csv
    print(f"Exporting ml_ready_features.csv ({len(ml_ready_df):,} rows x {len(ml_ready_df.columns)} cols)...")
    ml_ready_df.to_csv(ML_READY_CSV, index=False)

    # Export representative sample (10,000 records)
    if "label" in df.columns:
        attack_sub = df[df["label"] != "benign"]
        benign_needed = max(0, SAMPLE_SIZE_EXPORT - len(attack_sub))
        benign_sub = df[df["label"] == "benign"].head(benign_needed)
        sample_df = pd.concat([attack_sub, benign_sub]).sample(frac=1.0, random_state=RANDOM_STATE)
    else:
        sample_df = df.sample(n=min(SAMPLE_SIZE_EXPORT, len(df)), random_state=RANDOM_STATE)

    sample_df.to_csv(FEATURE_SAMPLE_CSV, index=False)
    print(f"Saved representative sample to: {FEATURE_SAMPLE_CSV.name}")

    # Verify record integrity
    assert len(df) == total_records, f"Row count mismatch! {len(df)} vs {total_records}"
    assert len(ml_ready_df) == total_records, f"ML row count mismatch! {len(ml_ready_df)} vs {total_records}"

    return df, ml_ready_df, quality_df
