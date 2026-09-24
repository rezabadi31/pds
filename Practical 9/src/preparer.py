"""preparer.py
Part 2 & Part 3: Feature Preparation, Leakage Elimination, and Data Cleaning
"""

from typing import Tuple, List, Dict, Any
import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer


def prepare_and_clean_features(
    df: pd.DataFrame,
) -> Tuple[pd.DataFrame, pd.Series, List[str], Dict[str, Any]]:
    """Isolates target y, eliminates target leakage, selects valid numeric features,

    cleans infinite and missing values using SimpleImputer.
    """
    print("\n" + "=" * 60)
    print("PART 2 — PREPARE FEATURES")
    print("=" * 60)

    target_col = "label"
    if target_col not in df.columns:
        raise ValueError(f"Target column '{target_col}' not found in dataframe!")

    y = df[target_col].copy()

    # Columns explicitly excluded to eliminate target leakage and raw unencoded identifiers
    excluded_cols = [
        "label",
        "label_reason",
        "category_type",
        "payload",
        "timestamp",
        "client_ip",
        "user_agent",
        "accept_language",
        "proxy_ip",
        "request_type",
        "resource_requested",
        "normalized_resource",
        "referrer",
        "user_agent_type",
        "target",
        "anomaly_flag",
        "anomaly_score",
    ]

    # Automatically identify all candidate columns not in excluded list
    candidate_cols = [col for col in df.columns if col not in excluded_cols]

    # Check for target leakage
    has_leakage = any(c.lower() in ["label", "label_reason", "target"] for c in candidate_cols)
    if has_leakage:
        raise ValueError("CRITICAL: Target leakage detected in candidate feature set!")

    # Filter to strictly numeric columns
    numeric_candidates = [
        col for col in candidate_cols if np.issubdtype(df[col].dtype, np.number)
    ]

    print(f"Candidate numeric features: {len(numeric_candidates)}")
    print(f"Final ML features: {len(numeric_candidates)}")
    print("No target leakage verified: PASS")

    X = df[numeric_candidates].copy()

    print("\n" + "=" * 60)
    print("PART 3 — DATA CLEANING")
    print("=" * 60)

    # Count before cleaning
    inf_before = int(np.isinf(X.to_numpy()).sum())
    missing_before = int(X.isna().sum().sum())

    # Step 1: Replace +inf and -inf with NaN
    X.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Step 2: Documented imputation strategy using SimpleImputer (median)
    # Median is robust to extreme outliers in cybersecurity telemetry
    imputer = SimpleImputer(strategy="median")
    X_imputed = pd.DataFrame(
        imputer.fit_transform(X),
        columns=numeric_candidates,
        index=X.index,
    )

    # Step 3: Count after cleaning
    inf_after = int(np.isinf(X_imputed.to_numpy()).sum())
    missing_after = int(X_imputed.isna().sum().sum())

    # Step 4: Verify all features numeric and no NaNs remain
    assert X_imputed.shape[1] == len(numeric_candidates), "Feature count mismatch!"
    assert missing_after == 0, "Residual NaN values detected after imputation!"
    assert inf_after == 0, "Residual infinite values detected!"

    print(f"Missing values before: {missing_before:,}")
    print(f"Missing values after:  {missing_after:,}")
    print(f"Infinite values before: {inf_before:,}")
    print(f"Infinite values after:  {inf_after:,}")
    print(f"Cleaned feature matrix: {X_imputed.shape[0]:,} rows x {X_imputed.shape[1]} numeric features.")

    cleaning_meta = {
        "candidate_numeric_features": len(numeric_candidates),
        "final_ml_features": len(numeric_candidates),
        "feature_names": numeric_candidates,
        "missing_before": missing_before,
        "missing_after": missing_after,
        "inf_before": inf_before,
        "inf_after": inf_after,
    }

    return X_imputed, y, numeric_candidates, cleaning_meta
