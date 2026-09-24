"""anomaly.py
Part G & Part H: Unsupervised Anomaly Detection (Isolation Forest) & Top 20 Feature Importance
Evaluates feature efficacy and flags statistically unusual records without target leakage.
"""

from typing import Tuple, Dict, Any
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from src.config import RANDOM_STATE, FEATURE_IMPORTANCE_CSV


def run_anomaly_detection(
    ml_df: pd.DataFrame, full_df: pd.DataFrame
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Runs unsupervised Isolation Forest anomaly detection.
    
    Produces anomaly_score and anomaly_flag (-1: anomalous, 1: normal).
    Includes separate statistical comparison with ground-truth labels if available.
    """
    print("\n" + "=" * 60)
    print("PART H - UNSUPERVISED ANOMALY DETECTION (ISOLATION FOREST)")
    print("=" * 60)

    n_total = len(ml_df)
    sample_size = min(50000, n_total)
    fit_sample = ml_df.sample(n=sample_size, random_state=RANDOM_STATE)

    print(f"Fitting IsolationForest on representative sample ({sample_size:,} records)...")
    iso = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    iso.fit(fit_sample)

    print(f"Scoring all {n_total:,} records across the full dataset...")
    scores = iso.decision_function(ml_df)
    flags = iso.predict(ml_df)

    full_df["anomaly_score"] = np.round(scores, 4)
    full_df["anomaly_flag"] = flags

    anomalous_count = int((flags == -1).sum())
    normal_count = int((flags == 1).sum())
    anomaly_pct = (anomalous_count / n_total) * 100

    print(f"  -> Normal Records    (flag =  1): {normal_count:,} ({100 - anomaly_pct:.2f}%)")
    print(f"  -> Anomalous Records (flag = -1): {anomalous_count:,} ({anomaly_pct:.2f}%)")

    # Post-hoc comparison with Practical 4 labels if available
    overlap_info = ""
    if "label" in full_df.columns:
        attack_mask = full_df["label"] != "benign"
        total_attacks = int(attack_mask.sum())
        attacks_flagged_anomalous = int(((full_df["anomaly_flag"] == -1) & attack_mask).sum())
        det_rate = (attacks_flagged_anomalous / total_attacks * 100) if total_attacks > 0 else 0.0
        overlap_info = f"Attacks flagged anomalous: {attacks_flagged_anomalous:,}/{total_attacks:,} ({det_rate:.2f}%)"
        print(f"  -> Validation Check: {overlap_info}")

    stats = {
        "model": "Isolation Forest",
        "normal_records": normal_count,
        "anomalous_records": anomalous_count,
        "anomaly_percentage": anomaly_pct,
        "overlap_info": overlap_info,
        "mean_score": float(np.mean(scores)),
        "min_score": float(np.min(scores)),
        "max_score": float(np.max(scores)),
    }

    return full_df, stats


def evaluate_feature_importance(
    ml_df: pd.DataFrame, full_df: pd.DataFrame, top_n: int = 20
) -> pd.DataFrame:
    """Computes Top 20 feature importances using RandomForestClassifier for validation.
    
    Excludes label and label_reason from candidate features.
    """
    print("\n" + "=" * 60)
    print("PART G - FEATURE IMPORTANCE VALIDATION (TOP 20)")
    print("=" * 60)

    if "label" not in full_df.columns:
        print("Practical 4 labels not present. Using Isolation Forest anomaly flags as target.")
        y = (full_df["anomaly_flag"] == -1).astype(int)
    else:
        y = (full_df["label"] != "benign").astype(int)

    # Balanced representative sample for training
    sample_size = min(50000, len(ml_df))
    if y.nunique() > 1:
        sample_indices = full_df.groupby(y, group_keys=False).apply(
            lambda x: x.sample(min(len(x), sample_size // 2), random_state=RANDOM_STATE)
        ).index
    else:
        sample_indices = full_df.sample(sample_size, random_state=RANDOM_STATE).index

    X_train = ml_df.loc[sample_indices]
    y_train = y.loc[sample_indices]

    rf = RandomForestClassifier(
        n_estimators=50,
        max_depth=12,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)

    importances = rf.feature_importances_
    features = list(X_train.columns)

    imp_df = pd.DataFrame({
        "feature": features,
        "importance": importances,
    }).sort_values(by="importance", ascending=False).reset_index(drop=True)

    imp_df["rank"] = imp_df.index + 1
    top_20 = imp_df.head(top_n)

    print(f"Top {top_n} Engineered Features by Discriminative Importance:")
    for _, row in top_20.iterrows():
        print(f"  {int(row['rank']):>2}. {row['feature']:<35} : {row['importance']:.4f}")

    imp_df.to_csv(FEATURE_IMPORTANCE_CSV, index=False)
    print(f"\nSaved Top 20 feature importance rankings to: {FEATURE_IMPORTANCE_CSV.name}")

    return imp_df
