"""feature_selection.py
Part F: Statistical Feature Selection using scikit-learn
Evaluates feature variance (unsupervised) and SelectKBest / Mutual Information (validation).
"""

from typing import Tuple, List, Dict, Any
import time
import numpy as np
import pandas as pd
from sklearn.feature_selection import VarianceThreshold, SelectKBest, f_classif
from src.config import SELECTED_FEATURES_CSV, FEATURE_SELECTION_REPORT_TXT, RANDOM_STATE


def run_feature_selection(
    ml_df: pd.DataFrame, full_df: pd.DataFrame, top_k: int = 25
) -> Tuple[pd.DataFrame, List[str], Dict[str, Any]]:
    """Performs target-independent feature filtering and supervised validation ranking.
    
    Excludes label and label_reason from candidate feature inputs.
    Uses VarianceThreshold to remove near-constant columns, followed by SelectKBest (ANOVA F-value)
    strictly for validation ranking.
    """
    print("\n" + "=" * 60)
    print("PART F - STATISTICAL FEATURE SELECTION (SCIKIT-LEARN)")
    print("=" * 60)
    t0 = time.time()

    candidate_cols = list(ml_df.columns)
    print(f"Initial candidate features: {len(candidate_cols)}")

    # 1. Unsupervised Filter: VarianceThreshold
    # Eliminates zero or near-zero variance features
    selector_var = VarianceThreshold(threshold=0.001)
    selector_var.fit(ml_df)
    var_mask = selector_var.get_support()
    passed_var_cols = [c for c, m in zip(candidate_cols, var_mask) if m]
    print(f"Features passing VarianceThreshold (>0.001): {len(passed_var_cols)} / {len(candidate_cols)}")

    # 2. Validation Ranking: SelectKBest (f_classif / mutual information)
    # Uses sample to ensure fast, reproducible execution
    sample_n = min(50000, len(ml_df))
    if "label" in full_df.columns:
        y_val = (full_df["label"] != "benign").astype(int)
        target_name = "Practical 4 Attack vs Benign (Supervised Validation Only)"
    else:
        y_val = (full_df["anomaly_flag"] == -1).astype(int)
        target_name = "Isolation Forest Anomaly Flag (Unsupervised Objective)"

    sample_idx = ml_df.sample(n=sample_n, random_state=RANDOM_STATE).index
    X_sample = ml_df.loc[sample_idx, passed_var_cols]
    y_sample = y_val.loc[sample_idx]

    # Handle NaNs or Infs if any
    X_sample = X_sample.fillna(0.0)

    # Compute F-score and p-values
    k_actual = min(top_k, len(passed_var_cols))
    selector_kbest = SelectKBest(score_func=f_classif, k=k_actual)
    selector_kbest.fit(X_sample, y_sample)

    scores = selector_kbest.scores_
    p_values = selector_kbest.pvalues_

    ranking_df = pd.DataFrame({
        "feature": passed_var_cols,
        "f_score": np.nan_to_num(scores, nan=0.0),
        "p_value": np.nan_to_num(p_values, nan=1.0),
    }).sort_values(by="f_score", ascending=False).reset_index(drop=True)

    ranking_df["rank"] = ranking_df.index + 1
    selected_k_features = ranking_df.head(k_actual)["feature"].tolist()

    # Save outputs/features/selected_features.csv
    ranking_df.to_csv(SELECTED_FEATURES_CSV, index=False)
    print(f"Saved ranked and selected feature table to: {SELECTED_FEATURES_CSV.name}")

    print(f"\nTop {k_actual} Selected Features by Statistical Discriminability:")
    for _, row in ranking_df.head(k_actual).iterrows():
        print(f"  {int(row['rank']):>2}. {row['feature']:<35} (F-score: {row['f_score']:>10.2f}, p-val: {row['p_value']:.2e})")

    # Generate Report
    duration = time.time() - t0
    with open(FEATURE_SELECTION_REPORT_TXT, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("PRACTICAL 5: FEATURE SELECTION & RANKING REPORT\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Candidate Features Evaluated:  {len(candidate_cols)}\n")
        f.write(f"Passed VarianceThreshold:     {len(passed_var_cols)}\n")
        f.write(f"Top Features Selected (K):     {k_actual}\n")
        f.write(f"Validation Objective:          {target_name}\n")
        f.write(f"Execution Duration:            {duration:.2f} seconds\n")
        f.write("Integrity Note:                Feature selection was performed strictly for\n")
        f.write("                               ranking and post-hoc validation; labels were NEVER\n")
        f.write("                               used during feature creation.\n\n")
        f.write(f"{'Rank':<5} | {'Feature Name':<35} | {'F-Score':<14} | {'p-value':<12}\n")
        f.write("-" * 75 + "\n")
        for _, row in ranking_df.head(k_actual).iterrows():
            f.write(f"{int(row['rank']):<5} | {row['feature']:<35} | {row['f_score']:<14.4f} | {row['p_value']:<12.2e}\n")
        f.write("=" * 80 + "\n")

    print(f"Saved feature selection report to: {FEATURE_SELECTION_REPORT_TXT.name}")

    stats = {
        "candidate_count": len(candidate_cols),
        "passed_variance": len(passed_var_cols),
        "selected_k": k_actual,
        "top_feature": ranking_df.iloc[0]["feature"],
    }

    return ranking_df, selected_k_features, stats
