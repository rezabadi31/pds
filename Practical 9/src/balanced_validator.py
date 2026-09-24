"""balanced_validator.py
Part 13: Optional Balanced-Data Validation Experiment
Compares models trained on Practical 5 imbalanced split vs Practical 6 balanced training data,
strictly evaluated on the untouched test dataset.
"""

from typing import Dict, Any, Optional
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

from src.config import (
    P6_BALANCED_TRAIN_CSV,
    P6_TEST_CSV,
    BALANCED_EXPERIMENT_CSV,
    RANDOM_STATE,
    LR_MAX_ITER,
    RF_N_ESTIMATORS,
    RF_N_JOBS,
)


def run_balanced_validation(
    main_comparison_df: pd.DataFrame,
) -> Optional[pd.DataFrame]:
    """Runs Experiment B: trains on Practical 6 balanced training data, evaluates on

    Practical 6 untouched test dataset, and saves comparison with Experiment A.
    """
    print("\n" + "=" * 60)
    print("PART 13 — BALANCED-DATA VALIDATION EXPERIMENT")
    print("=" * 60)

    if not P6_BALANCED_TRAIN_CSV.exists() or not P6_TEST_CSV.exists():
        print(f"[INFO] Practical 6 balanced dataset not found at {P6_BALANCED_TRAIN_CSV}.")
        print("Skipping balanced-data validation experiment.")
        return None

    print(f"Loading balanced training dataset from:\n  -> {P6_BALANCED_TRAIN_CSV}")
    print(f"Loading untouched test dataset from:\n  -> {P6_TEST_CSV}")

    df_train = pd.read_csv(P6_BALANCED_TRAIN_CSV)
    df_test = pd.read_csv(P6_TEST_CSV)

    target_col = "label"
    if target_col not in df_train.columns or target_col not in df_test.columns:
        print("[WARN] Target column 'label' missing in Practical 6 datasets. Skipping.")
        return None

    # Common numeric feature alignment
    excluded = [
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
    ]

    features = [
        c
        for c in df_test.columns
        if c in df_train.columns
        and c not in excluded
        and np.issubdtype(df_test[c].dtype, np.number)
    ]

    print(f"Aligned {len(features)} common numeric features across datasets.")

    X_train = df_train[features].copy().replace([np.inf, -np.inf], np.nan)
    X_train = X_train.fillna(X_train.median())
    y_train = df_train[target_col].copy()

    X_test = df_test[features].copy().replace([np.inf, -np.inf], np.nan)
    X_test = X_test.fillna(X_train.median())  # Impute test with train medians
    y_test = df_test[target_col].copy()

    print(f"Training on: {X_train.shape[0]:,} balanced records (6 balanced classes)")
    print(f"Evaluating on: {X_test.shape[0]:,} untouched real-world test records")

    # 1. Logistic Regression on Balanced Data
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    lr_bal = LogisticRegression(max_iter=LR_MAX_ITER, random_state=RANDOM_STATE)
    lr_bal.fit(X_train_scaled, y_train)
    y_pred_lr = lr_bal.predict(X_test_scaled)

    acc_lr = accuracy_score(y_test, y_pred_lr)
    p_macro_lr, r_macro_lr, f1_macro_lr, _ = precision_recall_fscore_support(
        y_test, y_pred_lr, average="macro", zero_division=0
    )

    # 2. Random Forest on Balanced Data
    rf_bal = RandomForestClassifier(
        n_estimators=RF_N_ESTIMATORS,
        random_state=RANDOM_STATE,
        n_jobs=RF_N_JOBS,
    )
    rf_bal.fit(X_train, y_train)
    y_pred_rf = rf_bal.predict(X_test)

    acc_rf = accuracy_score(y_test, y_pred_rf)
    p_macro_rf, r_macro_rf, f1_macro_rf, _ = precision_recall_fscore_support(
        y_test, y_pred_rf, average="macro", zero_division=0
    )

    # Compile Comparison Table
    records = []
    # Experiment A records from main comparison
    for _, row in main_comparison_df.iterrows():
        records.append({
            "Experiment": "Experiment A (Practical 5 Natural Split)",
            "Model": row["Model"],
            "Accuracy": row["Accuracy"],
            "Macro Precision": row["Macro Precision"],
            "Macro Recall": row["Macro Recall"],
            "Macro F1": row["Macro F1"],
            "Weighted F1": row["Weighted F1"],
        })

    # Experiment B records
    records.append({
        "Experiment": "Experiment B (Practical 6 Balanced Train + Untouched Test)",
        "Model": "Logistic Regression",
        "Accuracy": acc_lr,
        "Macro Precision": float(p_macro_lr),
        "Macro Recall": float(r_macro_lr),
        "Macro F1": float(f1_macro_lr),
        "Weighted F1": float(
            precision_recall_fscore_support(y_test, y_pred_lr, average="weighted", zero_division=0)[2]
        ),
    })
    records.append({
        "Experiment": "Experiment B (Practical 6 Balanced Train + Untouched Test)",
        "Model": "Random Forest",
        "Accuracy": acc_rf,
        "Macro Precision": float(p_macro_rf),
        "Macro Recall": float(r_macro_rf),
        "Macro F1": float(f1_macro_rf),
        "Weighted F1": float(
            precision_recall_fscore_support(y_test, y_pred_rf, average="weighted", zero_division=0)[2]
        ),
    })

    comp_exp_df = pd.DataFrame(records)
    comp_exp_df.to_csv(BALANCED_EXPERIMENT_CSV, index=False)
    print(f"Saved balanced validation experiment comparison to:\n  -> {BALANCED_EXPERIMENT_CSV}")
    print("\nExperiment B Results (Evaluated strictly on untouched test data):")
    print(f"  - Logistic Regression: Accuracy={acc_lr:.4f}, Macro F1={f1_macro_lr:.4f}")
    print(f"  - Random Forest:       Accuracy={acc_rf:.4f}, Macro F1={f1_macro_rf:.4f}")

    return comp_exp_df
