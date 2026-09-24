"""splitter.py
Part 3 & Part 4: Target Leakage Elimination and Stratified Train/Test Partitioning
Guarantees strict train/test isolation BEFORE any balancing method is executed.
"""

from typing import Tuple, Dict, Any, List
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from src.config import TEST_DATASET_CSV, TEST_SIZE, RANDOM_STATE, PLOTS_DIR


def prepare_and_split_data(
    df: pd.DataFrame,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, List[str], Dict[str, Any]]:
    """Separates feature matrix X and target y, eliminates target leakage, and splits 80/20.
    
    Immediately exports untouched test dataset to test_dataset.csv.
    """
    print("\n" + "=" * 60)
    print("PART 3 — REMOVE TARGET LEAKAGE & ISOLATE FEATURES")
    print("=" * 60)

    target_col = "label"
    y = df[target_col].copy()

    # Columns strictly excluded to prevent target leakage and non-numeric issues
    leakage_and_metadata_cols = [
        "label",
        "label_reason",
        "anomaly_flag",
        "anomaly_score",
        # Raw non-numeric strings
        "timestamp",
        "client_ip",
        "category_type",
        "payload",
        "user_agent",
        "accept_language",
        "proxy_ip",
        "request_type",
        "resource_requested",
        "normalized_resource",
        "referrer",
    ]

    candidate_feature_cols = [c for c in df.columns if c not in leakage_and_metadata_cols]

    # Verify no target leakage in candidate feature set
    has_leakage = any(c in candidate_feature_cols for c in ["label", "label_reason", "target"])
    if has_leakage:
        raise ValueError("CRITICAL: Target leakage detected in candidate feature set!")

    print("Target leakage check: PASS")
    print(f"Features isolated for ML matrix: {len(candidate_feature_cols)} candidate attributes.")

    # Prepare strictly numeric feature matrix
    X_raw = df[candidate_feature_cols].copy()

    # One-hot encode user_agent_type if present
    if "user_agent_type" in X_raw.columns:
        ua_dummies = pd.get_dummies(X_raw["user_agent_type"], prefix="ua", dtype=float)
        X_raw = X_raw.drop(columns=["user_agent_type"])
        X = pd.concat([X_raw, ua_dummies], axis=1)
    else:
        X = X_raw

    # Ensure all columns in X are numeric
    non_num = X.select_dtypes(exclude=[np.number]).columns.tolist()
    if non_num:
        X = X.drop(columns=non_num)

    # Impute NaNs with column median and replace infs
    if "time_since_previous_request" in X.columns:
        X["time_since_previous_request"] = X["time_since_previous_request"].fillna(999.0)

    num_cols = X.select_dtypes(include=[np.number]).columns
    X[num_cols] = X[num_cols].fillna(X[num_cols].median())
    X[num_cols] = X[num_cols].replace([np.inf, -np.inf], 0.0)

    feature_names = list(X.columns)
    print(f"Final clean numeric feature matrix dimensions: {X.shape[0]:,} rows x {X.shape[1]} features.")

    # Part 4: Train / Test Split
    print("\n" + "=" * 60)
    print("PART 4 — STRATIFIED TRAIN / TEST SPLIT")
    print("=" * 60)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    n_train = len(y_train)
    n_test = len(y_test)

    print(f"Training Records: {n_train:,} ({100 - TEST_SIZE*100:.1f}%)")
    print(f"Testing Records:  {n_test:,} ({TEST_SIZE*100:.1f}%)")
    print()

    train_counts = y_train.value_counts()
    test_counts = y_test.value_counts()

    print("Training Class Distribution:")
    for cls, cnt in train_counts.items():
        pct = (cnt / n_train) * 100
        print(f"  - {cls:<20}: {cnt:>10,} ({pct:>6.2f}%)")

    print("\nTesting Class Distribution:")
    for cls, cnt in test_counts.items():
        pct = (cnt / n_test) * 100
        print(f"  - {cls:<20}: {cnt:>10,} ({pct:>6.2f}%)")

    # Save Untouched Test Dataset (Features + Label)
    print(f"\nSaving untouched test dataset ({n_test:,} records) to:\n  -> {TEST_DATASET_CSV}")
    test_export = X_test.copy()
    test_export["label"] = y_test.values
    test_export.to_csv(TEST_DATASET_CSV, index=False)
    print(f"Test dataset saved successfully. It will remain completely untouched.")

    # Plot Training Class Distribution
    fig, ax = plt.subplots(figsize=(9, 5.5), dpi=300)
    labels = list(train_counts.index)
    values = list(train_counts.values)
    colors = ["#2563eb", "#d97706", "#dc2626", "#9333ea", "#059669", "#e11d48"][:len(labels)]

    bars = ax.bar(labels, values, color=colors, edgecolor="#1e293b", width=0.55)
    ax.set_yscale("log")
    ax.set_title("Training Set Class Distribution (Before Balancing - Log Scale)", fontsize=12, fontweight="bold", pad=12)
    ax.set_xlabel("Traffic Category", fontsize=10, labelpad=8)
    ax.set_ylabel("Record Count (Log Scale)", fontsize=10, labelpad=8)
    ax.grid(True, linestyle="--", alpha=0.5, axis="y")

    for bar, val in zip(bars, values):
        p = (val / n_train) * 100
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() * 1.25,
            f"{val:,}\n({p:.2f}%)",
            ha="center",
            va="bottom",
            fontsize=8.5,
            fontweight="semibold",
        )

    plt.tight_layout()
    p_train = PLOTS_DIR / "training_class_distribution.png"
    plt.savefig(p_train)
    plt.close()
    print(f"Saved training distribution chart to: {p_train.name}")

    split_meta = {
        "n_train": n_train,
        "n_test": n_test,
        "train_counts": train_counts.to_dict(),
        "test_counts": test_counts.to_dict(),
        "feature_count": len(feature_names),
    }

    return X_train, X_test, y_train, y_test, feature_names, split_meta
