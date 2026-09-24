"""balancers.py
Parts 5, 6, 7 & 9: Dataset Balancing Engines (Undersampling, Oversampling, SMOTE)
Executes class balancing exclusively on the training partition without test contamination.
"""

from typing import Tuple, Dict, Any
import time
import numpy as np
import pandas as pd
from imblearn.under_sampling import RandomUnderSampler
from imblearn.over_sampling import RandomOverSampler, SMOTE
from src.config import (
    BALANCED_UNDERSAMPLED_CSV,
    BALANCED_OVERSAMPLED_CSV,
    BALANCED_SMOTE_CSV,
    FINAL_BALANCED_TRAIN_CSV,
    OVERSAMPLE_BENIGN_CEILING,
    RANDOM_STATE,
)


def run_random_undersampling(
    X_train: pd.DataFrame, y_train: pd.Series
) -> Tuple[pd.DataFrame, pd.Series, Dict[str, int]]:
    """Applies RandomUnderSampler to balance training classes down to the minority count."""
    print("\n" + "=" * 60)
    print("PART 5 — RANDOM UNDERSAMPLING")
    print("=" * 60)
    t0 = time.time()

    rus = RandomUnderSampler(random_state=RANDOM_STATE)
    X_train_under, y_train_under = rus.fit_resample(X_train, y_train)

    under_counts = y_train_under.value_counts().to_dict()
    print(f"Undersampling completed in {time.time() - t0:.2f}s")
    print(f"Total Undersampled Records: {len(y_train_under):,}")
    print("Resulting Class Distribution:")
    for cls, cnt in under_counts.items():
        print(f"  - {cls:<20}: {cnt:>8,}")

    # Export to data/processed/balanced_train_undersampled.csv
    df_under = X_train_under.copy()
    df_under["label"] = y_train_under.values
    df_under.to_csv(BALANCED_UNDERSAMPLED_CSV, index=False)
    print(f"Saved: {BALANCED_UNDERSAMPLED_CSV.name}")

    return X_train_under, y_train_under, under_counts


def run_random_oversampling(
    X_train: pd.DataFrame, y_train: pd.Series
) -> Tuple[pd.DataFrame, pd.Series, Dict[str, int]]:
    """Applies RandomOverSampler to balance training classes up to the benign target ceiling.
    
    Memory-Safe Large Dataset Handling:
    Retains 100% of all attack instances, with benign training records calibrated to a
    reproducible representative volume (10,000 records) to prevent multithread memory blowups.
    """
    print("\n" + "=" * 60)
    print("PART 6 — RANDOM OVERSAMPLING")
    print("=" * 60)
    t0 = time.time()

    # Create memory-safe training subset for oversampling
    attack_mask = y_train != "benign"
    benign_indices = y_train[~attack_mask].sample(
        n=min(OVERSAMPLE_BENIGN_CEILING, int((~attack_mask).sum())),
        random_state=RANDOM_STATE,
    ).index
    attack_indices = y_train[attack_mask].index
    combined_idx = attack_indices.union(benign_indices)

    X_train_sub = X_train.loc[combined_idx]
    y_train_sub = y_train.loc[combined_idx]

    ros = RandomOverSampler(random_state=RANDOM_STATE)
    X_train_over, y_train_over = ros.fit_resample(X_train_sub, y_train_sub)

    over_counts = y_train_over.value_counts().to_dict()
    print(f"Random oversampling completed in {time.time() - t0:.2f}s")
    print(f"Total Random Oversampled Records: {len(y_train_over):,}")
    print("Resulting Class Distribution:")
    for cls, cnt in over_counts.items():
        print(f"  - {cls:<20}: {cnt:>8,}")

    # Export to data/processed/balanced_train_random_oversampled.csv
    df_over = X_train_over.copy()
    df_over["label"] = y_train_over.values
    df_over.to_csv(BALANCED_OVERSAMPLED_CSV, index=False)
    print(f"Saved: {BALANCED_OVERSAMPLED_CSV.name}")

    return X_train_over, y_train_over, over_counts


def run_smote_balancing(
    X_train: pd.DataFrame, y_train: pd.Series
) -> Tuple[pd.DataFrame, pd.Series, Dict[str, int]]:
    """Applies SMOTE (Synthetic Minority Over-sampling Technique) to interpolate minority classes.
    
    Uses k_neighbors=5 on the clean numeric feature matrix.
    """
    print("\n" + "=" * 60)
    print("PART 7 — SMOTE (SYNTHETIC MINORITY OVER-SAMPLING)")
    print("=" * 60)
    t0 = time.time()

    # Memory-safe representative training subset
    attack_mask = y_train != "benign"
    benign_indices = y_train[~attack_mask].sample(
        n=min(OVERSAMPLE_BENIGN_CEILING, int((~attack_mask).sum())),
        random_state=RANDOM_STATE,
    ).index
    attack_indices = y_train[attack_mask].index
    combined_idx = attack_indices.union(benign_indices)

    X_train_sub = X_train.loc[combined_idx]
    y_train_sub = y_train.loc[combined_idx]

    # Pre-SMOTE verification
    assert not X_train_sub.isnull().any().any(), "SMOTE requires zero NaN values in feature matrix"
    assert not np.isinf(X_train_sub.values).any(), "SMOTE requires zero Infinite values in feature matrix"

    print("Synthesizing novel minority manifold vectors using k-NN (k=5)...")
    smote = SMOTE(k_neighbors=5, random_state=RANDOM_STATE)
    X_train_smote, y_train_smote = smote.fit_resample(X_train_sub, y_train_sub)

    smote_counts = y_train_smote.value_counts().to_dict()
    print(f"SMOTE synthesis completed in {time.time() - t0:.2f}s")
    print(f"Total SMOTE Balanced Records: {len(y_train_smote):,}")
    print("Resulting Class Distribution:")
    for cls, cnt in smote_counts.items():
        print(f"  - {cls:<20}: {cnt:>8,}")

    # Export to data/processed/balanced_train_smote.csv
    df_smote = X_train_smote.copy()
    df_smote["label"] = y_train_smote.values
    df_smote.to_csv(BALANCED_SMOTE_CSV, index=False)
    print(f"Saved: {BALANCED_SMOTE_CSV.name}")

    return X_train_smote, y_train_smote, smote_counts


def select_and_save_final_balanced_dataset(
    X_train_smote: pd.DataFrame,
    y_train_smote: pd.Series,
    X_train_over: pd.DataFrame,
    y_train_over: pd.Series,
) -> Tuple[str, pd.DataFrame, str]:
    """Selects the optimal balanced dataset for downstream ML/DL training (Part 9).
    
    Prefers SMOTE because synthetic interpolation mitigates model overfitting compared
    to exact duplicated records in Random Oversampling.
    """
    print("\n" + "=" * 60)
    print("PART 9 — SELECT FINAL BALANCED TRAINING DATASET")
    print("=" * 60)

    selected_method = "SMOTE"
    rationale = (
        "SMOTE was selected as the optimal balancing methodology because it synthesizes novel, "
        "plausible feature vectors along k-nearest neighbor manifold line segments. Unlike Random "
        "Oversampling (which duplicates identical rows and creates exact decision boundary memorization), "
        "SMOTE expands minority class variance, providing superior generalization for downstream "
        "Deep Learning neural architectures and tree ensemble classifiers without target leakage."
    )

    final_df = X_train_smote.copy()
    final_df["label"] = y_train_smote.values

    final_df.to_csv(FINAL_BALANCED_TRAIN_CSV, index=False)
    print(f"Selected Final Method: {selected_method}")
    print(f"Saved Final Balanced Training Dataset ({len(final_df):,} rows) to:\n  -> {FINAL_BALANCED_TRAIN_CSV.name}")

    return selected_method, final_df, rationale
