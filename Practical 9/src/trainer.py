"""trainer.py
Part 4, 5, 6, 7: Train/Test Split, Feature Scaling, Model Training & Persistence
"""

import time
from typing import Tuple, Dict, Any, List
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier

from src.config import (
    TEST_SIZE,
    RANDOM_STATE,
    LR_MAX_ITER,
    LR_CLASS_WEIGHT,
    RF_N_ESTIMATORS,
    RF_CLASS_WEIGHT,
    RF_N_JOBS,
    LR_MODEL_FILE,
    RF_MODEL_FILE,
)


def split_data(
    X: pd.DataFrame, y: pd.Series
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, Dict[str, Any]]:
    """Part 4: Stratified Train / Test Partitioning.

    Preserves natural distribution and ensures test set remains strictly untouched.
    """
    print("\n" + "=" * 60)
    print("PART 4 — TRAIN / TEST SPLIT")
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

    train_dist = y_train.value_counts()
    test_dist = y_test.value_counts()

    print(f"Training records: {n_train:,} ({100 - TEST_SIZE*100:.1f}%)")
    print(f"Testing records:  {n_test:,} ({TEST_SIZE*100:.1f}%)")

    print("\nTraining class distribution:")
    for cls, cnt in train_dist.items():
        pct = (cnt / n_train) * 100
        print(f"  - {cls:<20}: {cnt:>10,} ({pct:>6.2f}%)")

    print("\nTesting class distribution:")
    for cls, cnt in test_dist.items():
        pct = (cnt / n_test) * 100
        print(f"  - {cls:<20}: {cnt:>10,} ({pct:>6.2f}%)")

    split_meta = {
        "n_train": n_train,
        "n_test": n_test,
        "train_dist": train_dist.to_dict(),
        "test_dist": test_dist.to_dict(),
    }

    return X_train, X_test, y_train, y_test, split_meta


def scale_features_for_lr(
    X_train: pd.DataFrame, X_test: pd.DataFrame
) -> Tuple[np.ndarray, np.ndarray, StandardScaler]:
    """Part 5: Feature Scaling for Logistic Regression.

    Fits StandardScaler strictly on X_train to prevent data leakage.
    """
    print("\n" + "=" * 60)
    print("PART 5 — FEATURE SCALING (LOGISTIC REGRESSION)")
    print("=" * 60)
    print("Fitting StandardScaler strictly on X_train...")

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print("Transformed X_train and X_test successfully.")
    print("Random Forest will use unscaled features directly (tree invariants).")

    return X_train_scaled, X_test_scaled, scaler


def train_logistic_regression(
    X_train_scaled: np.ndarray,
    y_train: pd.Series,
    feature_names: List[str],
    scaler: StandardScaler,
) -> Tuple[LogisticRegression, float]:
    """Part 6: Train Logistic Regression model with class balancing."""
    print("\n" + "=" * 60)
    print("PART 6 — TRAIN LOGISTIC REGRESSION")
    print("=" * 60)
    print(f"Configuration: max_iter={LR_MAX_ITER}, random_state={RANDOM_STATE}, class_weight='{LR_CLASS_WEIGHT}'")

    lr = LogisticRegression(
        max_iter=LR_MAX_ITER,
        random_state=RANDOM_STATE,
        class_weight=LR_CLASS_WEIGHT,
    )

    t0 = time.time()
    lr.fit(X_train_scaled, y_train)
    elapsed = time.time() - t0

    print(f"Logistic Regression training completed in {elapsed:.2f} seconds.")

    # Save model and artifacts
    joblib_payload = {
        "model": lr,
        "scaler": scaler,
        "feature_names": feature_names,
        "classes": list(lr.classes_),
        "config": {
            "max_iter": LR_MAX_ITER,
            "random_state": RANDOM_STATE,
            "class_weight": LR_CLASS_WEIGHT,
        },
    }
    joblib.dump(joblib_payload, LR_MODEL_FILE)
    print(f"Saved Logistic Regression model to:\n  -> {LR_MODEL_FILE}")

    return lr, elapsed


def train_random_forest(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    feature_names: List[str],
) -> Tuple[RandomForestClassifier, float]:
    """Part 7: Train Random Forest Classifier with class balancing."""
    print("\n" + "=" * 60)
    print("PART 7 — TRAIN RANDOM FOREST")
    print("=" * 60)
    print(
        f"Configuration: n_estimators={RF_N_ESTIMATORS}, random_state={RANDOM_STATE}, "
        f"n_jobs={RF_N_JOBS}, class_weight='{RF_CLASS_WEIGHT}'"
    )

    rf = RandomForestClassifier(
        n_estimators=RF_N_ESTIMATORS,
        random_state=RANDOM_STATE,
        n_jobs=RF_N_JOBS,
        class_weight=RF_CLASS_WEIGHT,
    )

    t0 = time.time()
    rf.fit(X_train, y_train)
    elapsed = time.time() - t0

    print(f"Random Forest training completed in {elapsed:.2f} seconds.")

    # Save model and artifacts
    joblib_payload = {
        "model": rf,
        "feature_names": feature_names,
        "classes": list(rf.classes_),
        "config": {
            "n_estimators": RF_N_ESTIMATORS,
            "random_state": RANDOM_STATE,
            "n_jobs": RF_N_JOBS,
            "class_weight": RF_CLASS_WEIGHT,
        },
    }
    joblib.dump(joblib_payload, RF_MODEL_FILE)
    print(f"Saved Random Forest model to:\n  -> {RF_MODEL_FILE}")

    return rf, elapsed
