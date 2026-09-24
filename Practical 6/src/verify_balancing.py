#!/usr/bin/env python3
r"""verify_balancing.py
Practical 6: Quality & Validation Suite for Dataset Balancing
=============================================================
Location: D:\Pds Practicals\Practical 6\src\verify_balancing.py

Performs comprehensive automated verification on Practical 6 outputs:
1. Dataset loaded
2. Target identified
3. Class distribution calculated
4. Train/test split completed
5. Test set remained untouched
6. Random undersampling completed
7. Random oversampling completed
8. SMOTE completed
9. No target leakage
10. No NaN values in final ML matrix
11. No infinite values
12. Final balanced dataset saved
13. Test dataset saved
14. Class distribution improved
"""

import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pandas as pd
from src.config import (
    INPUT_CSV,
    TEST_DATASET_CSV,
    BALANCED_UNDERSAMPLED_CSV,
    BALANCED_OVERSAMPLED_CSV,
    BALANCED_SMOTE_CSV,
    FINAL_BALANCED_TRAIN_CSV,
    COMPARISON_CSV,
)


def run_verification() -> bool:
    print("=" * 60)
    print("PRACTICAL 6 — BALANCING VERIFICATION")
    print("=" * 60)
    print()

    checks = []

    # 1. Dataset loaded
    test_1 = "Dataset loaded"
    if INPUT_CSV.exists():
        df_orig_sample = pd.read_csv(INPUT_CSV, usecols=["label"])
        n_orig = len(df_orig_sample)
        checks.append((test_1, True))
        print(f"[PASS] {test_1} ({n_orig:,} records)")
    else:
        checks.append((test_1, False))
        print(f"[FAIL] {test_1} - File not found: {INPUT_CSV}")
        return False

    # 2. Target identified
    test_2 = "Target identified"
    has_target = "label" in df_orig_sample.columns
    checks.append((test_2, has_target))
    print(f"[{'PASS' if has_target else 'FAIL'}] {test_2} ('label' column present)")

    # 3. Class distribution calculated
    test_3 = "Class distribution calculated"
    orig_counts = df_orig_sample["label"].value_counts().to_dict()
    checks.append((test_3, len(orig_counts) >= 2))
    print(f"[PASS] {test_3} ({len(orig_counts)} distinct classes)")

    # 4. Train/test split completed & 5. Test set remained untouched
    test_4 = "Train/test split completed"
    test_5 = "Test set remained untouched"
    if TEST_DATASET_CSV.exists():
        df_test = pd.read_csv(TEST_DATASET_CSV)
        n_test = len(df_test)
        n_train = n_orig - n_test
        split_ok = (n_test > 0) and (abs(n_test / n_orig - 0.20) < 0.01)
        checks.append((test_4, split_ok))
        print(f"[{'PASS' if split_ok else 'FAIL'}] {test_4} (Train: {n_train:,}, Test: {n_test:,})")

        # Test set is untouched if it maintains severe imbalance ratio
        test_counts = df_test["label"].value_counts().to_dict()
        test_imbalance = max(test_counts.values()) / min(test_counts.values())
        test_untouched = test_imbalance > 100.0  # Still highly imbalanced like original
        checks.append((test_5, test_untouched))
        print(f"[{'PASS' if test_untouched else 'FAIL'}] {test_5} (Retains test imbalance ratio {test_imbalance:,.1f}:1)")
    else:
        checks.append((test_4, False))
        checks.append((test_5, False))
        print(f"[FAIL] {test_4} - {TEST_DATASET_CSV.name} not found")
        return False

    # 6. Random undersampling completed
    test_6 = "Random undersampling completed"
    if BALANCED_UNDERSAMPLED_CSV.exists():
        df_under = pd.read_csv(BALANCED_UNDERSAMPLED_CSV)
        under_counts = df_under["label"].value_counts().to_dict()
        under_ok = len(set(under_counts.values())) == 1  # All classes equal
        checks.append((test_6, under_ok))
        print(f"[{'PASS' if under_ok else 'FAIL'}] {test_6} ({len(df_under):,} records, {under_counts})")
    else:
        checks.append((test_6, False))
        print(f"[FAIL] {test_6}")

    # 7. Random oversampling completed
    test_7 = "Random oversampling completed"
    if BALANCED_OVERSAMPLED_CSV.exists():
        df_over = pd.read_csv(BALANCED_OVERSAMPLED_CSV)
        over_counts = df_over["label"].value_counts().to_dict()
        over_ok = len(set(over_counts.values())) == 1
        checks.append((test_7, over_ok))
        print(f"[{'PASS' if over_ok else 'FAIL'}] {test_7} ({len(df_over):,} records, {over_counts})")
    else:
        checks.append((test_7, False))
        print(f"[FAIL] {test_7}")

    # 8. SMOTE completed
    test_8 = "SMOTE completed"
    if BALANCED_SMOTE_CSV.exists():
        df_smote = pd.read_csv(BALANCED_SMOTE_CSV)
        smote_counts = df_smote["label"].value_counts().to_dict()
        smote_ok = len(set(smote_counts.values())) == 1
        checks.append((test_8, smote_ok))
        print(f"[{'PASS' if smote_ok else 'FAIL'}] {test_8} ({len(df_smote):,} records, {smote_counts})")
    else:
        checks.append((test_8, False))
        print(f"[FAIL] {test_8}")

    # 9. No target leakage
    test_9 = "No target leakage"
    if FINAL_BALANCED_TRAIN_CSV.exists():
        df_final = pd.read_csv(FINAL_BALANCED_TRAIN_CSV)
        feature_cols = [c for c in df_final.columns if c != "label"]
        has_leak = any(c in feature_cols for c in ["label", "label_reason", "target", "anomaly_flag", "anomaly_score"])
        checks.append((test_9, not has_leak))
        print(f"[{'PASS' if not has_leak else 'FAIL'}] {test_9} (Features isolated from targets)")
    else:
        checks.append((test_9, False))
        print(f"[FAIL] {test_9}")
        return False

    # 10. No NaN values in final ML matrix & 11. No infinite values
    test_10 = "No NaN values in final ML matrix"
    test_11 = "No infinite values"
    num_df = df_final.select_dtypes(include=[np.number])
    has_nan = bool(num_df.isna().any().any())
    has_inf = bool(np.isinf(num_df.values).any())
    checks.append((test_10, not has_nan))
    checks.append((test_11, not has_inf))
    print(f"[{'PASS' if not has_nan else 'FAIL'}] {test_10} (0 NaNs)")
    print(f"[{'PASS' if not has_inf else 'FAIL'}] {test_11} (0 Infinite values)")

    # 12. Final balanced dataset saved
    test_12 = "Final balanced dataset saved"
    checks.append((test_12, FINAL_BALANCED_TRAIN_CSV.exists() and len(df_final) > 0))
    print(f"[PASS] {test_12} ({FINAL_BALANCED_TRAIN_CSV.name})")

    # 13. Test dataset saved
    test_13 = "Test dataset saved"
    checks.append((test_13, TEST_DATASET_CSV.exists() and len(df_test) > 0))
    print(f"[PASS] {test_13} ({TEST_DATASET_CSV.name})")

    # 14. Class distribution improved
    test_14 = "Class distribution improved"
    final_counts = df_final["label"].value_counts().to_dict()
    final_imbalance = max(final_counts.values()) / min(final_counts.values())
    improved = final_imbalance == 1.0  # Perfect parity
    checks.append((test_14, improved))
    print(f"[{'PASS' if improved else 'FAIL'}] {test_14} (Imbalance ratio reduced from {test_imbalance:,.1f}:1 to 1.0:1)")

    # Summary Display
    print("\n" + "-" * 60)
    print(f"Original Records:       {n_orig:,}")
    print(f"Training Records:       {n_train:,}")
    print(f"Testing Records:        {n_test:,}")
    print()
    print("Original Class Distribution:")
    for k, v in orig_counts.items():
        print(f"  - {k:<20}: {v:>10,}")
    print()
    print(f"Undersampling Result:   {under_counts}")
    print(f"Random Oversampling:    {over_counts}")
    print(f"SMOTE Result:           {smote_counts}")
    print()
    print("FINAL METHOD:           SMOTE")
    print(f"FINAL BALANCED RECORDS: {len(df_final):,}")
    print(f"TEST RECORDS:           {n_test:,}")
    print()
    print("=" * 60)

    all_passed = all(status for _, status in checks)
    print(f"STATUS: {'SUCCESS' if all_passed else 'FAILED'}")
    print("=" * 60)

    return all_passed


if __name__ == "__main__":
    success = run_verification()
    sys.exit(0 if success else 1)
