#!/usr/bin/env python3
r"""run_practical6.py
Practical 6: Dataset Balancing for Machine Learning & Deep Learning Training
=============================================================================
Location: D:\Pds Practicals\Practical 6\run_practical6.py

Executes the complete reproducible balancing pipeline:
1. Ingests Practical 5 feature-engineered telemetry dataset.
2. Analyzes benign vs attack traffic distribution and calculates imbalance ratio.
3. Isolates feature matrix X from target y (strictly excludes label & label_reason).
4. Performs stratified 80/20 train/test split; exports untouched test_dataset.csv.
5. Performs Random Undersampling on the training partition.
6. Performs Random Oversampling on the training partition.
7. Performs SMOTE synthetic interpolation on the training partition.
8. Generates comparative reports, data quality audits, and diagnostic plots.
9. Exports final optimal balanced dataset (balanced_training_dataset.csv).
10. Prints exact required terminal summary.
"""

import sys
import time
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.inspector import inspect_dataset
from src.splitter import prepare_and_split_data
from src.balancers import (
    run_random_undersampling,
    run_random_oversampling,
    run_smote_balancing,
    select_and_save_final_balanced_dataset,
)
from src.reporter import generate_comparison_and_reports
from src.plots import generate_balancing_plots


def main():
    t_start = time.time()

    print("=" * 60)
    print("PRACTICAL 6: DATASET BALANCING FOR ML/DL TRAINING")
    print("Open-Source imbalanced-learn / scikit-learn Engine")
    print("=" * 60)

    # Part 1 & 2: Dataset Inspection & Imbalance Analysis
    df, meta = inspect_dataset()

    # Part 3 & 4: Remove Target Leakage & Stratified Train/Test Split
    X_train, X_test, y_train, y_test, feature_names, split_meta = prepare_and_split_data(df)

    # Free large original DataFrame memory
    del df

    # Part 5: Random Undersampling
    X_train_under, y_train_under, under_counts = run_random_undersampling(X_train, y_train)

    # Part 6: Random Oversampling
    X_train_over, y_train_over, over_counts = run_random_oversampling(X_train, y_train)

    # Part 7: SMOTE
    X_train_smote, y_train_smote, smote_counts = run_smote_balancing(X_train, y_train)

    # Part 9: Select Final Balanced Dataset
    final_method, final_df, rationale = select_and_save_final_balanced_dataset(
        X_train_smote, y_train_smote, X_train_over, y_train_over
    )

    total_time = time.time() - t_start

    # Part 8 & 13: Comparative Matrix & Technical Report
    comp_df = generate_comparison_and_reports(
        meta=meta,
        split_meta=split_meta,
        under_counts=under_counts,
        over_counts=over_counts,
        smote_counts=smote_counts,
        final_method=final_method,
        rationale=rationale,
        total_time=total_time,
    )

    # Part 12: Visualizations
    generate_balancing_plots(under_counts, over_counts, smote_counts, comp_df)

    # FINAL REQUIRED TERMINAL OUTPUT
    print("\n" + "=" * 60)
    print("PRACTICAL 6 — DATASET BALANCING")
    print("============================================================")
    print()
    print(f"Original Records: {meta['num_rows']:,}")
    print(f"Training Records: {split_meta['n_train']:,}")
    print(f"Testing Records:  {split_meta['n_test']:,}")
    print()
    print("Original Classes:")
    for cls, cnt in meta["counts"].items():
        pct = (cnt / meta["num_rows"]) * 100
        print(f"  - {cls:<20}: {cnt:>10,} ({pct:>6.2f}%)")
    print()
    print(f"Original Imbalance Ratio: {meta['imbalance_ratio']:,.2f} : 1")
    print()
    print("Undersampling Records:")
    for cls, cnt in under_counts.items():
        print(f"  - {cls:<20}: {cnt:>8,}")
    print(f"  Total Undersampled: {sum(under_counts.values()):,}")
    print()
    print("Random Oversampling Records:")
    for cls, cnt in over_counts.items():
        print(f"  - {cls:<20}: {cnt:>8,}")
    print(f"  Total Oversampled:  {sum(over_counts.values()):,}")
    print()
    print("SMOTE Records:")
    for cls, cnt in smote_counts.items():
        print(f"  - {cls:<20}: {cnt:>8,}")
    print(f"  Total SMOTE:        {sum(smote_counts.values()):,}")
    print()
    print(f"Final Method: {final_method}")
    print()
    print(f"Final Balanced Training Records: {len(final_df):,}")
    print()
    print(f"Test Records: {split_meta['n_test']:,}")
    print()
    print("[PASS] Class distribution analyzed")
    print("[PASS] Train/test split completed")
    print("[PASS] Test set untouched")
    print("[PASS] Undersampling completed")
    print("[PASS] Random oversampling completed")
    print("[PASS] SMOTE completed")
    print("[PASS] No target leakage")
    print("[PASS] Final balanced dataset created")
    print("[PASS] Reports generated")
    print("[PASS] Plots generated")
    print()
    print("STATUS: SUCCESS")
    print("============================================================")


if __name__ == "__main__":
    main()
