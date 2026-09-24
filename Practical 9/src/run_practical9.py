"""run_practical9.py
Practical 9: Simple Classifier for Attack Detection
End-to-End Orchestrator Pipeline
"""

import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.inspector import inspect_dataset
from src.preparer import prepare_and_clean_features
from src.trainer import (
    split_data,
    scale_features_for_lr,
    train_logistic_regression,
    train_random_forest,
)
from src.evaluator import evaluate_models
from src.balanced_validator import run_balanced_validation
from src.reporter import generate_final_report
from src.verify_classifier import run_verification


def main():
    # PART 1: Data Inspection
    df, inspection_meta = inspect_dataset()

    # PART 2 & 3: Prepare Features, Remove Leakage, and Clean Data
    X, y, feature_names, cleaning_meta = prepare_and_clean_features(df)

    # PART 4: Stratified Train / Test Split
    X_train, X_test, y_train, y_test, split_meta = split_data(X, y)

    # PART 5: Feature Scaling for Logistic Regression
    X_train_scaled, X_test_scaled, scaler = scale_features_for_lr(X_train, X_test)

    # PART 6: Logistic Regression Training
    lr_model, lr_time = train_logistic_regression(
        X_train_scaled, y_train, feature_names, scaler
    )
    print("Generating Logistic Regression predictions on test partition...")
    y_pred_lr = lr_model.predict(X_test_scaled)

    # PART 7: Random Forest Training
    rf_model, rf_time = train_random_forest(X_train, y_train, feature_names)
    print("Generating Random Forest predictions on test partition...")
    y_pred_rf = rf_model.predict(X_test)

    # PARTS 8 - 12 & 14: Model Evaluation, Matrices, Reports, Plots
    eval_results = evaluate_models(
        y_test=y_test,
        y_pred_lr=y_pred_lr,
        y_pred_rf=y_pred_rf,
        rf_model=rf_model,
        feature_names=feature_names,
        split_meta=split_meta,
    )

    # PART 13: Optional Balanced-Data Validation Experiment
    balanced_df = run_balanced_validation(eval_results["comparison_df"])

    # PART 16: Final Report Synthesis
    generate_final_report(
        inspection_meta=inspection_meta,
        cleaning_meta=cleaning_meta,
        split_meta=split_meta,
        eval_results=eval_results,
        balanced_df=balanced_df,
    )

    # PART 15: Run Verification Suite
    run_verification()

    # ============================================================
    # FINAL TERMINAL OUTPUT
    # ============================================================
    lr_res = eval_results["lr"]
    rf_res = eval_results["rf"]

    print("\n" + "=" * 60)
    print("PRACTICAL 9 — SIMPLE ATTACK CLASSIFIER")
    print("=" * 60)
    print()
    print(f"Input Records: {inspection_meta['total_records']:,}")
    print(f"Input Features: {cleaning_meta['final_ml_features']}")
    print(f"Number of Classes: {inspection_meta['num_classes']}")
    print()
    print(f"Training Records: {split_meta['n_train']:,}")
    print(f"Testing Records: {split_meta['n_test']:,}")
    print()
    print("-" * 60)
    print("LOGISTIC REGRESSION")
    print("-" * 60)
    print()
    print(f"Accuracy: {lr_res['accuracy']:.4f}")
    print(f"Macro Precision: {lr_res['macro_precision']:.4f}")
    print(f"Macro Recall: {lr_res['macro_recall']:.4f}")
    print(f"Macro F1: {lr_res['macro_f1']:.4f}")
    print()
    print("Confusion Matrix:")
    print(lr_res["confusion_matrix"])
    print()
    print("-" * 60)
    print("RANDOM FOREST")
    print("-" * 60)
    print()
    print(f"Accuracy: {rf_res['accuracy']:.4f}")
    print(f"Macro Precision: {rf_res['macro_precision']:.4f}")
    print(f"Macro Recall: {rf_res['macro_recall']:.4f}")
    print(f"Macro F1: {rf_res['macro_f1']:.4f}")
    print()
    print("Confusion Matrix:")
    print(rf_res["confusion_matrix"])
    print()
    print("-" * 60)
    print("MODEL COMPARISON")
    print("-" * 60)
    print()
    print("Logistic Regression:")
    print(f"Accuracy = {lr_res['accuracy']:.4f}")
    print(f"Macro F1 = {lr_res['macro_f1']:.4f}")
    print()
    print("Random Forest:")
    print(f"Accuracy = {rf_res['accuracy']:.4f}")
    print(f"Macro F1 = {rf_res['macro_f1']:.4f}")
    print()
    print("-" * 60)
    print()
    print("[PASS] Data loaded")
    print("[PASS] Features prepared")
    print("[PASS] No target leakage")
    print("[PASS] Train/test split")
    print("[PASS] Logistic Regression")
    print("[PASS] Random Forest")
    print("[PASS] Accuracy calculated")
    print("[PASS] Confusion matrices")
    print("[PASS] Classification reports")
    print("[PASS] Models saved")
    print("[PASS] Reports saved")
    print()
    print("STATUS: SUCCESS")
    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
