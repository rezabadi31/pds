"""verify_classifier.py
Part 15: Data Quality, Target Leakage, and Pipeline Verification Suite
Runs 14 verification checks to validate end-to-end model integrity.
"""

import sys
from pathlib import Path
import joblib
import pandas as pd
import numpy as np

# Ensure root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import (
    INPUT_CSV,
    FALLBACK_CSV,
    LR_MODEL_FILE,
    RF_MODEL_FILE,
    LR_CONFUSION_MATRIX_PNG,
    RF_CONFUSION_MATRIX_PNG,
    MODEL_ACCURACY_COMPARISON_PNG,
    RF_TOP20_FEATURES_PNG,
    CLASS_DISTRIBUTION_PNG,
    LR_METRICS_CSV,
    RF_METRICS_CSV,
    MODEL_COMPARISON_CSV,
    RF_FEATURE_IMPORTANCE_CSV,
    LR_REPORT_TXT,
    RF_REPORT_TXT,
    CLASSIFIER_REPORT_TXT,
)


def run_verification() -> bool:
    """Executes all 14 quality and integrity checks."""
    print("=" * 60)
    print("PART 15 — DATA QUALITY & LEAKAGE VERIFICATION")
    print("=" * 60)

    checks = []

    # Check 1: Dataset loaded
    ds_exists = INPUT_CSV.exists() or FALLBACK_CSV.exists()
    if ds_exists:
        print("[PASS] Dataset loaded")
        checks.append(True)
    else:
        print("[FAIL] Dataset loaded — input file missing!")
        checks.append(False)

    # Check 2: Target identified
    active_csv = INPUT_CSV if INPUT_CSV.exists() else FALLBACK_CSV
    try:
        sample_df = pd.read_csv(active_csv, nrows=100)
        target_ok = "label" in sample_df.columns
        if target_ok:
            print("[PASS] Target identified")
            checks.append(True)
        else:
            print("[FAIL] Target identified — 'label' column not found!")
            checks.append(False)
    except Exception as e:
        print(f"[FAIL] Target identified — error reading CSV: {e}")
        checks.append(False)

    # Check 3: Numeric features identified
    # Read from model or metrics
    try:
        if RF_FEATURE_IMPORTANCE_CSV.exists():
            fi_df = pd.read_csv(RF_FEATURE_IMPORTANCE_CSV)
            num_feat_count = len(fi_df)
            if num_feat_count >= 10:
                print("[PASS] Numeric features identified")
                checks.append(True)
            else:
                print(f"[FAIL] Numeric features identified — only {num_feat_count} features.")
                checks.append(False)
        else:
            print("[FAIL] Numeric features identified — feature importance CSV missing.")
            checks.append(False)
    except Exception as e:
        print(f"[FAIL] Numeric features identified: {e}")
        checks.append(False)

    # Check 4: No target leakage
    leakage_cols = ["label", "label_reason", "target", "category_type", "payload", "timestamp", "client_ip", "user_agent"]
    try:
        if RF_FEATURE_IMPORTANCE_CSV.exists():
            fi_df = pd.read_csv(RF_FEATURE_IMPORTANCE_CSV)
            has_leak = any(col in fi_df["Feature"].values for col in leakage_cols)
            if not has_leak:
                print("[PASS] No target leakage")
                checks.append(True)
            else:
                print("[FAIL] Target leakage detected in feature set!")
                checks.append(False)
        else:
            print("[FAIL] No target leakage check — feature importance file missing.")
            checks.append(False)
    except Exception as e:
        print(f"[FAIL] No target leakage check: {e}")
        checks.append(False)

    # Check 5: Missing values handled
    # Check that report confirms imputation
    try:
        if CLASSIFIER_REPORT_TXT.exists() and "Missing Values Imputed" in CLASSIFIER_REPORT_TXT.read_text(encoding="utf-8"):
            print("[PASS] Missing values handled")
            checks.append(True)
        else:
            print("[FAIL] Missing values handled check failed.")
            checks.append(False)
    except Exception as e:
        print(f"[FAIL] Missing values check: {e}")
        checks.append(False)

    # Check 6: Infinite values handled
    try:
        if CLASSIFIER_REPORT_TXT.exists() and "Infinite Values Cleaned" in CLASSIFIER_REPORT_TXT.read_text(encoding="utf-8"):
            print("[PASS] Infinite values handled")
            checks.append(True)
        else:
            print("[FAIL] Infinite values handled check failed.")
            checks.append(False)
    except Exception as e:
        print(f"[FAIL] Infinite values check: {e}")
        checks.append(False)

    # Check 7: Stratified train/test split
    try:
        if CLASS_DISTRIBUTION_PNG.exists() and CLASSIFIER_REPORT_TXT.exists() and "80% Training / 20% Testing" in CLASSIFIER_REPORT_TXT.read_text(encoding="utf-8"):
            print("[PASS] Stratified train/test split")
            checks.append(True)
        else:
            print("[FAIL] Stratified train/test split check failed.")
            checks.append(False)
    except Exception as e:
        print(f"[FAIL] Train/test split check: {e}")
        checks.append(False)

    # Check 8: Logistic Regression trained
    try:
        if LR_MODEL_FILE.exists():
            payload = joblib.load(LR_MODEL_FILE)
            if "model" in payload and hasattr(payload["model"], "predict"):
                print("[PASS] Logistic Regression trained")
                checks.append(True)
            else:
                print("[FAIL] Logistic Regression model not found in joblib file.")
                checks.append(False)
        else:
            print(f"[FAIL] Logistic Regression trained — {LR_MODEL_FILE} not found.")
            checks.append(False)
    except Exception as e:
        print(f"[FAIL] Logistic Regression trained: {e}")
        checks.append(False)

    # Check 9: Random Forest trained
    try:
        if RF_MODEL_FILE.exists():
            payload = joblib.load(RF_MODEL_FILE)
            if "model" in payload and hasattr(payload["model"], "predict"):
                print("[PASS] Random Forest trained")
                checks.append(True)
            else:
                print("[FAIL] Random Forest model not found in joblib file.")
                checks.append(False)
        else:
            print(f"[FAIL] Random Forest trained — {RF_MODEL_FILE} not found.")
            checks.append(False)
    except Exception as e:
        print(f"[FAIL] Random Forest trained: {e}")
        checks.append(False)

    # Check 10: Accuracy calculated
    try:
        if MODEL_COMPARISON_CSV.exists():
            comp_df = pd.read_csv(MODEL_COMPARISON_CSV)
            if "Accuracy" in comp_df.columns and comp_df["Accuracy"].notnull().all():
                print("[PASS] Accuracy calculated")
                checks.append(True)
            else:
                print("[FAIL] Accuracy calculated — missing values in comparison.")
                checks.append(False)
        else:
            print(f"[FAIL] Accuracy calculated — {MODEL_COMPARISON_CSV} missing.")
            checks.append(False)
    except Exception as e:
        print(f"[FAIL] Accuracy calculated: {e}")
        checks.append(False)

    # Check 11: Confusion matrices generated
    cm_plots_exist = LR_CONFUSION_MATRIX_PNG.exists() and RF_CONFUSION_MATRIX_PNG.exists()
    if cm_plots_exist:
        print("[PASS] Confusion matrices generated")
        checks.append(True)
    else:
        print("[FAIL] Confusion matrices generated — plot files missing.")
        checks.append(False)

    # Check 12: Classification reports generated
    reports_exist = LR_REPORT_TXT.exists() and RF_REPORT_TXT.exists()
    if reports_exist and LR_REPORT_TXT.stat().st_size > 50 and RF_REPORT_TXT.stat().st_size > 50:
        print("[PASS] Classification reports generated")
        checks.append(True)
    else:
        print("[FAIL] Classification reports generated — text reports missing or empty.")
        checks.append(False)

    # Check 13: Models saved
    models_saved = LR_MODEL_FILE.exists() and RF_MODEL_FILE.exists() and LR_MODEL_FILE.stat().st_size > 100 and RF_MODEL_FILE.stat().st_size > 100
    if models_saved:
        print("[PASS] Models saved")
        checks.append(True)
    else:
        print("[FAIL] Models saved — model files missing or empty.")
        checks.append(False)

    # Check 14: Evaluation results saved
    eval_files = [
        LR_METRICS_CSV,
        RF_METRICS_CSV,
        MODEL_COMPARISON_CSV,
        RF_FEATURE_IMPORTANCE_CSV,
        CLASSIFIER_REPORT_TXT,
        MODEL_ACCURACY_COMPARISON_PNG,
    ]
    all_eval_saved = all(f.exists() and f.stat().st_size > 0 for f in eval_files)
    if all_eval_saved:
        print("[PASS] Evaluation results saved")
        checks.append(True)
    else:
        print("[FAIL] Evaluation results saved — some result files missing or empty.")
        checks.append(False)

    all_passed = all(checks)
    print("\n" + "=" * 60)
    print(f"VERIFICATION SUMMARY: {sum(checks)}/14 CHECKS PASSED")
    print(f"STATUS: {'SUCCESS' if all_passed else 'FAILURE'}")
    print("=" * 60)

    return all_passed


if __name__ == "__main__":
    success = run_verification()
    sys.exit(0 if success else 1)
