#!/usr/bin/env python3
r"""verify_labeling.py
Practical 4: Labeling Quality & Security Rules Verification Suite
================================================================
Location: D:\Pds Practicals\Practical 4\verify_labeling.py

Performs comprehensive automated verification on the labeled dataset:
1. Label column created
2. No missing labels (100% non-null)
3. Only approved labels used
4. SQLi rule applied
5. Path traversal rule applied
6. Brute-force rule evaluated
7. Original 14 columns preserved
8. Output dataset readable
9. Total records matches sum of all category counts
10. Extracts and displays 10 real examples directly from the actual dataset
"""

import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pandas as pd


APPROVED_LABELS = {
    "benign",
    "sqli",
    "path_traversal",
    "command_injection",
    "xss",
    "brute_force",
}

ORIGINAL_COLUMNS = [
    "category_type",
    "payload",
    "timestamp",
    "client_ip",
    "client_port",
    "user_agent",
    "accept_language",
    "proxy_ip",
    "request_type",
    "status_code",
    "resource_requested",
    "bytes_sent",
    "referrer",
    "normalized_resource",
]


def run_verification():
    print("=" * 70)
    print("PRACTICAL 4: AUTOMATED LABELING & RULE VERIFICATION")
    print("=" * 70)

    labeled_csv = PROJECT_ROOT / "data" / "processed" / "labeled_access_logs.csv"

    if not labeled_csv.exists():
        print(f"[FAIL] Labeled dataset not found at: {labeled_csv}")
        return False

    # Load dataset
    print(f"Loading labeled dataset: {labeled_csv.name}...")
    df = pd.read_csv(labeled_csv, low_memory=False)
    total_rows = len(df)
    print(f"Loaded {total_rows:,} records across {len(df.columns)} columns.\n")

    results = []

    # 1. Output dataset readable
    test_1 = "Output dataset readable"
    if total_rows > 0 and len(df.columns) >= 16:
        results.append((test_1, True, f"{total_rows:,} rows, {len(df.columns)} cols"))
        print(f"[PASS] {test_1}")
    else:
        results.append((test_1, False, f"Unexpected dimensions: {df.shape}"))
        print(f"[FAIL] {test_1}")

    # 2. Label column created
    test_2 = "Label column created"
    if "label" in df.columns and "label_reason" in df.columns:
        results.append((test_2, True, "'label' and 'label_reason' present"))
        print(f"[PASS] {test_2}")
    else:
        results.append((test_2, False, "Missing 'label' or 'label_reason' column"))
        print(f"[FAIL] {test_2}")

    # 3. No missing labels
    test_3 = "No missing labels"
    missing_labels = df["label"].isnull().sum()
    if missing_labels == 0:
        results.append((test_3, True, "0 missing labels"))
        print(f"[PASS] {test_3}")
    else:
        results.append((test_3, False, f"{missing_labels} missing labels found"))
        print(f"[FAIL] {test_3}")

    # 4. Only approved labels used
    test_4 = "Only approved labels used"
    found_labels = set(df["label"].unique())
    invalid_labels = found_labels - APPROVED_LABELS
    if not invalid_labels:
        results.append((test_4, True, f"Labels: {sorted(list(found_labels))}"))
        print(f"[PASS] {test_4}")
    else:
        results.append((test_4, False, f"Unapproved labels: {invalid_labels}"))
        print(f"[FAIL] {test_4}")

    # 5. Original columns preserved
    test_5 = "Original columns preserved"
    missing_orig = [c for c in ORIGINAL_COLUMNS if c not in df.columns]
    if not missing_orig:
        results.append((test_5, True, f"All {len(ORIGINAL_COLUMNS)} original columns intact"))
        print(f"[PASS] {test_5}")
    else:
        results.append((test_5, False, f"Missing columns: {missing_orig}"))
        print(f"[FAIL] {test_5}")

    # 6. SQLi rule applied
    test_6 = "SQLi rule applied"
    sqli_count = int((df["label"] == "sqli").sum())
    if sqli_count > 0:
        results.append((test_6, True, f"{sqli_count:,} SQLi records identified"))
        print(f"[PASS] {test_6}")
    else:
        results.append((test_6, False, "0 SQLi records found"))
        print(f"[FAIL] {test_6}")

    # 7. Path traversal rule applied
    test_7 = "Path traversal rule applied"
    pt_count = int((df["label"] == "path_traversal").sum())
    if pt_count > 0:
        results.append((test_7, True, f"{pt_count:,} Path Traversal records identified"))
        print(f"[PASS] {test_7}")
    else:
        results.append((test_7, False, "0 Path Traversal records found"))
        print(f"[FAIL] {test_7}")

    # 8. Brute-force rule evaluated
    test_8 = "Brute-force rule evaluated"
    bf_count = int((df["label"] == "brute_force").sum())
    if bf_count > 0:
        results.append((test_8, True, f"{bf_count:,} Brute-force records identified"))
        print(f"[PASS] {test_8}")
    else:
        results.append((test_8, False, "0 Brute-force records found"))
        print(f"[FAIL] {test_8}")

    # 9. Total records = benign + all attack categories
    test_9 = "Mathematical total verification (Total = Benign + Attacks)"
    benign_count = int((df["label"] == "benign").sum())
    attack_count = total_rows - benign_count
    sum_categories = sum((df["label"] == lbl).sum() for lbl in found_labels)
    if total_rows == sum_categories:
        results.append((test_9, True, f"{total_rows:,} == {sum_categories:,}"))
        print(f"[PASS] {test_9}")
    else:
        results.append((test_9, False, f"Sum mismatch: {total_rows} vs {sum_categories}"))
        print(f"[FAIL] {test_9}")

    # Statistics printout
    print("\n" + "-" * 70)
    print("DATASET CLASSIFICATION METRICS")
    print("-" * 70)
    print(f"Total records:         {total_rows:,}")
    print(f"Benign records:        {benign_count:,} ({benign_count / total_rows * 100:.2f}%)")
    print(f"Total attack records:  {attack_count:,} ({attack_count / total_rows * 100:.2f}%)")
    print()
    for lbl in sorted(list(found_labels)):
        cnt = int((df["label"] == lbl).sum())
        print(f"  - {lbl:<20}: {cnt:>10,} ({cnt / total_rows * 100:>6.2f}%)")

    # Display 10 Real Examples from the actual dataset
    print("\n" + "=" * 70)
    print("10 REAL DATASET EXAMPLES (ACTUAL LOG OBSERVATIONS)")
    print("=" * 70)

    # Collect 10 distinct examples covering all detected classes
    examples = []
    for l in ["sqli", "path_traversal", "command_injection", "xss", "brute_force", "benign"]:
        matches = df[df["label"] == l].head(2)
        for _, row in matches.iterrows():
            examples.append(row)
            if len(examples) >= 10:
                break
        if len(examples) >= 10:
            break

    for idx, ex in enumerate(examples[:10], 1):
        print(f"\n--- Example {idx} [{ex['label'].upper()}] ---")
        print(f"Request/resource: {ex['resource_requested']}")
        print(f"Payload:          {ex['payload']}")
        print(f"Client IP:        {ex['client_ip']}")
        print(f"Label:            {ex['label']}")
        print(f"Reason:           {ex['label_reason']}")

    print("\n" + "=" * 70)
    all_passed = all(status for _, status, _ in results)
    print(f"VERIFICATION SUMMARY: {sum(1 for _, s, _ in results if s)}/{len(results)} TESTS PASSED")
    print(f"STATUS: {'SUCCESS' if all_passed else 'FAILED'}")
    print("=" * 70)

    return all_passed


if __name__ == "__main__":
    success = run_verification()
    sys.exit(0 if success else 1)
