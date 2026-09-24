"""inspector.py
Part 1: Data Loading, Telemetry Inspection, and Quality Diagnostics
"""

from typing import Tuple, Dict, Any, List
from pathlib import Path
import numpy as np
import pandas as pd
from src.config import INPUT_CSV, FALLBACK_CSV


def inspect_dataset(csv_path: Path = INPUT_CSV) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Loads Practical 5 dataset and runs comprehensive data inspection."""
    print("=" * 60)
    print("PART 1 — DATA INSPECTION")
    print("=" * 60)

    if not csv_path.exists():
        if FALLBACK_CSV.exists():
            print(f"[WARN] Primary dataset not found at {csv_path}. Using fallback: {FALLBACK_CSV}")
            csv_path = FALLBACK_CSV
        else:
            raise FileNotFoundError(f"Neither {csv_path} nor fallback {FALLBACK_CSV} exists!")

    print(f"Loading dataset from: {csv_path}")
    df = pd.read_csv(csv_path)

    total_records, total_columns = df.shape
    target_col = "label" if "label" in df.columns else None

    if target_col is None:
        raise ValueError("Critical: 'label' column not found in dataset!")

    classes = sorted(df[target_col].dropna().unique().tolist())
    num_classes = len(classes)
    class_counts = df[target_col].value_counts().to_dict()

    # Identify numeric vs categorical features
    numeric_features: List[str] = df.select_dtypes(include=[np.number]).columns.tolist()
    categorical_features: List[str] = df.select_dtypes(exclude=[np.number]).columns.tolist()

    # Exclude target from feature lists if present
    if target_col in numeric_features:
        numeric_features.remove(target_col)
    if target_col in categorical_features:
        categorical_features.remove(target_col)

    # Missing values check
    missing_counts = df.isnull().sum()
    total_missing = int(missing_counts.sum())
    cols_with_missing = {col: int(cnt) for col, cnt in missing_counts.items() if cnt > 0}

    # Infinite values check
    inf_counts = 0
    cols_with_inf = {}
    for col in numeric_features:
        infs = int(np.isinf(df[col]).sum())
        if infs > 0:
            cols_with_inf[col] = infs
            inf_counts += infs

    print(f"Total records: {total_records:,}")
    print(f"Total columns: {total_columns}")
    print(f"Target column: {target_col}")
    print(f"Number of classes: {num_classes}")
    print(f"Class names: {classes}")
    print(f"Numeric features detected: {len(numeric_features)}")
    print(f"Categorical features detected: {len(categorical_features)}")
    print(f"Total missing values: {total_missing:,} across {len(cols_with_missing)} columns")
    print(f"Total infinite values: {inf_counts:,} across {len(cols_with_inf)} columns")
    print("\nClass distribution:")
    for cls_name, count in class_counts.items():
        pct = (count / total_records) * 100
        print(f"  - {cls_name:<20}: {count:>10,} ({pct:>6.2f}%)")

    inspection_summary = {
        "total_records": total_records,
        "total_columns": total_columns,
        "target_col": target_col,
        "num_classes": num_classes,
        "classes": classes,
        "class_counts": class_counts,
        "numeric_features": numeric_features,
        "categorical_features": categorical_features,
        "total_missing": total_missing,
        "cols_with_missing": cols_with_missing,
        "total_inf": inf_counts,
        "cols_with_inf": cols_with_inf,
        "csv_path": str(csv_path),
    }

    return df, inspection_summary
