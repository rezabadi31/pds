"""inspector.py
Part 1: Data Loading & Inspection
Loads the balanced dataset, converts timestamps, inspects dataset dimensions,
schema, unique entities, and exports outputs/reports/data_inspection_report.txt.
"""

from typing import Dict, Any, Tuple
import pandas as pd
from src.config import PRIMARY_INPUT_CSV, DATA_INSPECTION_REPORT_TXT


def load_and_inspect_dataset() -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Loads the balanced dataset and performs comprehensive initial inspection."""
    print("=" * 60)
    print("PART 1 — DATA LOADING & INSPECTION")
    print("=" * 60)

    if not PRIMARY_INPUT_CSV.exists():
        raise FileNotFoundError(f"Primary input dataset not found at: {PRIMARY_INPUT_CSV}")

    # Load dataset
    df = pd.read_csv(PRIMARY_INPUT_CSV)
    num_records, num_columns = df.shape

    # Inspect missing values and duplicate rows
    missing_counts = df.isnull().sum()
    total_missing = int(missing_counts.sum())
    duplicate_rows = int(df.duplicated().sum())

    # Timestamp conversion
    if "timestamp" in df.columns:
        df["timestamp_raw"] = df["timestamp"]
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        valid_timestamps = int(df["timestamp"].notnull().sum())
        invalid_timestamps = int(df["timestamp"].isnull().sum())
    else:
        print("[timestamp] unavailable — corresponding analysis skipped.")
        valid_timestamps = 0
        invalid_timestamps = 0

    # Entity uniqueness
    unique_ips = int(df["client_ip"].nunique()) if "client_ip" in df.columns else 0
    unique_labels = int(df["label"].nunique()) if "label" in df.columns else 0
    unique_request_types = int(df["request_type"].nunique()) if "request_type" in df.columns else 0

    meta: Dict[str, Any] = {
        "num_records": num_records,
        "num_columns": num_columns,
        "total_missing": total_missing,
        "duplicate_rows": duplicate_rows,
        "valid_timestamps": valid_timestamps,
        "invalid_timestamps": invalid_timestamps,
        "unique_ips": unique_ips,
        "unique_labels": unique_labels,
        "unique_request_types": unique_request_types,
        "columns": df.columns.tolist(),
        "dtypes": {col: str(dtype) for col, dtype in df.dtypes.items()},
    }

    # Print summary metrics to console
    print(f"Total Records:        {num_records:,}")
    print(f"Total Columns:        {num_columns}")
    print(f"Valid Timestamps:     {valid_timestamps:,}")
    print(f"Invalid Timestamps:   {invalid_timestamps}")
    print(f"Unique IPs:           {unique_ips:,}")
    print(f"Unique Labels:        {unique_labels}")
    print(f"Unique Request Types: {unique_request_types}")
    print(f"Duplicate Rows:       {duplicate_rows:,}")
    print(f"Total Missing Values: {total_missing:,}")
    print()
    print("First 5 rows preview:")
    preview_cols = [c for c in ["client_ip", "timestamp", "label", "request_type", "status_code", "user_agent"] if c in df.columns]
    if not preview_cols:
        preview_cols = df.columns[:6].tolist()
    print(df[preview_cols].head())

    # Save outputs/reports/data_inspection_report.txt
    with open(DATA_INSPECTION_REPORT_TXT, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("PRACTICAL 7: DATA INSPECTION REPORT\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Source Dataset:       {PRIMARY_INPUT_CSV}\n")
        f.write(f"Total Records:        {num_records:,}\n")
        f.write(f"Total Columns:        {num_columns}\n")
        f.write(f"Valid Timestamps:     {valid_timestamps:,}\n")
        f.write(f"Invalid Timestamps:   {invalid_timestamps}\n")
        f.write(f"Unique IPs:           {unique_ips:,}\n")
        f.write(f"Unique Labels:        {unique_labels}\n")
        f.write(f"Unique Request Types: {unique_request_types}\n")
        f.write(f"Duplicate Rows:       {duplicate_rows:,}\n")
        f.write(f"Total Missing Values: {total_missing:,}\n\n")

        f.write("Label Value Counts:\n")
        if "label" in df.columns:
            for lbl, cnt in df["label"].value_counts().items():
                pct = (cnt / num_records) * 100
                f.write(f"  - {lbl:<20}: {cnt:>8,} ({pct:6.2f}%)\n")
        f.write("\n")

        f.write("Column Names & Data Types:\n")
        for col, dt in meta["dtypes"].items():
            f.write(f"  - {col:<30}: {dt}\n")

    print(f"\nInspection report saved to: {DATA_INSPECTION_REPORT_TXT.name}")
    return df, meta
