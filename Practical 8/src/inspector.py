"""inspector.py
Part 1: Data Ingestion and Schema Inspection
Loads the dataset, parses timestamps, extracts structural statistics,
and prints the required EDA DATASET INFORMATION block.
"""

from typing import Tuple, Dict, Any
import pandas as pd
from pathlib import Path
from src.config import PRIMARY_INPUT_CSV, FALLBACK_INPUT_CSV


def inspect_and_load_dataset() -> Tuple[pd.DataFrame, Dict[str, Any], Path]:
    """Loads and inspects the cybersecurity dataset."""
    # Determine active input source
    if PRIMARY_INPUT_CSV.exists():
        input_path = PRIMARY_INPUT_CSV
    elif FALLBACK_INPUT_CSV.exists():
        input_path = FALLBACK_INPUT_CSV
    else:
        raise FileNotFoundError(
            f"Neither primary ({PRIMARY_INPUT_CSV}) nor fallback ({FALLBACK_INPUT_CSV}) dataset found!"
        )

    df = pd.read_csv(input_path)
    num_records, num_columns = df.shape

    # Missing values and duplicates
    missing_values = int(df.isnull().sum().sum())
    duplicate_records = int(df.duplicated().sum())

    # Timestamp conversion
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        valid_timestamps = int(df["timestamp"].notnull().sum())
    else:
        valid_timestamps = 0

    # Entity uniqueness
    unique_ips = int(df["client_ip"].nunique()) if "client_ip" in df.columns else 0
    unique_labels = int(df["label"].nunique()) if "label" in df.columns else 0
    unique_request_types = int(df["request_type"].nunique()) if "request_type" in df.columns else 0
    unique_status_codes = int(df["status_code"].nunique()) if "status_code" in df.columns else 0

    meta: Dict[str, Any] = {
        "input_path": str(input_path),
        "num_records": num_records,
        "num_columns": num_columns,
        "unique_ips": unique_ips,
        "unique_labels": unique_labels,
        "unique_request_types": unique_request_types,
        "unique_status_codes": unique_status_codes,
        "valid_timestamps": valid_timestamps,
        "missing_values": missing_values,
        "duplicate_records": duplicate_records,
        "columns": df.columns.tolist(),
    }

    # REQUIRED TERMINAL BLOCK (PART 1)
    print("=" * 60)
    print("EDA DATASET INFORMATION")
    print("=" * 60)
    print()
    print(f"Total Records:        {num_records:,}")
    print(f"Total Columns:        {num_columns}")
    print(f"Unique IPs:           {unique_ips:,}")
    print(f"Unique Labels:        {unique_labels}")
    print(f"Unique Request Types: {unique_request_types}")
    print(f"Unique Status Codes:  {unique_status_codes}")
    print(f"Valid Timestamps:     {valid_timestamps:,}")
    print(f"Missing Values:       {missing_values:,}")
    print()

    return df, meta, input_path
