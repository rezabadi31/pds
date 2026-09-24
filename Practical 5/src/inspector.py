"""inspector.py
Step 1: Ingestion and Automated Dataset Inspection for Practical 5.
"""

from typing import Dict, Any, Tuple
import pandas as pd
from pathlib import Path
from src.config import PRACTICAL4_CSV, PRACTICAL3_CSV


def inspect_and_load_dataset() -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Loads the access-log dataset and runs automated exploratory inspection.
    
    Checks Practical 4 first; falls back to Practical 3 if Practical 4 is not found.
    Preserves all original records and detects available schemas.
    """
    if PRACTICAL4_CSV.exists():
        input_path = PRACTICAL4_CSV
        source_desc = f"Practical 4 labeled dataset: {PRACTICAL4_CSV}"
        practical4_available = True
    elif PRACTICAL3_CSV.exists():
        input_path = PRACTICAL3_CSV
        source_desc = f"Practical 3 preprocessed dataset: {PRACTICAL3_CSV} (Practical 4 labeled data was UNAVAILABLE)"
        practical4_available = False
    else:
        raise FileNotFoundError(
            f"Neither Practical 4 ({PRACTICAL4_CSV}) nor Practical 3 ({PRACTICAL3_CSV}) datasets were found."
        )

    print("=" * 60)
    print("STEP 1 - DATA INSPECTION & INGESTION")
    print("=" * 60)
    print(f"Loading input dataset from:\n  -> {input_path}")
    if not practical4_available:
        print("  [NOTICE] Practical 4 labeled data was UNAVAILABLE; falling back to Practical 3.")

    df = pd.read_csv(input_path, low_memory=False)
    num_rows, num_cols = df.shape
    columns = list(df.columns)
    
    dtypes = {col: str(dtype) for col, dtype in df.dtypes.items()}
    missing_vals = df.isnull().sum().to_dict()
    
    unique_ips = int(df["client_ip"].nunique()) if "client_ip" in df.columns else 0
    unique_user_agents = int(df["user_agent"].nunique()) if "user_agent" in df.columns else 0
    
    if "timestamp" in df.columns:
        min_time = str(df["timestamp"].min())
        max_time = str(df["timestamp"].max())
    else:
        min_time = "N/A"
        max_time = "N/A"

    print(f"\nDataset Dimensions : {num_rows:,} rows x {num_cols} columns")
    print(f"Unique Client IPs  : {unique_ips:,}")
    print(f"Unique User Agents : {unique_user_agents:,}")
    print(f"Time Range         : {min_time}  -->  {max_time}")
    print("\nDetected Columns & Data Types:")
    for col in columns:
        missing = missing_vals.get(col, 0)
        print(f"  - {col:<22} : {dtypes[col]:<10} (Missing: {missing:,})")

    has_status_code = "status_code" in df.columns or "status" in df.columns or "http_status" in df.columns
    print(f"\nStatus Code Field Available: {has_status_code}")

    metadata = {
        "input_path": str(input_path),
        "source_desc": source_desc,
        "practical4_available": practical4_available,
        "rows": num_rows,
        "cols": num_cols,
        "columns": columns,
        "dtypes": dtypes,
        "missing_values": missing_vals,
        "unique_ips": unique_ips,
        "unique_user_agents": unique_user_agents,
        "min_time": min_time,
        "max_time": max_time,
        "has_status_code": has_status_code,
    }

    return df, metadata
