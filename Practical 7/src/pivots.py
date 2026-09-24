"""pivots.py
Part 6: Request Type × Label Pivot Table & Percentages
Part 7: Status Code × Label Pivot Table & Error Rates
"""

from typing import Tuple, Dict, Any, Optional
import pandas as pd
from pathlib import Path
from src.config import (
    REQUEST_TYPE_PIVOT_CSV,
    REQUEST_TYPE_PCT_CSV,
    STATUS_CODE_PIVOT_CSV,
)


def create_request_type_pivot(
    df: pd.DataFrame,
    export_pivot_path: Path = REQUEST_TYPE_PIVOT_CSV,
    export_pct_path: Path = REQUEST_TYPE_PCT_CSV,
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Analyzes the relationship between request_type and label."""
    print("\n" + "=" * 60)
    print("PART 6 — REQUEST TYPE × LABEL PIVOT TABLE")
    print("=" * 60)

    if "request_type" not in df.columns or "label" not in df.columns:
        print("[request_type] unavailable — pivot analysis skipped.")
        return pd.DataFrame(), pd.DataFrame()

    pivot = pd.crosstab(df["request_type"], df["label"])
    pivot = pivot.reset_index()

    export_pivot_path.parent.mkdir(parents=True, exist_ok=True)
    pivot.to_csv(export_pivot_path, index=False)
    print(f"Exported Request Type × Label Pivot to: {export_pivot_path.name}")

    # Row-wise percentages
    pct_pivot = pivot.copy()
    label_cols = [c for c in pivot.columns if c != "request_type"]
    row_sums = pct_pivot[label_cols].sum(axis=1)
    for col in label_cols:
        pct_pivot[col] = (pct_pivot[col] / row_sums * 100).round(2)

    export_pct_path.parent.mkdir(parents=True, exist_ok=True)
    pct_pivot.to_csv(export_pct_path, index=False)
    print(f"Exported Request Type × Label Percentage Table to: {export_pct_path.name}")

    print("\nRequest Type × Label Pivot Sample:")
    print(pivot)

    return pivot, pct_pivot


def create_status_code_pivot(
    df: pd.DataFrame,
    export_path: Path = STATUS_CODE_PIVOT_CSV,
) -> Tuple[pd.DataFrame, Dict[str, float]]:
    """Analyzes the relationship between HTTP status_code and label."""
    print("\n" + "=" * 60)
    print("PART 7 — STATUS CODE × LABEL ANALYSIS")
    print("=" * 60)

    if "status_code" not in df.columns or "label" not in df.columns:
        print("[status_code] unavailable — corresponding analysis skipped.")
        return pd.DataFrame(), {}

    # Format status code as clean integer string
    df_clean = df.copy()
    df_clean["status_code"] = pd.to_numeric(df_clean["status_code"], errors="coerce").fillna(0).astype(int)

    pivot = pd.crosstab(df_clean["status_code"], df_clean["label"]).reset_index()
    export_path.parent.mkdir(parents=True, exist_ok=True)
    pivot.to_csv(export_path, index=False)
    print(f"Exported Status Code × Label Pivot to: {export_path.name}")

    # Calculate 4xx and 5xx error rates
    total_reqs = len(df_clean)
    codes = df_clean["status_code"]
    count_4xx = int(((codes >= 400) & (codes < 500)).sum())
    count_5xx = int(((codes >= 500) & (codes < 600)).sum())
    rate_4xx = round(count_4xx / total_reqs * 100, 2) if total_reqs > 0 else 0.0
    rate_5xx = round(count_5xx / total_reqs * 100, 2) if total_reqs > 0 else 0.0

    rates = {
        "count_4xx": count_4xx,
        "rate_4xx": rate_4xx,
        "count_5xx": count_5xx,
        "rate_5xx": rate_5xx,
    }

    print(f"Total 4xx Client Errors: {count_4xx:,} ({rate_4xx}%)")
    print(f"Total 5xx Server Errors: {count_5xx:,} ({rate_5xx}%)")
    print("\nStatus Code × Label Pivot Sample:")
    print(pivot.head(5))

    return pivot, rates
