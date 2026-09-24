"""metrics.py
Metric Extraction and Synthesis Utilities
Pulls authoritative numbers from generated reports and CSV outputs across Practicals 1 to 10.
"""

from pathlib import Path
from typing import Dict, Any, Optional
import pandas as pd
from config import PRACTICAL_DIRS, PROJECT_BASELINE_METRICS
from utils.data_loader import read_json_data, read_text_report


def get_model_comparison_metrics() -> pd.DataFrame:
    """Reads model comparison table from Practical 9 or returns baseline."""
    comp_csv = PRACTICAL_DIRS[9] / "outputs" / "data" / "model_comparison.csv"
    if comp_csv.exists():
        try:
            return pd.read_csv(comp_csv)
        except Exception:
            pass

    # Baseline fallback
    data = [
        {
            "Model": "Logistic Regression",
            "Accuracy": 0.9707,
            "Macro Precision": 0.3867,
            "Macro Recall": 0.9845,
            "Macro F1": 0.4518,
            "Weighted Precision": 0.9984,
            "Weighted Recall": 0.9707,
            "Weighted F1": 0.9841,
        },
        {
            "Model": "Random Forest",
            "Accuracy": 0.9997,
            "Macro Precision": 0.9308,
            "Macro Recall": 0.9763,
            "Macro F1": 0.9526,
            "Weighted Precision": 0.9997,
            "Weighted Recall": 0.9997,
            "Weighted F1": 0.9997,
        },
    ]
    return pd.DataFrame(data)


def get_balanced_experiment_metrics() -> Optional[pd.DataFrame]:
    """Reads Part 13 balanced experiment comparison from Practical 9."""
    csv_file = PRACTICAL_DIRS[9] / "outputs" / "data" / "balanced_experiment_comparison.csv"
    if csv_file.exists():
        try:
            return pd.read_csv(csv_file)
        except Exception:
            pass
    return None


def get_rf_feature_importance_df(top_n: int = 20) -> Optional[pd.DataFrame]:
    """Reads top feature importances from Practical 9."""
    csv_file = PRACTICAL_DIRS[9] / "outputs" / "data" / "random_forest_feature_importance.csv"
    if csv_file.exists():
        try:
            df = pd.read_csv(csv_file)
            return df.head(top_n)
        except Exception:
            pass
    return None


def get_class_distribution_dict() -> Dict[str, int]:
    """Retrieves class distribution from Practical 4 or Practical 10 summary."""
    p10_json = PRACTICAL_DIRS[10] / "outputs" / "pipeline_summary.json"
    if p10_json.exists():
        summary = read_json_data(p10_json)
        if summary and "label_distribution" in summary:
            return summary["label_distribution"]

    p4_csv = PRACTICAL_DIRS[4] / "outputs" / "reports" / "label_distribution.csv"
    if p4_csv.exists():
        try:
            df = pd.read_csv(p4_csv)
            if "label" in df.columns and "count" in df.columns:
                return dict(zip(df["label"], df["count"]))
        except Exception:
            pass

    return PROJECT_BASELINE_METRICS["class_distribution"]


def get_home_metrics() -> Dict[str, Any]:
    """Aggregates high-level project summary metrics for the Home dashboard."""
    metrics = PROJECT_BASELINE_METRICS.copy()

    # Try reading dynamic values from Practical 10 summary
    p10_json = PRACTICAL_DIRS[10] / "outputs" / "pipeline_summary.json"
    if p10_json.exists():
        summary = read_json_data(p10_json)
        if summary:
            metrics["raw_records"] = summary.get("raw_records", metrics["raw_records"])
            metrics["structured_records"] = summary.get("structured_records", metrics["structured_records"])
            metrics["preprocessed_records"] = summary.get("preprocessed_records", metrics["preprocessed_records"])
            metrics["duplicates_removed"] = summary.get("duplicates_removed", metrics["duplicates_removed"])

    # Try reading model metrics from Practical 9
    comp_df = get_model_comparison_metrics()
    if not comp_df.empty:
        rf_row = comp_df[comp_df["Model"].str.contains("Random Forest", case=False, na=False)]
        if not rf_row.empty:
            metrics["rf_accuracy"] = float(rf_row["Accuracy"].iloc[0])
            metrics["rf_macro_f1"] = float(rf_row["Macro F1"].iloc[0])

        lr_row = comp_df[comp_df["Model"].str.contains("Logistic", case=False, na=False)]
        if not lr_row.empty:
            metrics["lr_accuracy"] = float(lr_row["Accuracy"].iloc[0])
            metrics["lr_macro_f1"] = float(lr_row["Macro F1"].iloc[0])

    return metrics
