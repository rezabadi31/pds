"""inspector.py
Part 1 & Part 2: Dataset Ingestion, Inspection, and Class Imbalance Profiling
Analyzes the distribution of benign vs. attack classes across all security categories.
"""

from typing import Tuple, Dict, Any
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from src.config import INPUT_CSV, PLOTS_DIR


def inspect_dataset() -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Loads the Practical 5 feature-engineered dataset and inspects schema and distributions."""
    if not INPUT_CSV.exists():
        raise FileNotFoundError(
            f"Input dataset not found at: {INPUT_CSV}\n"
            "Please ensure Practical 5 has completed and generated feature_engineered_access_logs.csv."
        )

    print(f"Loading feature-engineered telemetry dataset from:\n  -> {INPUT_CSV}")
    df = pd.read_csv(INPUT_CSV, low_memory=False)

    num_rows, num_cols = df.shape
    target_col = "label" if "label" in df.columns else None
    if target_col is None:
        raise ValueError("Target column 'label' was not found in the input dataset.")

    # Distinct classes
    classes = df[target_col].dropna().unique().tolist()
    num_classes = len(classes)

    # Missing & Infinite Values
    num_missing = int(df.isnull().sum().sum())
    
    # Check infinite values in numeric columns
    numeric_df = df.select_dtypes(include=[np.number])
    num_inf = int(np.isinf(numeric_df.values).sum())

    print("\n" + "=" * 60)
    print("DATASET INFORMATION")
    print("============================================================")
    print()
    print(f"Total Records:      {num_rows:,}")
    print(f"Total Columns:      {num_cols}")
    print(f"Target Column:      {target_col}")
    print(f"Number of Classes:  {num_classes}")
    print(f"Class Names:        {classes}")
    print(f"Total Missing:      {num_missing:,}")
    print(f"Total Infinite:     {num_inf:,}")
    print()

    # Part 2: Class Distribution Analysis
    print("=" * 60)
    print("PART 2 — CLASS DISTRIBUTION & IMBALANCE RATIO")
    print("=" * 60)
    print()

    counts = df[target_col].value_counts()
    dist_records = []
    for cls_name, count in counts.items():
        pct = (count / num_rows) * 100
        dist_records.append({
            "Class": cls_name,
            "Count": count,
            "Percentage": f"{pct:.4f}%",
            "pct_num": pct,
        })

    dist_df = pd.DataFrame(dist_records)
    print(f"{'Class':<22} | {'Count':<12} | {'Percentage':<12}")
    print("-" * 52)
    for _, r in dist_df.iterrows():
        print(f"{r['Class']:<22} | {r['Count']:<12,} | {r['Percentage']:<12}")

    majority_class = counts.index[0]
    majority_count = counts.iloc[0]
    minority_class = counts.index[-1]
    minority_count = counts.iloc[-1]
    imbalance_ratio = majority_count / minority_count if minority_count > 0 else np.nan

    print()
    print(f"Majority Class:   {majority_class} ({majority_count:,} records)")
    print(f"Minority Class:   {minority_class} ({minority_count:,} records)")
    print(f"Imbalance Ratio:  {imbalance_ratio:,.2f} : 1")
    print()

    # Create outputs\plots\original_class_distribution.png
    fig, ax = plt.subplots(figsize=(9, 5.5), dpi=300)
    labels = list(counts.index)
    values = list(counts.values)
    colors = ["#2563eb", "#d97706", "#dc2626", "#9333ea", "#059669", "#e11d48"][:len(labels)]

    bars = ax.bar(labels, values, color=colors, edgecolor="#1e293b", width=0.55)
    ax.set_yscale("log")
    ax.set_title("Original Dataset Class Distribution (Log Scale)", fontsize=12, fontweight="bold", pad=12)
    ax.set_xlabel("Traffic Category", fontsize=10, labelpad=8)
    ax.set_ylabel("Record Count (Logarithmic Scale)", fontsize=10, labelpad=8)
    ax.grid(True, linestyle="--", alpha=0.5, axis="y")

    for bar, val in zip(bars, values):
        p = (val / num_rows) * 100
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() * 1.25,
            f"{val:,}\n({p:.2f}%)",
            ha="center",
            va="bottom",
            fontsize=8.5,
            fontweight="semibold",
            color="#0f172a",
        )

    plt.tight_layout()
    p_orig = PLOTS_DIR / "original_class_distribution.png"
    plt.savefig(p_orig)
    plt.close()
    print(f"Saved original distribution chart to: {p_orig.name}")

    meta = {
        "num_rows": num_rows,
        "num_cols": num_cols,
        "target_col": target_col,
        "classes": classes,
        "num_classes": num_classes,
        "counts": counts.to_dict(),
        "majority_class": majority_class,
        "majority_count": majority_count,
        "minority_class": minority_class,
        "minority_count": minority_count,
        "imbalance_ratio": imbalance_ratio,
        "dist_df": dist_df,
    }

    return df, meta
