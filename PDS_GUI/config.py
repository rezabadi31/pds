"""config.py
PDS_GUI Configuration and Practical Paths
Centralizes directory references, file status mappings, and constants.
"""

from pathlib import Path

# Base Paths
GUI_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = GUI_ROOT.parent

# Practical Roots
PRACTICAL_DIRS = {
    i: PROJECT_ROOT / f"Practical {i}" for i in range(1, 11)
}

# Key Artifact and Output Definitions for Status Tracking
EXPECTED_OUTPUTS = {
    1: {
        "title": "Data Inspection",
        "primary_file": PRACTICAL_DIRS[1] / "data" / "raw" / "cj.log",
        "report_file": PRACTICAL_DIRS[1] / "outputs" / "reports" / "inspection_report.txt",
        "runner_script": PRACTICAL_DIRS[1] / "run_practical1.py",
        "description": "Raw honeypot access log inspection and characterization.",
    },
    2: {
        "title": "Log Parsing & Structuring",
        "primary_file": PRACTICAL_DIRS[2] / "data" / "processed" / "structured_access_logs.csv",
        "report_file": PRACTICAL_DIRS[2] / "outputs" / "reports" / "parsing_report.txt",
        "runner_script": PRACTICAL_DIRS[2] / "run_practical2.py",
        "description": "Unstructured JSON array parsing into 13-column structured dataset.",
    },
    3: {
        "title": "Data Cleaning & Preprocessing",
        "primary_file": PRACTICAL_DIRS[3] / "data" / "processed" / "preprocessed_access_logs.csv",
        "report_file": PRACTICAL_DIRS[3] / "outputs" / "reports" / "preprocessing_report.txt",
        "runner_script": PRACTICAL_DIRS[3] / "run_practical3.py",
        "description": "Timestamp conversion, exact deduplication, imputation, and URL normalization.",
    },
    4: {
        "title": "Attack Labeling",
        "primary_file": PRACTICAL_DIRS[4] / "data" / "processed" / "labeled_access_logs.csv",
        "report_file": PRACTICAL_DIRS[4] / "outputs" / "reports" / "labeling_report.txt",
        "runner_script": PRACTICAL_DIRS[4] / "run_practical4.py",
        "description": "Deterministic rule-based multi-class attack labeling (6 classes).",
    },
    5: {
        "title": "Feature Engineering",
        "primary_file": PRACTICAL_DIRS[5] / "data" / "processed" / "feature_engineered_access_logs.csv",
        "report_file": PRACTICAL_DIRS[5] / "outputs" / "reports" / "feature_engineering_report.txt",
        "runner_script": PRACTICAL_DIRS[5] / "run_practical5.py",
        "description": "66 behavioral, lexical, rate, Featuretools, and tsfresh features.",
    },
    6: {
        "title": "Dataset Balancing",
        "primary_file": PRACTICAL_DIRS[6] / "data" / "processed" / "balanced_training_dataset.csv",
        "report_file": PRACTICAL_DIRS[6] / "outputs" / "reports" / "balancing_report.txt",
        "runner_script": PRACTICAL_DIRS[6] / "run_practical6.py",
        "description": "Mitigating 9,298:1 class imbalance using SMOTE on training data only.",
    },
    7: {
        "title": "Data Wrangling",
        "primary_file": PRACTICAL_DIRS[7] / "data" / "processed" / "wrangled_filtered_dataset.csv",
        "report_file": PRACTICAL_DIRS[7] / "outputs" / "reports" / "wrangling_report.txt",
        "runner_script": PRACTICAL_DIRS[7] / "run_practical7.py",
        "description": "Multi-dimensional aggregations, IP pivot analysis, and time-series rollups.",
    },
    8: {
        "title": "Data Visualization & EDA",
        "primary_file": PRACTICAL_DIRS[8] / "outputs" / "plots" / "01_requests_per_hour.png",
        "report_file": PRACTICAL_DIRS[8] / "outputs" / "reports" / "visualization_report.txt",
        "runner_script": PRACTICAL_DIRS[8] / "run_practical8.py",
        "description": "Comprehensive exploratory data analysis and 15 security visualization charts.",
    },
    9: {
        "title": "Simple Attack Classifier",
        "primary_file": PRACTICAL_DIRS[9] / "outputs" / "models" / "random_forest.joblib",
        "report_file": PRACTICAL_DIRS[9] / "outputs" / "reports" / "classifier_report.txt",
        "runner_script": PRACTICAL_DIRS[9] / "run_practical9.py",
        "description": "Logistic Regression vs. Random Forest attack classification and evaluation.",
    },
    10: {
        "title": "Reusable Data Pipeline",
        "primary_file": PRACTICAL_DIRS[10] / "data" / "processed" / "feature_engineered_logs.parquet",
        "report_file": PRACTICAL_DIRS[10] / "reports" / "pipeline_report.txt",
        "runner_script": PRACTICAL_DIRS[10] / "run_pipeline.py",
        "description": "Automated 7-stage reusable CLI pipeline with Parquet serialization.",
    },
}

# Empirical Baseline Project Metrics
PROJECT_BASELINE_METRICS = {
    "raw_records": 2_061_431,
    "raw_size_mb": 215.40,
    "structured_records": 2_062_226,
    "duplicates_removed": 570_179,
    "preprocessed_records": 1_492_047,
    "classes_count": 6,
    "engineered_features_count": 66,
    "balanced_train_records": 60_000,
    "untouched_test_records": 298_437,
    "rf_accuracy": 0.9997,
    "rf_macro_f1": 0.9526,
    "lr_accuracy": 0.9707,
    "lr_macro_f1": 0.4518,
    "class_distribution": {
        "benign": 1_487_682,
        "brute_force": 1_342,
        "path_traversal": 1_098,
        "xss": 960,
        "command_injection": 805,
        "sqli": 160,
    },
}

# Theme Colors (Professional academic palette)
THEME_COLORS = {
    "primary": "#1e40af",      # Academic Navy Blue
    "secondary": "#0d9488",    # Teal
    "accent": "#2563eb",       # Royal Blue
    "success": "#16a34a",      # Green
    "warning": "#d97706",      # Amber
    "danger": "#dc2626",       # Red
    "background": "#f8fafc",   # Light Slate
    "card_bg": "#ffffff",      # Pure White
    "text": "#0f172a",         # Deep Navy / Black
    "muted": "#64748b",        # Slate Gray
}
