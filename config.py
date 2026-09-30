"""config.py
Log Intelligence Platform — Central Configuration
Defines the dark color system, project paths, baseline metrics, and practical index.
"""

from pathlib import Path

# Base Paths
PROJECT_ROOT = Path(__file__).resolve().parent

# Practical Directory Registry
PRACTICAL_DIRS = {
    i: PROJECT_ROOT / f"Practical {i}" for i in range(1, 11)
}

# Dark Cybersecurity Product Color System
THEME = {
    "bg": "#080B12",               # Darkest background
    "bg_secondary": "#10151F",     # Secondary surface background
    "card_bg": "#151B26",          # Default card background
    "card_elevated": "#1B2330",    # Hover/elevated card background
    "text_primary": "#F5F7FA",     # Main heading & high contrast text
    "text_secondary": "#A7B0BE",   # Subtitle & body text
    "accent": "#6C63FF",           # Neon purple/indigo accent
    "accent_secondary": "#00D9FF", # Cyan secondary accent
    "success": "#39D98A",          # Green success
    "warning": "#FFB547",          # Amber warning
    "danger": "#FF5C7A",           # Crimson danger
    "border": "rgba(255, 255, 255, 0.08)", # Subtle dark borders
    "border_highlight": "rgba(108, 99, 255, 0.3)",
}

# Empirical Baseline Numbers (Verified from Project Files)
BASELINE_METRICS = {
    "raw_records": 2_061_431,
    "raw_size_mb": 215.40,
    "physical_lines": 2_062_365,
    "structured_records": 2_062_361,
    "duplicates_removed": 570_179,
    "preprocessed_records": 1_492_182,
    "attack_classes": 6,
    "total_attacks": 4_359,
    "benign_records": 1_487_823,
    "engineered_features_total": 66,
    "pipeline_features_count": 26,
    "imbalance_ratio": "9,298.89 : 1",
    "balanced_train_records": 60_000,
    "untouched_test_records": 298_437,
    "wrangled_records": 59_497,
    "rf_accuracy": 0.999705,
    "rf_macro_f1": 0.952579,
    "lr_accuracy": 0.970744,
    "lr_macro_f1": 0.451820,
    "pipeline_runtime_sec": 108.67,
    "parquet_compression_reduction": "97.8%",
    "pipeline_status": "READY",
}

# 10 Practicals Product Index
PRACTICAL_INDEX = [
    {
        "id": 1,
        "number_str": "Practical 01",
        "title": "Access Log Data Exploration",
        "short_title": "Access Log Data Exploration",
        "one_liner": "Stream-read raw honeypot JSON arrays, audit 2.06M lines, and explore schema characteristics.",
        "icon": "📥",
        "stage": "Ingestion",
        "status": "COMPLETED",
        "badge_color": "#6C63FF",
    },
    {
        "id": 2,
        "number_str": "Practical 02",
        "title": "Convert Unstructured Logs into Structured Dataset",
        "short_title": "Convert Unstructured Logs into Structured Dataset",
        "one_liner": "Transform serialized JSON logs into a canonical 13-column tabular dataset with 100% parsing success.",
        "icon": "🧱",
        "stage": "Structuring",
        "status": "COMPLETED",
        "badge_color": "#00D9FF",
    },
    {
        "id": 3,
        "number_str": "Practical 03",
        "title": "Data Cleaning & Preprocessing",
        "short_title": "Data Cleaning & Preprocessing",
        "one_liner": "Deduplicate 570,179 rows, resolve 18.4M missing values, parse timestamps, and normalize URLs.",
        "icon": "🧹",
        "stage": "Preprocessing",
        "status": "COMPLETED",
        "badge_color": "#39D98A",
    },
    {
        "id": 4,
        "number_str": "Practical 04",
        "title": "Basic Attack Classification",
        "short_title": "Basic Attack Classification",
        "one_liner": "Apply deterministic signature regexes & temporal rolling rules across 6 security classes.",
        "icon": "🏷️",
        "stage": "Ground Truth",
        "status": "COMPLETED",
        "badge_color": "#FF5C7A",
    },
    {
        "id": 5,
        "number_str": "Practical 05",
        "title": "Feature Engineering",
        "short_title": "Feature Engineering",
        "one_liner": "Engineer 66 behavioral, lexical, rate, Featuretools, and tsfresh features without label leakage.",
        "icon": "⚙️",
        "stage": "Feature Engineering",
        "status": "COMPLETED",
        "badge_color": "#6C63FF",
    },
    {
        "id": 6,
        "number_str": "Practical 06",
        "title": "Dataset Balancing",
        "short_title": "Dataset Balancing",
        "one_liner": "Mitigate 9,298:1 imbalance using SMOTE on training split (60k) while preserving 298k test records.",
        "icon": "⚖️",
        "stage": "Balancing",
        "status": "COMPLETED",
        "badge_color": "#FFB547",
    },
    {
        "id": 7,
        "number_str": "Practical 07",
        "title": "Data Wrangling",
        "short_title": "Data Wrangling",
        "one_liner": "Generate IP attack profiles, hourly/daily time-series, cross-tabs, and filter automated bots.",
        "icon": "🔄",
        "stage": "Wrangling",
        "status": "COMPLETED",
        "badge_color": "#00D9FF",
    },
    {
        "id": 8,
        "number_str": "Practical 08",
        "title": "Data Visualization & EDA",
        "short_title": "Data Visualization & EDA",
        "one_liner": "Analyze 15 exploratory static charts and interactive Plotly visual dashboards across telemetry dimensions.",
        "icon": "📊",
        "stage": "Exploratory Analysis",
        "status": "COMPLETED",
        "badge_color": "#6C63FF",
    },
    {
        "id": 9,
        "number_str": "Practical 09",
        "title": "Simple Attack Classifier",
        "short_title": "Simple Attack Classifier",
        "one_liner": "Compare Logistic Regression vs Random Forest on natural split and SMOTE-balanced training.",
        "icon": "🛡️",
        "stage": "Machine Learning",
        "status": "COMPLETED",
        "badge_color": "#39D98A",
    },
    {
        "id": 10,
        "number_str": "Practical 10",
        "title": "Reusable Log Processing Pipeline",
        "short_title": "Reusable Log Processing Pipeline",
        "one_liner": "Execute automated 7-stage CLI & Python pipeline in 108s with 97.8% Parquet compression.",
        "icon": "🚀",
        "stage": "Production Pipeline",
        "status": "COMPLETED",
        "badge_color": "#00D9FF",
    },
]
