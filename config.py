"""config.py
Rox Log Intelligence Platform — Central Configuration
Defines the dark color system, project paths, empirical baseline metrics, and practical index.
Works completely portably across Local Streamlit and Streamlit Community Cloud without absolute paths.
"""

from pathlib import Path

# Base Paths (Strictly Relative to Repository Root)
PROJECT_ROOT = Path(__file__).resolve().parent
ASSETS_DIR = PROJECT_ROOT / "assets"
METADATA_DIR = PROJECT_ROOT / "metadata"
DATA_DIR = PROJECT_ROOT / "data"

# Practical Directory Registry (for development/inspection, falls back to assets on Cloud)
PRACTICAL_DIRS = {
    i: PROJECT_ROOT / f"Practical {i}" for i in range(1, 11)
}

# Dark Cybersecurity Product Color System
THEME = {
    "bg": "#060912",               # Darkest background
    "bg_sidebar": "#080D17",       # Compact sidebar background
    "card_bg": "#101827",          # Main card background
    "card_elevated": "#151E2E",    # Elevated card background
    "border": "rgba(120, 180, 255, 0.12)", # Subtle blue/cyan border
    "border_hover": "rgba(34, 211, 238, 0.35)",
    "text_primary": "#F4F7FB",     # Main heading & high contrast text
    "text_secondary": "#8E9BAD",   # Subtitle & body text
    "text_muted": "#5A6678",       # Muted text
    "accent_cyan": "#22D3EE",      # Cyan accent
    "accent_blue": "#1687FF",      # Blue accent
    "success": "#21D98B",          # Green success
    "danger": "#FF5577",           # Red danger
    "warning": "#FFB547",          # Amber warning
}

# Empirical Baseline Numbers (Verified from Practical 1-10 Artifacts)
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
        "short_title": "Log Exploration",
        "one_liner": "Stream-read raw honeypot JSON arrays, audit 2.06M lines, and explore schema characteristics.",
        "icon": "📥",
        "stage": "Ingestion",
        "badge_color": "#22D3EE",
    },
    {
        "id": 2,
        "number_str": "Practical 02",
        "title": "Convert Unstructured Logs into Structured Dataset",
        "short_title": "Structuring",
        "one_liner": "Transform serialized JSON logs into a canonical 13-column tabular dataset with 100% parsing success.",
        "icon": "🧱",
        "stage": "Structuring",
        "badge_color": "#1687FF",
    },
    {
        "id": 3,
        "number_str": "Practical 03",
        "title": "Data Cleaning & Preprocessing",
        "short_title": "Preprocessing",
        "one_liner": "Deduplicate 570,179 rows, resolve 18.4M missing values, parse timestamps, and normalize URLs.",
        "icon": "🧹",
        "stage": "Cleaning",
        "badge_color": "#21D98B",
    },
    {
        "id": 4,
        "number_str": "Practical 04",
        "title": "Basic Attack Classification",
        "short_title": "Attack Labeling",
        "one_liner": "Apply deterministic signature regexes & temporal rolling rules across 6 security classes.",
        "icon": "🏷️",
        "stage": "Labeling",
        "badge_color": "#FF5577",
    },
    {
        "id": 5,
        "number_str": "Practical 05",
        "title": "Feature Engineering & Anomaly Detection",
        "short_title": "Feature Engineering",
        "one_liner": "Extract 66 domain, Featuretools, and tsfresh features; run Isolation Forest anomaly detection.",
        "icon": "⚙️",
        "stage": "Features",
        "badge_color": "#22D3EE",
    },
    {
        "id": 6,
        "number_str": "Practical 06",
        "title": "Handling Imbalanced Dataset",
        "short_title": "Dataset Balancing",
        "one_liner": "Address 9,298:1 class imbalance using SMOTE and sampling; produce 60,000 balanced training set.",
        "icon": "⚖️",
        "stage": "Balancing",
        "badge_color": "#FFB547",
    },
    {
        "id": 7,
        "number_str": "Practical 07",
        "title": "Data Wrangling & Aggregation",
        "short_title": "Data Wrangling",
        "one_liner": "Multi-dimensional slicing, temporal grouping, bot filtering, and security IP threat aggregation.",
        "icon": "🔀",
        "stage": "Wrangling",
        "badge_color": "#1687FF",
    },
    {
        "id": 8,
        "number_str": "Practical 08",
        "title": "Exploratory Data Analysis (EDA)",
        "short_title": "EDA & Telemetry",
        "one_liner": "15 statistical telemetry visualizations, correlation analysis, and behavioral distributions.",
        "icon": "📊",
        "stage": "Visualization",
        "badge_color": "#22D3EE",
    },
    {
        "id": 9,
        "number_str": "Practical 09",
        "title": "Attack Classification Models",
        "short_title": "Model Training",
        "one_liner": "Train Random Forest (99.97% accuracy) & Logistic Regression on 298k untouched test records.",
        "icon": "🎯",
        "stage": "Machine Learning",
        "badge_color": "#21D98B",
    },
    {
        "id": 10,
        "number_str": "Practical 10",
        "title": "Reusable Log Processing Pipeline",
        "short_title": "Reusable Pipeline",
        "one_liner": "Integrated 7-stage automated pipeline; processes 2.06M records in 108s with 97.8% Parquet drop.",
        "icon": "🚀",
        "stage": "Production",
        "badge_color": "#22D3EE",
    },
]
