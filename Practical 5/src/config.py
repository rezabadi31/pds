"""config.py
Practical 5 Configuration, Paths, and Feature Schema Definitions
Open-Source Automated Feature Engineering (Domain + Featuretools + tsfresh)
"""

from pathlib import Path

# Base Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
PARENT_ROOT = PROJECT_ROOT.parent

PRACTICAL4_CSV = PARENT_ROOT / "Practical 4" / "data" / "processed" / "labeled_access_logs.csv"
PRACTICAL3_CSV = PARENT_ROOT / "Practical 3" / "data" / "processed" / "preprocessed_access_logs.csv"

DATA_DIR = PROJECT_ROOT / "data"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
OUTPUTS_DIR = PROJECT_ROOT / "outputs"
REPORTS_DIR = OUTPUTS_DIR / "reports"
FEATURES_DIR = OUTPUTS_DIR / "features"
PLOTS_DIR = OUTPUTS_DIR / "plots"
SAMPLES_DIR = OUTPUTS_DIR / "samples"

# Output files
FEATURE_ENGINEERED_CSV = PROCESSED_DATA_DIR / "feature_engineered_access_logs.csv"
ML_READY_CSV = PROCESSED_DATA_DIR / "ml_ready_features.csv"
FEATURE_SAMPLE_CSV = SAMPLES_DIR / "feature_engineered_sample.csv"

# Feature catalog files
FEATURETOOLS_CSV = FEATURES_DIR / "featuretools_features.csv"
FEATURETOOLS_DEFS_TXT = FEATURES_DIR / "featuretools_feature_definitions.txt"
TSFRESH_CSV = FEATURES_DIR / "tsfresh_features.csv"
SELECTED_FEATURES_CSV = FEATURES_DIR / "selected_features.csv"
FEATURE_IMPORTANCE_CSV = FEATURES_DIR / "feature_importance.csv"
FEATURE_QUALITY_CSV = FEATURES_DIR / "feature_quality_metrics.csv"

# Reports
FEATURE_REPORT_TXT = REPORTS_DIR / "feature_engineering_report.txt"
FEATURETOOLS_REPORT_TXT = REPORTS_DIR / "featuretools_report.txt"
TSFRESH_REPORT_TXT = REPORTS_DIR / "tsfresh_report.txt"
FEATURE_SELECTION_REPORT_TXT = REPORTS_DIR / "feature_selection_report.txt"
FEATURE_COMPARISON_REPORT_TXT = REPORTS_DIR / "feature_comparison_report.txt"

# Parameters
RANDOM_STATE = 42
SAMPLE_SIZE_EXPORT = 10000
TSFRESH_IP_SAMPLE_SIZE = 500  # Number of IPs sampled for intensive time-series extraction
TSFRESH_RECORD_SAMPLE_MAX = 50000
HIGH_404_RATIO_THRESH = 0.50
HIGH_404_COUNT_THRESH = 20
