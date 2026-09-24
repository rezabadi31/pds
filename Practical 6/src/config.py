"""config.py
Practical 6 Configuration and Path Definitions
Dataset balancing engine for ML and Deep Learning training.
"""

from pathlib import Path

# Base Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
PARENT_ROOT = PROJECT_ROOT.parent

# Input Telemetry from Practical 5
INPUT_CSV = PARENT_ROOT / "Practical 5" / "data" / "processed" / "feature_engineered_access_logs.csv"

# Directories
DATA_DIR = PROJECT_ROOT / "data"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
OUTPUTS_DIR = PROJECT_ROOT / "outputs"
REPORTS_DIR = OUTPUTS_DIR / "reports"
PLOTS_DIR = OUTPUTS_DIR / "plots"

# Processed Data Exports
TEST_DATASET_CSV = PROCESSED_DATA_DIR / "test_dataset.csv"
BALANCED_UNDERSAMPLED_CSV = PROCESSED_DATA_DIR / "balanced_train_undersampled.csv"
BALANCED_OVERSAMPLED_CSV = PROCESSED_DATA_DIR / "balanced_train_random_oversampled.csv"
BALANCED_SMOTE_CSV = PROCESSED_DATA_DIR / "balanced_train_smote.csv"
FINAL_BALANCED_TRAIN_CSV = PROCESSED_DATA_DIR / "balanced_training_dataset.csv"

# Reports
COMPARISON_CSV = REPORTS_DIR / "balancing_comparison.csv"
BALANCING_REPORT_TXT = REPORTS_DIR / "balancing_report.txt"

# Parameters
RANDOM_STATE = 42
TEST_SIZE = 0.20

# Memory-Safe Representative Sample Target for SMOTE & OverSampling on 1.49M records
# Benign class in training set (~1.19M) is downsampled to this ceiling so minority classes
# can be synthesized/oversampled up to match without consuming excessive RAM or disk space.
OVERSAMPLE_BENIGN_CEILING = 10000
