"""config.py
Practical 9 Configuration and Path Definitions
Machine Learning Attack Classification Pipeline
"""

from pathlib import Path

# Base Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
PARENT_ROOT = PROJECT_ROOT.parent

# Input Datasets
PRACTICAL_5_DIR = PARENT_ROOT / "Practical 5"
INPUT_CSV = PRACTICAL_5_DIR / "data" / "processed" / "feature_engineered_access_logs.csv"
FALLBACK_CSV = PRACTICAL_5_DIR / "data" / "processed" / "ml_ready_features.csv"

# Practical 6 Datasets for Validation (Part 13)
PRACTICAL_6_DIR = PARENT_ROOT / "Practical 6"
P6_BALANCED_TRAIN_CSV = PRACTICAL_6_DIR / "data" / "processed" / "balanced_training_dataset.csv"
P6_TEST_CSV = PRACTICAL_6_DIR / "data" / "processed" / "test_dataset.csv"

# Practical 9 Output Directories
OUTPUTS_DIR = PROJECT_ROOT / "outputs"
DATA_DIR = OUTPUTS_DIR / "data"
MODELS_DIR = OUTPUTS_DIR / "models"
PLOTS_DIR = OUTPUTS_DIR / "plots"
REPORTS_DIR = OUTPUTS_DIR / "reports"

# Ensure all output directories exist
for directory in [DATA_DIR, MODELS_DIR, PLOTS_DIR, REPORTS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Output Data Files
LR_METRICS_CSV = DATA_DIR / "logistic_regression_metrics.csv"
RF_METRICS_CSV = DATA_DIR / "random_forest_metrics.csv"
MODEL_COMPARISON_CSV = DATA_DIR / "model_comparison.csv"
RF_FEATURE_IMPORTANCE_CSV = DATA_DIR / "random_forest_feature_importance.csv"
BALANCED_EXPERIMENT_CSV = DATA_DIR / "balanced_experiment_comparison.csv"

# Output Model Files
LR_MODEL_FILE = MODELS_DIR / "logistic_regression.joblib"
RF_MODEL_FILE = MODELS_DIR / "random_forest.joblib"

# Output Plot Files
LR_CONFUSION_MATRIX_PNG = PLOTS_DIR / "logistic_regression_confusion_matrix.png"
RF_CONFUSION_MATRIX_PNG = PLOTS_DIR / "random_forest_confusion_matrix.png"
MODEL_ACCURACY_COMPARISON_PNG = PLOTS_DIR / "model_accuracy_comparison.png"
RF_TOP20_FEATURES_PNG = PLOTS_DIR / "random_forest_top20_features.png"
CLASS_DISTRIBUTION_PNG = PLOTS_DIR / "class_distribution.png"

# Output Report Files
LR_REPORT_TXT = REPORTS_DIR / "logistic_regression_report.txt"
RF_REPORT_TXT = REPORTS_DIR / "random_forest_report.txt"
CLASSIFIER_REPORT_TXT = REPORTS_DIR / "classifier_report.txt"

# Model Hyperparameters and Settings
RANDOM_STATE = 42
TEST_SIZE = 0.20
LR_MAX_ITER = 300
LR_CLASS_WEIGHT = "balanced"
RF_N_ESTIMATORS = 100
RF_CLASS_WEIGHT = "balanced"
RF_N_JOBS = -1
