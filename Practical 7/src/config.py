"""config.py
Practical 7: Data Wrangling for Aggregated Analysis
Configuration, directory definitions, and analytical constants.
"""

from pathlib import Path

# Base Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
PARENT_ROOT = PROJECT_ROOT.parent

# Input Balanced Dataset from Practical 6
PRIMARY_INPUT_CSV = PARENT_ROOT / "Practical 6" / "data" / "processed" / "balanced_training_dataset.csv"

# Directories
DATA_DIR = PROJECT_ROOT / "data"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
OUTPUTS_DIR = PROJECT_ROOT / "outputs"
AGGREGATED_DIR = OUTPUTS_DIR / "aggregated"
FILTERED_AGG_DIR = AGGREGATED_DIR / "filtered"
PLOTS_DIR = OUTPUTS_DIR / "plots"
REPORTS_DIR = OUTPUTS_DIR / "reports"

# Processed & Aggregated Exports
WRANGLED_FILTERED_CSV = PROCESSED_DATA_DIR / "wrangled_filtered_dataset.csv"

# Unfiltered Aggregations
IP_ATTACK_FREQ_CSV = AGGREGATED_DIR / "ip_attack_frequency.csv"
TOP_ATTACK_IPS_CSV = AGGREGATED_DIR / "top_attack_ips.csv"
IP_ATTACK_TYPE_MATRIX_CSV = AGGREGATED_DIR / "ip_attack_type_matrix.csv"
IP_ATTACK_TYPE_PCT_CSV = AGGREGATED_DIR / "ip_attack_type_percentage.csv"
HOURLY_TRAFFIC_CSV = AGGREGATED_DIR / "hourly_traffic.csv"
DAILY_TRAFFIC_CSV = AGGREGATED_DIR / "daily_traffic.csv"
DAILY_ATTACK_TYPES_CSV = AGGREGATED_DIR / "daily_attack_types.csv"
REQUEST_TYPE_PIVOT_CSV = AGGREGATED_DIR / "request_type_label_pivot.csv"
REQUEST_TYPE_PCT_CSV = AGGREGATED_DIR / "request_type_label_percentage.csv"
STATUS_CODE_PIVOT_CSV = AGGREGATED_DIR / "status_code_label_pivot.csv"
BOT_FILTERED_CSV = AGGREGATED_DIR / "bot_filtered_dataset.csv"
BOT_TRAFFIC_SUMMARY_CSV = AGGREGATED_DIR / "bot_traffic_summary.csv"
EXTERNAL_IP_CSV = AGGREGATED_DIR / "external_ip_dataset.csv"
INTERNAL_EXTERNAL_SUMMARY_CSV = AGGREGATED_DIR / "internal_external_summary.csv"

# Filtered Aggregations
FILTERED_IP_FREQ_CSV = FILTERED_AGG_DIR / "ip_attack_frequency.csv"
FILTERED_HOURLY_CSV = FILTERED_AGG_DIR / "hourly_traffic.csv"
FILTERED_DAILY_CSV = FILTERED_AGG_DIR / "daily_traffic.csv"
FILTERED_REQUEST_PIVOT_CSV = FILTERED_AGG_DIR / "request_type_label_pivot.csv"
FILTERED_STATUS_PIVOT_CSV = FILTERED_AGG_DIR / "status_code_label_pivot.csv"

# Reports
DATA_INSPECTION_REPORT_TXT = REPORTS_DIR / "data_inspection_report.txt"
WRANGLING_REPORT_TXT = REPORTS_DIR / "wrangling_report.txt"

# Bot Detection Keywords (case-insensitive substring match)
BOT_KEYWORDS = [
    "bot",
    "crawler",
    "spider",
    "slurp",
    "wget",
    "curl",
    "python-requests",
    "scrapy",
    "scanner",
]

# Ensure required directory tree exists
for d in [PROCESSED_DATA_DIR, AGGREGATED_DIR, FILTERED_AGG_DIR, PLOTS_DIR, REPORTS_DIR]:
    d.mkdir(parents=True, exist_ok=True)
