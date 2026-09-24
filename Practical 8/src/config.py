"""config.py
Practical 8: Data Visualization and Exploratory Data Analysis (EDA)
Path configurations, styling constants, security feature lists, and export paths.
"""

from pathlib import Path

# Base Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
PARENT_ROOT = PROJECT_ROOT.parent

# Input Telemetry Paths
PRIMARY_INPUT_CSV = PARENT_ROOT / "Practical 7" / "data" / "processed" / "wrangled_filtered_dataset.csv"
FALLBACK_INPUT_CSV = PARENT_ROOT / "Practical 6" / "data" / "processed" / "balanced_training_dataset.csv"

# Practical 7 Aggregated Reference Paths
P7_AGGREGATED_DIR = PARENT_ROOT / "Practical 7" / "outputs" / "aggregated"
P7_IP_ATTACK_FREQ_CSV = P7_AGGREGATED_DIR / "ip_attack_frequency.csv"
P7_HOURLY_TRAFFIC_CSV = P7_AGGREGATED_DIR / "hourly_traffic.csv"
P7_DAILY_TRAFFIC_CSV = P7_AGGREGATED_DIR / "daily_traffic.csv"
P7_REQUEST_TYPE_PIVOT_CSV = P7_AGGREGATED_DIR / "request_type_label_pivot.csv"
P7_STATUS_CODE_PIVOT_CSV = P7_AGGREGATED_DIR / "status_code_label_pivot.csv"

# Directories
DATA_DIR = PROJECT_ROOT / "data"
OUTPUTS_DIR = PROJECT_ROOT / "outputs"
OUTPUTS_DATA_DIR = OUTPUTS_DIR / "data"
PLOTS_DIR = OUTPUTS_DIR / "plots"
INTERACTIVE_DIR = OUTPUTS_DIR / "interactive"
REPORTS_DIR = OUTPUTS_DIR / "reports"

# Data Table Exports
TOP10_ATTACKING_IPS_CSV = DATA_DIR / "top10_attacking_ips.csv"
ATTACK_CATEGORIES_OVER_TIME_CSV = DATA_DIR / "attack_categories_over_time.csv"
STATUS_CODE_GROUPS_CSV = DATA_DIR / "status_code_groups.csv"
IP_VS_REQUEST_TYPE_CSV = DATA_DIR / "ip_vs_request_type.csv"

# Static Matplotlib / Seaborn Plot Paths
PLOT_01_REQUESTS_PER_HOUR = PLOTS_DIR / "01_requests_per_hour.png"
PLOT_02_TOP10_ATTACKING_IPS = PLOTS_DIR / "02_top10_attacking_ips.png"
PLOT_03_ATTACK_CATEGORIES_OVER_TIME = PLOTS_DIR / "03_attack_categories_over_time.png"
PLOT_04_STATUS_CODE_DIST = PLOTS_DIR / "04_status_code_distribution.png"
PLOT_05_STATUS_CODE_GROUPS = PLOTS_DIR / "05_status_code_group_distribution.png"
PLOT_06_IP_VS_REQUEST_HEATMAP = PLOTS_DIR / "06_ip_vs_request_type_heatmap.png"
PLOT_07_ATTACK_CATEGORY_DIST = PLOTS_DIR / "07_attack_category_distribution.png"
PLOT_08_REQUEST_TYPE_DIST = PLOTS_DIR / "08_request_type_distribution.png"
PLOT_09_BOT_VS_NONBOT = PLOTS_DIR / "09_bot_vs_nonbot.png"
PLOT_10_INTERNAL_VS_EXTERNAL = PLOTS_DIR / "10_internal_vs_external.png"
PLOT_11_URL_LENGTH_DIST = PLOTS_DIR / "11_url_length_distribution.png"
PLOT_12_PAYLOAD_LENGTH_DIST = PLOTS_DIR / "12_payload_length_distribution.png"
PLOT_13_REQUESTS_PER_IP_DIST = PLOTS_DIR / "13_requests_per_ip_distribution.png"
PLOT_14_INTER_REQUEST_TIME_DIST = PLOTS_DIR / "14_inter_request_time_distribution.png"
PLOT_15_CORRELATION_HEATMAP = PLOTS_DIR / "15_feature_correlation_heatmap.png"

# Interactive Plotly Paths
INTERACTIVE_01_REQUESTS_PER_HOUR = INTERACTIVE_DIR / "01_requests_per_hour.html"
INTERACTIVE_02_TOP10_IPS = INTERACTIVE_DIR / "02_top10_attacking_ips.html"
INTERACTIVE_03_ATTACK_OVER_TIME = INTERACTIVE_DIR / "03_attack_categories_over_time.html"
INTERACTIVE_04_STATUS_CODES = INTERACTIVE_DIR / "04_status_code_distribution.html"
INTERACTIVE_07_ATTACK_CATEGORIES = INTERACTIVE_DIR / "07_attack_category_distribution.html"
INTERACTIVE_EDA_DASHBOARD = INTERACTIVE_DIR / "eda_dashboard.html"

# Report Paths
EDA_SUMMARY_TXT = REPORTS_DIR / "eda_summary.txt"
VISUALIZATION_REPORT_TXT = REPORTS_DIR / "visualization_report.txt"

# Security Numeric Features for Correlation Heatmap
CANDIDATE_CORRELATION_FEATURES = [
    "requests_per_ip",
    "requests_per_ip_1min",
    "requests_per_ip_5min",
    "requests_per_ip_10min",
    "url_length",
    "payload_length",
    "url_entropy",
    "payload_entropy",
    "bytes_sent",
    "status_code",
    "time_since_previous_request",
    "unique_urls_per_ip",
    "unique_ports_per_ip",
    "unique_user_agents_per_ip",
]

# Ensure required directory tree exists
for d in [DATA_DIR, OUTPUTS_DIR, OUTPUTS_DATA_DIR, PLOTS_DIR, INTERACTIVE_DIR, REPORTS_DIR]:
    d.mkdir(parents=True, exist_ok=True)
