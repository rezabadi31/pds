"""config.py
Practical 10 Configuration and Central Constants
Reusable Data Pipeline for Access Log Telemetry
"""

from pathlib import Path
import re

# Base Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
PARENT_ROOT = PROJECT_ROOT.parent

# Default Input Dataset (Practical 1 raw log)
DEFAULT_INPUT_PATH = PARENT_ROOT / "Practical 1" / "data" / "raw" / "cj.log"

# Directory Structure
DATA_DIR = PROJECT_ROOT / "data"
DATA_RAW_DIR = DATA_DIR / "raw"
DATA_PROCESSED_DIR = DATA_DIR / "processed"
REPORTS_DIR = PROJECT_ROOT / "reports"
OUTPUTS_DIR = PROJECT_ROOT / "outputs"

# Ensure directories exist
for directory in [DATA_RAW_DIR, DATA_PROCESSED_DIR, REPORTS_DIR, OUTPUTS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Default Output File Paths
STRUCTURED_LOGS_CSV = DATA_PROCESSED_DIR / "structured_logs.csv"
LABELED_LOGS_CSV = DATA_PROCESSED_DIR / "labeled_logs.csv"
FEATURE_ENGINEERED_LOGS_CSV = DATA_PROCESSED_DIR / "feature_engineered_logs.csv"
FEATURE_ENGINEERED_LOGS_PARQUET = DATA_PROCESSED_DIR / "feature_engineered_logs.parquet"
PIPELINE_REPORT_TXT = REPORTS_DIR / "pipeline_report.txt"
PIPELINE_SUMMARY_JSON = OUTPUTS_DIR / "pipeline_summary.json"

# Execution Parameters
RANDOM_STATE = 42
SUPPORTED_FORMATS = ["csv", "parquet"]

# Schema Field Definitions
SOURCE_FIELDS = [
    "category_type",
    "payload",
    "timestamp",
    "client_ip",
    "client_port",
    "user_agent",
    "accept_language",
    "proxy_ip",
]

UNAVAILABLE_HTTP_FIELDS = [
    "request_type",
    "status_code",
    "resource_requested",
    "bytes_sent",
    "referrer",
]

ALL_STRUCTURED_COLUMNS = SOURCE_FIELDS + UNAVAILABLE_HTTP_FIELDS

# Attack Detection Parameters & Regular Expressions
BRUTE_FORCE_THRESHOLD = 10
BRUTE_FORCE_WINDOW_MINUTES = 10

SQLI_PATTERNS = [
    r"\bunion(?:\s+|/\*.*?\*/)+(?:all(?:\s+|/\*.*?\*/)+)?select\b",
    r"\bselect\b.*?\bfrom\b",
    r"\bdrop\s+table\b",
    r"\binsert\s+into\b",
    r"\bupdate\b.*?\bset\b",
    r"\bdelete\s+from\b",
    r"\b(?:sleep|waitfor\s+delay)\s*\(",
    r"\bxp_cmdshell\b",
    r"(?:\x27|\"|%27)?\s*\bor\b\s+(?:1\s*=\s*1|\x271\x27\s*=\s*\x271\x27|%271%27\s*=\s*%271%27)",
    r"--\s+",
    r"/\*.*?\*/",
]
SQLI_REGEX = re.compile("|".join(SQLI_PATTERNS), re.IGNORECASE)

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%2e%2e/",
    r"\.\.%2f",
    r"%2f\.\.%2f",
    r"/etc/passwd",
    r"winnt/win\.ini",
    r"windows/win\.ini",
    r"boot\.ini",
    r"etc/hosts",
]
PATH_TRAVERSAL_REGEX = re.compile("|".join(PATH_TRAVERSAL_PATTERNS), re.IGNORECASE)

COMMAND_INJECTION_PATTERNS = [
    r"(?:[;\|\&`\$\(]\s*(?:ls|whoami|cat|id|wget|curl|sh|bash|chmod|rm|nc|uname)\b)",
    r"/(?:bin|usr/bin)/(?:sh|bash)",
    r"\b(?:wget|chmod|rm\s+-rf)\b",
    r"sh\s+/tmp/",
    r"cd_/tmp;",
    r"chmod_777",
]
COMMAND_INJECTION_REGEX = re.compile("|".join(COMMAND_INJECTION_PATTERNS), re.IGNORECASE)

XSS_PATTERNS = [
    r"<script[\s>]",
    r"</script>",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"alert\s*\(",
    r"document\.cookie",
]
XSS_REGEX = re.compile("|".join(XSS_PATTERNS), re.IGNORECASE)

LOGIN_ENDPOINT_PATTERNS = [
    r"/login",
    r"/signin",
    r"/sign-in",
    r"/auth",
    r"/authenticate",
    r"/wp-login",
    r"/admin/login",
    r"logout",
    r"\bauthor\b",
    r"\blogin\b",
    r"\buser\b",
]
LOGIN_ENDPOINT_REGEX = re.compile("|".join(LOGIN_ENDPOINT_PATTERNS), re.IGNORECASE)

# Priority Order for Attack Attribution
ATTACK_PRIORITY_ORDER = [
    "sqli",
    "path_traversal",
    "command_injection",
    "xss",
    "brute_force",
    "benign",
]

# Bot / Scanner Detection Patterns in User-Agent
BOT_PATTERN = re.compile(r"bot|crawler|spider|slurp|facebook|google|bing|yandex", re.IGNORECASE)
SCANNER_PATTERN = re.compile(r"nikto|sqlmap|nmap|masscan|zgrab|acunetix|nessus|openvas|dirbuster|gobuster", re.IGNORECASE)
