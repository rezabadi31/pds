"""user_agent.py
Feature 4: User-Agent Parsing, Taxonomy Classification, and Tool Profiling
Classifies clients into browser, bot, scanner, script, or unknown without bias.
"""

from typing import Tuple, Dict, Any
import re
import pandas as pd

# Regular expression pattern sets (compiled for performance)
SCANNER_PATTERNS = re.compile(
    r"(?:gobuster|dirbuster|nikto|sqlmap|nmap|masscan|zgrab|censys|shodan|"
    r"acunetix|nessus|openvas|hydra|wpscan|arachni|havij|burpcollaborator|zaproxy)",
    re.IGNORECASE,
)

SCRIPT_PATTERNS = re.compile(
    r"(?:curl|wget|python-requests|requests|aiohttp|urllib|httpx|httpclient|"
    r"lwp::simple|libwww-perl|go-http-client|apache-httpclient|postman|insomnia)",
    re.IGNORECASE,
)

BOT_PATTERNS = re.compile(
    r"(?:googlebot|bingbot|yandex|duckduckbot|slurp|baiduspider|twitterbot|"
    r"facebookexternalhit|rogerbot|exabot|crawler|spider|archive\.org_bot|bot[\s/_-]|\bspy\b)",
    re.IGNORECASE,
)

BROWSER_PATTERNS = re.compile(
    r"(?:mozilla|chrome|safari|firefox|edg|edge|opera|opr|trident|msie)",
    re.IGNORECASE,
)


def _classify_single_ua(ua_str: str) -> Tuple[str, int, int]:
    """Classifies an individual User-Agent string into (category, is_bot, is_scanner).
    
    Priority order:
    1. Known Scanners (highest risk signature)
    2. Known Scripts/Libraries
    3. Known Crawlers/Bots
    4. Genuine Browsers
    5. Unknown/Empty/Malformed
    """
    if not isinstance(ua_str, str) or ua_str.strip().lower() in ("", "-", "none", "unknown", "null"):
        return "unknown", 0, 0

    s = ua_str.strip()

    # 1. Scanners
    if SCANNER_PATTERNS.search(s):
        return "scanner", 1, 1

    # 2. Scripts / Automated Libraries
    if SCRIPT_PATTERNS.search(s):
        return "script", 1, 0

    # 3. Search Engine / Web Bots
    if BOT_PATTERNS.search(s):
        return "bot", 1, 0

    # 4. Standard Browsers
    if BROWSER_PATTERNS.search(s):
        return "browser", 0, 0

    # 5. Default Unknown
    return "unknown", 0, 0


def extract_user_agent_features(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Applies taxonomy classification and length metrics across all user-agent strings.
    
    Evaluates uniquely over distinct strings for microsecond vectorized mapping.
    """
    stats: Dict[str, Any] = {}

    if "user_agent" not in df.columns:
        df["user_agent_type"] = "unknown"
        df["is_bot"] = 0
        df["is_scanner"] = 0
        df["user_agent_length"] = 0
        stats["ua_distribution"] = {"unknown": len(df)}
        return df, stats

    # Fast unique mapping
    unique_uas = df["user_agent"].dropna().unique()
    classification_dict = {}
    length_dict = {}

    for ua in unique_uas:
        cat, bot_flag, scanner_flag = _classify_single_ua(ua)
        classification_dict[ua] = (cat, bot_flag, scanner_flag)
        length_dict[ua] = len(str(ua))

    # Also handle NaN/empty
    classification_dict[None] = ("unknown", 0, 0)
    classification_dict[""] = ("unknown", 0, 0)
    length_dict[None] = 0
    length_dict[""] = 0

    # Vectorized mapping
    cat_map = {ua: classification_dict[ua][0] for ua in classification_dict}
    bot_map = {ua: classification_dict[ua][1] for ua in classification_dict}
    scanner_map = {ua: classification_dict[ua][2] for ua in classification_dict}

    df["user_agent_type"] = df["user_agent"].map(cat_map).fillna("unknown")
    df["is_bot"] = df["user_agent"].map(bot_map).fillna(0).astype(int)
    df["is_scanner"] = df["user_agent"].map(scanner_map).fillna(0).astype(int)
    df["user_agent_length"] = df["user_agent"].map(length_dict).fillna(0).astype(int)

    dist = df["user_agent_type"].value_counts().to_dict()
    stats["ua_distribution"] = dist
    stats["total_bots"] = int(df["is_bot"].sum())
    stats["total_scanners"] = int(df["is_scanner"].sum())

    return df, stats
