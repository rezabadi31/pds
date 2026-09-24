"""security_features.py
Additional Security Indicators & Payload Heuristics for Anomaly Detection
Computes content-based structural indicators WITHOUT target leakage.
"""

from typing import Tuple, Dict, Any
import re
import pandas as pd
from src.entropy_url import calculate_shannon_entropy

SQL_KEYWORD_REGEX = re.compile(
    r"(?:\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bOR\s+['\"0-9]=\b|--|\bAND\s+['\"0-9]=|\bSLEEP\s*\(|\bBENCHMARK\s*\()",
    re.IGNORECASE,
)

PATH_TRAVERSAL_REGEX = re.compile(
    r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|/etc/passwd|win\.ini|boot\.ini|/windows/system32)",
    re.IGNORECASE,
)

SCRIPT_TAG_REGEX = re.compile(
    r"(?:<script\b|javascript:|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie|<img\s+src=)",
    re.IGNORECASE,
)

CMD_SEPARATOR_REGEX = re.compile(
    r"(?:;\s*(?:ls|cat|id|whoami|sh|bash|nc|wget|curl)\b|\|\s*(?:ls|cat|id|sh|bash)\b|&&|`|\$\()",
    re.IGNORECASE,
)


def _compute_payload_metrics(p_str: str) -> Dict[str, Any]:
    """Computes payload length, entropy, and heuristic boolean flags for a single string."""
    if not isinstance(p_str, str) or p_str.lower() in ("none", "null", "-", ""):
        return {
            "payload_length": 0,
            "payload_entropy": 0.0,
            "contains_sql_keyword": 0,
            "contains_path_traversal": 0,
            "contains_script_tag": 0,
            "contains_command_separator": 0,
        }

    s = p_str.strip()
    return {
        "payload_length": len(s),
        "payload_entropy": calculate_shannon_entropy(s),
        "contains_sql_keyword": 1 if SQL_KEYWORD_REGEX.search(s) else 0,
        "contains_path_traversal": 1 if PATH_TRAVERSAL_REGEX.search(s) else 0,
        "contains_script_tag": 1 if SCRIPT_TAG_REGEX.search(s) else 0,
        "contains_command_separator": 1 if CMD_SEPARATOR_REGEX.search(s) else 0,
    }


def extract_security_features(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Calculates payload heuristics, rates, and cumulative pattern triggers.
    
    Operates strictly on raw inputs (payload, resources, time-windows) without
    using 'label' or 'label_reason'.
    """
    stats: Dict[str, Any] = {}

    if "payload" in df.columns:
        unique_payloads = df["payload"].dropna().unique()
        cache = {p: _compute_payload_metrics(p) for p in unique_payloads}
        cache[None] = _compute_payload_metrics("")
        cache[""] = _compute_payload_metrics("")

        for feat in [
            "payload_length",
            "payload_entropy",
            "contains_sql_keyword",
            "contains_path_traversal",
            "contains_script_tag",
            "contains_command_separator",
        ]:
            feat_map = {p: cache[p][feat] for p in cache}
            df[feat] = df["payload"].map(feat_map).fillna(0.0)
            if feat != "payload_entropy":
                df[feat] = df[feat].astype(int)
    else:
        for f in [
            "payload_length",
            "payload_entropy",
            "contains_sql_keyword",
            "contains_path_traversal",
            "contains_script_tag",
            "contains_command_separator",
        ]:
            df[f] = 0.0

    # Also check normalized_resource or resource_requested for path traversal
    res_col = "normalized_resource" if "normalized_resource" in df.columns else ("resource_requested" if "resource_requested" in df.columns else None)
    if res_col:
        unique_res = df[res_col].dropna().unique()
        res_pt_map = {r: 1 if PATH_TRAVERSAL_REGEX.search(str(r)) else 0 for r in unique_res}
        res_pt_flags = df[res_col].map(res_pt_map).fillna(0).astype(int)
        df["contains_path_traversal"] = (df["contains_path_traversal"] | res_pt_flags).astype(int)

    # Request rates per second
    if "requests_per_ip_1min" in df.columns:
        df["request_rate_1min"] = (df["requests_per_ip_1min"] / 60.0).round(4)
    else:
        df["request_rate_1min"] = 0.0

    if "requests_per_ip_5min" in df.columns:
        df["request_rate_5min"] = (df["requests_per_ip_5min"] / 300.0).round(4)
    else:
        df["request_rate_5min"] = 0.0

    # Failed pattern count: sum of suspicious heuristic pattern triggers
    pattern_cols = [
        "contains_sql_keyword",
        "contains_path_traversal",
        "contains_script_tag",
        "contains_command_separator",
    ]
    df["failed_pattern_count"] = df[pattern_cols].sum(axis=1).astype(int)

    stats["total_sql_triggers"] = int(df["contains_sql_keyword"].sum())
    stats["total_traversal_triggers"] = int(df["contains_path_traversal"].sum())
    stats["total_script_triggers"] = int(df["contains_script_tag"].sum())
    stats["total_cmd_triggers"] = int(df["contains_command_separator"].sum())
    stats["total_failed_patterns"] = int((df["failed_pattern_count"] > 0).sum())

    return df, stats
