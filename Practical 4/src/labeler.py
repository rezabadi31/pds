r"""src/labeler.py
Practical 4: Rule-Based Request Labeling Engine (Benign vs Attack)
==================================================================
Provides deterministic, pattern-based attack detection and request classification
for web access-log telemetry without relying on machine learning models.
"""

import re
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np
import pandas as pd


# ---------------------------------------------------------------------------
# RULE 1: SQL INJECTION (SQLi)
# ---------------------------------------------------------------------------
SQLI_PATTERNS = [
    # UNION SELECT variants with comments / spaces
    r"\bunion(?:\s+|/\*.*?\*/)+(?:all(?:\s+|/\*.*?\*/)+)?select\b",
    # Classic SELECT ... FROM
    r"\bselect\b.*?\bfrom\b",
    # DDL & DML statements
    r"\bdrop\s+table\b",
    r"\binsert\s+into\b",
    r"\bupdate\b.*?\bset\b",
    r"\bdelete\s+from\b",
    # Time-based blind SQLi functions
    r"\b(?:sleep|waitfor\s+delay)\s*\(",
    # Stored procedures
    r"\bxp_cmdshell\b",
    # Boolean tautologies: ' OR 1=1, OR '1'='1', OR 1=1 --
    r"(?:\x27|\"|%27)?\s*\bor\b\s+(?:1\s*=\s*1|\x271\x27\s*=\s*\x271\x27|%271%27\s*=\s*%271%27)",
    # SQL comment indicators
    r"--\s+",
    r"/\*.*?\*/",
]
SQLI_REGEX = re.compile("|".join(SQLI_PATTERNS), re.IGNORECASE)


# ---------------------------------------------------------------------------
# RULE 2: PATH TRAVERSAL
# ---------------------------------------------------------------------------
PATH_TRAVERSAL_PATTERNS = [
    # Directory climbing sequences (standard & encoded)
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%2e%2e/",
    r"\.\.%2f",
    r"%2f\.\.%2f",
    # Sensitive OS configuration & authentication files
    r"/etc/passwd",
    r"winnt/win\.ini",
    r"windows/win\.ini",
    r"boot\.ini",
    r"etc/hosts",
]
PATH_TRAVERSAL_REGEX = re.compile("|".join(PATH_TRAVERSAL_PATTERNS), re.IGNORECASE)


# ---------------------------------------------------------------------------
# RULE 3: COMMAND INJECTION (CMDi)
# ---------------------------------------------------------------------------
COMMAND_INJECTION_PATTERNS = [
    # Chained separators followed by Unix/Windows system commands
    r"(?:[;\|\&`\$\(]\s*(?:ls|whoami|cat|id|wget|curl|sh|bash|chmod|rm|nc|uname)\b)",
    # Absolute shell binary paths
    r"/(?:bin|usr/bin)/(?:sh|bash)",
    # Malware downloader & dropper commands
    r"\b(?:wget|chmod|rm\s+-rf)\b",
    r"sh\s+/tmp/",
    r"cd_/tmp;",
    r"chmod_777",
]
COMMAND_INJECTION_REGEX = re.compile("|".join(COMMAND_INJECTION_PATTERNS), re.IGNORECASE)


# ---------------------------------------------------------------------------
# RULE 4: CROSS-SITE SCRIPTING (XSS)
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# RULE 5: BRUTE FORCE (Authentication / Login Endpoints)
# ---------------------------------------------------------------------------
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


def build_searchable_text(df: pd.DataFrame) -> pd.Series:
    r"""Combines relevant searchable text attributes safely to avoid NaNs.

    Searches across:
    - payload
    - resource_requested
    - normalized_resource
    - category_type
    """
    p = df["payload"].fillna("").astype(str)
    r = df["resource_requested"].fillna("").astype(str)
    nr = (
        df["normalized_resource"].fillna("").astype(str)
        if "normalized_resource" in df.columns
        else ""
    )
    c = df["category_type"].fillna("").astype(str)

    return (p + " " + r + " " + nr + " " + c).str.strip()


def detect_brute_force(
    df: pd.DataFrame,
    threshold: int = 10,
    window_minutes: int = 10,
) -> Tuple[pd.Series, Dict[str, Any]]:
    r"""Detects brute-force authentication attacks using client IP and timestamp rolling window.

    Rules:
    1. Identify requests targeting login or authentication endpoints.
    2. Group candidate requests by client_ip.
    3. Sort entries chronologically.
    4. For any client_ip making >= threshold login requests within window_minutes,
       mark those matching requests as brute_force.

    Returns:
        Tuple[pd.Series, Dict[str, Any]]: Boolean mask of brute-force rows and statistics.
    """
    search_text = build_searchable_text(df)
    is_login_req = search_text.str.contains(LOGIN_ENDPOINT_REGEX, regex=True)

    bf_mask = pd.Series(False, index=df.index)
    candidate_indices = df[is_login_req].index

    if len(candidate_indices) == 0:
        return bf_mask, {
            "candidate_login_requests": 0,
            "unique_login_ips": 0,
            "brute_force_ips": 0,
            "brute_force_requests": 0,
            "threshold": threshold,
            "window_minutes": window_minutes,
        }

    sub_df = df.loc[candidate_indices, ["client_ip", "timestamp"]].copy()
    sub_df["timestamp"] = pd.to_datetime(sub_df["timestamp"], errors="coerce")
    sub_df = sub_df.dropna(subset=["timestamp", "client_ip"])
    sub_df = sub_df.sort_values(by=["client_ip", "timestamp"])

    bf_indices: Set[int] = set()
    bf_ips: Set[str] = set()
    window_delta = pd.Timedelta(minutes=window_minutes)

    for ip, group in sub_df.groupby("client_ip"):
        if len(group) < threshold:
            continue

        timestamps = group["timestamp"].values
        n = len(timestamps)

        for i in range(n):
            t_start = timestamps[i]
            t_end = t_start + window_delta
            in_window = (group["timestamp"] >= t_start) & (
                group["timestamp"] <= t_end
            )

            if in_window.sum() >= threshold:
                bf_indices.update(group[in_window].index)
                bf_ips.add(ip)

    bf_mask.loc[list(bf_indices)] = True

    stats = {
        "candidate_login_requests": int(len(candidate_indices)),
        "unique_login_ips": int(sub_df["client_ip"].nunique()),
        "brute_force_ips": int(len(bf_ips)),
        "brute_force_requests": int(len(bf_indices)),
        "threshold": threshold,
        "window_minutes": window_minutes,
    }
    return bf_mask, stats


def apply_rule_based_labeling(
    df: pd.DataFrame,
    brute_force_threshold: int = 10,
    window_minutes: int = 10,
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    r"""Applies the deterministic rule-based attack classification engine.

    Deterministic Priority Order:
    1. sqli (SQL Injection)
    2. path_traversal (Path Traversal)
    3. command_injection (Command Injection)
    4. xss (Cross-Site Scripting)
    5. brute_force (Repeated authentication attempts)
    6. benign (Default / Normal traffic)

    Parameters:
        df (pd.DataFrame): Input preprocessed access logs.
        brute_force_threshold (int): Minimum login attempts to flag brute force.
        window_minutes (int): Time window in minutes for brute force.

    Returns:
        Tuple[pd.DataFrame, Dict[str, Any]]: Labeled DataFrame and execution statistics.
    """
    df_labeled = df.copy()
    search_text = build_searchable_text(df_labeled)

    # Initialize default labels
    labels = pd.Series("benign", index=df_labeled.index, dtype="string")
    reasons = pd.Series(
        "No attack pattern detected (standard request)",
        index=df_labeled.index,
        dtype="string",
    )

    # 1. Evaluate Rule 5: Brute Force
    bf_mask, bf_stats = detect_brute_force(
        df_labeled, threshold=brute_force_threshold, window_minutes=window_minutes
    )
    labels[bf_mask] = "brute_force"
    reasons[bf_mask] = (
        f"Brute-force attack detected (>={brute_force_threshold} login attempts within {window_minutes}m from same IP)"
    )

    # 2. Evaluate Rule 4: XSS
    m_xss = search_text.str.contains(XSS_REGEX, regex=True)
    labels[m_xss] = "xss"
    reasons[m_xss] = (
        "Cross-site scripting (XSS) pattern detected (<script>, alert, or document.cookie)"
    )

    # 3. Evaluate Rule 3: Command Injection
    m_cmdi = search_text.str.contains(COMMAND_INJECTION_REGEX, regex=True)
    labels[m_cmdi] = "command_injection"
    reasons[m_cmdi] = (
        "OS command injection pattern detected (shell separator and system binary)"
    )

    # 4. Evaluate Rule 2: Path Traversal
    m_pt = search_text.str.contains(PATH_TRAVERSAL_REGEX, regex=True)
    labels[m_pt] = "path_traversal"
    reasons[m_pt] = (
        "Path traversal sequence detected (directory climbing or sensitive system file probe)"
    )

    # 5. Evaluate Rule 1: SQL Injection (Highest Priority)
    m_sqli = search_text.str.contains(SQLI_REGEX, regex=True)
    labels[m_sqli] = "sqli"
    reasons[m_sqli] = (
        "SQL injection pattern detected (SQL keywords, comments, or tautology)"
    )

    df_labeled["label"] = labels
    df_labeled["label_reason"] = reasons

    # Compute summary statistics
    dist = df_labeled["label"].value_counts().to_dict()
    total = len(df_labeled)
    benign_cnt = dist.get("benign", 0)
    attack_cnt = total - benign_cnt

    stats = {
        "total_records": total,
        "label_distribution": dist,
        "benign_count": benign_cnt,
        "attack_count": attack_cnt,
        "benign_percentage": round((benign_cnt / total) * 100, 4),
        "attack_percentage": round((attack_cnt / total) * 100, 4),
        "sqli_count": dist.get("sqli", 0),
        "path_traversal_count": dist.get("path_traversal", 0),
        "command_injection_count": dist.get("command_injection", 0),
        "xss_count": dist.get("xss", 0),
        "brute_force_count": dist.get("brute_force", 0),
        "brute_force_details": bf_stats,
    }

    return df_labeled, stats
