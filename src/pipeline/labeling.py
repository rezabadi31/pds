"""src/pipeline/labeling.py
Rule-Based Attack Classification Engine for Rox Platform
Strictly reproduces Practical 04 deterministic security signatures and temporal sliding-window detection.
Labels: benign, brute_force, path_traversal, xss, command_injection, sqli.
Priority: sqli > path_traversal > command_injection > xss > brute_force > benign.
"""

import re
from typing import Tuple, Dict, Any
import numpy as np
import pandas as pd

# Regex definitions matching Practical 04 & 10
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

BRUTE_FORCE_THRESHOLD = 10
BRUTE_FORCE_WINDOW_MINUTES = 10


class AttackLabeler:
    """Classifies log records into multi-class attack categories deterministically."""

    @staticmethod
    def label(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """Applies Practical 04 deterministic attack rules in strict priority.
        
        Returns:
            Tuple of (df_labeled, label_metrics)
        """
        df_out = df.copy()
        n = len(df_out)
        
        # Initialize default benign state
        df_out["label"] = "benign"
        df_out["label_reason"] = "No attack pattern detected"

        # Search field: combination of payload, normalized_resource, and resource_requested
        search_series = (
            df_out["payload"].fillna("").astype(str) + " " +
            df_out.get("normalized_resource", df_out.get("resource_requested", "")).fillna("").astype(str)
        )

        # 1. Regex evaluations
        mask_sqli = search_series.str.contains(SQLI_REGEX, regex=True, na=False)
        mask_pt = search_series.str.contains(PATH_TRAVERSAL_REGEX, regex=True, na=False)
        mask_ci = search_series.str.contains(COMMAND_INJECTION_REGEX, regex=True, na=False)
        mask_xss = search_series.str.contains(XSS_REGEX, regex=True, na=False)

        # 2. Brute Force rolling window detection
        mask_login = search_series.str.contains(LOGIN_ENDPOINT_REGEX, regex=True, na=False)
        mask_brute = pd.Series(False, index=df_out.index)

        if "parsed_timestamp" in df_out.columns and "client_ip" in df_out.columns and mask_login.any():
            login_subset = df_out[mask_login].copy()
            if not login_subset.empty:
                # Rolling window count per IP
                login_subset["rolling_count"] = 0
                for ip, group in login_subset.groupby("client_ip"):
                    ts = group["parsed_timestamp"].values
                    n_ts = len(ts)
                    if n_ts < BRUTE_FORCE_THRESHOLD:
                        continue
                    window_ns = np.timedelta64(BRUTE_FORCE_WINDOW_MINUTES, "m")
                    idx_win = np.searchsorted(ts, ts - window_ns, side="left")
                    cnts = np.arange(n_ts) - idx_win + 1
                    brute_hit_mask = cnts >= BRUTE_FORCE_THRESHOLD
                    if brute_hit_mask.any():
                        mask_brute.loc[group.index[brute_hit_mask]] = True

        # 3. Apply labels according to strict priority order:
        # Priority: sqli (1) > path_traversal (2) > command_injection (3) > xss (4) > brute_force (5) > benign (6)
        # Apply in reverse so higher priority overwrites lower priority
        df_out.loc[mask_brute, "label"] = "brute_force"
        df_out.loc[mask_brute, "label_reason"] = f">={BRUTE_FORCE_THRESHOLD} login attempts within {BRUTE_FORCE_WINDOW_MINUTES}-min window"

        df_out.loc[mask_xss, "label"] = "xss"
        df_out.loc[mask_xss, "label_reason"] = "Cross-Site Scripting signature matched"

        df_out.loc[mask_ci, "label"] = "command_injection"
        df_out.loc[mask_ci, "label_reason"] = "OS command execution / shell injection signature matched"

        df_out.loc[mask_pt, "label"] = "path_traversal"
        df_out.loc[mask_pt, "label_reason"] = "Directory traversal / sensitive system file signature matched"

        df_out.loc[mask_sqli, "label"] = "sqli"
        df_out.loc[mask_sqli, "label_reason"] = "SQL injection pattern matched (union, tautology, comments)"

        label_counts = df_out["label"].value_counts().to_dict()
        total_attacks = n - label_counts.get("benign", 0)

        metrics = {
            "total_records": n,
            "benign_count": label_counts.get("benign", 0),
            "attack_count": total_attacks,
            "attack_percentage": round((total_attacks / n) * 100, 2) if n > 0 else 0.0,
            "label_distribution": label_counts,
        }

        return df_out, metrics
