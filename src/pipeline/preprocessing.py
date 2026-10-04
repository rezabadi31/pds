"""src/pipeline/preprocessing.py
Data Cleaning & Preprocessing Module for Rox Platform
Implements Practical 03 standards: URL path normalization, ISO-8601 datetime parsing,
missing value resolution with domain sentinels, and exact row deduplication.
"""

import re
import urllib.parse
from typing import Tuple, Dict, Any
import pandas as pd


def normalize_url(raw_url: Any) -> str:
    """Normalizes an HTTP URL path according to Practical 03 & 10 rules."""
    if raw_url is None or pd.isna(raw_url):
        return "/unknown"
    val = str(raw_url).strip()
    if not val or val.lower() in ("nan", "none", "null", ""):
        return "/unknown"

    try:
        parsed = urllib.parse.urlsplit(val)
        path = parsed.path
        query = parsed.query
    except Exception:
        path = val
        query = ""

    path = path.strip().lower()
    if not path:
        path = "/"
    elif not path.startswith("/"):
        path = "/" + path

    # Collapse multiple consecutive slashes
    path = re.sub(r"/{2,}", "/", path)
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    # Strip standard static extensions (.html, .htm)
    path = re.sub(r"\.(?:html?)$", "", path, flags=re.IGNORECASE)
    if not path:
        path = "/"

    if query:
        path = f"{path}?{query}"
    return path


class LogPreprocessor:
    """Preprocesses raw structured logs into a clean, normalized working set."""

    @staticmethod
    def preprocess(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """Cleans, normalizes, and deduplicates the structured log DataFrame.
        
        Returns:
            Tuple of (df_clean, metrics)
        """
        initial_records = len(df)
        df_clean = df.copy()

        # 1. Fill missing values with domain sentinels
        missing_count_before = int(df_clean.isna().sum().sum())
        sentinels = {
            "category_type": "web",
            "payload": "",
            "client_ip": "127.0.0.1",
            "client_port": "80",
            "user_agent": "-",
            "accept_language": "-",
            "proxy_ip": "-",
            "request_type": "GET",
            "status_code": "200",
            "resource_requested": "/unknown",
            "bytes_sent": "0",
            "referrer": "-",
        }
        for col, default_val in sentinels.items():
            if col in df_clean.columns:
                df_clean[col] = df_clean[col].fillna(default_val).astype(str)

        # 2. Parse timestamps to datetime safely
        df_clean["parsed_timestamp"] = pd.to_datetime(
            df_clean["timestamp"],
            errors="coerce",
            utc=True,
            format="mixed",
        )
        invalid_ts_count = int(df_clean["parsed_timestamp"].isna().sum())

        # If timestamps could not be parsed, create synthetic sequence
        if invalid_ts_count == len(df_clean):
            base_time = pd.Timestamp.now(tz="UTC")
            df_clean["parsed_timestamp"] = [base_time + pd.Timedelta(seconds=i) for i in range(len(df_clean))]
            invalid_ts_count = 0

        # Sort chronologically
        df_clean.sort_values(by="parsed_timestamp", inplace=True)
        df_clean.reset_index(drop=True, inplace=True)

        # 3. Normalize resource requested URL (Optimized unique mapping)
        if "resource_requested" in df_clean.columns:
            uniq_res = pd.Series(df_clean["resource_requested"].unique())
            res_norm_map = dict(zip(uniq_res, uniq_res.apply(normalize_url)))
            df_clean["normalized_resource"] = df_clean["resource_requested"].map(res_norm_map).fillna("/unknown")
        else:
            df_clean["normalized_resource"] = "/unknown"

        # 4. Remove exact duplicates
        df_dedup = df_clean.drop_duplicates(subset=[
            c for c in ["client_ip", "parsed_timestamp", "resource_requested", "payload"] if c in df_clean.columns
        ]).copy()
        df_dedup.reset_index(drop=True, inplace=True)

        duplicates_removed = initial_records - len(df_dedup)

        metrics = {
            "initial_records": initial_records,
            "preprocessed_records": len(df_dedup),
            "duplicates_removed": duplicates_removed,
            "missing_values_handled": missing_count_before,
            "invalid_timestamps": invalid_ts_count,
        }

        return df_dedup, metrics
