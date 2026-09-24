r"""src/preprocessor.py
Practical 3: Access Log Cleaning and Preprocessing Engine
==========================================================
Provides modular, robust, and reproducible routines to clean, standardize,
normalize, and validate structured web access-log datasets.
"""

import re
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd


# Regex pattern to match common web document extensions (.html, .htm) at end of path
HTML_EXT_PATTERN = re.compile(r"\.(?:html?)$", re.IGNORECASE)


def normalize_url_path(raw_url: Any) -> str:
    r"""Normalizes an HTTP URL or resource path according to standard web normalization rules.

    Rules:
    1. Strip leading and trailing whitespace.
    2. Convert path components to lowercase.
    3. Remove trailing slashes (except for the root path '/').
    4. Normalize common extensions (.html, .htm):
       /index.html -> /index
       /login.html -> /login
       /about.htm  -> /about
    5. Preserve query parameters, anchors, and meaningful path characters:
       / ? = & : . - _ %
    6. Return standard placeholder '/unknown' for null, empty, or whitespace-only inputs.

    Parameters:
        raw_url (Any): Original URL or resource string.

    Returns:
        str: Cleaned and normalized resource path.
    """
    if raw_url is None or pd.isna(raw_url):
        return "/unknown"

    val = str(raw_url).strip()
    if not val or val.lower() in ("nan", "none", "null", ""):
        return "/unknown"

    # Handle full URLs (e.g. http://example.com/index.html?q=1) vs relative paths
    try:
        parsed = urllib.parse.urlsplit(val)
        scheme = parsed.scheme.lower() if parsed.scheme else ""
        netloc = parsed.netloc.lower() if parsed.netloc else ""
        path = parsed.path
        query = parsed.query
        fragment = parsed.fragment
    except Exception:
        # Fallback if split fails on malformed input
        path = val
        query = ""
        fragment = ""
        scheme = ""
        netloc = ""

    # Normalize path
    path = path.strip().lower()

    # If empty or not starting with slash, ensure initial slash unless protocol URL
    if not path:
        path = "/"
    elif not path.startswith("/") and not netloc:
        path = "/" + path

    # Normalize repetitive consecutive slashes inside path (e.g., //index -> /index)
    path = re.sub(r"/{2,}", "/", path)

    # Normalize trailing slash (keep root '/' intact)
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    # Normalize .html and .htm extensions (/index.html -> /index, /login.htm -> /login)
    if HTML_EXT_PATTERN.search(path):
        path = HTML_EXT_PATTERN.sub("", path)
        if not path:
            path = "/"

    # Reassemble normalized URL or path
    result = path
    if netloc:
        prefix = f"{scheme}://{netloc}" if scheme else f"//{netloc}"
        result = prefix + result

    if query:
        result = f"{result}?{query}"
    if fragment:
        result = f"{result}#{fragment}"

    return result


def clean_text_field(val: Any, lowercase: bool = True) -> str:
    r"""Cleans a string or text field by trimming extraneous whitespace,
    standardizing empty representations, and optionally converting to lowercase.
    Preserves all necessary symbols (/ ? = & : . - _ %).

    Parameters:
        val (Any): Raw value.
        lowercase (bool): Whether to convert text to lowercase.

    Returns:
        str: Cleaned string.
    """
    if val is None or pd.isna(val):
        return "unknown"

    s = str(val).strip()
    if not s or s.lower() in ("nan", "none", "null", ""):
        return "unknown"

    # Normalize multiple internal whitespace characters to a single space
    s = re.sub(r"\s+", " ", s)

    if lowercase:
        s = s.lower()

    return s


def inspect_data(df: pd.DataFrame) -> Dict[str, Any]:
    r"""Inspects DataFrame and returns summary of rows, columns, types, nulls, duplicates."""
    return {
        "num_rows": len(df),
        "num_cols": len(df.columns),
        "columns": list(df.columns),
        "dtypes": {col: str(dtype) for col, dtype in df.dtypes.items()},
        "missing_counts": df.isnull().sum().to_dict(),
        "missing_percentages": ((df.isnull().sum() / len(df)) * 100).round(4).to_dict(),
        "duplicate_rows": int(df.duplicated().sum()),
    }


def convert_timestamps(
    df: pd.DataFrame, col: str = "timestamp"
) -> Tuple[pd.Series, Dict[str, Any]]:
    r"""Safely converts timestamp column using pd.to_datetime with errors='coerce'.

    Returns:
        Tuple[pd.Series, Dict[str, Any]]: Converted datetime Series and summary report.
    """
    orig_dtype = str(df[col].dtype)
    converted = pd.to_datetime(df[col], errors="coerce")
    valid_count = int(converted.notnull().sum())
    nat_count = int(converted.isnull().sum())

    stats = {
        "original_dtype": orig_dtype,
        "final_dtype": str(converted.dtype),
        "valid_count": valid_count,
        "invalid_count": nat_count,
        "min_timestamp": str(converted.min()) if valid_count > 0 else "N/A",
        "max_timestamp": str(converted.max()) if valid_count > 0 else "N/A",
    }
    return converted, stats


def remove_exact_duplicates(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    r"""Identifies and eliminates exact duplicate records across all attributes.
    Preserves repeated requests having differing timestamps or ports.

    Returns:
        Tuple[pd.DataFrame, Dict[str, Any]]: Deduplicated DataFrame and statistics.
    """
    dups_before = int(df.duplicated().sum())
    df_dedup = df.drop_duplicates(keep="first").copy()
    dups_after = int(df_dedup.duplicated().sum())

    stats = {
        "duplicates_before": dups_before,
        "duplicates_after": dups_after,
        "rows_removed": dups_before,
        "initial_rows": len(df),
        "final_rows": len(df_dedup),
    }
    return df_dedup, stats


def handle_missing_values(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
    r"""Handles missing values for every column using justified domain strategies.

    Strategies applied:
    - category_type: Categorical -> Impute 'unknown'
    - payload: Categorical -> Impute 'none' (benign request without payload)
    - timestamp: Datetime -> Retain valid timestamps; do not fabricate synthetic dates
    - client_ip: Categorical -> Impute 'unknown' (network identifier)
    - client_port: Numerical -> Port 0 as sentinel if missing; cast to int64
    - user_agent: Categorical -> Impute 'unknown'
    - accept_language: Categorical -> Impute 'unknown'
    - proxy_ip: Categorical -> Impute 'none' (indicates direct client connection)
    - request_type: Categorical -> Impute 'unknown' (unrecorded HTTP verb)
    - status_code: Numerical -> Impute 0 (unrecorded response/connection drop) -> int64
    - resource_requested: Categorical -> Derive from payload if URL-like, else '/unknown'
    - bytes_sent: Numerical -> Impute 0 (0 bytes body transferred) -> int64
    - referrer: Categorical -> Impute 'none' (direct request with no Referer header)

    Returns:
        Tuple[pd.DataFrame, pd.DataFrame]: Cleaned DataFrame and before/after comparison table.
    """
    records = []
    df_clean = df.copy()

    strategies = {
        "timestamp": {
            "type": "datetime64[ns]",
            "strategy": "Retain NaT; do not fabricate fake dates",
            "fill": None,
        },
        "category_type": {
            "type": "categorical (string)",
            "strategy": "Impute 'unknown' for unclassified requests",
            "fill": "unknown",
        },
        "payload": {
            "type": "categorical (string)",
            "strategy": "Impute 'none' for benign requests without payload",
            "fill": "none",
        },
        "client_ip": {
            "type": "categorical (string)",
            "strategy": "Impute 'unknown' for missing network identifier",
            "fill": "unknown",
        },
        "client_port": {
            "type": "numerical (int64)",
            "strategy": "Impute 0 for unrecorded port",
            "fill": 0,
        },
        "user_agent": {
            "type": "categorical (string)",
            "strategy": "Impute 'unknown' for missing client header",
            "fill": "unknown",
        },
        "accept_language": {
            "type": "categorical (string)",
            "strategy": "Impute 'unknown' for missing language header",
            "fill": "unknown",
        },
        "proxy_ip": {
            "type": "categorical (string)",
            "strategy": "Impute 'none' indicating direct client connection",
            "fill": "none",
        },
        "request_type": {
            "type": "categorical (string)",
            "strategy": "Impute 'unknown' for unrecorded HTTP verb",
            "fill": "unknown",
        },
        "status_code": {
            "type": "numerical (int64)",
            "strategy": "Impute 0 indicating unrecorded response/connection drop",
            "fill": 0,
        },
        "resource_requested": {
            "type": "categorical (string)",
            "strategy": "Derive from path payload if available, else '/unknown'",
            "fill": "/unknown",
        },
        "bytes_sent": {
            "type": "numerical (int64)",
            "strategy": "Impute 0 for 0 bytes transferred",
            "fill": 0,
        },
        "referrer": {
            "type": "categorical (string)",
            "strategy": "Impute 'none' indicating direct traffic",
            "fill": "none",
        },
    }

    # Ensure string/categorical columns can hold strings (prevent float64 LossySetitemError in pandas 3+)
    string_cols = [
        "category_type",
        "payload",
        "client_ip",
        "user_agent",
        "accept_language",
        "proxy_ip",
        "request_type",
        "resource_requested",
        "referrer",
    ]
    for sc in string_cols:
        if sc in df_clean.columns:
            df_clean[sc] = df_clean[sc].astype(object)

    # Derive resource_requested from payload if resource_requested is null but payload has a path
    if "payload" in df_clean.columns and "resource_requested" in df_clean.columns:
        path_pattern = re.compile(
            r"^(?:https?://|/|\./|\.\./|[a-zA-Z0-9_\-]+\.(?:html?|php|asp|jsp|ini|conf))",
            re.IGNORECASE,
        )
        is_missing_resource = df_clean["resource_requested"].isnull()
        has_path_payload = (
            df_clean["payload"].notnull()
            & df_clean["payload"].astype(str).str.contains(path_pattern, regex=True)
        )
        mask = is_missing_resource & has_path_payload
        df_clean.loc[mask, "resource_requested"] = df_clean.loc[mask, "payload"].astype(str)

    total_rows = len(df_clean)

    for col in df.columns:
        before_count = int(df[col].isnull().sum())
        before_pct = round((before_count / total_rows) * 100, 4)

        cfg = strategies.get(
            col,
            {
                "type": "string",
                "strategy": "Impute 'unknown'",
                "fill": "unknown",
            },
        )

        fill_val = cfg["fill"]
        if fill_val is not None:
            df_clean[col] = df_clean[col].fillna(fill_val)

        after_count = int(df_clean[col].isnull().sum())
        after_pct = round((after_count / total_rows) * 100, 4)

        records.append(
            {
                "column_name": col,
                "data_type": cfg["type"],
                "missing_before": before_count,
                "missing_pct_before": f"{before_pct:.2f}%",
                "imputation_strategy": cfg["strategy"],
                "missing_after": after_count,
                "missing_pct_after": f"{after_pct:.2f}%",
            }
        )

    summary_df = pd.DataFrame(records)
    return df_clean, summary_df


def standardize_text_and_paths(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    r"""Cleans strings (whitespace trimming, lowercase standardization)
    and generates the normalized URL/path column 'normalized_resource'.

    Returns:
        Tuple[pd.DataFrame, Dict[str, Any]]: Processed DataFrame and transformation counts.
    """
    df_out = df.copy()

    # Standardize string fields: lowercase category_type, accept_language, request_type
    string_cols_to_lower = [
        "category_type",
        "accept_language",
        "request_type",
        "referrer",
        "proxy_ip",
    ]
    for col in string_cols_to_lower:
        if col in df_out.columns:
            df_out[col] = (
                df_out[col]
                .astype(str)
                .str.strip()
                .str.lower()
                .replace({"nan": "unknown", "": "unknown"})
            )

    # Trim client_ip and user_agent (keep user-agent casing intact for browser signature fidelity)
    if "client_ip" in df_out.columns:
        df_out["client_ip"] = (
            df_out["client_ip"].astype(str).str.strip().str.lower()
        )
    if "user_agent" in df_out.columns:
        df_out["user_agent"] = (
            df_out["user_agent"]
            .astype(str)
            .str.strip()
            .replace({"nan": "unknown", "": "unknown"})
        )
    if "payload" in df_out.columns:
        df_out["payload"] = (
            df_out["payload"]
            .astype(str)
            .str.strip()
            .replace({"nan": "none", "": "none"})
        )

    # Resource requested normalization
    if "resource_requested" in df_out.columns:
        df_out["resource_requested"] = (
            df_out["resource_requested"]
            .astype(str)
            .str.strip()
            .replace({"nan": "/unknown", "": "/unknown"})
        )
        # Vectorized / series application of normalize_url_path
        df_out["normalized_resource"] = df_out["resource_requested"].apply(
            normalize_url_path
        )

    stats = {
        "text_columns_standardized": string_cols_to_lower
        + ["client_ip", "user_agent", "payload"],
        "normalized_resource_created": "normalized_resource" in df_out.columns,
        "unique_normalized_resources": int(df_out["normalized_resource"].nunique())
        if "normalized_resource" in df_out.columns
        else 0,
    }
    return df_out, stats


def cast_data_types(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, str]]:
    r"""Enforces strict standardized data types across all columns.

    - timestamp: datetime64[ns]
    - client_port, status_code, bytes_sent: int64
    - category_type, payload, client_ip, user_agent, accept_language,
      proxy_ip, request_type, resource_requested, normalized_resource, referrer: string

    Returns:
        Tuple[pd.DataFrame, Dict[str, str]]: Typed DataFrame and dtype map.
    """
    df_typed = df.copy()

    # Numerical columns to int64
    numeric_cols = ["client_port", "status_code", "bytes_sent"]
    for col in numeric_cols:
        if col in df_typed.columns:
            df_typed[col] = pd.to_numeric(df_typed[col], errors="coerce").fillna(0).astype("int64")

    # Timestamp to datetime64[ns]
    if "timestamp" in df_typed.columns:
        df_typed["timestamp"] = pd.to_datetime(df_typed["timestamp"], errors="coerce")

    # String columns to string dtype
    string_cols = [
        "category_type",
        "payload",
        "client_ip",
        "user_agent",
        "accept_language",
        "proxy_ip",
        "request_type",
        "resource_requested",
        "normalized_resource",
        "referrer",
    ]
    for col in string_cols:
        if col in df_typed.columns:
            df_typed[col] = df_typed[col].astype("string")

    dtypes_map = {col: str(df_typed[col].dtype) for col in df_typed.columns}
    return df_typed, dtypes_map
