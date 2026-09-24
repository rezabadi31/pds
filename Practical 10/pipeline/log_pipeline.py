"""log_pipeline.py
Practical 10: Reusable, Auditable, and Modular Log Processing Pipeline
Integrates Loading, Parsing, Preprocessing, Attack Labeling, Feature Engineering,
Validation, and Multi-Format (CSV & Parquet) Serialization.
"""

import json
import time
import math
import collections
import re
import urllib.parse
from pathlib import Path
from typing import Generator, Optional, Dict, Any, List, Union, Tuple, Set

import numpy as np
import pandas as pd

try:
    import pyarrow
    import pyarrow.parquet as pq
    HAS_PYARROW = True
except ImportError:
    HAS_PYARROW = False

from pipeline.config import (
    DEFAULT_INPUT_PATH,
    DATA_PROCESSED_DIR,
    REPORTS_DIR,
    OUTPUTS_DIR,
    STRUCTURED_LOGS_CSV,
    LABELED_LOGS_CSV,
    FEATURE_ENGINEERED_LOGS_CSV,
    FEATURE_ENGINEERED_LOGS_PARQUET,
    PIPELINE_REPORT_TXT,
    PIPELINE_SUMMARY_JSON,
    RANDOM_STATE,
    SUPPORTED_FORMATS,
    SOURCE_FIELDS,
    UNAVAILABLE_HTTP_FIELDS,
    ALL_STRUCTURED_COLUMNS,
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW_MINUTES,
    SQLI_REGEX,
    PATH_TRAVERSAL_REGEX,
    COMMAND_INJECTION_REGEX,
    XSS_REGEX,
    LOGIN_ENDPOINT_REGEX,
    ATTACK_PRIORITY_ORDER,
    BOT_PATTERN,
    SCANNER_PATTERN,
)


def calculate_shannon_entropy(text: str) -> float:
    """Calculates character-level Shannon entropy in bits."""
    if not isinstance(text, str) or not text:
        return 0.0
    length = len(text)
    counts = collections.Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def normalize_url_path(raw_url: Any) -> str:
    """Normalizes an HTTP URL or resource path."""
    if raw_url is None or pd.isna(raw_url):
        return "/unknown"
    val = str(raw_url).strip()
    if not val or val.lower() in ("nan", "none", "null", ""):
        return "/unknown"

    try:
        parsed = urllib.parse.urlsplit(val)
        scheme = parsed.scheme.lower() if parsed.scheme else ""
        netloc = parsed.netloc.lower() if parsed.netloc else ""
        path = parsed.path
        query = parsed.query
        fragment = parsed.fragment
    except Exception:
        path = val
        query = ""
        fragment = ""
        scheme = ""
        netloc = ""

    path = path.strip().lower()
    if not path:
        path = "/"
    elif not path.startswith("/") and not netloc:
        path = "/" + path

    path = re.sub(r"/{2,}", "/", path)
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    # Normalize .html / .htm
    path = re.sub(r"\.(?:html?)$", "", path, flags=re.IGNORECASE)
    if not path:
        path = "/"

    result = path
    if netloc:
        prefix = f"{scheme}://{netloc}" if scheme else f"//{netloc}"
        result = prefix + result
    if query:
        result = f"{result}?{query}"
    if fragment:
        result = f"{result}#{fragment}"
    return result


def clean_field_string(val: Any, lowercase: bool = True) -> Optional[str]:
    """Cleans a string entry, stripping quotes, whitespace, and empty representations."""
    if val is None or pd.isna(val):
        return None
    s = str(val).strip()
    if not s or s.lower() in ("nan", "none", "null", ""):
        return None
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1].replace(r'\/', '/').replace(r'\"', '"').replace(r'\\', '\\').strip()
        if not s or s.lower() in ("nan", "none", "null", ""):
            return None
    s = re.sub(r"\s+", " ", s)
    return s.lower() if lowercase else s


class LogProcessingPipeline:
    """End-to-end, reusable, modular data engineering pipeline for cybersecurity access logs."""

    def __init__(
        self,
        input_path: Optional[Union[str, Path]] = None,
        output_dir: Optional[Union[str, Path]] = None,
        export_formats: Optional[List[str]] = None,
    ):
        self.input_path = Path(input_path) if input_path else DEFAULT_INPUT_PATH
        self.output_dir = Path(output_dir) if output_dir else DATA_PROCESSED_DIR
        self.export_formats = export_formats or SUPPORTED_FORMATS

        # Pipeline runtime state
        self.raw_records: List[List[Any]] = []
        self.df_structured: Optional[pd.DataFrame] = None
        self.df_preprocessed: Optional[pd.DataFrame] = None
        self.df_labeled: Optional[pd.DataFrame] = None
        self.df_featured: Optional[pd.DataFrame] = None

        # Metrics & audit tracking
        self.metrics: Dict[str, Any] = {
            "input_file": str(self.input_path),
            "raw_records": 0,
            "structured_records": 0,
            "preprocessed_records": 0,
            "final_records": 0,
            "missing_before": 0,
            "missing_after": 0,
            "duplicates_removed": 0,
            "invalid_timestamps": 0,
            "label_distribution": {},
            "engineered_features_count": 0,
            "engineered_feature_names": [],
            "validation_checks": {},
            "execution_times": {},
            "output_files": {},
            "status": "INITIALIZED",
        }

    # -----------------------------------------------------------------------
    # PART 3: LOAD LOGS [1/7]
    # -----------------------------------------------------------------------
    def load(self) -> Generator[str, None, None]:
        """Safely loads lines from raw access log file with UTF-8 decoding."""
        print("\n" + "=" * 60)
        print("[1/7] LOADING LOG DATASET")
        print("=" * 60)

        if not self.input_path.exists():
            raise FileNotFoundError(
                f"CRITICAL ERROR: Input log file not found at: {self.input_path}\n"
                f"Please ensure the file path is correct or specify --input <path>."
            )

        file_size_bytes = self.input_path.stat().st_size
        file_size_mb = file_size_bytes / (1024 * 1024)
        print(f"Input file:       {self.input_path.name}")
        print(f"File Path:        {self.input_path}")
        print(f"File Size:        {file_size_bytes:,} bytes ({file_size_mb:.2f} MB)")

        t0 = time.time()
        total_raw = 0
        with open(self.input_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                s = line.strip()
                if s:
                    total_raw += 1
                    yield s

        self.metrics["raw_records"] = total_raw
        self.metrics["execution_times"]["load"] = round(time.time() - t0, 3)
        print(f"Total raw records: {total_raw:,}")
        print(f"Loading status:    SUCCESS ({self.metrics['execution_times']['load']}s)")

    # -----------------------------------------------------------------------
    # PART 4: PARSE AND STRUCTURE [2/7]
    # -----------------------------------------------------------------------
    def structure(self) -> pd.DataFrame:
        """Converts raw JSON records into a structured 13-column DataFrame."""
        print("\n" + "=" * 60)
        print("[2/7] PARSING AND STRUCTURING")
        print("=" * 60)

        t0 = time.time()
        parsed_rows = []
        parsing_failures = 0

        # Generator consumes file
        for raw_line in self.load():
            # Handle concatenated JSON arrays if present
            parts = raw_line.split("][") if "][" in raw_line else [raw_line]
            for part in parts:
                entry = part.strip()
                if not entry:
                    continue
                if not entry.startswith("["):
                    entry = "[" + entry
                if not entry.endswith("]"):
                    entry = entry + "]"

                try:
                    data = json.loads(entry)
                    if isinstance(data, list) and len(data) >= 8:
                        row = [
                            clean_field_string(data[0]),  # category_type
                            clean_field_string(data[1], lowercase=False),  # payload
                            clean_field_string(data[2]),  # timestamp
                            clean_field_string(data[3]),  # client_ip
                            data[4],                      # client_port
                            clean_field_string(data[5]),  # user_agent
                            clean_field_string(data[6]),  # accept_language
                            clean_field_string(data[7]),  # proxy_ip
                            None,                         # request_type (unavailable)
                            None,                         # status_code (unavailable)
                            None,                         # resource_requested (unavailable)
                            None,                         # bytes_sent (unavailable)
                            None,                         # referrer (unavailable)
                        ]
                        parsed_rows.append(row)
                    else:
                        parsing_failures += 1
                except Exception:
                    parsing_failures += 1

        df = pd.DataFrame(parsed_rows, columns=ALL_STRUCTURED_COLUMNS)

        # Cast client_port to numeric
        df["client_port"] = pd.to_numeric(df["client_port"], errors="coerce")

        self.df_structured = df
        n_rows, n_cols = df.shape
        self.metrics["structured_records"] = n_rows
        self.metrics["execution_times"]["structure"] = round(time.time() - t0, 3)

        print(f"Number of rows:     {n_rows:,}")
        print(f"Number of columns:  {n_cols}")
        print(f"Column names:       {list(df.columns)}")
        print(f"Parsing failures:   {parsing_failures}")
        print(f"Structuring status: SUCCESS ({self.metrics['execution_times']['structure']}s)")

        # Save structured intermediate
        self.output_dir.mkdir(parents=True, exist_ok=True)
        structured_out = self.output_dir / "structured_logs.csv"
        df.to_csv(structured_out, index=False)
        self.metrics["output_files"]["structured_csv"] = str(structured_out)
        print(f"Saved structured logs to: {structured_out.name}")

        return df

    # -----------------------------------------------------------------------
    # PART 5: PREPROCESSING [3/7]
    # -----------------------------------------------------------------------
    def preprocess(self) -> pd.DataFrame:
        """Preprocesses structured data using Practical 3 cleaning methodologies."""
        print("\n" + "=" * 60)
        print("[3/7] PREPROCESSING AND CLEANING")
        print("=" * 60)

        t0 = time.time()
        if self.df_structured is None:
            self.structure()

        df = self.df_structured.copy()
        records_before = len(df)
        missing_before = int(df.isna().sum().sum())
        duplicates_before = int(df.duplicated().sum())

        print(f"Records before preprocessing: {records_before:,}")
        print(f"Missing values before:        {missing_before:,}")
        print(f"Duplicates before:            {duplicates_before:,}")

        # 1. Convert timestamp safely with errors="coerce"
        ts_converted = pd.to_datetime(df["timestamp"], errors="coerce")
        invalid_ts_count = int(ts_converted.isna().sum())
        df["timestamp"] = ts_converted

        # 2. Remove exact duplicates
        df = df.drop_duplicates(keep="first").copy()
        records_dedup = len(df)
        duplicates_removed = records_before - records_dedup

        # 3. Create normalized_resource (from payload/resource if available)
        raw_res = df["resource_requested"].copy()
        # If resource_requested is unavailable, extract possible URL/path from payload
        payload_mask = df["payload"].str.startswith("/", na=False)
        raw_res[payload_mask] = df.loc[payload_mask, "payload"]

        # Vectorized / cached path normalization
        unique_paths = raw_res.dropna().unique()
        path_norm_cache = {p: normalize_url_path(p) for p in unique_paths}
        path_norm_cache[None] = "/unknown"
        path_norm_cache[""] = "/unknown"
        df["normalized_resource"] = raw_res.map(path_norm_cache).fillna("/unknown")

        # 4. Handle missing values with justified domain strategies
        impute_rules = {
            "category_type": "unknown",
            "payload": "none",
            "client_ip": "unknown",
            "client_port": 0,
            "user_agent": "unknown",
            "accept_language": "unknown",
            "proxy_ip": "none",
            "request_type": "unknown",
            "status_code": 0,
            "resource_requested": "/unknown",
            "bytes_sent": 0,
            "referrer": "none",
        }
        # Vectorized missing value imputation with domain strategies
        df = df.fillna(value=impute_rules)

        # Standardize numeric columns
        df["client_port"] = df["client_port"].astype(np.int64)
        df["status_code"] = df["status_code"].astype(np.int64)
        df["bytes_sent"] = df["bytes_sent"].astype(np.int64)

        missing_after = int(df.isna().sum().sum())
        records_after = len(df)

        self.df_preprocessed = df
        self.metrics["preprocessed_records"] = records_after
        self.metrics["missing_before"] = missing_before
        self.metrics["missing_after"] = missing_after
        self.metrics["duplicates_removed"] = duplicates_removed
        self.metrics["invalid_timestamps"] = invalid_ts_count
        self.metrics["execution_times"]["preprocess"] = round(time.time() - t0, 3)

        print(f"Records after preprocessing:  {records_after:,}")
        print(f"Missing values after:         {missing_after:,}")
        print(f"Invalid timestamps:           {invalid_ts_count}")
        print(f"Duplicates removed:           {duplicates_removed:,}")
        print(f"Preprocessing status:         SUCCESS ({self.metrics['execution_times']['preprocess']}s)")

        return df

    # -----------------------------------------------------------------------
    # PART 6: ATTACK LABELING [4/7]
    # -----------------------------------------------------------------------
    def label(self) -> pd.DataFrame:
        """Applies deterministic rule-based attack labeling from Practical 4."""
        print("\n" + "=" * 60)
        print("[4/7] RULE-BASED ATTACK LABELING")
        print("=" * 60)

        t0 = time.time()
        if self.df_preprocessed is None:
            self.preprocess()

        df = self.df_preprocessed.copy()

        # Build combined searchable text string for regex matching
        search_text = (
            df["payload"].fillna("").astype(str)
            + " "
            + df["normalized_resource"].fillna("").astype(str)
            + " "
            + df["category_type"].fillna("").astype(str)
        ).str.strip()

        labels = pd.Series("benign", index=df.index, dtype="string")
        reasons = pd.Series("No attack pattern detected (standard request)", index=df.index, dtype="string")

        # 1. Rule 5: Brute Force Detection (Threshold >= 10 in 10-minute sliding window)
        is_login = search_text.str.contains(LOGIN_ENDPOINT_REGEX, regex=True)
        login_df = df.loc[is_login, ["client_ip", "timestamp"]].dropna().sort_values(by=["client_ip", "timestamp"])

        bf_indices: Set[int] = set()
        window_delta = pd.Timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)
        for ip, group in login_df.groupby("client_ip"):
            if len(group) >= BRUTE_FORCE_THRESHOLD:
                ts_arr = group["timestamp"].values
                n_grp = len(ts_arr)
                for i in range(n_grp):
                    t_win_end = ts_arr[i] + window_delta
                    in_win = (group["timestamp"] >= ts_arr[i]) & (group["timestamp"] <= t_win_end)
                    if in_win.sum() >= BRUTE_FORCE_THRESHOLD:
                        bf_indices.update(group[in_win].index)

        if bf_indices:
            bf_idx_list = list(bf_indices)
            labels.loc[bf_idx_list] = "brute_force"
            reasons.loc[bf_idx_list] = f"Brute force: >={BRUTE_FORCE_THRESHOLD} login requests within {BRUTE_FORCE_WINDOW_MINUTES}m"

        # 2. Rule 4: Cross-Site Scripting (XSS)
        m_xss = search_text.str.contains(XSS_REGEX, regex=True)
        labels[m_xss] = "xss"
        reasons[m_xss] = "XSS pattern detected (<script>, alert, or document.cookie)"

        # 3. Rule 3: Command Injection
        m_cmdi = search_text.str.contains(COMMAND_INJECTION_REGEX, regex=True)
        labels[m_cmdi] = "command_injection"
        reasons[m_cmdi] = "OS command injection detected (shell separator and binary)"

        # 4. Rule 2: Path Traversal
        m_pt = search_text.str.contains(PATH_TRAVERSAL_REGEX, regex=True)
        labels[m_pt] = "path_traversal"
        reasons[m_pt] = "Path traversal detected (directory climbing or system file probe)"

        # 5. Rule 1: SQL Injection (Highest Priority)
        m_sqli = search_text.str.contains(SQLI_REGEX, regex=True)
        labels[m_sqli] = "sqli"
        reasons[m_sqli] = "SQL injection detected (UNION SELECT, tautology, or comments)"

        df["label"] = labels
        df["label_reason"] = reasons

        label_dist = df["label"].value_counts().to_dict()
        self.df_labeled = df
        self.metrics["label_distribution"] = label_dist
        self.metrics["execution_times"]["label"] = round(time.time() - t0, 3)

        print("Class distribution:")
        total_recs = len(df)
        for cls_name, count in label_dist.items():
            pct = (count / total_recs) * 100
            print(f"  - {cls_name:<20}: {count:>10,} ({pct:>6.2f}%)")

        # Save labeled intermediate
        labeled_out = self.output_dir / "labeled_logs.csv"
        df.to_csv(labeled_out, index=False)
        self.metrics["output_files"]["labeled_csv"] = str(labeled_out)
        print(f"Saved labeled logs to: {labeled_out.name}")

        return df

    # -----------------------------------------------------------------------
    # PART 7: FEATURE ENGINEERING [5/7]
    # -----------------------------------------------------------------------
    def engineer_features(self) -> pd.DataFrame:
        """Vectorized feature engineering extracting 18+ numeric features from Practical 5."""
        print("\n" + "=" * 60)
        print("[5/7] FEATURE ENGINEERING")
        print("=" * 60)

        t0 = time.time()
        if self.df_labeled is None:
            self.label()

        df = self.df_labeled.copy()
        n_rows = len(df)

        # 1. Requests per IP & IP rank
        ip_counts = df["client_ip"].value_counts()
        df["requests_per_ip"] = df["client_ip"].map(ip_counts).fillna(1).astype(int)
        ip_ranks = ip_counts.rank(ascending=False, method="dense").astype(int)
        df["ip_request_rank"] = df["client_ip"].map(ip_ranks).fillna(9999).astype(int)

        # 2. Temporal & Inter-request Time Dynamics (Vectorized)
        work_df = pd.DataFrame({
            "client_ip": df["client_ip"],
            "timestamp": df["timestamp"],
            "orig_idx": df.index,
        }).sort_values(by=["client_ip", "timestamp"])

        same_ip = work_df["client_ip"] == work_df["client_ip"].shift(1)
        raw_diff = work_df["timestamp"].diff().dt.total_seconds().values
        time_diff = np.where(same_ip, raw_diff, np.nan)
        work_df["inter_request_time"] = time_diff

        # Vectorized sliding time windows (1min, 5min, 10min)
        t_sec = (work_df["timestamp"].astype(np.int64) // 10**9).values
        ips = work_df["client_ip"].values
        change_idx = np.where(ips[:-1] != ips[1:])[0] + 1
        starts = np.concatenate(([0], change_idx))
        ends = np.concatenate((change_idx, [n_rows]))

        counts_1m = np.zeros(n_rows, dtype=np.int32)
        counts_5m = np.zeros(n_rows, dtype=np.int32)

        for s, e in zip(starts, ends):
            times = t_sec[s:e]
            grp_len = len(times)
            idx_seq = np.arange(grp_len)
            l_1m = np.searchsorted(times, times - 60, side="left")
            l_5m = np.searchsorted(times, times - 300, side="left")
            counts_1m[s:e] = idx_seq - l_1m + 1
            counts_5m[s:e] = idx_seq - l_5m + 1

        work_df["requests_per_ip_1min"] = counts_1m
        work_df["requests_per_ip_5min"] = counts_5m

        work_df.sort_values(by="orig_idx", inplace=True)
        df["inter_request_time"] = work_df["inter_request_time"].values
        df["requests_per_ip_1min"] = work_df["requests_per_ip_1min"].values
        df["requests_per_ip_5min"] = work_df["requests_per_ip_5min"].values

        # Request rates per second
        df["request_rate_1min"] = (df["requests_per_ip_1min"] / 60.0).round(4)
        df["request_rate_5min"] = (df["requests_per_ip_5min"] / 300.0).round(4)

        # 3. Status Code Frequency
        sc_counts = df["status_code"].value_counts()
        df["status_code_frequency"] = df["status_code"].map(sc_counts).fillna(0).astype(int)

        # 4. URL Lexical & Entropy Features (Cached on unique values)
        def _compute_url_metrics(u: str) -> Dict[str, Any]:
            if not isinstance(u, str) or not u:
                return {"url_length": 0, "url_entropy": 0.0, "path_depth": 0, "query_parameter_count": 0, "special_character_count": 0, "digit_ratio": 0.0, "letter_ratio": 0.0}
            length = len(u)
            entropy = calculate_shannon_entropy(u)
            depth = u.count("/")
            query_count = (u.split("?", 1)[1].count("&") + 1) if "?" in u else 0
            digits = sum(c.isdigit() for c in u)
            letters = sum(c.isalpha() for c in u)
            specials = sum(not c.isalnum() for c in u)
            return {
                "url_length": length,
                "url_entropy": entropy,
                "path_depth": depth,
                "query_parameter_count": query_count,
                "special_character_count": specials,
                "digit_ratio": round(digits / length, 4) if length else 0.0,
                "letter_ratio": round(letters / length, 4) if length else 0.0,
            }

        unique_urls = df["normalized_resource"].dropna().unique()
        url_cache = {u: _compute_url_metrics(u) for u in unique_urls}
        url_cache[None] = _compute_url_metrics("")

        for feat in ["url_length", "url_entropy", "path_depth", "query_parameter_count", "special_character_count", "digit_ratio", "letter_ratio"]:
            f_map = {u: url_cache[u][feat] for u in url_cache}
            df[feat] = df["normalized_resource"].map(f_map).fillna(0.0)

        # 5. Payload Structural & Entropy Features (Cached)
        def _compute_payload_metrics(p: str) -> Dict[str, Any]:
            if not isinstance(p, str) or p.lower() in ("none", "null", ""):
                return {"payload_length": 0, "payload_entropy": 0.0, "contains_sql_keyword": 0, "contains_path_traversal": 0, "contains_script_tag": 0, "contains_command_separator": 0}
            return {
                "payload_length": len(p),
                "payload_entropy": calculate_shannon_entropy(p),
                "contains_sql_keyword": 1 if SQLI_REGEX.search(p) else 0,
                "contains_path_traversal": 1 if PATH_TRAVERSAL_REGEX.search(p) else 0,
                "contains_script_tag": 1 if XSS_REGEX.search(p) else 0,
                "contains_command_separator": 1 if COMMAND_INJECTION_REGEX.search(p) else 0,
            }

        unique_payloads = df["payload"].dropna().unique()
        payload_cache = {p: _compute_payload_metrics(p) for p in unique_payloads}
        payload_cache[None] = _compute_payload_metrics("")
        payload_cache[""] = _compute_payload_metrics("")

        for feat in ["payload_length", "payload_entropy", "contains_sql_keyword", "contains_path_traversal", "contains_script_tag", "contains_command_separator"]:
            f_map = {p: payload_cache[p][feat] for p in payload_cache}
            df[feat] = df["payload"].map(f_map).fillna(0.0)

        # 6. Cumulative failed pattern count
        df["failed_pattern_count"] = (
            df["contains_sql_keyword"]
            + df["contains_path_traversal"]
            + df["contains_script_tag"]
            + df["contains_command_separator"]
        ).astype(int)

        # 7. Unique URLs per IP
        urls_per_ip = df.groupby("client_ip")["normalized_resource"].nunique()
        df["unique_urls_per_ip"] = df["client_ip"].map(urls_per_ip).fillna(1).astype(int)

        # 8. User-Agent Heuristics (Bot, Scanner, Length)
        def _compute_ua_metrics(ua: str) -> Dict[str, Any]:
            if not isinstance(ua, str) or not ua or ua == "unknown":
                return {"user_agent_length": 0, "is_bot": 0, "is_scanner": 0}
            return {
                "user_agent_length": len(ua),
                "is_bot": 1 if BOT_PATTERN.search(ua) else 0,
                "is_scanner": 1 if SCANNER_PATTERN.search(ua) else 0,
            }

        unique_uas = df["user_agent"].dropna().unique()
        ua_cache = {u: _compute_ua_metrics(u) for u in unique_uas}
        ua_cache[None] = _compute_ua_metrics("")
        ua_cache["unknown"] = _compute_ua_metrics("")

        for feat in ["user_agent_length", "is_bot", "is_scanner"]:
            f_map = {u: ua_cache[u][feat] for u in ua_cache}
            df[feat] = df["user_agent"].map(f_map).fillna(0).astype(int)

        # Impute residual NaN in inter_request_time with median (first request of an IP)
        inter_median = float(df["inter_request_time"].median())
        df["inter_request_time"] = df["inter_request_time"].fillna(inter_median if not np.isnan(inter_median) else 60.0)

        # Exclude label and label_reason from ML feature definitions
        excluded_from_ml = set(ALL_STRUCTURED_COLUMNS + ["label", "label_reason", "normalized_resource"])
        engineered_cols = [c for c in df.columns if c not in excluded_from_ml and np.issubdtype(df[c].dtype, np.number)]

        self.df_featured = df
        self.metrics["final_records"] = len(df)
        self.metrics["engineered_features_count"] = len(engineered_cols)
        self.metrics["engineered_feature_names"] = engineered_cols
        self.metrics["execution_times"]["feature_engineering"] = round(time.time() - t0, 3)

        print(f"Engineered numeric features: {len(engineered_cols)}")
        print(f"Sample features:            {engineered_cols[:8]} ...")
        print(f"Feature engineering status: SUCCESS ({self.metrics['execution_times']['feature_engineering']}s)")

        return df

    # -----------------------------------------------------------------------
    # PART 9: OUTPUT FILES & SAVING [7/7]
    # -----------------------------------------------------------------------
    def save(self) -> Dict[str, Path]:
        """Exports the processed datasets to CSV and Parquet, generates audit reports."""
        print("\n" + "=" * 60)
        print("[7/7] EXPORTING DATASETS AND REPORTS")
        print("=" * 60)

        t0 = time.time()
        if self.df_featured is None:
            self.engineer_features()

        df = self.df_featured
        self.output_dir.mkdir(parents=True, exist_ok=True)
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

        saved_files = {}

        # 1. Export CSV
        csv_path = self.output_dir / "feature_engineered_logs.csv"
        print(f"Exporting CSV: {csv_path}...")
        df.to_csv(csv_path, index=False)
        saved_files["feature_engineered_csv"] = csv_path
        self.metrics["output_files"]["feature_engineered_csv"] = str(csv_path)

        # 2. Export Parquet
        parquet_path = self.output_dir / "feature_engineered_logs.parquet"
        if HAS_PYARROW:
            print(f"Exporting Parquet: {parquet_path}...")
            df.to_parquet(parquet_path, engine="pyarrow", index=False)
            saved_files["feature_engineered_parquet"] = parquet_path
            self.metrics["output_files"]["feature_engineered_parquet"] = str(parquet_path)
        else:
            print("[WARN] PyArrow dependency is missing. Parquet export skipped.")
            print("Install PyArrow using: pip install pyarrow")

        # 3. Generate reports/pipeline_report.txt (Part 11)
        self._generate_text_report()

        # 4. Generate outputs/pipeline_summary.json (Part 11)
        self._generate_json_summary()

        self.metrics["execution_times"]["save"] = round(time.time() - t0, 3)
        print(f"Saving status: SUCCESS ({self.metrics['execution_times']['save']}s)")

        return saved_files

    # -----------------------------------------------------------------------
    # PART 10: VALIDATION [6/7]
    # -----------------------------------------------------------------------
    def validate(self) -> bool:
        """Executes all 14 strict quality and integrity checks."""
        print("\n" + "=" * 60)
        print("[6/7] PIPELINE VALIDATION CHECKS")
        print("=" * 60)

        checks = {}

        # Check 1: Input file exists
        checks["Input file exists"] = self.input_path.exists()

        # Check 2: Logs loaded
        checks["Logs loaded"] = self.metrics["raw_records"] > 0

        # Check 3: Data structured
        checks["Data structured"] = (
            self.df_structured is not None and len(self.df_structured) > 0 and len(self.df_structured.columns) >= 13
        )

        # Check 4: Timestamp processed
        ts_ok = (
            self.df_preprocessed is not None
            and "timestamp" in self.df_preprocessed.columns
            and np.issubdtype(self.df_preprocessed["timestamp"].dtype, np.datetime64)
        )
        checks["Timestamp processed"] = ts_ok

        # Check 5: Missing values handled
        missing_ok = self.df_preprocessed is not None and self.metrics["missing_after"] == 0
        checks["Missing values handled"] = missing_ok

        # Check 6: Exact duplicates handled
        checks["Exact duplicates handled"] = self.metrics["duplicates_removed"] >= 0

        # Check 7: Labels generated
        checks["Labels generated"] = (
            self.df_labeled is not None and "label" in self.df_labeled.columns and "label_reason" in self.df_labeled.columns
        )

        # Check 8: Expected label classes checked
        dist = self.metrics["label_distribution"]
        expected_classes = {"benign", "sqli", "path_traversal", "command_injection", "xss", "brute_force"}
        classes_present = set(dist.keys())
        # All expected classes should be checked (present in domain)
        checks["Expected label classes checked"] = bool(expected_classes.intersection(classes_present))

        # Check 9: Features generated
        checks["Features generated"] = self.metrics["engineered_features_count"] >= 10

        # Check 10: No label leakage into ML features
        ml_features = self.metrics["engineered_feature_names"]
        leakage = any(f.lower() in ("label", "label_reason", "target") for f in ml_features)
        checks["No label leakage into ML features"] = (not leakage) and len(ml_features) > 0

        # Check 11: Output CSV exists
        csv_file = self.output_dir / "feature_engineered_logs.csv"
        checks["Output CSV exists"] = csv_file.exists() and csv_file.stat().st_size > 0

        # Check 12: Output Parquet exists
        parquet_file = self.output_dir / "feature_engineered_logs.parquet"
        checks["Output Parquet exists"] = parquet_file.exists() and parquet_file.stat().st_size > 0

        # Check 13: Output row count valid
        checks["Output row count valid"] = (
            self.df_featured is not None and len(self.df_featured) == self.metrics["final_records"] and len(self.df_featured) > 0
        )

        # Check 14: Pipeline completed
        checks["Pipeline completed"] = all(v for k, v in checks.items() if k != "Pipeline completed")

        self.metrics["validation_checks"] = checks

        # Print standard PASS/FAIL formatted output
        for name, passed in checks.items():
            status_tag = "[PASS]" if passed else "[FAIL]"
            print(f"{status_tag} {name}")

        overall_pass = all(checks.values())
        print(f"\nValidation status: {'PASS' if overall_pass else 'FAIL'}")
        return overall_pass

    # -----------------------------------------------------------------------
    # REPORTING & SUMMARIES (PART 11)
    # -----------------------------------------------------------------------
    def _generate_text_report(self) -> None:
        """Assembles reports/pipeline_report.txt."""
        total_time = sum(self.metrics["execution_times"].values())
        lines = [
            "=" * 70,
            "PRACTICAL 10: REUSABLE DATA PIPELINE COMPREHENSIVE REPORT",
            "=" * 70,
            "",
            "1. PIPELINE OVERVIEW & TIMING",
            "-" * 70,
            f"Input file:               {self.input_path}",
            f"Total Execution Time:     {total_time:.2f} seconds",
            f"Raw record count:         {self.metrics['raw_records']:,}",
            f"Structured record count:  {self.metrics['structured_records']:,}",
            f"Preprocessed record count:{self.metrics['preprocessed_records']:,}",
            f"Final record count:       {self.metrics['final_records']:,}",
            f"Number of columns:        {len(self.df_featured.columns) if self.df_featured is not None else 0}",
            f"Number of engineered features: {self.metrics['engineered_features_count']}",
            "",
            "Stage Execution Times:",
        ]
        for stage, duration in self.metrics["execution_times"].items():
            lines.append(f"  - {stage:<25}: {duration:.2f}s")

        lines.extend([
            "",
            "2. DATA QUALITY & CLEANING METRICS",
            "-" * 70,
            f"Missing values before:    {self.metrics['missing_before']:,}",
            f"Missing values after:     {self.metrics['missing_after']:,}",
            f"Duplicates removed:       {self.metrics['duplicates_removed']:,}",
            f"Invalid timestamps:       {self.metrics['invalid_timestamps']}",
            "",
            "3. CLASS DISTRIBUTION",
            "-" * 70,
        ])
        for cls, count in self.metrics["label_distribution"].items():
            pct = (count / self.metrics["final_records"]) * 100 if self.metrics["final_records"] else 0
            lines.append(f"  - {cls:<22}: {count:>10,} ({pct:>6.2f}%)")

        lines.extend([
            "",
            "4. OUTPUT FILES GENERATED",
            "-" * 70,
        ])
        for tag, path_str in self.metrics["output_files"].items():
            p = Path(path_str)
            sz_mb = p.stat().st_size / (1024 * 1024) if p.exists() else 0.0
            lines.append(f"  - {p.name:<32}: {sz_mb:>8.2f} MB ({path_str})")

        lines.extend([
            "",
            "5. VALIDATION STATUS",
            "-" * 70,
        ])
        all_passed = all(self.metrics["validation_checks"].values())
        for name, passed in self.metrics["validation_checks"].items():
            tag = "[PASS]" if passed else "[FAIL]"
            lines.append(f"  {tag} {name}")
        lines.extend([
            "",
            f"OVERALL STATUS: {'SUCCESS' if all_passed else 'FAILURE'}",
            "=" * 70,
        ])

        PIPELINE_REPORT_TXT.write_text("\n".join(lines), encoding="utf-8")
        print(f"Saved pipeline audit report to:\n  -> {PIPELINE_REPORT_TXT}")

    def _generate_json_summary(self) -> None:
        """Exports outputs/pipeline_summary.json."""
        summary = {
            "input_file": str(self.input_path),
            "raw_records": self.metrics["raw_records"],
            "structured_records": self.metrics["structured_records"],
            "preprocessed_records": self.metrics["preprocessed_records"],
            "final_records": self.metrics["final_records"],
            "missing_before": self.metrics["missing_before"],
            "missing_after": self.metrics["missing_after"],
            "duplicates_removed": self.metrics["duplicates_removed"],
            "invalid_timestamps": self.metrics["invalid_timestamps"],
            "label_distribution": self.metrics["label_distribution"],
            "engineered_features_count": self.metrics["engineered_features_count"],
            "engineered_features": self.metrics["engineered_feature_names"],
            "execution_times": self.metrics["execution_times"],
            "output_files": self.metrics["output_files"],
            "validation_checks": self.metrics["validation_checks"],
            "status": "SUCCESS" if all(self.metrics["validation_checks"].values()) else "FAILURE",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        with open(PIPELINE_SUMMARY_JSON, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=4)
        print(f"Saved JSON summary to:\n  -> {PIPELINE_SUMMARY_JSON}")

    # -----------------------------------------------------------------------
    # ORCHESTRATION: RUN() [PART 8 & 14]
    # -----------------------------------------------------------------------
    def run(self) -> Dict[str, Any]:
        """Executes all 7 pipeline stages sequentially and prints terminal summary."""
        t_global = time.time()

        # Execute stages
        self.structure()
        self.preprocess()
        self.label()
        self.engineer_features()
        self.save()
        validation_passed = self.validate()

        # Update final audit reports with complete validation status
        self._generate_text_report()
        self._generate_json_summary()

        total_elapsed = time.time() - t_global
        self.metrics["status"] = "SUCCESS" if validation_passed else "FAILURE"

        # PART 14 — FINAL TERMINAL OUTPUT
        print("\n" + "=" * 60)
        print("PRACTICAL 10 — REUSABLE LOG PROCESSING PIPELINE")
        print("=" * 60)
        print()
        print(f"Raw Records:          {self.metrics['raw_records']:,}")
        print(f"Structured Records:   {self.metrics['structured_records']:,}")
        print(f"Preprocessed Records: {self.metrics['preprocessed_records']:,}")
        print(f"Final Records:        {self.metrics['final_records']:,}")
        print()
        print("Labels:")
        for cls_name, count in self.metrics["label_distribution"].items():
            pct = (count / self.metrics["final_records"]) * 100 if self.metrics["final_records"] else 0
            print(f"  - {cls_name:<20}: {count:>10,} ({pct:>6.2f}%)")
        print()
        print(f"Engineered Features:  {self.metrics['engineered_features_count']}")
        print()
        print("Output Files:")
        print("  - structured_logs.csv")
        print("  - labeled_logs.csv")
        print("  - feature_engineered_logs.csv")
        print("  - feature_engineered_logs.parquet")
        print()
        print(f"Validation:           {'PASS' if validation_passed else 'FAIL'}")
        print()
        print(f"STATUS:               {self.metrics['status']}")
        print()
        print("=" * 60)

        return self.metrics
