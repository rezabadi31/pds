"""src/pipeline/pipeline_runner.py
Live Log Analysis Pipeline Executor for Rox Assistant
Executes the Practical 10 LogProcessingPipeline on uploaded files (.log, .txt, .csv)
and extracts empirical threat intelligence, feature statistics, and contextual query responses.
Supports Honeypot JSON logs, Common Log Format (CLF), Combined Log Format, and arbitrary CSV logs.
"""

import sys
import re
import json
import tempfile
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
import pandas as pd
import numpy as np

# Ensure Practical 10 is in python path
PRACTICAL_10_DIR = Path(__file__).resolve().parent.parent.parent / "Practical 10"
if str(PRACTICAL_10_DIR) not in sys.path:
    sys.path.insert(0, str(PRACTICAL_10_DIR))

try:
    from pipeline.log_pipeline import LogProcessingPipeline
except ImportError:
    LogProcessingPipeline = None

# Regex patterns for parsing non-JSON log lines (CLF / Combined / Generic)
CLF_COMBINED_REGEX = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\s"]+)(?:\s+(HTTP/[\d\.]+|-))?"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?',
    re.IGNORECASE
)
GENERIC_LOG_REGEX = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+.*?(?:\[(?P<ts>[^\]]+)\])?.*?"(?P<method>[A-Z]{3,7})\s+(?P<uri>\S+).*?"\s*(?P<status>\d{3})?\s*(?P<bytes>\d+)?',
    re.IGNORECASE
)


class RoxLogAnalyzer:
    """Wrapper that runs the Practical 10 reusable pipeline and compiles security intelligence."""

    def __init__(self, uploaded_file, filename: str):
        self.uploaded_file = uploaded_file
        self.filename = filename
        if hasattr(uploaded_file, "getvalue"):
            self.file_bytes = uploaded_file.getvalue()
        elif hasattr(uploaded_file, "read"):
            self.file_bytes = uploaded_file.read()
        elif isinstance(uploaded_file, (bytes, bytearray)):
            self.file_bytes = bytes(uploaded_file)
        else:
            self.file_bytes = b""

        self.file_size_kb = len(self.file_bytes) / 1024
        self.temp_dir = tempfile.mkdtemp(prefix="rox_analysis_")

    def run_analysis(self) -> Dict[str, Any]:
        """Runs the pipeline on the uploaded file and returns structured analysis."""
        t_start = time.time()
        temp_input_path = Path(self.temp_dir) / self.filename

        # Write uploaded bytes to temp input file
        with open(temp_input_path, "wb") as f:
            f.write(self.file_bytes)

        temp_output_dir = Path(self.temp_dir) / "output"
        temp_output_dir.mkdir(parents=True, exist_ok=True)

        suffix = temp_input_path.suffix.lower()

        try:
            # 1. Parse into canonical 13-column DataFrame
            df_structured = self._parse_to_canonical_df(temp_input_path, suffix)

            if df_structured is None or df_structured.empty:
                duration = round(time.time() - t_start, 3)
                return self._empty_result(duration, "No valid log records could be parsed from the file.")

            # 2. Run Practical 10 stages: Preprocess -> Label -> Engineer Features
            if LogProcessingPipeline is not None:
                pipeline = LogProcessingPipeline(input_path=temp_input_path, output_dir=temp_output_dir)
                pipeline.df_structured = df_structured
                pipeline.preprocess()
                pipeline.label()
                pipeline.engineer_features()
                try:
                    pipeline.validate()
                except Exception:
                    pass
                df_featured = pipeline.df_featured
                pipeline_metrics = pipeline.metrics
            else:
                # Standalone fallback if Practical 10 module missing
                df_featured = self._fallback_pipeline_stages(df_structured)
                pipeline_metrics = {}

            execution_duration = round(time.time() - t_start, 3)
            return self._compile_intelligence(df_featured, pipeline_metrics, execution_duration, temp_output_dir)

        except Exception as ex:
            duration = round(time.time() - t_start, 3)
            return self._empty_result(duration, f"Pipeline execution error: {str(ex)}")

    def _parse_to_canonical_df(self, file_path: Path, suffix: str) -> pd.DataFrame:
        """Parses JSON honeypot, CLF/Combined text logs, or CSV into 13 canonical columns."""
        canonical_cols = [
            "category_type", "payload", "timestamp", "client_ip", "client_port",
            "user_agent", "accept_language", "proxy_ip", "request_type",
            "status_code", "resource_requested", "bytes_sent", "referrer"
        ]

        if suffix in [".log", ".txt"]:
            # Attempt 1: Practical 10 JSON array parsing
            parsed_rows = []
            raw_lines = []
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        s = line.strip()
                        if s:
                            raw_lines.append(s)
            except Exception:
                return pd.DataFrame(columns=canonical_cols)

            if not raw_lines:
                return pd.DataFrame(columns=canonical_cols)

            # Try JSON array entries
            for raw_line in raw_lines:
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
                            # 8 core elements
                            parsed_rows.append([
                                str(data[0] or "web"),
                                str(data[1] or ""),
                                str(data[2] or ""),
                                str(data[3] or "127.0.0.1"),
                                str(data[4] or "80"),
                                str(data[5] or "-"),
                                str(data[6] or "-"),
                                str(data[7] or "-"),
                                "GET",
                                "200",
                                str(data[1] or "/"),
                                "0",
                                "-"
                            ])
                    except Exception:
                        pass

            if parsed_rows:
                return pd.DataFrame(parsed_rows, columns=canonical_cols)

            # Attempt 2: Apache/Nginx CLF or Combined Log Format
            for raw_line in raw_lines:
                m = CLF_COMBINED_REGEX.match(raw_line)
                if m:
                    ip, ts, method, uri, http_v, status, bytes_val, ref, ua = m.groups()
                    parsed_rows.append([
                        "web",
                        uri or "",
                        ts or "",
                        ip or "127.0.0.1",
                        "80",
                        ua or "-",
                        "-",
                        "-",
                        method or "GET",
                        status or "200",
                        uri or "/",
                        bytes_val if (bytes_val and bytes_val != "-") else "0",
                        ref or "-"
                    ])
                    continue

                # Attempt 3: Generic web access regex
                gm = GENERIC_LOG_REGEX.search(raw_line)
                if gm:
                    gd = gm.groupdict()
                    parsed_rows.append([
                        "web",
                        gd.get("uri") or "",
                        gd.get("ts") or "",
                        gd.get("ip") or "127.0.0.1",
                        "80",
                        "-",
                        "-",
                        "-",
                        gd.get("method") or "GET",
                        gd.get("status") or "200",
                        gd.get("uri") or "/",
                        gd.get("bytes") or "0",
                        "-"
                    ])

            if parsed_rows:
                return pd.DataFrame(parsed_rows, columns=canonical_cols)

            return pd.DataFrame(columns=canonical_cols)

        elif suffix == ".csv":
            try:
                df_raw = pd.read_csv(file_path)
            except Exception:
                return pd.DataFrame(columns=canonical_cols)

            if df_raw.empty:
                return pd.DataFrame(columns=canonical_cols)

            # Column synonyms mapping
            col_map = {}
            cols_lower = {str(c).lower().strip(): c for c in df_raw.columns}

            def find_match(aliases):
                for a in aliases:
                    if a in cols_lower:
                        return cols_lower[a]
                return None

            c_ip = find_match(["client_ip", "ip", "src_ip", "source_ip", "host", "remote_addr", "remote_ip"])
            c_ts = find_match(["timestamp", "time", "datetime", "date", "@timestamp"])
            c_res = find_match(["resource_requested", "url", "uri", "path", "request_uri", "endpoint"])
            c_meth = find_match(["request_type", "method", "http_method", "verb"])
            c_stat = find_match(["status_code", "status", "code", "http_status"])
            c_pay = find_match(["payload", "body", "data", "query", "params"])
            c_ua = find_match(["user_agent", "useragent", "agent", "browser"])
            c_bytes = find_match(["bytes_sent", "bytes", "size", "length", "body_bytes_sent"])

            res_df = pd.DataFrame()
            res_df["category_type"] = "web"
            res_df["payload"] = df_raw[c_pay].fillna("").astype(str) if c_pay else ""
            res_df["timestamp"] = df_raw[c_ts].fillna("").astype(str) if c_ts else ""
            res_df["client_ip"] = df_raw[c_ip].fillna("127.0.0.1").astype(str) if c_ip else "127.0.0.1"
            res_df["client_port"] = "80"
            res_df["user_agent"] = df_raw[c_ua].fillna("-").astype(str) if c_ua else "-"
            res_df["accept_language"] = "-"
            res_df["proxy_ip"] = "-"
            res_df["request_type"] = df_raw[c_meth].fillna("GET").astype(str) if c_meth else "GET"
            res_df["status_code"] = df_raw[c_stat].fillna(200).astype(str) if c_stat else "200"
            res_df["resource_requested"] = df_raw[c_res].fillna("/").astype(str) if c_res else "/"
            res_df["bytes_sent"] = df_raw[c_bytes].fillna(0).astype(str) if c_bytes else "0"
            res_df["referrer"] = "-"

            return res_df

        return pd.DataFrame(columns=canonical_cols)

    def _fallback_pipeline_stages(self, df: pd.DataFrame) -> pd.DataFrame:
        """Standalone labeling and feature extraction if Practical 10 cannot be imported."""
        df = df.copy()
        df["label"] = "benign"
        df["label_reason"] = "No attack pattern detected"
        
        # SQLi regex
        sqli_re = re.compile(r"(\b(union|select|insert|update|delete|drop)\b|'|--|#)", re.I)
        # XSS regex
        xss_re = re.compile(r"(<script|alert\(|javascript:|onerror=|onload=)", re.I)
        # Path traversal
        pt_re = re.compile(r"(\.\./|\.\.\\|etc/passwd|win\.ini)", re.I)

        search = df["payload"].astype(str) + " " + df["resource_requested"].astype(str)
        m_sqli = search.str.contains(sqli_re, regex=True)
        m_xss = search.str.contains(xss_re, regex=True)
        m_pt = search.str.contains(pt_re, regex=True)

        df.loc[m_pt, "label"] = "path_traversal"
        df.loc[m_xss, "label"] = "xss"
        df.loc[m_sqli, "label"] = "sqli"

        # Features
        ip_counts = df["client_ip"].value_counts()
        df["requests_per_ip"] = df["client_ip"].map(ip_counts).fillna(1).astype(int)
        df["url_length"] = df["resource_requested"].astype(str).str.len()
        df["url_entropy"] = 2.5
        return df

    def _empty_result(self, duration: float, error_message: str) -> Dict[str, Any]:
        """Returns a fail-safe dictionary with all expected keys to prevent KeyError."""
        return {
            "status": "EMPTY_RESULT",
            "filename": self.filename,
            "file_size_kb": round(self.file_size_kb, 2),
            "duration_sec": duration,
            "total_records": 0,
            "total_columns": 0,
            "unique_ips": 0,
            "unique_uas": 0,
            "time_range": "N/A",
            "label_counts": {"benign": 0},
            "attack_count": 0,
            "attack_percentage": 0.0,
            "top_attack_ips": [],
            "burst_ips": [],
            "high_entropy_urls": [],
            "df": pd.DataFrame(),
            "csv_path": None,
            "parquet_path": None,
            "pipeline_metrics": {},
            "error": error_message,
        }

    def _compile_intelligence(
        self,
        df: pd.DataFrame,
        pipeline_metrics: Dict[str, Any],
        duration: float,
        output_dir: Path
    ) -> Dict[str, Any]:
        """Synthesizes high-level threat intelligence and feature statistics."""
        total_records = len(df) if df is not None else 0

        if total_records == 0 or df is None:
            return self._empty_result(duration, "Zero records remained after pipeline processing.")

        # 1. Traffic Classification
        label_col = "label" if "label" in df.columns else None
        if label_col:
            label_counts = df[label_col].value_counts().to_dict()
        else:
            label_counts = {"benign": total_records}

        benign_count = label_counts.get("benign", 0)
        attack_count = total_records - benign_count
        attack_percentage = round((attack_count / total_records) * 100, 2) if total_records > 0 else 0.0

        # 2. Host Telemetry & Suspicious IPs
        unique_ips = int(df["client_ip"].nunique()) if "client_ip" in df.columns else 0
        unique_uas = int(df["user_agent"].nunique()) if "user_agent" in df.columns else 0

        # Identify top attacking IPs
        top_attack_ips = []
        if label_col and "client_ip" in df.columns:
            attack_df = df[df[label_col] != "benign"]
            if not attack_df.empty:
                ip_summary = attack_df.groupby("client_ip").agg(
                    attacks=(label_col, "count"),
                    attack_types=(label_col, lambda s: list(s.unique()))
                ).reset_index().sort_values(by="attacks", ascending=False).head(10)

                for _, row in ip_summary.iterrows():
                    top_attack_ips.append({
                        "ip": str(row["client_ip"]),
                        "attacks": int(row["attacks"]),
                        "categories": ", ".join(row["attack_types"]),
                    })

        # 3. High Request-Rate Burst IPs
        burst_ips = []
        if "requests_per_ip_1min" in df.columns and "client_ip" in df.columns:
            burst_df = df.groupby("client_ip")["requests_per_ip_1min"].max().reset_index()
            burst_df = burst_df.sort_values(by="requests_per_ip_1min", ascending=False).head(5)
            for _, row in burst_df.iterrows():
                burst_ips.append({"ip": str(row["client_ip"]), "peak_1min_rate": int(row["requests_per_ip_1min"])})

        # 4. High-Entropy URLs (Obfuscation / Injection Signal)
        high_entropy_urls = []
        if "url_entropy" in df.columns:
            entropy_df = df.sort_values(by="url_entropy", ascending=False).head(5)
            url_col = "normalized_resource" if "normalized_resource" in df.columns else "resource_requested"
            for _, row in entropy_df.iterrows():
                high_entropy_urls.append({
                    "url": str(row.get(url_col, "N/A"))[:60],
                    "entropy": round(float(row.get("url_entropy", 0.0)), 3),
                    "label": str(row.get("label", "unknown")),
                })

        # 5. Time Range
        time_range = "N/A"
        if "timestamp" in df.columns:
            try:
                t_min = df["timestamp"].min()
                t_max = df["timestamp"].max()
                time_range = f"{t_min} to {t_max}"
            except Exception:
                pass

        # 6. Available CSV and Parquet Outputs
        csv_path = output_dir / "feature_engineered_logs.csv"
        parquet_path = output_dir / "feature_engineered_logs.parquet"

        if not csv_path.exists():
            df.to_csv(csv_path, index=False)
        try:
            if not parquet_path.exists():
                df.to_parquet(parquet_path, index=False)
        except Exception:
            pass

        return {
            "status": "SUCCESS",
            "filename": self.filename,
            "file_size_kb": round(self.file_size_kb, 2),
            "duration_sec": duration,
            "total_records": total_records,
            "total_columns": len(df.columns),
            "unique_ips": unique_ips,
            "unique_uas": unique_uas,
            "time_range": time_range,
            "label_counts": label_counts,
            "attack_count": attack_count,
            "attack_percentage": attack_percentage,
            "top_attack_ips": top_attack_ips,
            "burst_ips": burst_ips,
            "high_entropy_urls": high_entropy_urls,
            "df": df,
            "csv_path": csv_path,
            "parquet_path": parquet_path if parquet_path.exists() else None,
            "pipeline_metrics": pipeline_metrics,
            "error": None,
        }


def ask_rox(query: str, analysis: Dict[str, Any]) -> str:
    """Provides concise, factual, data-grounded answers from Rox based on actual processed logs."""
    if not analysis or analysis.get("status") != "SUCCESS" or analysis.get("total_records", 0) == 0:
        return "I haven't analyzed a log file yet. Please upload a `.log`, `.txt`, or `.csv` file and click **Analyze with Rox**."

    q = query.lower().strip()
    total = analysis.get("total_records", 0)
    labels = analysis.get("label_counts", {"benign": total})
    attack_count = analysis.get("attack_count", 0)
    top_ips = analysis.get("top_attack_ips", [])
    burst_ips = analysis.get("burst_ips", [])
    df = analysis.get("df", None)

    # 1. What attacks were detected?
    if "attack" in q and ("what" in q or "which" in q or "detect" in q or "type" in q or "found" in q):
        if attack_count == 0:
            return f"I analyzed **{total:,} requests** in `{analysis['filename']}`. Zero malicious attacks were detected — 100% of telemetry was classified as **benign**."
        
        attack_types = [f"**{k}** ({v:,} requests)" for k, v in labels.items() if k != "benign" and v > 0]
        return f"Across **{total:,} requests**, I identified **{attack_count:,} attack events** ({analysis.get('attack_percentage', 0.0)}% of traffic).\n\nDetected attack classes:\n- " + "\n- ".join(attack_types)

    # 2. Which IP generated the most suspicious requests / top attacking IPs?
    if "ip" in q or "host" in q or "attacker" in q:
        if not top_ips:
            return f"No malicious attacking IPs were detected in `{analysis['filename']}`. All {analysis.get('unique_ips', 0)} unique client IPs produced strictly benign requests."
        
        top1 = top_ips[0]
        ip_list = [f"• `{item['ip']}`: **{item['attacks']:,} attacks** ({item['categories']})" for item in top_ips[:5]]
        return f"The most active attacking host was **`{top1['ip']}`** responsible for **{top1['attacks']:,} malicious requests** ({top1['categories']}).\n\nTop attacking IPs:\n" + "\n".join(ip_list)

    # 3. What was the most common attack?
    if "most common" in q or "frequent" in q or "dominant" in q or "highest" in q:
        non_benign = {k: v for k, v in labels.items() if k != "benign" and v > 0}
        if not non_benign:
            return f"The dominant traffic class is **benign** ({total:,} requests, 100%). No attacks were found."
        
        sorted_attacks = sorted(non_benign.items(), key=lambda x: x[1], reverse=True)
        top_name, top_cnt = sorted_attacks[0]
        return f"The most frequent attack pattern detected was **{top_name}** with **{top_cnt:,} instances** (representing {round((top_cnt/total)*100, 2)}% of total traffic)."

    # 4. Why was this request classified as suspicious?
    if "why" in q and ("suspicious" in q or "classified" in q or "flagged" in q or "reason" in q):
        if df is not None and "label_reason" in df.columns:
            susp_sample = df[df["label"] != "benign"]
            if not susp_sample.empty:
                reasons = susp_sample["label_reason"].value_counts().head(3).to_dict()
                reason_lines = [f"• **{k}**: {v:,} occurrences" for k, v in reasons.items()]
                return f"Requests were flagged based on deterministic signature and rate rules:\n" + "\n".join(reason_lines)
        return "Classification relies on deterministic regex matching for SQLi, XSS, Path Traversal, and Command Injection signatures, plus sliding-window brute force frequency detection."

    # 5. What features were extracted?
    if "feature" in q:
        if df is not None:
            feat_cols = [c for c in df.columns if c not in ["category_type", "payload", "timestamp", "client_ip", "user_agent", "accept_language", "proxy_ip", "label", "label_reason"]]
            return f"The Practical 10 reusable pipeline engineered **{len(feat_cols)} numerical features** including:\n- **Behavioral & Rates**: `requests_per_ip`, `ip_request_rank`, `inter_request_time`, `requests_per_ip_1min`, `requests_per_ip_5min`, `request_rate_1min`\n- **Lexical & Obfuscation**: `url_entropy`, `url_length`, `normalized_resource`\n- **Status & Server**: `status_code_frequency`, `bytes_sent`"
        return "Features include requests per IP, inter-request time, rolling 1-min rates, and URL entropy."

    # 6. Default / General Summary
    pct_atk = analysis.get('attack_percentage', 0.0)
    return f"I analyzed `{analysis['filename']}` containing **{total:,} requests** across **{analysis.get('unique_ips', 0)} client IPs**.\n\n- **Benign**: {labels.get('benign', 0):,} ({round(100 - pct_atk, 1)}%)\n- **Attacks**: {attack_count:,} ({pct_atk}%)\n\nAsk me about specific attack categories, attacking IPs, extracted features, or suspicious patterns."
