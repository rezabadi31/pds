"""src/pipeline/pipeline_runner.py
Live Log Analysis Pipeline Executor for Rox Assistant
Executes the Practical 10 LogProcessingPipeline on uploaded files (.log, .txt, .csv)
and extracts empirical threat intelligence, feature statistics, and contextual query responses.
"""

import sys
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


class RoxLogAnalyzer:
    """Wrapper that runs the Practical 10 reusable pipeline and compiles security intelligence."""

    def __init__(self, uploaded_file, filename: str):
        self.uploaded_file = uploaded_file
        self.filename = filename
        self.file_bytes = uploaded_file.getvalue() if hasattr(uploaded_file, "getvalue") else uploaded_file.read()
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

        # Check format
        suffix = temp_input_path.suffix.lower()

        if suffix in [".log", ".txt"]:
            # Run LogProcessingPipeline stages directly to avoid overwriting Practical 10 master report
            if LogProcessingPipeline is None:
                raise ImportError("Practical 10 LogProcessingPipeline could not be imported.")

            pipeline = LogProcessingPipeline(input_path=temp_input_path, output_dir=temp_output_dir)
            pipeline.structure()
            pipeline.preprocess()
            pipeline.label()
            pipeline.engineer_features()
            pipeline.validate()
            df_featured = pipeline.df_featured
            pipeline_metrics = pipeline.metrics

        elif suffix == ".csv":
            # For CSV, check if already structured or raw lines
            try:
                df_test = pd.read_csv(temp_input_path)
            except Exception:
                df_test = pd.DataFrame()

            # If it already has structured columns like client_ip, timestamp, payload
            if "client_ip" in df_test.columns and "timestamp" in df_test.columns:
                pipeline = LogProcessingPipeline(input_path=temp_input_path, output_dir=temp_output_dir)
                pipeline.df_structured = df_test
                pipeline.preprocess()
                pipeline.label()
                pipeline.engineer_features()
                pipeline.validate()
                df_featured = pipeline.df_featured
                pipeline_metrics = pipeline.metrics
            else:
                # Treat CSV as raw text log lines
                pipeline = LogProcessingPipeline(input_path=temp_input_path, output_dir=temp_output_dir)
                pipeline_metrics = pipeline.run()
                df_featured = pipeline.df_featured

        else:
            raise ValueError(f"Unsupported file format: {suffix}. Supported formats: .log, .txt, .csv")

        execution_duration = round(time.time() - t_start, 3)

        # Extract Intelligence Summaries
        return self._compile_intelligence(df_featured, pipeline_metrics, execution_duration, temp_output_dir)

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
            return {
                "status": "EMPTY_RESULT",
                "filename": self.filename,
                "file_size_kb": self.file_size_kb,
                "duration_sec": duration,
                "total_records": 0,
            }

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
        unique_ips = df["client_ip"].nunique() if "client_ip" in df.columns else 0
        unique_uas = df["user_agent"].nunique() if "user_agent" in df.columns else 0

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
                        "ip": row["client_ip"],
                        "attacks": int(row["attacks"]),
                        "categories": ", ".join(row["attack_types"]),
                    })

        # 3. High Request-Rate Burst IPs
        burst_ips = []
        if "requests_per_ip_1min" in df.columns and "client_ip" in df.columns:
            burst_df = df.groupby("client_ip")["requests_per_ip_1min"].max().reset_index()
            burst_df = burst_df.sort_values(by="requests_per_ip_1min", ascending=False).head(5)
            for _, row in burst_df.iterrows():
                burst_ips.append({"ip": row["client_ip"], "peak_1min_rate": int(row["requests_per_ip_1min"])})

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

        # If CSV was not saved directly to temp, save df now
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
        }


def ask_rox(query: str, analysis: Dict[str, Any]) -> str:
    """Provides concise, factual, data-grounded answers from Rox based on actual processed logs."""
    if not analysis or analysis.get("status") != "SUCCESS":
        return "I haven't analyzed a log file yet. Please upload a `.log`, `.txt`, or `.csv` file and click **Analyze with Rox**."

    q = query.lower().strip()
    total = analysis["total_records"]
    labels = analysis["label_counts"]
    attack_count = analysis["attack_count"]
    top_ips = analysis["top_attack_ips"]
    burst_ips = analysis["burst_ips"]
    df = analysis.get("df", None)

    # 1. What attacks were detected?
    if "attack" in q and ("what" in q or "which" in q or "detect" in q or "type" in q or "found" in q):
        if attack_count == 0:
            return f"I analyzed **{total:,} requests** in `{analysis['filename']}`. Zero malicious attacks were detected — 100% of telemetry was classified as **benign**."
        
        attack_types = [f"**{k}** ({v:,} requests)" for k, v in labels.items() if k != "benign" and v > 0]
        return f"Across **{total:,} requests**, I identified **{attack_count:,} attack events** ({analysis['attack_percentage']}% of traffic).\n\nDetected attack classes:\n- " + "\n- ".join(attack_types)

    # 2. Which IP generated the most suspicious requests / top attacking IPs?
    if "ip" in q or "host" in q or "attacker" in q:
        if not top_ips:
            return f"No malicious attacking IPs were detected in `{analysis['filename']}`. All {analysis['unique_ips']} unique client IPs produced strictly benign requests."
        
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
        if "label_reason" in df.columns:
            susp_sample = df[df["label"] != "benign"]
            if not susp_sample.empty:
                reasons = susp_sample["label_reason"].value_counts().head(3).to_dict()
                reason_lines = [f"• **{k}**: {v:,} occurrences" for k, v in reasons.items()]
                return f"Requests were flagged based on deterministic signature and rate rules:\n" + "\n".join(reason_lines)
        return "Classification relies on deterministic regex matching for SQLi, XSS, Path Traversal, and Command Injection signatures, plus sliding-window brute force frequency detection."

    # 5. What features were extracted?
    if "feature" in q:
        feat_cols = [c for c in df.columns if c not in ["category_type", "payload", "timestamp", "client_ip", "user_agent", "accept_language", "proxy_ip", "label", "label_reason"]]
        return f"The Practical 10 reusable pipeline engineered **{len(feat_cols)} numerical features** including:\n- **Behavioral & Rates**: `requests_per_ip`, `ip_request_rank`, `inter_request_time`, `requests_per_ip_1min`, `requests_per_ip_5min`, `request_rate_1min`\n- **Lexical & Obfuscation**: `url_entropy`, `url_length`, `normalized_resource`\n- **Status & Server**: `status_code_frequency`, `bytes_sent`"

    # 6. Default / General Summary
    return f"I analyzed `{analysis['filename']}` containing **{total:,} requests** across **{analysis['unique_ips']} client IPs**.\n\n- **Benign**: {analysis['label_counts'].get('benign', 0):,} ({round(100 - analysis['attack_percentage'], 1)}%)\n- **Attacks**: {attack_count:,} ({analysis['attack_percentage']}%)\n\nAsk me about specific attack categories, attacking IPs, extracted features, or suspicious patterns."
