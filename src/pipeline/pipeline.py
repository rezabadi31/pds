"""src/pipeline/pipeline.py
Master Reusable Pipeline Coordinator for Rox Platform
Integrates:
1. Loader (safe loading of .log, .txt, .csv, .json)
2. Parser (Honeypot JSON, CLF/Combined, Generic, CSV, NDJSON)
3. Preprocessor (cleaning, normalization, ISO-8601 timestamps, deduplication)
4. Labeler (Practical 04 multi-class attack attribution)
5. Feature Engineering (Domain, Featuretools, tsfresh, feature selection)
6. Anomaly Detection (Practical 05 Isolation Forest)
7. Deterministic Rox Log Q&A (100% offline, fact-grounded)
"""

import time
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable
import pandas as pd

from src.pipeline.loader import LogLoader
from src.pipeline.parser import LogParser
from src.pipeline.preprocessing import LogPreprocessor
from src.pipeline.labeling import AttackLabeler
from src.pipeline.feature_engineering import FeatureEngineer
from src.pipeline.anomaly_detection import AnomalyDetector


class RoxPipeline:
    """Master pipeline runner executing the complete end-to-end log engineering lifecycle."""

    def __init__(self, uploaded_file, filename: str, max_records: Optional[int] = None):
        self.uploaded_file = uploaded_file
        self.filename = filename
        self.max_records = max_records
        if hasattr(uploaded_file, "getvalue"):
            self.file_bytes = uploaded_file.getvalue()
        elif hasattr(uploaded_file, "read"):
            self.file_bytes = uploaded_file.read()
        elif isinstance(uploaded_file, (bytes, bytearray)):
            self.file_bytes = bytes(uploaded_file)
        else:
            self.file_bytes = b""

        self.file_size_kb = len(self.file_bytes) / 1024.0
        self.temp_dir = tempfile.mkdtemp(prefix="rox_exec_")

    def run(self, progress_callback: Optional[Callable[[str, int], None]] = None) -> Dict[str, Any]:
        """Runs all pipeline stages sequentially, triggering progress callbacks."""
        t_start = time.time()

        def update_progress(msg: str, step_pct: int):
            if progress_callback:
                progress_callback(msg, step_pct)

        try:
            # Stage 1: Loading
            update_progress("Loading raw log stream...", 10)
            raw_lines, fname, size_kb, load_err = LogLoader.load_bytes_or_file(
                self.file_bytes, self.filename, max_rows=self.max_records
            )
            if load_err:
                return self._build_error_result(load_err, time.time() - t_start)

            # Stage 2: Parsing & Structuring
            update_progress("Parsing and harmonizing schema...", 25)
            df_structured, schema_info, parse_err = LogParser.parse_lines_or_csv(
                raw_lines, self.filename, self.file_bytes
            )
            if parse_err:
                return self._build_error_result(parse_err, time.time() - t_start)
            if df_structured is None or df_structured.empty:
                return self._build_error_result("Rox could not extract any valid records from this file.", time.time() - t_start)

            # Stage 3: Preprocessing & Cleaning
            update_progress("Deduplicating and normalizing timestamps & URLs...", 40)
            df_preprocessed, clean_metrics = LogPreprocessor.preprocess(df_structured)
            if df_preprocessed.empty:
                return self._build_error_result("Zero records remained after data cleaning and deduplication.", time.time() - t_start)

            # Stage 4: Attack Classification
            update_progress("Applying deterministic signature & rolling window attack rules...", 55)
            df_labeled, label_metrics = AttackLabeler.label(df_preprocessed)

            # Stage 5: Feature Engineering
            update_progress("Extracting Domain, Featuretools & time-series behavioral features...", 75)
            df_featured, feat_summary = FeatureEngineer.engineer_features(df_labeled)

            # Stage 6: Anomaly Detection
            update_progress("Running unsupervised Isolation Forest anomaly scoring...", 90)
            feature_names = feat_summary.get("feature_names", [])
            df_final, anomaly_metrics = AnomalyDetector.detect_anomalies(df_featured, feature_names)

            # Stage 7: Export Serialized Files
            update_progress("Finalizing intelligence and preparing download artifacts...", 100)
            output_dir = Path(self.temp_dir) / "output"
            output_dir.mkdir(parents=True, exist_ok=True)
            csv_path = output_dir / "analyzed_security_logs.csv"
            parquet_path = output_dir / "analyzed_security_logs.parquet"

            df_final.to_csv(csv_path, index=False)
            try:
                df_final.to_parquet(parquet_path, index=False)
            except Exception:
                parquet_path = None

            duration = round(time.time() - t_start, 2)
            return self._build_success_result(
                df_final,
                duration,
                schema_info,
                clean_metrics,
                label_metrics,
                feat_summary,
                anomaly_metrics,
                csv_path,
                parquet_path,
            )

        except Exception as e:
            duration = round(time.time() - t_start, 2)
            # Mask internal traceback behind readable message
            return self._build_error_result(
                f"Analysis interrupted during pipeline execution. Details: {str(e)}",
                duration
            )

    def _build_error_result(self, error_message: str, duration: float) -> Dict[str, Any]:
        """Constructs safe structured error dictionary without tracebacks."""
        return {
            "status": "ERROR",
            "filename": self.filename,
            "file_size_kb": round(self.file_size_kb, 2),
            "duration_sec": round(duration, 2),
            "error": error_message,
            "total_records": 0,
            "attacks_count": 0,
            "benign_count": 0,
            "anomalous_count": 0,
            "df": pd.DataFrame(),
        }

    def _build_success_result(
        self,
        df: pd.DataFrame,
        duration: float,
        schema_info: Dict[str, Any],
        clean_metrics: Dict[str, Any],
        label_metrics: Dict[str, Any],
        feat_summary: Dict[str, Any],
        anomaly_metrics: Dict[str, Any],
        csv_path: Path,
        parquet_path: Optional[Path],
    ) -> Dict[str, Any]:
        """Constructs comprehensive analysis intelligence dictionary."""
        total_records = len(df)
        benign_count = label_metrics.get("benign_count", total_records)
        attacks_count = label_metrics.get("attack_count", 0)
        anomalous_count = anomaly_metrics.get("anomalous_count", 0)

        # Top Suspicious IPs table (IP, Requests, Attacks, Anomalies)
        top_suspicious_ips = []
        if "client_ip" in df.columns:
            ip_group = df.groupby("client_ip")
            ip_summary = ip_group.agg(
                total_requests=("client_ip", "count"),
                attacks=("label", lambda s: int((s != "benign").sum()) if "label" in df.columns else 0),
                anomalies=("anomaly_flag", lambda s: int((s == -1).sum()) if "anomaly_flag" in df.columns else 0),
                top_attack=("label", lambda s: s[s != "benign"].iloc[0] if (s != "benign").any() else "None"),
            ).reset_index()

            # Rank by attacks first, then anomalies, then requests
            ip_summary.sort_values(by=["attacks", "anomalies", "total_requests"], ascending=False, inplace=True)
            for _, row in ip_summary.head(10).iterrows():
                top_suspicious_ips.append({
                    "IP": str(row["client_ip"]),
                    "Requests": int(row["total_requests"]),
                    "Attacks": int(row["attacks"]),
                    "Anomalies": int(row["anomalies"]),
                    "Primary Threat": str(row["top_attack"]),
                })

        # Top Suspicious Requests table (timestamp, client_ip, resource, status, label, anomaly_score)
        top_suspicious_requests = []
        req_df = df[(df.get("label", "benign") != "benign") | (df.get("anomaly_flag", 1) == -1)].copy()
        if req_df.empty:
            req_df = df.head(10).copy()
        else:
            req_df.sort_values(by=["anomaly_score"], ascending=True, inplace=True)

        candidate_cols = ["timestamp", "client_ip", "resource_requested", "status_code", "label", "anomaly_score", "label_reason"]
        avail_cols = [c for c in candidate_cols if c in df.columns]
        req_df_display = req_df[avail_cols].head(15)

        return {
            "status": "SUCCESS",
            "filename": self.filename,
            "file_size_kb": round(self.file_size_kb, 2),
            "duration_sec": duration,
            "total_records": total_records,
            "attacks_count": attacks_count,
            "benign_count": benign_count,
            "anomalous_count": anomalous_count,
            "normal_count": anomaly_metrics.get("normal_count", total_records),
            "unique_ips": int(df["client_ip"].nunique()) if "client_ip" in df.columns else 0,
            "label_distribution": label_metrics.get("label_distribution", {}),
            "top_suspicious_ips": top_suspicious_ips,
            "top_suspicious_requests_df": req_df_display,
            "feature_summary": feat_summary,
            "anomaly_metrics": anomaly_metrics,
            "schema_info": schema_info,
            "clean_metrics": clean_metrics,
            "csv_path": csv_path,
            "parquet_path": parquet_path,
            "df": df,
            "error": None,
        }


def ask_rox(query: str, analysis: Optional[Dict[str, Any]]) -> str:
    """Answers user questions deterministically from the uploaded dataset without external LLM dependencies."""
    if not analysis or analysis.get("status") != "SUCCESS" or analysis.get("total_records", 0) == 0:
        return "I haven't analyzed a log file yet. Upload a `.log`, `.txt`, `.csv`, or `.json` file below and click **Analyze with Rox**."

    q = query.lower().strip()
    total = analysis.get("total_records", 0)
    attacks = analysis.get("attacks_count", 0)
    benign = analysis.get("benign_count", 0)
    anomalous = analysis.get("anomalous_count", 0)
    labels = analysis.get("label_distribution", {})
    top_ips = analysis.get("top_suspicious_ips", [])
    df = analysis.get("df", None)
    feat_summary = analysis.get("feature_summary", {})

    # Question 1: What attacks were detected?
    if "attack" in q and ("what" in q or "which" in q or "detect" in q or "found" in q or "type" in q or "list" in q):
        if attacks == 0:
            return f"In `{analysis['filename']}`, across **{total:,} requests**, zero attack signatures were detected. 100% of telemetry was classified as **benign**."
        
        lines = [f"- **{k}**: {v:,} requests ({round((v/total)*100, 2)}%)" for k, v in labels.items() if k != "benign" and v > 0]
        return f"Across **{total:,} requests**, I detected **{attacks:,} attack events** ({round((attacks/total)*100, 2)}% of traffic):\n" + "\n".join(lines)

    # Question 2: Which IP is most suspicious? / Top attacking hosts
    if "ip" in q or "host" in q or "suspicious" in q or "attacker" in q:
        if not top_ips:
            return f"All {analysis.get('unique_ips', 0)} client IPs produced solely benign requests with normal behavior."
        
        top1 = top_ips[0]
        ip_rows = [f"- **`{r['IP']}`**: {r['Requests']} requests | {r['Attacks']} attacks | {r['Anomalies']} anomalies ({r['Primary Threat']})" for r in top_ips[:5]]
        return f"The most suspicious client IP is **`{top1['IP']}`** with **{top1['Attacks']} attacks** and **{top1['Anomalies']} anomalies** out of {top1['Requests']} total requests.\n\nTop suspicious hosts:\n" + "\n".join(ip_rows)

    # Question 3: What was the most common attack?
    if "most common" in q or "frequent" in q or "dominant" in q or "highest" in q:
        non_benign = {k: v for k, v in labels.items() if k != "benign" and v > 0}
        if not non_benign:
            return f"The dominant traffic class is **benign** ({total:,} requests, 100%). No attacks were found."
        sorted_attacks = sorted(non_benign.items(), key=lambda x: x[1], reverse=True)
        top_name, top_cnt = sorted_attacks[0]
        return f"The most frequent attack pattern is **{top_name}** with **{top_cnt:,} instances** ({round((top_cnt/total)*100, 2)}% of traffic)."

    # Question 4: Which features were extracted?
    if "feature" in q or "engineered" in q:
        feat_count = feat_summary.get("total_engineered_features", 0)
        groups = feat_summary.get("feature_groups", {})
        group_lines = [f"- **{g}**: {', '.join([f'`{f}`' for f in flist[:4]])}{'...' if len(flist)>4 else ''}" for g, flist in groups.items()]
        return f"The pipeline engineered **{feat_count} behavioral and mathematical features** across {len(groups)} feature groups:\n" + "\n".join(group_lines)

    # Question 5: Show anomalous requests / anomalies
    if "anomal" in q:
        anom_pct = round((anomalous / total) * 100, 2) if total > 0 else 0.0
        return (
            f"Isolation Forest flagged **{anomalous:,} requests ({anom_pct}%)** as anomalous (statistically unusual request timing, bursts, or high entropy).\n\n"
            f"*Reminder*: An anomaly indicates statistical deviance from normal traffic; it is evaluated independently of rule-based attack signatures."
        )

    # Question 6: Why was this request suspicious?
    if "why" in q or "reason" in q:
        if df is not None and "label_reason" in df.columns:
            attack_sub = df[df["label"] != "benign"]
            if not attack_sub.empty:
                reasons = attack_sub["label_reason"].value_counts().head(3).to_dict()
                reason_lines = [f"- **{k}**: {v:,} occurrences" for k, v in reasons.items()]
                return "Requests were flagged based on deterministic rules and anomalous features:\n" + "\n".join(reason_lines)
        return "Classification relies on deterministic regex matching for SQLi, XSS, Path Traversal, Command Injection, and sliding-window Brute Force tracking."

    # Default / General summary
    pct_atk = round((attacks / total) * 100, 2) if total > 0 else 0.0
    return (
        f"**Rox Analysis Summary for `{analysis['filename']}`**:\n\n"
        f"- **Total Requests**: {total:,}\n"
        f"- **Attacks Detected**: {attacks:,} ({pct_atk}%)\n"
        f"- **Benign Traffic**: {benign:,} ({round(100 - pct_atk, 2)}%)\n"
        f"- **Anomalies Flagged**: {anomalous:,} (Isolation Forest)\n"
        f"- **Engineered Features**: {feat_summary.get('total_engineered_features', 0)}\n\n"
        f"You can ask me: *'What attacks were detected?'*, *'Which IP is most suspicious?'*, *'What was the most common attack?'*, or *'Which features were extracted?'*"
    )
