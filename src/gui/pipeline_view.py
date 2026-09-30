"""src/gui/pipeline_view.py
Reusable Pipeline Page
Demonstrates the Practical 10 reusable architecture across 8 interactive, expandable stages.
"""

from pathlib import Path
import streamlit as st
import pandas as pd

from config import THEME, BASELINE_METRICS
from src.gui.charts import plot_pipeline_stage_durations_dark
from utils.data_loader import load_parquet_preview, load_csv_preview, read_text_file, get_file_info


def render_pipeline_view():
    """Renders the Reusable Pipeline visualizer page."""

    st.markdown(
        f"""
        <div style="margin-bottom: 1.5rem;">
            <div class="product-hero-eyebrow">
                <span>⚡</span> Automated Production Architecture
            </div>
            <h1 style="font-size: 2.2rem; font-weight: 800; color: #FFFFFF; margin: 0.2rem 0 0.5rem 0;">
                Reusable Log Processing Pipeline
            </h1>
            <div style="font-size: 1.05rem; color: {THEME['text_secondary']}; line-height: 1.5;">
                Engineered in Practical 10: a modular 7-stage CLI and Python pipeline processing 2.06 million records in 108.67s with 97.8% Parquet storage reduction.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Pipeline Performance KPI Cards
    p1, p2, p3, p4, p5 = st.columns(5)
    with p1:
        st.metric("Total Pipeline Runtime", "108.67s", "End-to-End Execution")
    with p2:
        st.metric("Raw Ingestion", "2,061,431", "215.40 MB cj.log")
    with p3:
        st.metric("Clean Output Records", "1,492,047", "0 Missing • 0 Duplicates")
    with p4:
        st.metric("Storage Reduction", "97.8%", "429.8 MB CSV -> 9.46 MB Parquet")
    with p5:
        st.metric("Pipeline Status", "SUCCESS", "14/14 QA Checks Passed")

    st.write("")

    # Interactive Stage Flow Visualizer
    st.markdown("### 🔄 Interactive Pipeline Stages")

    # Stages data
    stages = [
        {
            "id": "01",
            "name": "Load",
            "time": "20.57s",
            "input": "Practical 1/data/raw/cj.log (215.40 MB)",
            "output": "Raw line stream (UTF-8 generator)",
            "records": "2,061,431 non-blank lines",
            "file": "cj.log",
            "status": "PASS",
            "desc": "Memory-safe Python generator streaming raw lines line-by-line without buffer exhaustion. Resolves multi-record line concatenations (911 lines containing '][' split into 1,841 distinct records)."
        },
        {
            "id": "02",
            "name": "Parse",
            "time": "12.10s",
            "input": "Streamed raw lines",
            "output": "Deserialized 8-element positional JSON arrays",
            "records": "2,062,226 parsed entries",
            "file": "In-memory token stream",
            "status": "PASS",
            "desc": "Deserializes JSON arrays with json.loads and strict exception handling, extracting category, payload, timestamp, IP, port, user agent, language, and proxy fields."
        },
        {
            "id": "03",
            "name": "Structure",
            "time": "11.11s",
            "input": "Parsed positional tokens",
            "output": "Structured 13-column tabular DataFrame",
            "records": "2,062,226 rows x 13 columns",
            "file": "structured_logs.csv",
            "status": "PASS",
            "desc": "Maps 8 source honeypot attributes to canonical fields and initializes 5 standard web HTTP fields (request_type, status_code, resource_requested, bytes_sent, referrer) as structured columns."
        },
        {
            "id": "04",
            "name": "Preprocess & Clean",
            "time": "9.48s",
            "input": "2,062,226 structured rows (570k duplicates)",
            "output": "Deduplicated, imputed, normalized dataset",
            "records": "1,492,047 clean rows x 14 columns",
            "file": "Cleaned working DataFrame",
            "status": "PASS",
            "desc": "Eliminated 570,179 exact duplicate rows (-27.65%), converted timestamps to microsecond datetime64, imputed 18.4M missing values, and created normalized_resource column."
        },
        {
            "id": "05",
            "name": "Attack Labeling",
            "time": "20.48s",
            "input": "1,492,047 clean rows",
            "output": "Multi-class labeled dataset with label_reason",
            "records": "1,487,682 benign • 4,365 attacks (6 classes)",
            "file": "labeled_logs.csv",
            "status": "PASS",
            "desc": "Executes deterministic multi-class rule hierarchy: SQLi (160), Path Traversal (1,098), Command Injection (805), XSS (960), Brute Force (1,342 rolling login window checks), and Benign default."
        },
        {
            "id": "06",
            "name": "Engineer Features",
            "time": "4.96s",
            "input": "1,492,047 labeled rows",
            "output": "Feature matrix with 26 numeric signals",
            "records": "1,492,047 rows x 42 columns",
            "file": "Feature matrix",
            "status": "PASS",
            "desc": "Computes vectorized sliding rate windows (1min, 5min), inter-request arrival times, IP ranks, Shannon entropy of URL and payload, and status code frequencies."
        },
        {
            "id": "07",
            "name": "Validate Quality",
            "time": "0.18s",
            "input": "Engineered dataset",
            "output": "14/14 automated QA assertion verifications",
            "records": "100% verified integrity",
            "file": "pipeline_summary.json",
            "status": "PASS",
            "desc": "Automated verification suite asserting 0 missing values, 0 duplicates, 100% valid timestamps, expected label classes present, and zero label leakage into ML features."
        },
        {
            "id": "08",
            "name": "Export & Serialize",
            "time": "29.80s",
            "input": "Validated feature dataset",
            "output": "High-efficiency Parquet & canonical CSV",
            "records": "1,492,047 rows (9.46 MB Parquet • 429.8 MB CSV)",
            "file": "feature_engineered_logs.parquet",
            "status": "PASS",
            "desc": "Serializes production dataset into Snappy-compressed Apache Parquet achieving 97.8% disk space reduction over standard CSV."
        }
    ]

    for stage in stages:
        with st.expander(f"Stage {stage['id']} — {stage['name']} ({stage['time']}) • Status: {stage['status']}", expanded=(stage["id"] == "08")):
            st.markdown(f"**What happens:** {stage['desc']}")
            
            c1, c2, c3 = st.columns(3)
            with c1:
                st.markdown(f"**Input:** `{stage['input']}`")
                st.markdown(f"**Output Records:** `{stage['records']}`")
            with c2:
                st.markdown(f"**Output Format:** `{stage['output']}`")
                st.markdown(f"**Artifact File:** `{stage['file']}`")
            with c3:
                st.markdown(f"**Execution Duration:** `{stage['time']}`")
                st.markdown(f"**Verification:** <span style='color: {THEME['success']}; font-weight: bold;'>● {stage['status']}</span>", unsafe_allow_html=True)

    st.write("")

    # Pipeline Timing Chart
    st.plotly_chart(plot_pipeline_stage_durations_dark(), use_container_width=True)

    # Parquet Preview
    with st.container():
        st.markdown(
            f"""
            <div class="detail-section">
                <div class="detail-section-title">
                    <span>⚡</span> SERIALIZED OUTPUT: APACHE PARQUET DATASET
                </div>
                <div style="font-size: 0.92rem; color: {THEME['text_secondary']}; margin-bottom: 0.8rem;">
                    Parquet columnar storage reduces disk footprint from <strong>429.8 MB to 9.46 MB (97.8% reduction)</strong> while dramatically accelerating multi-column analytic queries.
                </div>
            """,
            unsafe_allow_html=True
        )

        pq_file = Path("Practical 10/data/processed/feature_engineered_logs.parquet")
        f_info = get_file_info(pq_file)
        st.caption(f"📁 Path: `{f_info['path']}` • Size on Disk: **{f_info['size_str']}**")

        df_preview = load_parquet_preview(pq_file, nrows=30)
        if not df_preview.empty:
            st.dataframe(df_preview, use_container_width=True)

        st.markdown("</div>", unsafe_allow_html=True)
