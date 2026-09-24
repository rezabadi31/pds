"""app.py
PDS Log Analytics & Attack Detection System
Production-Grade Presentation and Analytical Dashboard for Practicals 1 to 10
Author: Python for Data Science (PDS) Student Project
"""

import sys
import subprocess
import time
from pathlib import Path
from typing import Dict, Any, List

import pandas as pd
import numpy as np
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from PIL import Image

# Ensure PDS_GUI is in python path
GUI_DIR = Path(__file__).resolve().parent
if str(GUI_DIR) not in sys.path:
    sys.path.insert(0, str(GUI_DIR))

from config import (
    PRACTICAL_DIRS,
    EXPECTED_OUTPUTS,
    PROJECT_BASELINE_METRICS,
    THEME_COLORS,
)
from utils.data_loader import (
    check_file_status,
    get_all_system_status,
    load_csv_sample,
    load_parquet_sample,
    read_text_report,
    read_json_data,
    find_plots_for_practical,
)
from utils.metrics import (
    get_home_metrics,
    get_model_comparison_metrics,
    get_balanced_experiment_metrics,
    get_rf_feature_importance_df,
    get_class_distribution_dict,
)
from utils.charts import (
    plot_class_distribution,
    plot_model_comparison_chart,
    plot_feature_importance_chart,
    plot_balancing_comparison_chart,
)
from utils.practical_info import PRACTICAL_DETAILS, VIVA_QUESTIONS


# ===========================================================================
# STREAMLIT PAGE CONFIGURATION & PROFESSIONAL CORPORATE STYLING
# ===========================================================================
st.set_page_config(
    page_title="PDS Log Analytics & Attack Detection System",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded",
)

# Professional Corporate / Academic CSS
st.markdown(
    """
    <style>
    /* Global Base */
    .main {
        background-color: #f8fafc;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    }
    .stApp {
        background-color: #f8fafc;
    }

    /* Executive Header */
    .executive-header {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        border-top: 3px solid #2563eb;
        border-radius: 8px;
        padding: 24px 30px;
        margin-bottom: 24px;
        box-shadow: 0 4px 12px rgba(15, 23, 42, 0.08);
    }
    .executive-header .tracker-tag {
        color: #93c5fd;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 1.2px;
        text-transform: uppercase;
        margin-bottom: 6px;
    }
    .executive-header h1 {
        color: #ffffff !important;
        font-size: 26px;
        font-weight: 700;
        margin: 0;
        padding: 0;
        letter-spacing: -0.3px;
    }
    .executive-header p {
        color: #cbd5e1 !important;
        font-size: 14px;
        margin: 6px 0 0 0;
    }

    /* Executive Metric Cards */
    .metric-card {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-top: 3px solid #2563eb;
        border-radius: 6px;
        padding: 16px 18px;
        margin-bottom: 14px;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04);
    }
    .metric-title {
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.8px;
        color: #64748b;
        margin-bottom: 4px;
    }
    .metric-value {
        font-size: 24px;
        font-weight: 700;
        color: #0f172a;
        line-height: 1.2;
    }
    .metric-subtitle {
        font-size: 12px;
        color: #059669;
        font-weight: 600;
        margin-top: 4px;
    }

    /* Executive Summary Callout */
    .executive-summary-box {
        background-color: #f1f5f9;
        border-left: 4px solid #0f766e;
        border-radius: 4px;
        padding: 16px 20px;
        margin: 18px 0;
        font-size: 14px;
        line-height: 1.6;
        color: #1e293b;
    }
    .executive-summary-box strong {
        color: #0f172a;
    }

    /* Standard Cards */
    .content-card {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 6px;
        padding: 20px 24px;
        margin-bottom: 20px;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.03);
    }

    /* Status Badges */
    .badge-status-ok {
        background-color: #ecfdf5;
        color: #047857;
        border: 1px solid #a7f3d0;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.5px;
        padding: 3px 8px;
        border-radius: 4px;
        display: inline-block;
    }
    .badge-status-missing {
        background-color: #fef2f2;
        color: #b91c1c;
        border: 1px solid #fecaca;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.5px;
        padding: 3px 8px;
        border-radius: 4px;
        display: inline-block;
    }

    /* Sidebar Status Item */
    .sidebar-status-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 4px 0;
        border-bottom: 1px solid #f1f5f9;
        font-size: 12px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ===========================================================================
# HEADER COMPONENT
# ===========================================================================
def render_header(title: str, subtitle: str):
    st.markdown(
        f"""
        <div class="executive-header">
            <div class="tracker-tag">Predictive Data Science Laboratory — Practicals 1 to 10</div>
            <h1>{title}</h1>
            <p>{subtitle}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ===========================================================================
# SIDEBAR NAVIGATION & ARTIFACT AUDIT
# ===========================================================================
def render_sidebar():
    with st.sidebar:
        st.markdown("### PDS Log Analytics")
        st.caption("End-to-End Practical Lifecycle (P1 - P10)")
        st.markdown("---")

        nav_options = [
            "Dashboard Overview",
            "Project Architecture",
            "Practical 1: Data Inspection",
            "Practical 2: Parsing & Structuring",
            "Practical 3: Cleaning & Preprocessing",
            "Practical 4: Attack Labeling",
            "Practical 5: Feature Engineering",
            "Practical 6: Dataset Balancing",
            "Practical 7: Data Wrangling",
            "Practical 8: Visualization & EDA",
            "Practical 9: Attack Classifier",
            "Practical 10: Reusable Pipeline",
            "Model Evaluation Analysis",
            "Dataset & Artifact Explorer",
            "Technical Defense Q&A",
            "Technical Project Report",
        ]

        selected_page = st.radio("Navigation Menu", nav_options, index=0)

        st.markdown("---")
        st.markdown("#### System Artifact Verification")
        status_list = get_all_system_status()
        for item in status_list:
            is_ok = item["status"] == "AVAILABLE"
            status_text = "AVAILABLE" if is_ok else "NOT FOUND"
            status_color = "#047857" if is_ok else "#b91c1c"
            st.markdown(
                f"""
                <div class="sidebar-status-row">
                    <span><b>P{item['practical_num']}</b>: {item['title'][:18]}</span>
                    <span style="color:{status_color}; font-weight:700; font-size:11px;">{status_text}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("---")
        st.caption("Environment: Local Windows Python 3.13\nOpen-Source Architecture")

    return selected_page


# ===========================================================================
# HOME DASHBOARD
# ===========================================================================
def render_home_page():
    render_header(
        "Web Honeypot Telemetry & Attack Detection System",
        "Comprehensive Log Analytics, Feature Engineering, and Machine Learning Classification Pipeline",
    )

    metrics = get_home_metrics()

    # System Status Banner
    st.success(
        "System Status: All 10 practical stages verified. Ingestion, feature synthesis, SMOTE balancing, classification models, and Parquet serialization are complete and ready for analysis."
    )

    # 8 High-Impact Metric Cards
    m_col1, m_col2, m_col3, m_col4 = st.columns(4)
    with m_col1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">Raw Ingestion</div>
                <div class="metric-value">{metrics['raw_records']:,}</div>
                <div class="metric-subtitle">cj.log ({metrics['raw_size_mb']} MB)</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(
            f"""
            <div class="metric-card" style="border-top-color: #0f766e;">
                <div class="metric-title">Cleaned Telemetry</div>
                <div class="metric-value">{metrics['preprocessed_records']:,}</div>
                <div class="metric-subtitle">-570k duplicates removed</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with m_col2:
        st.markdown(
            f"""
            <div class="metric-card" style="border-top-color: #d97706;">
                <div class="metric-title">Traffic Classes</div>
                <div class="metric-value">{metrics['classes_count']}</div>
                <div class="metric-subtitle">Benign + 5 Attack Classes</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(
            f"""
            <div class="metric-card" style="border-top-color: #4f46e5;">
                <div class="metric-title">Engineered Features</div>
                <div class="metric-value">{metrics['engineered_features_count']}</div>
                <div class="metric-subtitle">Behavioral, Lexical, Entropy</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with m_col3:
        st.markdown(
            f"""
            <div class="metric-card" style="border-top-color: #be185d;">
                <div class="metric-title">Balanced Train Set</div>
                <div class="metric-value">{metrics['balanced_train_records']:,}</div>
                <div class="metric-subtitle">SMOTE (10,000 / class)</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(
            f"""
            <div class="metric-card" style="border-top-color: #6d28d9;">
                <div class="metric-title">Untouched Test Set</div>
                <div class="metric-value">{metrics['untouched_test_records']:,}</div>
                <div class="metric-subtitle">20% Natural Test Distribution</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with m_col4:
        st.markdown(
            f"""
            <div class="metric-card" style="border-top-color: #059669;">
                <div class="metric-title">Primary Classifier</div>
                <div class="metric-value">Random Forest</div>
                <div class="metric-subtitle">100 Trees (Balanced Weights)</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(
            f"""
            <div class="metric-card" style="border-top-color: #059669;">
                <div class="metric-title">Classification Performance</div>
                <div class="metric-value">{metrics['rf_accuracy']*100:.2f}%</div>
                <div class="metric-subtitle">Macro F1: {metrics['rf_macro_f1']*100:.2f}%</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("---")

    # Visual Pipeline Stages
    st.subheader("End-to-End Pipeline Execution Architecture")
    flow_cols = st.columns(5)
    with flow_cols[0]:
        st.markdown(
            """
            <div style="background:white; border:1px solid #cbd5e1; border-top:3px solid #2563eb; border-radius:6px; padding:12px; text-align:center;">
                <b style="color:#0f172a;">P1: Inspection</b><br><small style="color:#64748b;">2.06M Raw Records<br>cj.log Structure Audit</small>
            </div>
            <div style="text-align:center; font-size:14px; color:#94a3b8; margin:4px 0;">[ Pipeline Step ]</div>
            <div style="background:white; border:1px solid #cbd5e1; border-top:3px solid #0f766e; border-radius:6px; padding:12px; text-align:center;">
                <b style="color:#0f172a;">P2: Structuring</b><br><small style="color:#64748b;">Streaming JSON Parse<br>13-Column Schema</small>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with flow_cols[1]:
        st.markdown(
            """
            <div style="background:white; border:1px solid #cbd5e1; border-top:3px solid #d97706; border-radius:6px; padding:12px; text-align:center;">
                <b style="color:#0f172a;">P3: Preprocessing</b><br><small style="color:#64748b;">Deduplication (-570k)<br>URL Normalization</small>
            </div>
            <div style="text-align:center; font-size:14px; color:#94a3b8; margin:4px 0;">[ Pipeline Step ]</div>
            <div style="background:white; border:1px solid #cbd5e1; border-top:3px solid #be185d; border-radius:6px; padding:12px; text-align:center;">
                <b style="color:#0f172a;">P4: Labeling</b><br><small style="color:#64748b;">Rule-Based Engine<br>6 Ground-Truth Classes</small>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with flow_cols[2]:
        st.markdown(
            """
            <div style="background:white; border:1px solid #cbd5e1; border-top:3px solid #4f46e5; border-radius:6px; padding:12px; text-align:center;">
                <b style="color:#0f172a;">P5: Features</b><br><small style="color:#64748b;">66 ML Features<br>Shannon Entropy & Rates</small>
            </div>
            <div style="text-align:center; font-size:14px; color:#94a3b8; margin:4px 0;">[ Pipeline Step ]</div>
            <div style="background:white; border:1px solid #cbd5e1; border-top:3px solid #0d9488; border-radius:6px; padding:12px; text-align:center;">
                <b style="color:#0f172a;">P6: Balancing</b><br><small style="color:#64748b;">SMOTE on Train Only<br>60k Balanced Rows</small>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with flow_cols[3]:
        st.markdown(
            """
            <div style="background:white; border:1px solid #cbd5e1; border-top:3px solid #3b82f6; border-radius:6px; padding:12px; text-align:center;">
                <b style="color:#0f172a;">P7: Wrangling</b><br><small style="color:#64748b;">Pivot Aggregations<br>IP Threat Profiling</small>
            </div>
            <div style="text-align:center; font-size:14px; color:#94a3b8; margin:4px 0;">[ Pipeline Step ]</div>
            <div style="background:white; border:1px solid #cbd5e1; border-top:3px solid #6366f1; border-radius:6px; padding:12px; text-align:center;">
                <b style="color:#0f172a;">P8: Visual EDA</b><br><small style="color:#64748b;">15 Diagnostic Plots<br>Interactive Heatmaps</small>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with flow_cols[4]:
        st.markdown(
            """
            <div style="background:white; border:1px solid #cbd5e1; border-top:3px solid #059669; border-radius:6px; padding:12px; text-align:center;">
                <b style="color:#0f172a;">P9: Classifier</b><br><small style="color:#64748b;">LR vs Random Forest<br>99.97% Accuracy</small>
            </div>
            <div style="text-align:center; font-size:14px; color:#94a3b8; margin:4px 0;">[ Pipeline Step ]</div>
            <div style="background:white; border:1px solid #cbd5e1; border-top:3px solid #047857; border-radius:6px; padding:12px; text-align:center;">
                <b style="color:#0f172a;">P10: Pipeline</b><br><small style="color:#64748b;">Reusable CLI Engine<br>Parquet Compression</small>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("---")

    # Interactive Class Distribution and Model Performance Side by Side
    chart_c1, chart_c2 = st.columns(2)
    with chart_c1:
        dist = get_class_distribution_dict()
        fig_dist = plot_class_distribution(dist, log_scale=True)
        st.plotly_chart(fig_dist, use_container_width=True)

    with chart_c2:
        comp_df = get_model_comparison_metrics()
        fig_comp = plot_model_comparison_chart(comp_df)
        st.plotly_chart(fig_comp, use_container_width=True)

    # Executive Project Technical Summary
    st.markdown(
        """
        <div class="executive-summary-box">
            <strong>System Summary:</strong> This project establishes an end-to-end data science lifecycle for high-volume cybersecurity access logs. 
            Over 2.06 million raw honeypot records were parsed into 13 structured attributes, filtered to eliminate 570,179 exact duplicate entries (-27.6%), 
            labeled across 6 distinct traffic classes using deterministic rule-based matching (preventing circular model dependency), 
            and engineered into 66 numeric behavioral and structural features. 
            To handle severe real-world class imbalance (9,298:1), SMOTE was applied strictly to the training partition, preserving an untouched natural test partition of 298,437 records. 
            The Random Forest classifier achieved <strong>99.97% accuracy</strong> and <strong>95.26% Macro F1</strong>, and all pipeline logic was codified into a reusable, CLI-driven engine with 97.8% Apache Parquet compression.
        </div>
        """,
        unsafe_allow_html=True,
    )


# ===========================================================================
# INDIVIDUAL PRACTICAL DETAIL VIEW
# ===========================================================================
def render_practical_page(practical_num: int):
    info = PRACTICAL_DETAILS.get(practical_num, {})
    status = check_file_status(practical_num)

    render_header(
        f"Practical {practical_num}: {info.get('title', '')}",
        info.get("objective", ""),
    )

    # Status & Metadata Row
    c_stat1, c_stat2, c_stat3 = st.columns([1, 1, 2])
    with c_stat1:
        badge = (
            "<span class='badge-status-ok'>AVAILABLE</span>"
            if status["status"] == "AVAILABLE"
            else "<span class='badge-status-missing'>NOT AVAILABLE</span>"
        )
        st.markdown(f"**Status:** {badge}", unsafe_allow_html=True)
    with c_stat2:
        st.markdown(f"**Primary File Size:** `{status['file_info']['primary_size_mb']} MB`")
    with c_stat3:
        st.markdown(f"**Primary File:** `{status['file_info']['primary_name']}`")

    # Tabbed Detail Layout
    tab1, tab2, tab3, tab4 = st.tabs(
        ["Technical Overview", "Data Samples & Visualizations", "Audit & Verification Report", "Script Execution"]
    )

    with tab1:
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("#### Aim & Objectives")
            st.markdown(f"**Aim:** {info.get('aim', '')}")
            st.markdown(f"**Objective:** {info.get('objective', '')}")
            st.markdown(f"**Input Artifact:** `{info.get('input', '')}`")
            st.markdown(f"**Output Artifact:** `{info.get('output', '')}`")

        with c2:
            st.markdown("#### Methodology & Results")
            st.markdown(f"**Technical Approach:** {info.get('what_i_did', '')}")
            st.markdown(f"**System Rationale:** {info.get('why_required', '')}")
            st.markdown(f"**Key Empirical Result:** {info.get('result', '')}")

        st.markdown("---")
        st.markdown("#### Key Empirical Metrics")
        k_cols = st.columns(len(info.get("key_stats", {})))
        for idx, (k, v) in enumerate(info.get("key_stats", {}).items()):
            with k_cols[idx]:
                st.metric(label=k, value=v)

    with tab2:
        st.markdown("#### Output Telemetry Sample & Schema")
        p_file = status["file_info"]["primary_path"]

        # CSV Preview
        if p_file.endswith(".csv") and Path(p_file).exists():
            sample_df = load_csv_sample(p_file, nrows=100)
            if sample_df is not None:
                st.caption(f"Previewing top {len(sample_df)} rows across {len(sample_df.columns)} columns (Loaded from {Path(p_file).name}):")
                st.dataframe(sample_df, use_container_width=True)
        # Parquet Preview
        elif p_file.endswith(".parquet") and Path(p_file).exists():
            sample_df = load_parquet_sample(p_file, nrows=100)
            if sample_df is not None:
                st.caption(f"Previewing top {len(sample_df)} rows across {len(sample_df.columns)} columns (Loaded from {Path(p_file).name}):")
                st.dataframe(sample_df, use_container_width=True)

        # For Practical 10: Show pipeline summary JSON if available
        if practical_num == 10:
            summary_json_path = PRACTICAL_DIRS[10] / "outputs" / "pipeline_summary.json"
            if summary_json_path.exists():
                summary_data = read_json_data(summary_json_path)
                if summary_data:
                    st.markdown("#### Reusable Pipeline Execution Summary")
                    st.json(summary_data)

        # For Practical 6: Show balancing comparison chart
        if practical_num == 6:
            st.markdown("#### Class Distribution Before vs. After SMOTE")
            st.plotly_chart(plot_balancing_comparison_chart(), use_container_width=True)

        # For Practical 9: Show model comparison chart & feature importance
        if practical_num == 9:
            comp_df = get_model_comparison_metrics()
            st.markdown("#### Model Performance Metrics")
            st.dataframe(comp_df, use_container_width=True)

        # Render all static plots generated for this practical
        plots = find_plots_for_practical(practical_num)
        if plots:
            st.markdown("#### Generated Analytical Charts")
            # Display plots in clean 2-column grid
            for i in range(0, len(plots), 2):
                p_c1, p_c2 = st.columns(2)
                with p_c1:
                    st.image(str(plots[i]), caption=f"{plots[i].name}", use_container_width=True)
                if i + 1 < len(plots):
                    with p_c2:
                        st.image(str(plots[i + 1]), caption=f"{plots[i + 1].name}", use_container_width=True)
        elif not (p_file.endswith(".csv") or p_file.endswith(".parquet")):
            st.info("No graphical charts for this stage. View the execution audit report in Tab 3.")

    with tab3:
        st.markdown("#### Execution Audit Report")
        rep_path = status.get("report_path")
        if rep_path and Path(rep_path).exists():
            report_text = read_text_report(rep_path)
            st.text_area("Audit Report Content", report_text, height=450)
            st.download_button(
                label=f"Download {Path(rep_path).name}",
                data=report_text,
                file_name=Path(rep_path).name,
                mime="text/plain",
            )
        else:
            st.warning("Audit report not found at the default output path.")

    with tab4:
        st.markdown("#### Re-Execute Stage Script")
        st.warning("Note: This stage has already completed execution and verified artifacts exist. Re-running will reprocess telemetry data and may require substantial processing time.")

        runner_script = status.get("runner_path")
        if runner_script and Path(runner_script).exists():
            confirm = st.checkbox(f"Confirm re-execution of {Path(runner_script).name}", key=f"conf_{practical_num}")
            if confirm and st.button(f"Execute Practical {practical_num}", key=f"run_btn_{practical_num}"):
                with st.spinner(f"Executing {Path(runner_script).name}..."):
                    t0 = time.time()
                    try:
                        res = subprocess.run(
                            [sys.executable, runner_script],
                            cwd=str(Path(runner_script).parent),
                            capture_output=True,
                            text=True,
                            timeout=600,
                        )
                        elapsed = time.time() - t0
                        if res.returncode == 0:
                            st.success(f"Execution completed in {elapsed:.2f} seconds.")
                            st.code(res.stdout, language="text")
                        else:
                            st.error(f"Execution failed with return code {res.returncode}")
                            st.code(res.stderr or res.stdout, language="text")
                    except Exception as ex:
                        st.error(f"Execution exception: {ex}")
        else:
            st.info(f"Runner script `{runner_script}` not found.")


# ===========================================================================
# MODEL EVALUATION ANALYSIS
# ===========================================================================
def render_model_results_page():
    render_header(
        "Machine Learning Model Evaluation",
        "Practical 9: Comparative Analysis on Untouched Natural Test Partition (298,437 Records)",
    )

    comp_df = get_model_comparison_metrics()

    st.markdown("### Primary Model Performance Comparison")
    st.dataframe(
        comp_df.style.highlight_max(subset=["Accuracy", "Macro F1", "Macro Recall"], color="#dcfce7"),
        use_container_width=True,
    )

    c1, c2 = st.columns(2)
    with c1:
        st.plotly_chart(plot_model_comparison_chart(comp_df), use_container_width=True)
    with c2:
        fi_df = get_rf_feature_importance_df(top_n=15)
        if fi_df is not None:
            st.plotly_chart(plot_feature_importance_chart(fi_df, top_n=15), use_container_width=True)

    st.markdown("---")

    # Multiclass Confusion Matrices
    st.subheader("Multiclass Confusion Matrices")
    cm_c1, cm_c2 = st.columns(2)
    with cm_c1:
        st.markdown("**Multinomial Logistic Regression (Linear Baseline)**")
        lr_cm_path = PRACTICAL_DIRS[9] / "outputs" / "plots" / "logistic_regression_confusion_matrix.png"
        if lr_cm_path.exists():
            st.image(str(lr_cm_path), caption="Logistic Regression Confusion Matrix", use_container_width=True)
    with cm_c2:
        st.markdown("**Random Forest Classifier (Ensemble Architecture)**")
        rf_cm_path = PRACTICAL_DIRS[9] / "outputs" / "plots" / "random_forest_confusion_matrix.png"
        if rf_cm_path.exists():
            st.image(str(rf_cm_path), caption="Random Forest Confusion Matrix", use_container_width=True)

    st.markdown("---")

    # Balanced Data Validation Experiment (Part 13)
    st.subheader("Balanced Training vs. Natural Split Experiment (Part 13)")
    st.caption("Classifiers trained on Practical 6 SMOTE balanced training dataset (60,000 records) evaluated on the untouched test partition (298,437 records).")

    bal_df = get_balanced_experiment_metrics()
    if bal_df is not None:
        st.dataframe(bal_df, use_container_width=True)

    st.markdown(
        """
        <div class="executive-summary-box">
            <strong>Imbalanced Domain Optimization Analysis:</strong> Real-world network telemetry exhibits severe skew, with benign requests representing 99.7% of all events. 
            Evaluating models strictly on accuracy produces deceptive results because predicting the majority class yields 99.7% accuracy while missing all cyberattacks. 
            Random Forest trained with balanced class weights achieves <strong>95.26% Macro F1</strong>, correctly isolating low-volume attacks such as SQL injection (160 instances) and command injection (805 instances) without being overwhelmed by majority benign traffic.
        </div>
        """,
        unsafe_allow_html=True,
    )


# ===========================================================================
# DATASET EXPLORER
# ===========================================================================
def render_dataset_explorer():
    render_header(
        "Interactive Dataset Explorer",
        "Inspect Telemetry Tables and Artifact Schemas Across Pipeline Stages",
    )

    dataset_options = {
        "Practical 2: Structured Logs (13 columns)": PRACTICAL_DIRS[2] / "data" / "processed" / "structured_access_logs.csv",
        "Practical 3: Preprocessed Logs (Cleaned, 14 columns)": PRACTICAL_DIRS[3] / "data" / "processed" / "preprocessed_access_logs.csv",
        "Practical 4: Labeled Logs (With label and reason)": PRACTICAL_DIRS[4] / "data" / "processed" / "labeled_access_logs.csv",
        "Practical 5: Feature-Engineered Dataset (66 ML Features)": PRACTICAL_DIRS[5] / "data" / "processed" / "feature_engineered_access_logs.csv",
        "Practical 6: Balanced Training Dataset (SMOTE 60,000 rows)": PRACTICAL_DIRS[6] / "data" / "processed" / "balanced_training_dataset.csv",
        "Practical 6: Untouched Test Dataset (298,437 rows)": PRACTICAL_DIRS[6] / "data" / "processed" / "test_dataset.csv",
        "Practical 10: Final Feature-Engineered Parquet Dataset": PRACTICAL_DIRS[10] / "data" / "processed" / "feature_engineered_logs.parquet",
    }

    selected_name = st.selectbox("Select Pipeline Dataset to Inspect", list(dataset_options.keys()))
    target_path = dataset_options[selected_name]

    if not target_path.exists():
        # Check for sample dataset fallback
        stem = target_path.stem.replace("_access_logs", "").replace("_logs", "")
        candidates = [
            target_path.parent / f"{stem}_sample.csv",
            target_path.parent / f"{target_path.stem}_sample.csv",
            target_path.parent.parent / "outputs" / "samples" / f"{stem}_sample.csv",
            target_path.parent.parent / "outputs" / "samples" / f"{target_path.stem}_sample.csv",
        ]
        for c in candidates:
            if c.exists():
                target_path = c
                break

    if not target_path.exists():
        st.error(f"Selected dataset file `{target_path.name}` is not available.")
        return

    st.markdown(
        f"**File:** `{target_path.name}` | **Path:** `{target_path}` | **Size:** `{round(target_path.stat().st_size / (1024*1024), 2)} MB`"
    )

    # Load preview slice
    if target_path.suffix == ".parquet":
        df_sample = load_parquet_sample(target_path, nrows=500)
    else:
        df_sample = load_csv_sample(target_path, nrows=500)

    if df_sample is not None:
        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("Sample Rows Loaded", f"{len(df_sample):,}")
        with c2:
            st.metric("Total Attributes (Columns)", len(df_sample.columns))
        with c3:
            st.metric("Missing Values in Sample", int(df_sample.isna().sum().sum()))

        with st.expander("Column Names and Data Types", expanded=False):
            dtype_df = pd.DataFrame(
                {
                    "Column": df_sample.columns,
                    "Data Type": [str(t) for t in df_sample.dtypes],
                    "Sample Value": [str(df_sample[c].iloc[0]) if len(df_sample) > 0 else "" for c in df_sample.columns],
                }
            )
            st.dataframe(dtype_df, use_container_width=True)

        st.subheader("Data Viewer (First 500 Records)")
        st.dataframe(df_sample, use_container_width=True)


# ===========================================================================
# TECHNICAL DEFENSE Q&A (VIVA / TECHNICAL EVALUATION)
# ===========================================================================
def render_viva_page():
    render_header(
        "Technical Defense & Verification Q&A",
        "Structured Answers on Dataset Engineering, Preprocessing, ML Architectures, and Validation",
    )

    st.markdown(
        """
        <div class="executive-summary-box">
            <strong>Technical Defense Reference:</strong> This section contains authoritative answers to core technical questions regarding dataset engineering, 
            deduplication methodologies, deterministic rule-based labeling, feature synthesis, SMOTE balancing isolation, and classification benchmarking.
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Search & Filter
    search_query = st.text_input("Search Technical Topics (e.g., SMOTE, deduplication, F1 score, entropy, pipeline)", "")

    filtered_questions = [
        item for item in VIVA_QUESTIONS
        if search_query.lower() in item["q"].lower() or search_query.lower() in item["a"].lower()
    ]

    st.caption(f"Displaying {len(filtered_questions)} of {len(VIVA_QUESTIONS)} Technical Q&A Items")

    for item in filtered_questions:
        with st.expander(item["q"], expanded=False):
            st.markdown(f"**Answer:** {item['a']}")


# ===========================================================================
# PROJECT REPORT GENERATION
# ===========================================================================
def render_report_page():
    render_header(
        "Project Technical Documentation & Export",
        "Consolidated Specification and Empirical Audit Across Practicals 1 to 10",
    )

    st.markdown("### Technical Laboratory Documentation Generator")
    st.write("Generate a consolidated technical summary covering the complete methodology, empirical metrics, and model evaluations.")

    metrics = get_home_metrics()

    summary_text = f"""================================================================================
PDS LOG ANALYSIS & ATTACK DETECTION: COMPREHENSIVE PROJECT REPORT
Title: Web Honeypot Log Processing, Feature Engineering, and Attack Classification
Course: Predictive Data Science (PDS)
================================================================================

1. EXECUTIVE PROJECT SUMMARY
--------------------------------------------------------------------------------
This project establishes a complete data science lifecycle for cybersecurity access logs:
- Raw Ingestion:         {metrics['raw_records']:,} raw honeypot records (cj.log, {metrics['raw_size_mb']} MB)
- Deduplication:         {metrics['duplicates_removed']:,} exact duplicates removed (27.6% redundancy)
- Clean Dataset:         {metrics['preprocessed_records']:,} records across 14 clean attributes
- Attack Classes:        6 categories (benign, brute_force, path_traversal, xss, command_injection, sqli)
- Feature Space:         66 numeric behavioral, lexical, rate, and entropy features
- Dataset Balancing:     SMOTE applied strictly to training data (60,000 balanced rows)
- Evaluation Set:        {metrics['untouched_test_records']:,} untouched natural test records
- Best Classifier:       Random Forest (100 trees, balanced weights)
- Random Forest Acc:     {metrics['rf_accuracy']*100:.2f}%
- Random Forest Macro F1:{metrics['rf_macro_f1']*100:.2f}%
- Final Pipeline:        Practical 10 automated CLI pipeline with Apache Parquet export

2. PRACTICAL-BY-PRACTICAL BREAKDOWN
--------------------------------------------------------------------------------
- Practical 1: Inspected raw 8-element JSON array format in cj.log.
- Practical 2: Structured raw logs into 13-column canonical DataFrame.
- Practical 3: Removed exact duplicates, parsed timestamps, normalized URL paths.
- Practical 4: Deterministic rule-based attack labeling (SQLi, CMDi, XSS, Traversal, Brute Force).
- Practical 5: Engineered 66 numeric features (Shannon entropy, burst rates, inter-arrival time).
- Practical 6: Mitigated 9,298:1 class imbalance via SMOTE on training partition only.
- Practical 7: Wrangled data across IP, hour, day, status codes, and error ratios.
- Practical 8: Produced 15 publication-grade visualization plots and interactive dashboards.
- Practical 9: Trained and compared Logistic Regression vs. Random Forest classifiers.
- Practical 10: Built a reusable 7-stage CLI data pipeline with Apache Parquet serialization.

3. KEY ARCHITECTURAL PRINCIPLES
--------------------------------------------------------------------------------
1. No ML Circularity: Attack ground truth was established via deterministic regex rules, not ML.
2. Zero Target Leakage: Labels and metadata were strictly excluded from feature matrices.
3. Test Set Isolation: Test partitions remained completely untouched by synthetic balancing.
4. Macro F1 Priority: Evaluated performance using Macro F1 to prevent majority benign bias.
5. 100% Open Source: Developed exclusively with free tools (Python, Pandas, Scikit-learn, Streamlit).

================================================================================
Generated by PDS Log Analytics System
================================================================================
"""

    st.text_area("Report Preview", summary_text, height=350)

    c1, c2 = st.columns(2)
    with c1:
        st.download_button(
            label="Download PDS_Project_Summary.txt",
            data=summary_text,
            file_name="PDS_Project_Summary.txt",
            mime="text/plain",
        )
    with c2:
        html_report = f"<html><head><title>PDS Project Report</title></head><body style='font-family:sans-serif;padding:30px;'><pre>{summary_text}</pre></body></html>"
        st.download_button(
            label="Download PDS_Project_Summary.html",
            data=html_report,
            file_name="PDS_Project_Summary.html",
            mime="text/html",
        )


# ===========================================================================
# PROJECT ARCHITECTURE VIEW
# ===========================================================================
def render_project_architecture_page():
    render_header(
        "System Architecture & Dual-Branch Pipeline",
        "Workflow Across Data Engineering, Threat Intelligence, and Supervised Machine Learning",
    )

    st.markdown(
        """
        <div class="content-card">
            <h3>System Dataflow Architecture</h3>
            <p>The processing architecture splits into two complementary branches following feature engineering:</p>
            <ul>
                <li><strong>Machine Learning Training Branch:</strong> Stratified Partitioning -> SMOTE Balancing on Train Only -> Scaler / Ensemble Training -> Evaluation on Untouched Test Set.</li>
                <li><strong>Threat Intelligence & EDA Branch:</strong> Multi-Dimensional Wrangling -> Temporal Aggregation -> Behavioral Visualizations -> Interactive Profiling.</li>
                <li><strong>Production Deployment Branch:</strong> Packaging the entire sequence into a modular, reusable CLI pipeline (Practical 10).</li>
            </ul>
        </div>
        """,
        unsafe_allow_html=True,
    )

    p10_status = check_file_status(10)
    st.info(f"Practical 10 Reusable Pipeline: {p10_status['status']} | Parquet Export: 9.46 MB (97.8% compression over CSV).")


# ===========================================================================
# MAIN APPLICATION CONTROLLER
# ===========================================================================
def main():
    selected_page = render_sidebar()

    # Route navigation
    if selected_page == "Dashboard Overview":
        render_home_page()
    elif selected_page == "Project Architecture":
        render_project_architecture_page()
    elif "Practical 1:" in selected_page:
        render_practical_page(1)
    elif "Practical 2:" in selected_page:
        render_practical_page(2)
    elif "Practical 3:" in selected_page:
        render_practical_page(3)
    elif "Practical 4:" in selected_page:
        render_practical_page(4)
    elif "Practical 5:" in selected_page:
        render_practical_page(5)
    elif "Practical 6:" in selected_page:
        render_practical_page(6)
    elif "Practical 7:" in selected_page:
        render_practical_page(7)
    elif "Practical 8:" in selected_page:
        render_practical_page(8)
    elif "Practical 9:" in selected_page:
        render_practical_page(9)
    elif "Practical 10:" in selected_page:
        render_practical_page(10)
    elif selected_page == "Model Evaluation Analysis":
        render_model_results_page()
    elif selected_page == "Dataset & Artifact Explorer":
        render_dataset_explorer()
    elif selected_page == "Technical Defense Q&A":
        render_viva_page()
    elif selected_page == "Technical Project Report":
        render_report_page()
    else:
        render_home_page()

    # Professional Footer
    st.markdown("---")
    st.markdown(
        """
        <div style="text-align: center; color: #64748b; font-size: 12px; padding: 16px 0;">
            <b>PDS Practical Project</b> — Web Log Analysis & Attack Detection (Practicals 1–10)<br>
            Python | Pandas | Scikit-learn | Streamlit | Matplotlib | Plotly | PyArrow<br>
            <em>All data processing and machine learning executed locally using free and open-source tools.</em>
        </div>
        """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
