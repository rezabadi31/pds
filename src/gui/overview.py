"""src/gui/overview.py
Log Intelligence Platform — Master Overview Dashboard
Product-grade dark cybersecurity overview communicating system capabilities and real telemetry metrics.
"""

import streamlit as st
from typing import Callable

from config import THEME, BASELINE_METRICS
from src.gui.charts import plot_class_distribution_dark, plot_dataset_journey_flow_dark


def render_overview_view(on_navigate: Callable[[str], None], on_select_practical: Callable[[int], None]):
    """Renders the master product overview view."""
    
    # Hero Section
    st.markdown(
        f"""
        <div class="product-hero">
            <div class="product-hero-eyebrow">
                <span>🛡️</span> Security Intelligence &amp; Log Telemetry Platform
            </div>
            <h1 class="product-hero-title">Log Intelligence Platform</h1>
            <div class="product-hero-subtitle">
                From raw access logs to structured, labeled, feature-rich security intelligence. Powered by an end-to-end automated data pipeline and machine learning threat detection.
            </div>
            <div style="display: flex; gap: 0.8rem; flex-wrap: wrap;">
                <span class="detail-badge-pill">● Engine Status: READY</span>
                <span class="detail-badge-pill">2.06M Raw Events</span>
                <span class="detail-badge-pill">6 Multi-Class Threat Categories</span>
                <span class="detail-badge-pill">66 Numerical Features</span>
                <span class="detail-badge-pill">Random Forest: 99.97% Accuracy</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Core Metric KPIs
    st.markdown(
        f"""
        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-label">Raw Telemetry</div>
                <div class="kpi-value">{BASELINE_METRICS['raw_records']:,}</div>
                <div class="kpi-sub">215.40 MB honeypot access logs</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Processed Working Set</div>
                <div class="kpi-value">{BASELINE_METRICS['preprocessed_records']:,}</div>
                <div class="kpi-sub">-570,179 exact duplicates removed</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Attack Classes</div>
                <div class="kpi-value">{BASELINE_METRICS['attack_classes']}</div>
                <div class="kpi-sub">4,359 malicious requests identified</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Engineered Features</div>
                <div class="kpi-value">{BASELINE_METRICS['engineered_features_total']}</div>
                <div class="kpi-sub">Behavioral, rates, entropy &amp; signals</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Pipeline Engine</div>
                <div class="kpi-value" style="color: {THEME['success']};">{BASELINE_METRICS['pipeline_status']}</div>
                <div class="kpi-sub">108.67s runtime • 97.8% Parquet drop</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Quick Action Buttons
    c_btn1, c_btn2, c_btn3 = st.columns(3)
    with c_btn1:
        if st.button("🤖 Launch Rox Assistant →", key="btn_hero_rox", use_container_width=True, type="primary"):
            on_navigate("Log Analyzer")
    with c_btn2:
        if st.button("📚 Explore Practicals (1 to 10) →", key="btn_hero_practicals", use_container_width=True):
            on_navigate("Practicals")
    with c_btn3:
        if st.button("⚙️ View Reusable Pipeline →", key="btn_hero_pipeline", use_container_width=True):
            on_navigate("Pipeline")

    st.write("")

    # Visual Threat Landscape
    col_chart1, col_chart2 = st.columns(2)
    with col_chart1:
        st.plotly_chart(plot_dataset_journey_flow_dark(), use_container_width=True)
    with col_chart2:
        st.plotly_chart(plot_class_distribution_dark(log_scale=True), use_container_width=True)

    # Architectural Overview Section
    with st.container():
        st.markdown(
            f"""
            <div class="detail-section">
                <div class="detail-section-title">
                    <span>⚡</span> System Architecture &amp; Intelligence Capabilities
                </div>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.2rem; margin-top: 0.5rem;">
                    
                    <div style="background: #10151F; border: 1px solid rgba(255,255,255,0.06); border-radius: 10px; padding: 1.2rem;">
                        <div style="color: {THEME['accent_secondary']}; font-weight: 700; font-size: 0.95rem; margin-bottom: 0.4rem;">
                            📥 01. Streaming Ingestion &amp; Structuring
                        </div>
                        <div style="font-size: 0.86rem; color: {THEME['text_secondary']}; line-height: 1.5;">
                            Consumes high-volume honeypot JSON arrays. Handles multi-record line splices, memory streaming without buffer overflow, and aligns 13 canonical columns.
                        </div>
                    </div>

                    <div style="background: #10151F; border: 1px solid rgba(255,255,255,0.06); border-radius: 10px; padding: 1.2rem;">
                        <div style="color: {THEME['success']}; font-weight: 700; font-size: 0.95rem; margin-bottom: 0.4rem;">
                            🧹 02. Cleaning &amp; Ground-Truth Labeling
                        </div>
                        <div style="font-size: 0.86rem; color: {THEME['text_secondary']}; line-height: 1.5;">
                            Eliminated 570k duplicate probes (-27.65%), imputed 18.4M missing values, and established deterministic labels across 6 categories without circular ML dependencies.
                        </div>
                    </div>

                    <div style="background: #10151F; border: 1px solid rgba(255,255,255,0.06); border-radius: 10px; padding: 1.2rem;">
                        <div style="color: {THEME['accent']}; font-weight: 700; font-size: 0.95rem; margin-bottom: 0.4rem;">
                            ⚙️ 03. Feature Engineering &amp; Balancing
                        </div>
                        <div style="font-size: 0.86rem; color: {THEME['text_secondary']}; line-height: 1.5;">
                            Extracts 66 features (sliding rates, Shannon entropy, tsfresh). Resolves 9,298:1 imbalance using SMOTE on training data while preserving 298k test records untouched.
                        </div>
                    </div>

                    <div style="background: #10151F; border: 1px solid rgba(255,255,255,0.06); border-radius: 10px; padding: 1.2rem;">
                        <div style="color: {THEME['warning']}; font-weight: 700; font-size: 0.95rem; margin-bottom: 0.4rem;">
                            🤖 04. Rox Live Assistant &amp; Pipeline
                        </div>
                        <div style="font-size: 0.86rem; color: {THEME['text_secondary']}; line-height: 1.5;">
                            Upload any new log file to run the reusable 7-stage engine. Rox analyzes attacks, highlights suspicious hosts, and answers questions using processed data.
                        </div>
                    </div>

                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
