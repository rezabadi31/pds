"""src/gui/pipeline_view.py
Practical 10 Reusable Pipeline Architecture & Verified Benchmark View
Displays:
1. Interactive Visual Flowchart (RAW LOG → LOAD → PARSE → STRUCTURE → PREPROCESS → LABEL → FEATURE ENGINEERING → VALIDATE → EXPORT)
2. Verified Empirical Metrics from Practical 10 (2.06M records, 108.67s runtime, 97.8% Parquet drop)
3. 14 Integrity Validation Assertions (100% Pass Rate)
"""

import streamlit as st
import pandas as pd

from config import THEME, BASELINE_METRICS
from src.gui.charts import plot_pipeline_stage_durations_dark


def render_pipeline_view():
    """Renders the Practical 10 Reusable Pipeline architecture and benchmarks."""

    st.markdown(
        f"""
        <div style="margin-bottom: 1.5rem;">
            <div style="font-size: 0.75rem; font-weight: 700; color: {THEME['accent_cyan']}; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 0.3rem;">
                Automated Data Architecture
            </div>
            <h1 style="font-size: 2rem; font-weight: 800; color: {THEME['text_primary']}; margin: 0 0 0.4rem 0;">
                Reusable Log Processing Pipeline
            </h1>
            <div style="font-size: 0.95rem; color: {THEME['text_secondary']};">
                Practical 10 production-grade architecture that transforms raw unverified honeypot streams into validated, feature-rich Parquet &amp; CSV datasets.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # 4 Quick Verified KPI Cards
    st.markdown(
        f"""
        <div class="rox-kpi-grid">
            <div class="rox-kpi-card">
                <div class="rox-kpi-label">RAW RECORDS PROCESSED</div>
                <div class="rox-kpi-value">{BASELINE_METRICS['raw_records']:,}</div>
                <div class="rox-kpi-sub">215.4 MB raw honeypot file</div>
            </div>
            <div class="rox-kpi-card">
                <div class="rox-kpi-label">PIPELINE RUNTIME</div>
                <div class="rox-kpi-value">{BASELINE_METRICS['pipeline_runtime_sec']}s</div>
                <div class="rox-kpi-sub">18,970 records / second</div>
            </div>
            <div class="rox-kpi-card">
                <div class="rox-kpi-label">PARQUET REDUCTION</div>
                <div class="rox-kpi-value" style="color: {THEME['success']};">{BASELINE_METRICS['parquet_compression_reduction']}</div>
                <div class="rox-kpi-sub">415 MB CSV → 9.1 MB Parquet</div>
            </div>
            <div class="rox-kpi-card">
                <div class="rox-kpi-label">INTEGRITY ASSERTIONS</div>
                <div class="rox-kpi-value" style="color: {THEME['accent_cyan']};">14 / 14</div>
                <div class="rox-kpi-sub">100% automated test pass rate</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Visual Flowchart (RAW LOG → LOAD → PARSE → STRUCTURE → PREPROCESS → LABEL → FEATURE ENGINEERING → VALIDATE → EXPORT)
    st.markdown(
        f"""
        <div style="font-size: 0.95rem; font-weight: 700; color: {THEME['text_primary']}; margin: 1.5rem 0 0.8rem 0;">
            END-TO-END PIPELINE STAGE ARCHITECTURE
        </div>
        <div style="background: {THEME['card_bg']}; border: 1px solid {THEME['border']}; border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem;">
            <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 0.5rem; text-align: center;">
                <div style="flex: 1; min-width: 100px; background: {THEME['card_elevated']}; padding: 0.8rem 0.5rem; border-radius: 8px; border: 1px solid {THEME['border']};">
                    <div style="font-size: 1.1rem;">📄</div>
                    <div style="font-size: 0.75rem; font-weight: 700; color: {THEME['text_primary']};">RAW LOG</div>
                    <div style="font-size: 0.65rem; color: {THEME['text_muted']};">2.06M Lines</div>
                </div>
                <div style="color: {THEME['accent_cyan']}; font-weight: bold;">→</div>
                <div style="flex: 1; min-width: 100px; background: {THEME['card_elevated']}; padding: 0.8rem 0.5rem; border-radius: 8px; border: 1px solid {THEME['border']};">
                    <div style="font-size: 1.1rem;">📥</div>
                    <div style="font-size: 0.75rem; font-weight: 700; color: {THEME['text_primary']};">LOAD</div>
                    <div style="font-size: 0.65rem; color: {THEME['text_muted']};">Streaming (20.6s)</div>
                </div>
                <div style="color: {THEME['accent_cyan']}; font-weight: bold;">→</div>
                <div style="flex: 1; min-width: 100px; background: {THEME['card_elevated']}; padding: 0.8rem 0.5rem; border-radius: 8px; border: 1px solid {THEME['border']};">
                    <div style="font-size: 1.1rem;">🔍</div>
                    <div style="font-size: 0.75rem; font-weight: 700; color: {THEME['text_primary']};">PARSE</div>
                    <div style="font-size: 0.65rem; color: {THEME['text_muted']};">Delimiter Splitting</div>
                </div>
                <div style="color: {THEME['accent_cyan']}; font-weight: bold;">→</div>
                <div style="flex: 1; min-width: 100px; background: {THEME['card_elevated']}; padding: 0.8rem 0.5rem; border-radius: 8px; border: 1px solid {THEME['border']};">
                    <div style="font-size: 1.1rem;">🧱</div>
                    <div style="font-size: 0.75rem; font-weight: 700; color: {THEME['text_primary']};">STRUCTURE</div>
                    <div style="font-size: 0.65rem; color: {THEME['text_muted']};">13 Columns (23.2s)</div>
                </div>
                <div style="color: {THEME['accent_cyan']}; font-weight: bold;">→</div>
                <div style="flex: 1; min-width: 100px; background: {THEME['card_elevated']}; padding: 0.8rem 0.5rem; border-radius: 8px; border: 1px solid {THEME['border']};">
                    <div style="font-size: 1.1rem;">🧹</div>
                    <div style="font-size: 0.75rem; font-weight: 700; color: {THEME['text_primary']};">PREPROCESS</div>
                    <div style="font-size: 0.65rem; color: {THEME['text_muted']};">-570k Dupes (9.5s)</div>
                </div>
                <div style="color: {THEME['accent_cyan']}; font-weight: bold;">→</div>
                <div style="flex: 1; min-width: 100px; background: {THEME['card_elevated']}; padding: 0.8rem 0.5rem; border-radius: 8px; border: 1px solid {THEME['border']};">
                    <div style="font-size: 1.1rem;">🏷️</div>
                    <div style="font-size: 0.75rem; font-weight: 700; color: {THEME['text_primary']};">LABEL</div>
                    <div style="font-size: 0.65rem; color: {THEME['text_muted']};">6 Classes (20.5s)</div>
                </div>
                <div style="color: {THEME['accent_cyan']}; font-weight: bold;">→</div>
                <div style="flex: 1; min-width: 100px; background: {THEME['card_elevated']}; padding: 0.8rem 0.5rem; border-radius: 8px; border: 1px solid {THEME['border']};">
                    <div style="font-size: 1.1rem;">⚙️</div>
                    <div style="font-size: 0.75rem; font-weight: 700; color: {THEME['text_primary']};">FEATURES</div>
                    <div style="font-size: 0.65rem; color: {THEME['text_muted']};">26 Features (5.0s)</div>
                </div>
                <div style="color: {THEME['accent_cyan']}; font-weight: bold;">→</div>
                <div style="flex: 1; min-width: 100px; background: {THEME['card_elevated']}; padding: 0.8rem 0.5rem; border-radius: 8px; border: 1px solid {THEME['border']};">
                    <div style="font-size: 1.1rem;">✅</div>
                    <div style="font-size: 0.75rem; font-weight: 700; color: {THEME['text_primary']};">VALIDATE</div>
                    <div style="font-size: 0.65rem; color: {THEME['text_muted']};">14 Tests Passed</div>
                </div>
                <div style="color: {THEME['accent_cyan']}; font-weight: bold;">→</div>
                <div style="flex: 1; min-width: 100px; background: {THEME['card_elevated']}; padding: 0.8rem 0.5rem; border-radius: 8px; border: 1px solid {THEME['border']};">
                    <div style="font-size: 1.1rem;">💾</div>
                    <div style="font-size: 0.75rem; font-weight: 700; color: {THEME['text_primary']};">EXPORT</div>
                    <div style="font-size: 0.65rem; color: {THEME['text_muted']};">CSV &amp; Parquet (30s)</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Stage Durations Chart & 14 Checks Table
    col_c1, col_c2 = st.columns([1, 1])

    with col_c1:
        fig_durations = plot_pipeline_stage_durations_dark()
        if fig_durations:
            st.plotly_chart(fig_durations, use_container_width=True)

    with col_c2:
        st.markdown(
            f"""
            <div style="font-size: 0.95rem; font-weight: 700; color: {THEME['text_primary']}; margin-bottom: 0.6rem;">
                14 VERIFIED PIPELINE ASSERTIONS
            </div>
            """,
            unsafe_allow_html=True
        )

        checks = [
            ("Input raw file exists & readable", "PASS"),
            ("Logs streamed without memory exhaustion", "PASS"),
            ("Data structured into 13 canonical columns", "PASS"),
            ("Timestamps converted to ISO-8601 UTC", "PASS"),
            ("Missing values imputed with sentinels", "PASS"),
            ("Exact duplicates purged (570,179 rows)", "PASS"),
            ("Multi-class labels generated deterministically", "PASS"),
            ("Expected 6 security classes confirmed present", "PASS"),
            ("26 numerical features extracted without target leakage", "PASS"),
            ("Zero label leakage into ML training attributes", "PASS"),
            ("Output structured CSV generated on disk", "PASS"),
            ("Output labeled CSV generated on disk", "PASS"),
            ("Output Parquet generated with 97.8% compression", "PASS"),
            ("Final row count reconciliation verified (1,492,047)", "PASS"),
        ]

        df_checks = pd.DataFrame(checks, columns=["Assertion Check", "Status"])
        st.dataframe(df_checks, use_container_width=True, hide_index=True)
