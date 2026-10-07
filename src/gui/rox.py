"""src/gui/rox.py
ROX — Master Live Log Analysis Assistant & Workspace
Implements the exact UI inspiration:
- Top status header (ROX ● Ready 📁 Log Status)
- Large central workspace with 1-click Ingestion & Demo trigger
- Auto-runs pipeline upon file upload or demo click (zero confusing blank states)
- Step-by-step real pipeline execution UI with progress updates
- Results Dashboard (4 KPI cards, Threat Distribution, Top Suspicious IPs, Top Suspicious Requests)
- Feature Intelligence collapsible section
- Fact-grounded Rox Deterministic Chat
- Download exports (CSV & Parquet)
"""

import io
from pathlib import Path
from typing import Dict, Any, Optional
import streamlit as st
import pandas as pd

from config import THEME, DATA_DIR
from src.pipeline.pipeline import RoxPipeline, ask_rox
from src.gui.charts import (
    plot_traffic_classification_donut,
    plot_threat_distribution_bar,
    plot_feature_importance_bar,
)


def render_rox_view():
    """Renders the main Rox Live Analyzer workspace with automatic execution upon file ingestion."""

    # Initialize Session States
    if "analysis_result" not in st.session_state:
        st.session_state.analysis_result = None
    if "current_file_bytes" not in st.session_state:
        st.session_state.current_file_bytes = None
    if "current_filename" not in st.session_state:
        st.session_state.current_filename = ""
    if "analyzed_filename" not in st.session_state:
        st.session_state.analyzed_filename = ""
    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []

    # -------------------------------------------------------------
    # 1. COMPACT TOP STATUS BAR
    # -------------------------------------------------------------
    analysis = st.session_state.analysis_result
    has_active_log = (analysis is not None and analysis.get("status") == "SUCCESS" and analysis.get("total_records", 0) > 0)
    
    status_text = "● Active" if has_active_log else "● Ready"
    file_status = f"📁 {st.session_state.current_filename}" if st.session_state.current_filename else "📁 No log file loaded"

    st.markdown(
        f"""
        <div class="rox-topbar">
            <div class="rox-topbar-left">
                <span style="font-size: 1.25rem;">🤖</span>
                <div>
                    <span class="rox-topbar-brand">ROX</span>
                    <span style="color: {THEME['text_muted']}; margin: 0 0.4rem;">|</span>
                    <span class="rox-topbar-subtitle">Log Intelligence</span>
                </div>
            </div>
            <div style="display: flex; align-items: center; gap: 1rem;">
                <span class="{"rox-badge-status" if not has_active_log else "rox-badge-status-active"}">{status_text}</span>
                <span style="font-size: 0.82rem; color: {THEME['text_secondary']}; font-weight: 500;">{file_status}</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # -------------------------------------------------------------
    # 2. INGESTION CONTROLS (Always accessible)
    # -------------------------------------------------------------
    with st.container():
        c_up, c_btn = st.columns([3, 1])
        with c_up:
            uploaded = st.file_uploader(
                "Upload log file (.log, .txt, .csv, .json)",
                type=["log", "txt", "csv", "json"],
                key="rox_master_uploader",
                help="Upload server access logs from Apache, Nginx, Honeypots, or SIEM exports."
            )
        with c_btn:
            st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
            demo_clicked = st.button("⚡ Load Demo Log", key="btn_demo_trigger", use_container_width=True)

    # -------------------------------------------------------------
    # 3. AUTO-EXECUTION ENGINE: Handle Demo or Upload Immediately
    # -------------------------------------------------------------
    if demo_clicked:
        demo_path = DATA_DIR / "sample_honeypot.log"
        if demo_path.exists():
            with open(demo_path, "rb") as f:
                demo_bytes = f.read()
            st.session_state.current_file_bytes = demo_bytes
            st.session_state.current_filename = "sample_honeypot.log"
            _execute_pipeline(demo_bytes, "sample_honeypot.log")
        else:
            st.error("Demo file data/sample_honeypot.log not found.")

    elif uploaded is not None:
        # If user uploaded a new file that has not been analyzed yet
        file_bytes = uploaded.getvalue()
        if uploaded.name != st.session_state.analyzed_filename:
            st.session_state.current_file_bytes = file_bytes
            st.session_state.current_filename = uploaded.name
            _execute_pipeline(file_bytes, uploaded.name)

    # Refresh analysis reference after potential execution
    analysis = st.session_state.analysis_result
    has_active_log = (analysis is not None and analysis.get("status") == "SUCCESS" and analysis.get("total_records", 0) > 0)

    # -------------------------------------------------------------
    # 4. MAIN WORKSPACE: RESULTS DASHBOARD OR WELCOME CARD
    # -------------------------------------------------------------
    if has_active_log:
        _render_analysis_dashboard(analysis)
    else:
        _render_empty_state()


def _render_empty_state():
    """Renders the clean, uncluttered empty state before a log is analyzed."""
    st.markdown(
        f"""
        <div class="rox-welcome-card" style="margin-top: 1.5rem; margin-bottom: 2rem;">
            <div class="rox-welcome-icon">🤖</div>
            <div class="rox-welcome-title">ROX</div>
            <div class="rox-welcome-tagline">"Hi, I'm Rox."</div>
            <div class="rox-welcome-desc">
                I can analyze your web access logs using the reusable log-processing pipeline.<br>
                Upload a log file above, or click <strong>⚡ Load Demo Log</strong> to inspect live honeypot telemetry instantly.
            </div>
            <div style="display: inline-flex; gap: 0.5rem; justify-content: center; background: {THEME['card_elevated']}; padding: 0.4rem 0.9rem; border-radius: 9999px; border: 1px solid {THEME['border']}; margin-top: 0.5rem;">
                <span style="font-size: 0.75rem; color: {THEME['text_muted']}; font-weight: 600; text-transform: uppercase;">Formats Supported:</span>
                <span style="font-size: 0.75rem; color: {THEME['accent_cyan']}; font-weight: 700;">Honeypot JSON (.LOG)</span>
                <span style="font-size: 0.75rem; color: {THEME['text_muted']};">·</span>
                <span style="font-size: 0.75rem; color: {THEME['accent_cyan']}; font-weight: 700;">Apache / Nginx Combined (.TXT)</span>
                <span style="font-size: 0.75rem; color: {THEME['text_muted']};">·</span>
                <span style="font-size: 0.75rem; color: {THEME['accent_cyan']}; font-weight: 700;">Structured CSV (.CSV)</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


def _render_analysis_dashboard(analysis: Dict[str, Any]):
    """Renders the comprehensive, dark cybersecurity analysis dashboard."""
    fname = analysis.get("filename", "log")
    total = analysis.get("total_records", 0)
    attacks = analysis.get("attacks_count", 0)
    benign = analysis.get("benign_count", 0)
    anomalous = analysis.get("anomalous_count", 0)
    dur = analysis.get("duration_sec", 0.0)
    labels = analysis.get("label_distribution", {})
    df = analysis.get("df", pd.DataFrame())

    # Header Card
    st.markdown(
        f"""
        <div style="display: flex; justify-content: space-between; align-items: center; background: {THEME['card_bg']}; border: 1px solid {THEME['border']}; border-radius: 12px; padding: 1rem 1.4rem; margin: 1.2rem 0;">
            <div>
                <span style="font-size: 0.75rem; color: {THEME['accent_cyan']}; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em;">
                    Security Analysis Complete
                </span>
                <div style="font-size: 1.3rem; font-weight: 800; color: {THEME['text_primary']};">
                    {fname}
                </div>
            </div>
            <div style="text-align: right;">
                <span style="font-size: 0.75rem; color: {THEME['text_muted']};">Execution Runtime</span>
                <div style="font-size: 1.1rem; font-weight: 700; color: {THEME['accent_cyan']}; font-family: 'JetBrains Mono', monospace;">
                    {dur:.2f}s
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # 4 Clean KPI Cards
    st.markdown(
        f"""
        <div class="rox-kpi-grid">
            <div class="rox-kpi-card">
                <div class="rox-kpi-label">TOTAL REQUESTS</div>
                <div class="rox-kpi-value">{total:,}</div>
                <div class="rox-kpi-sub">{analysis.get('unique_ips', 0)} unique client IPs</div>
            </div>
            <div class="rox-kpi-card">
                <div class="rox-kpi-label" style="color: {THEME['danger']};">ATTACKS</div>
                <div class="rox-kpi-value" style="color: {THEME['danger']};">{attacks:,}</div>
                <div class="rox-kpi-sub">Rule-based threat signatures</div>
            </div>
            <div class="rox-kpi-card">
                <div class="rox-kpi-label" style="color: {THEME['success']};">BENIGN</div>
                <div class="rox-kpi-value" style="color: {THEME['success']};">{benign:,}</div>
                <div class="rox-kpi-sub">Normal web access traffic</div>
            </div>
            <div class="rox-kpi-card">
                <div class="rox-kpi-label" style="color: {THEME['accent_cyan']};">ANOMALOUS</div>
                <div class="rox-kpi-value" style="color: {THEME['accent_cyan']};">{anomalous:,}</div>
                <div class="rox-kpi-sub">Isolation Forest deviance</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Threat Distribution Charts
    c_chart1, c_chart2 = st.columns(2)
    with c_chart1:
        fig_donut = plot_traffic_classification_donut(labels)
        if fig_donut:
            st.plotly_chart(fig_donut, use_container_width=True)
    with c_chart2:
        fig_bar = plot_threat_distribution_bar(labels)
        if fig_bar:
            st.plotly_chart(fig_bar, use_container_width=True)

    # Top Suspicious IPs Table
    top_ips = analysis.get("top_suspicious_ips", [])
    if top_ips:
        st.markdown(
            f"""
            <div style="font-size: 0.95rem; font-weight: 700; color: {THEME['text_primary']}; margin: 1.2rem 0 0.5rem 0;">
                TOP SUSPICIOUS CLIENT IPs
            </div>
            """,
            unsafe_allow_html=True
        )
        df_ips = pd.DataFrame(top_ips)
        st.dataframe(df_ips, use_container_width=True, hide_index=True)

    # Top Suspicious Requests Table
    req_df = analysis.get("top_suspicious_requests_df", pd.DataFrame())
    if not req_df.empty:
        st.markdown(
            f"""
            <div style="font-size: 0.95rem; font-weight: 700; color: {THEME['text_primary']}; margin: 1.4rem 0 0.5rem 0;">
                TOP SUSPICIOUS REQUESTS
            </div>
            """,
            unsafe_allow_html=True
        )
        st.dataframe(req_df, use_container_width=True, hide_index=True)

    # Feature Intelligence Collapsible Section
    feat_summary = analysis.get("feature_summary", {})
    with st.expander("🔍 FEATURE INTELLIGENCE", expanded=False):
        feat_count = feat_summary.get("total_engineered_features", 0)
        st.markdown(f"**Total Features Engineered**: `{feat_count}`")
        
        # Display Feature Groups
        groups = feat_summary.get("feature_groups", {})
        col_g1, col_g2 = st.columns(2)
        for idx, (grp_name, grp_feats) in enumerate(groups.items()):
            col_target = col_g1 if idx % 2 == 0 else col_g2
            with col_target:
                st.markdown(f"**{grp_name}** ({len(grp_feats)}):")
                st.caption(", ".join([f"`{f}`" for f in grp_feats]))

        # Feature Importance Chart
        imp_df = feat_summary.get("feature_importance", pd.DataFrame())
        if not imp_df.empty:
            fig_imp = plot_feature_importance_bar(imp_df, top_n=10)
            if fig_imp:
                st.plotly_chart(fig_imp, use_container_width=True)

        # Skipped Features Diagnostics
        skipped = feat_summary.get("skipped_features", [])
        if skipped:
            st.markdown("<div style='margin-top: 0.8rem;'></div>", unsafe_allow_html=True)
            for skip_msg in skipped:
                st.info(f"ℹ️ {skip_msg}")

    # Rox Offline Chat Section
    _render_rox_chat(analysis)

    # Export Downloads
    st.markdown("<div style='margin-top: 1.5rem;'></div>", unsafe_allow_html=True)
    c_dl1, c_dl2 = st.columns(2)
    csv_path = analysis.get("csv_path")
    parquet_path = analysis.get("parquet_path")

    with c_dl1:
        if csv_path and Path(csv_path).exists():
            with open(csv_path, "rb") as f:
                csv_bytes = f.read()
        else:
            csv_bytes = df.to_csv(index=False).encode("utf-8")

        st.download_button(
            label="💾 Download Analyzed CSV",
            data=csv_bytes,
            file_name=f"rox_analyzed_{Path(fname).stem}.csv",
            mime="text/csv",
            use_container_width=True,
        )

    with c_dl2:
        parquet_bytes = None
        if parquet_path and Path(parquet_path).exists():
            try:
                with open(parquet_path, "rb") as f:
                    parquet_bytes = f.read()
            except Exception:
                parquet_bytes = None
        elif not df.empty:
            try:
                parquet_buf = io.BytesIO()
                df.to_parquet(parquet_buf, index=False)
                parquet_bytes = parquet_buf.getvalue()
            except Exception:
                parquet_bytes = None

        if parquet_bytes is not None:
            st.download_button(
                label="📦 Download Analyzed Parquet (Compressed)",
                data=parquet_bytes,
                file_name=f"rox_analyzed_{Path(fname).stem}.parquet",
                mime="application/octet-stream",
                use_container_width=True,
            )
        else:
            st.caption("Parquet export not available.")


def _render_rox_chat(analysis: Dict[str, Any]):
    """Renders the fact-grounded Rox Chat Q&A interface."""
    st.markdown(
        f"""
        <div style="margin-top: 1.6rem; margin-bottom: 0.6rem; display: flex; align-items: center; gap: 0.6rem;">
            <span style="font-size: 1.1rem;">🤖</span>
            <span style="font-size: 1.05rem; font-weight: 700; color: {THEME['text_primary']};">
                ASK ROX (OFFLINE DETERMINISTIC Q&amp;A)
            </span>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Suggestion Chips
    st.caption("Suggested questions (click to ask Rox):")
    chips = [
        "What attacks were detected?",
        "Which IP is most suspicious?",
        "What was the most common attack?",
        "Which features were extracted?",
        "Show me the anomalous requests.",
        "Why was this request suspicious?",
    ]

    cols = st.columns(3)
    chosen_chip = None
    for i, chip_text in enumerate(chips):
        with cols[i % 3]:
            if st.button(chip_text, key=f"chip_{i}", use_container_width=True):
                chosen_chip = chip_text

    # Chat history display
    for msg in st.session_state.chat_history:
        if msg["role"] == "user":
            st.markdown(f'<div class="rox-chat-bubble-user"><strong>You:</strong> {msg["content"]}</div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="rox-chat-bubble-rox"><strong>🤖 Rox:</strong><br>{msg["content"]}</div>', unsafe_allow_html=True)

    # Chat Input
    user_input = st.chat_input("Ask Rox about this log analysis...") or chosen_chip
    if user_input:
        st.session_state.chat_history.append({"role": "user", "content": user_input})
        answer = ask_rox(user_input, analysis)
        st.session_state.chat_history.append({"role": "assistant", "content": answer})
        st.rerun()


def _execute_pipeline(file_bytes: bytes, filename: str, max_records: Optional[int] = None):
    """Executes the pipeline with visible, verified stage progress."""
    st.markdown(
        f"""
        <div style="background: {THEME['card_bg']}; border: 1px solid {THEME['accent_cyan']}; border-radius: 12px; padding: 1.2rem; margin: 1rem 0;">
            <div style="font-weight: 800; color: {THEME['text_primary']}; margin-bottom: 0.5rem;">
                ROX IS ANALYZING YOUR LOG: <code>{filename}</code>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    progress_bar = st.progress(0)
    status_label = st.empty()

    def update_cb(msg: str, pct: int):
        progress_bar.progress(pct)
        status_label.caption(f"⚙️ {msg} ({pct}%)")

    # Fast default ceiling of 100,000 records if file > 2MB to keep cloud execution within seconds
    if max_records is None and len(file_bytes) > 2 * 1024 * 1024:
        max_records = 100000

    pipeline = RoxPipeline(file_bytes, filename=filename, max_records=max_records)
    res = pipeline.run(progress_callback=update_cb)

    if res.get("status") == "SUCCESS" and res.get("total_records", 0) > 0:
        st.session_state.analysis_result = res
        st.session_state.analyzed_filename = filename
        st.session_state.chat_history = []
        throughput = int(res.get("total_records", 0) / max(0.01, res.get("duration_sec", 1.0)))
        st.toast(f"Analysis completed: {res.get('total_records', 0):,} records processed in {res.get('duration_sec', 0.0)}s!", icon="✅")
        st.rerun()
    else:
        err_msg = res.get("error", "No valid records could be parsed from this log.")
        st.session_state.analyzed_filename = ""
        st.error(f"Analysis halted: {err_msg}")
