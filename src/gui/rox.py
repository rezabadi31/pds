"""src/gui/rox.py
Rox — Live Log Analysis Assistant
Integrated AI assistant running the Practical 10 reusable pipeline on uploaded logs (.log, .txt, .csv),
displaying traffic classifications, suspicious behavior, feature inspection, chat Q&A, and downloads.
"""

import json
from pathlib import Path
import streamlit as st
import pandas as pd
from typing import Dict, Any

from config import THEME
from src.pipeline.pipeline_runner import RoxLogAnalyzer, ask_rox
from src.gui.charts import plot_traffic_classification_donut


def render_rox_view():
    """Renders the Rox Log Analysis Assistant page."""

    # Rox Header
    st.markdown(
        f"""
        <div class="rox-header-card">
            <div class="rox-avatar-circle">🤖</div>
            <div>
                <div style="font-size: 0.8rem; font-weight: 700; color: {THEME['accent_cyan']}; letter-spacing: 0.15em; text-transform: uppercase;">
                    Security Intelligence Engine
                </div>
                <h1 style="font-size: 2.2rem; font-weight: 800; color: #FFFFFF; margin: 0.1rem 0 0.3rem 0;">
                    Rox — Live Log Analysis Assistant
                </h1>
                <div style="font-size: 0.95rem; color: {THEME['text_secondary']};">
                    Upload new server logs to execute the automated 7-stage pipeline. Rox extracts features, classifies threats, and answers forensic questions.
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Initialize Session State for Rox
    if "rox_analysis" not in st.session_state:
        st.session_state.rox_analysis = None
    if "rox_messages" not in st.session_state:
        st.session_state.rox_messages = []

    # Upload Section Container
    with st.container():
        st.markdown(
            f"""
            <div class="detail-section">
                <div class="detail-section-title">
                    <span>📤</span> UPLOAD LOG TELEMETRY FOR ANALYSIS
                </div>
            """,
            unsafe_allow_html=True
        )

        col_up, col_demo = st.columns([3, 1])
        with col_up:
            uploaded_file = st.file_uploader(
                "Choose a server access log file (.log, .txt, .csv):",
                type=["log", "txt", "csv"],
                key="rox_uploader",
                help="Supported formats: Honeypot JSON logs (.log), Common/Combined Access Logs (.txt), Structured Logs (.csv)"
            )

        with col_demo:
            st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
            use_demo = st.button("⚡ Load Demo Honeypot Log", key="btn_load_demo", use_container_width=True)

        target_file = uploaded_file
        filename = uploaded_file.name if uploaded_file else ""

        # Handle demo file loading
        if use_demo:
            demo_path = Path("data/sample_honeypot.log")
            if demo_path.exists():
                with open(demo_path, "rb") as df_in:
                    import io
                    target_file = io.BytesIO(df_in.read())
                    filename = "sample_honeypot.log"
                st.toast("Loaded sample_honeypot.log (50 real honeypot connections)", icon="📥")
            else:
                st.warning("Demo file not found.")

        if target_file and filename:
            file_bytes = target_file.getvalue() if hasattr(target_file, "getvalue") else target_file.read()
            if hasattr(target_file, "seek"):
                target_file.seek(0)

            size_kb = len(file_bytes) / 1024
            ext = Path(filename).suffix.lower()

            st.markdown(
                f"""
                <div style="display: flex; gap: 1.5rem; background: #10151F; border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 0.9rem 1.2rem; margin: 1rem 0;">
                    <div><span style="color: {THEME['text_muted']}; font-size: 0.75rem; text-transform: uppercase;">File</span><br><strong>{filename}</strong></div>
                    <div><span style="color: {THEME['text_muted']}; font-size: 0.75rem; text-transform: uppercase;">Size</span><br><strong>{size_kb:.1f} KB</strong></div>
                    <div><span style="color: {THEME['text_muted']}; font-size: 0.75rem; text-transform: uppercase;">Format</span><br><strong>{ext.upper()}</strong></div>
                    <div><span style="color: {THEME['text_muted']}; font-size: 0.75rem; text-transform: uppercase;">Status</span><br><span style="color: {THEME['accent_cyan']}; font-weight: bold;">● READY TO ANALYZE</span></div>
                </div>
                """,
                unsafe_allow_html=True
            )

            # Analyze Button
            if st.button("🚀 Analyze with Rox", type="primary", key="btn_run_rox", use_container_width=True):
                with st.spinner("Rox is processing your logs through the Practical 10 Reusable Pipeline..."):
                    analyzer = RoxLogAnalyzer(target_file, filename=filename)
                    analysis = analyzer.run_analysis()
                    st.session_state.rox_analysis = analysis
                    st.session_state.rox_messages = [
                        {
                            "sender": "Rox",
                            "text": (
                                f"I completed analyzing `{filename}` using the Practical 10 pipeline. "
                                f"Processed **{analysis['total_records']:,} requests** across **{analysis['unique_ips']} client IPs** in **{analysis['duration_sec']}s**.\n\n"
                                f"Detected **{analysis['attack_count']:,} attack events** ({analysis['attack_percentage']}% of traffic). "
                                f"Review the classification breakdown below or ask me any question!"
                            )
                        }
                    ]
                st.success("Analysis complete!")
                st.rerun()

        st.markdown("</div>", unsafe_allow_html=True)

    # Display Analysis Dashboard if available
    analysis = st.session_state.rox_analysis
    if analysis and analysis.get("status") == "SUCCESS":
        st.markdown("---")

        # 1. High-Level Metrics Strip
        m1, m2, m3, m4, m5 = st.columns(5)
        with m1:
            st.metric("Total Records", f"{analysis['total_records']:,}")
        with m2:
            st.metric("Unique Client IPs", f"{analysis['unique_ips']:,}")
        with m3:
            st.metric("Total Attacks", f"{analysis['attack_count']:,}", f"{analysis['attack_percentage']}%")
        with m4:
            st.metric("Features Extracted", f"{analysis['total_columns']}")
        with m5:
            st.metric("Processing Time", f"{analysis['duration_sec']}s")

        # 2. Traffic Classification & Suspicious Activity
        c_left, c_right = st.columns([1, 1])

        with c_left:
            st.markdown(
                f"""
                <div class="detail-section">
                    <div class="detail-section-title">
                        <span>📊</span> TRAFFIC CLASSIFICATION BREAKDOWN
                    </div>
                """,
                unsafe_allow_html=True
            )
            st.plotly_chart(plot_traffic_classification_donut(analysis["label_counts"]), use_container_width=True)

            # Class count table
            table_data = [
                {"Category": k, "Count": f"{v:,}", "Share": f"{(v / analysis['total_records']) * 100:.2f}%"}
                for k, v in analysis["label_counts"].items()
            ]
            st.dataframe(pd.DataFrame(table_data), use_container_width=True, hide_index=True)
            st.markdown("</div>", unsafe_allow_html=True)

        with c_right:
            st.markdown(
                f"""
                <div class="detail-section">
                    <div class="detail-section-title">
                        <span>🚨</span> SUSPICIOUS ACTIVITY &amp; THREAT SIGNALS
                    </div>
                """,
                unsafe_allow_html=True
            )

            # Top Attacking IPs
            top_ips = analysis.get("top_attack_ips", [])
            if top_ips:
                st.markdown("**Top Attacking Hosts:**")
                st.dataframe(pd.DataFrame(top_ips), use_container_width=True, hide_index=True)
            else:
                st.markdown(f"<span style='color: {THEME['success']};'>● No malicious attack IPs identified.</span>", unsafe_allow_html=True)

            # High Entropy URLs
            entropy_urls = analysis.get("high_entropy_urls", [])
            if entropy_urls:
                st.markdown("**High-Entropy Resource Paths (Obfuscation Signal):**")
                st.dataframe(pd.DataFrame(entropy_urls), use_container_width=True, hide_index=True)

            # Burst IPs
            burst = analysis.get("burst_ips", [])
            if burst:
                st.markdown("**High Request-Rate IPs (Burst Traffic):**")
                st.dataframe(pd.DataFrame(burst), use_container_width=True, hide_index=True)

            st.markdown("</div>", unsafe_allow_html=True)

        # 3. Engineered Features Inspector
        df = analysis.get("df")
        if df is not None:
            with st.expander("🔍 Inspect Engineered Feature Matrix (Top 50 Rows)", expanded=False):
                st.dataframe(df.head(50), use_container_width=True)

        # 4. Downloads
        c_dl1, c_dl2, c_dl3 = st.columns(3)
        with c_dl1:
            csv_path = analysis.get("csv_path")
            if csv_path and Path(csv_path).exists():
                with open(csv_path, "rb") as f_csv:
                    st.download_button(
                        "📥 Download Processed CSV",
                        data=f_csv.read(),
                        file_name=f"processed_{analysis['filename']}.csv",
                        mime="text/csv",
                        use_container_width=True,
                    )
        with c_dl2:
            pq_path = analysis.get("parquet_path")
            if pq_path and Path(pq_path).exists():
                with open(pq_path, "rb") as f_pq:
                    st.download_button(
                        "⚡ Download Parquet",
                        data=f_pq.read(),
                        file_name=f"processed_{Path(analysis['filename']).stem}.parquet",
                        mime="application/octet-stream",
                        use_container_width=True,
                    )
        with c_dl3:
            summary_dict = {
                "file": analysis["filename"],
                "records": analysis["total_records"],
                "attack_count": analysis["attack_count"],
                "label_counts": analysis["label_counts"],
                "unique_ips": analysis["unique_ips"],
                "time_range": analysis["time_range"],
                "runtime_sec": analysis["duration_sec"],
            }
            st.download_button(
                "📋 Download Analysis Summary",
                data=json.dumps(summary_dict, indent=2),
                file_name=f"summary_{Path(analysis['filename']).stem}.json",
                mime="application/json",
                use_container_width=True,
            )

        st.markdown("---")

        # 5. ROX CHAT INTERFACE
        st.markdown(
            f"""
            <div class="detail-section">
                <div class="detail-section-title">
                    <span>💬</span> CONVERSATIONAL LOG INTELLIGENCE WITH ROX
                </div>
            """,
            unsafe_allow_html=True
        )

        # Quick Prompt Chips
        st.markdown("<span style='font-size: 0.82rem; color: #A7B0BE;'>Quick Questions for Rox:</span>", unsafe_allow_html=True)
        col_q1, col_q2, col_q3 = st.columns(3)
        with col_q1:
            if st.button("❓ What attacks were detected?", key="q_attacks", use_container_width=True):
                st.session_state.rox_messages.append({"sender": "You", "text": "What attacks were detected?"})
                st.session_state.rox_messages.append({"sender": "Rox", "text": ask_rox("What attacks were detected?", analysis)})
                st.rerun()
            if st.button("❓ Which IP is most suspicious?", key="q_top_ip", use_container_width=True):
                st.session_state.rox_messages.append({"sender": "You", "text": "Which IP generated the most suspicious requests?"})
                st.session_state.rox_messages.append({"sender": "Rox", "text": ask_rox("Which IP generated the most suspicious requests?", analysis)})
                st.rerun()

        with col_q2:
            if st.button("❓ What was the most common attack?", key="q_common", use_container_width=True):
                st.session_state.rox_messages.append({"sender": "You", "text": "What was the most common attack?"})
                st.session_state.rox_messages.append({"sender": "Rox", "text": ask_rox("What was the most common attack?", analysis)})
                st.rerun()
            if st.button("❓ Why were requests flagged?", key="q_reason", use_container_width=True):
                st.session_state.rox_messages.append({"sender": "You", "text": "Why was this request classified as suspicious?"})
                st.session_state.rox_messages.append({"sender": "Rox", "text": ask_rox("Why was this request classified as suspicious?", analysis)})
                st.rerun()

        with col_q3:
            if st.button("❓ What features were extracted?", key="q_features", use_container_width=True):
                st.session_state.rox_messages.append({"sender": "You", "text": "What features were extracted?"})
                st.session_state.rox_messages.append({"sender": "Rox", "text": ask_rox("What features were extracted?", analysis)})
                st.rerun()
            if st.button("❓ Show top attacking IPs", key="q_show_ips", use_container_width=True):
                st.session_state.rox_messages.append({"sender": "You", "text": "Show me the top attacking IPs."})
                st.session_state.rox_messages.append({"sender": "Rox", "text": ask_rox("Show me the top attacking IPs.", analysis)})
                st.rerun()

        st.write("")

        # Message History
        for msg in st.session_state.rox_messages:
            if msg["sender"] == "Rox":
                st.markdown(
                    f"""
                    <div style="display: flex; gap: 0.8rem; margin-bottom: 0.8rem;">
                        <div style="width: 36px; height: 36px; border-radius: 50%; background: #6C63FF; display: flex; align-items: center; justify-content: center; font-size: 1.1rem; flex-shrink: 0;">🤖</div>
                        <div class="rox-bubble">
                            <div style="font-weight: 700; color: {THEME['accent_cyan']}; font-size: 0.82rem; margin-bottom: 0.3rem;">Rox</div>
                            <div>{msg['text'].replace('\n', '<br>')}</div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            else:
                st.markdown(
                    f"""
                    <div class="user-bubble">
                        <div style="font-weight: 700; color: #FFFFFF; font-size: 0.82rem; margin-bottom: 0.2rem;">You</div>
                        <div>{msg['text']}</div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

        # User Text Input
        with st.form("rox_chat_form", clear_on_submit=True):
            user_input = st.text_input("Ask Rox anything about your uploaded log file...", placeholder="e.g. Which IP made the most requests?")
            col_send1, col_send2 = st.columns([5, 1])
            with col_send2:
                submitted = st.form_submit_button("Send →", use_container_width=True)

            if submitted and user_input.strip():
                st.session_state.rox_messages.append({"sender": "You", "text": user_input})
                response = ask_rox(user_input, analysis)
                st.session_state.rox_messages.append({"sender": "Rox", "text": response})
                st.rerun()

        st.markdown("</div>", unsafe_allow_html=True)
