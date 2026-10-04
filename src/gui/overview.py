"""src/gui/overview.py
Rox — Clean Minimal Overview Landing Screen
Designed with a focused welcome card, clear value proposition, and two prominent actions.
"""

from typing import Callable
import streamlit as st
from config import THEME


def render_overview_view(on_navigate: Callable[[str], None]):
    """Renders the ultra-clean, modern Rox landing screen."""

    # Centered Welcome Card
    st.markdown(
        f"""
        <div class="rox-welcome-card">
            <div class="rox-welcome-icon">🛡️</div>
            <div class="rox-welcome-title">ROX</div>
            <div class="rox-welcome-tagline">Your log analysis assistant.</div>
            <div class="rox-welcome-desc">
                Upload a web access log and analyze traffic, attacks, behavioral features,
                and anomalies through the reusable pipeline.
            </div>
            <div style="display: flex; gap: 0.6rem; justify-content: center; flex-wrap: wrap; margin-bottom: 2rem;">
                <span class="rox-badge-status">● Pipeline Ready</span>
                <span style="font-size: 0.75rem; color: {THEME['text_secondary']}; background: {THEME['card_elevated']}; padding: 0.25rem 0.65rem; border-radius: 9999px; border: 1px solid {THEME['border']};">
                    Multi-Format Support: .LOG · .TXT · .CSV · .JSON
                </span>
                <span style="font-size: 0.75rem; color: {THEME['text_secondary']}; background: {THEME['card_elevated']}; padding: 0.25rem 0.65rem; border-radius: 9999px; border: 1px solid {THEME['border']};">
                    Isolation Forest Anomaly Detection
                </span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Two Large Action Buttons
    col_left, col_btn1, col_btn2, col_right = st.columns([1, 2, 2, 1])

    with col_btn1:
        if st.button("▣ Explore Practicals", use_container_width=True, type="secondary"):
            on_navigate("Practicals")

    with col_btn2:
        if st.button("↑ Analyze a Log", use_container_width=True, type="primary"):
            on_navigate("ROX")

    st.write("")
    st.write("")

    # Three Clean Feature Pillars
    col_p1, col_p2, col_p3 = st.columns(3)
    with col_p1:
        st.markdown(
            f"""
            <div class="rox-card" style="padding: 1.3rem;">
                <div style="font-size: 1.3rem; margin-bottom: 0.5rem;">📥</div>
                <div style="font-size: 0.95rem; font-weight: 700; color: {THEME['text_primary']}; margin-bottom: 0.3rem;">
                    Universal Log Ingestion
                </div>
                <div style="font-size: 0.82rem; color: {THEME['text_secondary']}; line-height: 1.5;">
                    Automatically parses raw honeypot arrays, Apache/Nginx Combined logs, and arbitrary CSV telemetry into a canonical schema.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col_p2:
        st.markdown(
            f"""
            <div class="rox-card" style="padding: 1.3rem;">
                <div style="font-size: 1.3rem; margin-bottom: 0.5rem;">⚙️</div>
                <div style="font-size: 0.95rem; font-weight: 700; color: {THEME['text_primary']}; margin-bottom: 0.3rem;">
                    Multi-Domain Features
                </div>
                <div style="font-size: 0.82rem; color: {THEME['text_secondary']}; line-height: 1.5;">
                    Extracts behavioral rates, inter-request intervals, URL Shannon entropy, Featuretools relational aggregations, and tsfresh dynamics.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col_p3:
        st.markdown(
            f"""
            <div class="rox-card" style="padding: 1.3rem;">
                <div style="font-size: 1.3rem; margin-bottom: 0.5rem;">🤖</div>
                <div style="font-size: 0.95rem; font-weight: 700; color: {THEME['text_primary']}; margin-bottom: 0.3rem;">
                    Offline Rox Intelligence
                </div>
                <div style="font-size: 0.82rem; color: {THEME['text_secondary']}; line-height: 1.5;">
                    Ask Rox natural questions regarding detected threats, top suspicious IPs, and anomalous requests. 100% deterministic with zero API keys.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
