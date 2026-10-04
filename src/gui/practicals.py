"""src/gui/practicals.py
Practical Story Explorer — Clean Visual Product Presentation
Displays the 10 practical stages (01 to 10) as compact cards.
Each card opens a concise view showing:
- AIM
- INPUT
- PROCESS
- METHODS / TOOLS
- RESULT
- OUTPUT EVIDENCE
- Real generated screenshots loaded via relative repository paths
"""

import json
from pathlib import Path
from typing import Dict, Any, Callable, Optional, List
import streamlit as st
from PIL import Image

from config import THEME, METADATA_DIR, ASSETS_DIR
from utils.data_loader import get_all_practical_plots


@st.cache_data(show_spinner=False)
def load_practicals_metadata() -> List[Dict[str, Any]]:
    """Loads factual metadata from metadata/practicals.json."""
    meta_path = METADATA_DIR / "practicals.json"
    if meta_path.exists():
        with open(meta_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


def render_practicals_view(
    selected_practical_id: Optional[int],
    on_select_practical: Callable[[Optional[int]], None],
):
    """Renders either the 10 practical cards or the selected practical detail view."""
    practicals = load_practicals_metadata()

    if selected_practical_id is not None:
        p_data = next((p for p in practicals if p["id"] == selected_practical_id), None)
        if p_data:
            _render_practical_detail(p_data, on_back=lambda: on_select_practical(None))
        else:
            on_select_practical(None)
    else:
        _render_practicals_grid(practicals, on_open=on_select_practical)


def _render_practicals_grid(practicals: List[Dict[str, Any]], on_open: Callable[[int], None]):
    """Renders the 10 practical cards in a clean, compact 2-column grid."""
    st.markdown(
        f"""
        <div style="margin-bottom: 1.5rem;">
            <div style="font-size: 0.75rem; font-weight: 700; color: {THEME['accent_cyan']}; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 0.3rem;">
                Empirical Implementation Story
            </div>
            <h1 style="font-size: 2rem; font-weight: 800; color: {THEME['text_primary']}; margin: 0 0 0.4rem 0;">
                Practical Story (P01 → P10)
            </h1>
            <div style="font-size: 0.95rem; color: {THEME['text_secondary']};">
                Explore the verified data transformations, algorithms, metrics, and evidence from the 10 laboratory practicals.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    cols = st.columns(2)
    for idx, p in enumerate(practicals):
        with cols[idx % 2]:
            p_id = p["id"]
            num_str = p["number_str"]
            short_t = p.get("short_title", p["title"])
            aim = p.get("aim", "")

            st.markdown(
                f"""
                <div class="rox-practical-card">
                    <span class="rox-practical-badge">{num_str}</span>
                    <div class="rox-practical-title">{short_t}</div>
                    <div class="rox-practical-desc">{aim[:140]}...</div>
                </div>
                """,
                unsafe_allow_html=True
            )
            if st.button(f"View {num_str} Details →", key=f"btn_p_{p_id}", use_container_width=True):
                on_open(p_id)
                st.rerun()
            st.write("")


def _render_practical_detail(p: Dict[str, Any], on_back: Callable[[], None]):
    """Renders the concise, structured view for a practical."""
    p_id = p["id"]
    num_str = p["number_str"]
    title = p["title"]

    # Back Button
    if st.button("← Back to All Practicals", key="btn_back_p"):
        on_back()
        st.rerun()

    st.markdown(
        f"""
        <div style="background: {THEME['card_bg']}; border: 1px solid {THEME['border']}; border-radius: 12px; padding: 1.4rem 1.6rem; margin: 0.8rem 0 1.5rem 0;">
            <span class="rox-practical-badge">{num_str}</span>
            <h2 style="font-size: 1.6rem; font-weight: 800; color: {THEME['text_primary']}; margin: 0.2rem 0 0.4rem 0;">
                {title}
            </h2>
        </div>
        """,
        unsafe_allow_html=True
    )

    # 6 Section Structure: AIM, INPUT, PROCESS, METHODS/TOOLS, RESULT, OUTPUT EVIDENCE
    col_left, col_right = st.columns([1, 1])

    with col_left:
        # AIM
        st.markdown(
            f"""
            <div class="rox-card" style="padding: 1.2rem;">
                <div style="font-size: 0.75rem; font-weight: 700; color: {THEME['accent_cyan']}; text-transform: uppercase;">1. AIM</div>
                <div style="font-size: 0.9rem; color: {THEME['text_primary']}; margin-top: 0.3rem; line-height: 1.5;">{p.get('aim', 'N/A')}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # INPUT
        st.markdown(
            f"""
            <div class="rox-card" style="padding: 1.2rem;">
                <div style="font-size: 0.75rem; font-weight: 700; color: {THEME['accent_cyan']}; text-transform: uppercase;">2. INPUT DATA</div>
                <div style="font-size: 0.9rem; color: {THEME['text_primary']}; margin-top: 0.3rem; line-height: 1.5;">{p.get('input', 'N/A')}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # PROCESS
        st.markdown(
            f"""
            <div class="rox-card" style="padding: 1.2rem;">
                <div style="font-size: 0.75rem; font-weight: 700; color: {THEME['accent_cyan']}; text-transform: uppercase;">3. PROCESS / WORKFLOW</div>
                <div style="font-size: 0.9rem; color: {THEME['text_primary']}; margin-top: 0.3rem; line-height: 1.5;">{p.get('process', 'N/A')}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col_right:
        # METHODS / TOOLS
        st.markdown(
            f"""
            <div class="rox-card" style="padding: 1.2rem;">
                <div style="font-size: 0.75rem; font-weight: 700; color: {THEME['accent_cyan']}; text-transform: uppercase;">4. METHODS &amp; TOOLS</div>
                <div style="font-size: 0.9rem; color: {THEME['text_primary']}; margin-top: 0.3rem; line-height: 1.5;">{p.get('methods_tools', 'N/A')}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # RESULT
        st.markdown(
            f"""
            <div class="rox-card" style="padding: 1.2rem;">
                <div style="font-size: 0.75rem; font-weight: 700; color: {THEME['accent_cyan']}; text-transform: uppercase;">5. RESULTS &amp; KEY NUMBERS</div>
                <div style="font-size: 0.9rem; color: {THEME['text_primary']}; margin-top: 0.3rem; line-height: 1.5;">{p.get('result', 'N/A')}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # OUTPUT EVIDENCE
        st.markdown(
            f"""
            <div class="rox-card" style="padding: 1.2rem;">
                <div style="font-size: 0.75rem; font-weight: 700; color: {THEME['accent_cyan']}; text-transform: uppercase;">6. OUTPUT EVIDENCE</div>
                <div style="font-size: 0.9rem; color: {THEME['text_primary']}; margin-top: 0.3rem; line-height: 1.5;"><code>{p.get('output_evidence', 'N/A')}</code></div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # Key Metrics KPI Table
    metrics = p.get("metrics", {})
    if metrics:
        st.markdown(
            f"""
            <div style="font-size: 0.95rem; font-weight: 700; color: {THEME['text_primary']}; margin: 1rem 0 0.5rem 0;">
                EMPIRICAL METRICS (VERIFIED FROM CODE ARTIFACTS)
            </div>
            """,
            unsafe_allow_html=True
        )
        metric_cols = st.columns(min(len(metrics), 4))
        for idx, (label, val) in enumerate(metrics.items()):
            target_col = metric_cols[idx % len(metric_cols)]
            with target_col:
                st.markdown(
                    f"""
                    <div style="background: {THEME['card_elevated']}; border: 1px solid {THEME['border']}; border-radius: 8px; padding: 0.75rem 1rem; margin-bottom: 0.6rem;">
                        <div style="font-size: 0.72rem; color: {THEME['text_secondary']}; text-transform: uppercase;">{label}</div>
                        <div style="font-size: 1.15rem; font-weight: 800; color: {THEME['accent_cyan']}; font-family: 'JetBrains Mono', monospace;">{val}</div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

    # Actual Screenshots from Deployed Assets
    plots = get_all_practical_plots(p_id)
    if plots:
        st.markdown(
            f"""
            <div style="font-size: 0.95rem; font-weight: 700; color: {THEME['text_primary']}; margin: 1.5rem 0 0.6rem 0;">
                ACTUAL GENERATED VISUALIZATIONS &amp; EVIDENCE ({len(plots)} PLOTS)
            </div>
            """,
            unsafe_allow_html=True
        )

        for plot_info in plots:
            p_path = plot_info["path"]
            p_title = plot_info["title"]
            try:
                img = Image.open(p_path)
                st.image(img, caption=f"{p_title} ({plot_info['size_str']})", use_container_width=True)
            except Exception:
                pass
    else:
        st.caption("No screenshot plots generated for this practical.")
