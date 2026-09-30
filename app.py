"""app.py
Log Intelligence Platform — Master Application Entry Point
Production-grade dark cybersecurity analytics platform featuring:
- Practicals Explorer (Practicals 01 to 10)
- Rox Live Log Analysis Assistant
- Reusable Pipeline Visualizer
- Deep Security Analytics
"""

import sys
from pathlib import Path
import streamlit as st

# Ensure repository root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import THEME, PRACTICAL_INDEX
from src.gui.overview import render_overview_view
from src.gui.practicals import render_practicals_view
from src.gui.rox import render_rox_view
from src.gui.pipeline_view import render_pipeline_view
from src.gui.analytics import render_analytics_view


# Page Configuration
st.set_page_config(
    page_title="Rox — Log Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def load_dark_theme():
    """Injects the dark cybersecurity stylesheet."""
    css_path = PROJECT_ROOT / "assets" / "dark_theme.css"
    if css_path.exists():
        with open(css_path, "r", encoding="utf-8") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)


def init_state():
    """Initializes navigation and practical selection states."""
    if "nav_page" not in st.session_state:
        st.session_state.nav_page = "Overview"
    if "selected_practical_id" not in st.session_state:
        st.session_state.selected_practical_id = None


def main():
    """Master application controller."""
    load_dark_theme()
    init_state()

    # Sidebar
    with st.sidebar:
        # Rox Top Branding
        st.markdown(
            f"""
            <div style="display: flex; align-items: center; gap: 0.75rem; padding: 0.6rem 0 1.2rem 0; border-bottom: 1px solid rgba(255,255,255,0.08); margin-bottom: 1rem;">
                <div style="width: 38px; height: 38px; border-radius: 50%; background: linear-gradient(135deg, #6C63FF 0%, #00D9FF 100%); display: flex; align-items: center; justify-content: center; font-size: 1.2rem; box-shadow: 0 0 15px rgba(108, 99, 255, 0.4);">
                    🤖
                </div>
                <div>
                    <div style="font-size: 1.25rem; font-weight: 800; color: #FFFFFF; line-height: 1.1; letter-spacing: -0.01em;">
                        Rox
                    </div>
                    <div style="font-size: 0.75rem; color: {THEME['accent_cyan']}; font-weight: 600; letter-spacing: 0.05em; text-transform: uppercase;">
                        Log Intelligence
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # Primary Navigation
        nav_items = ["Overview", "Practicals", "Log Analyzer", "Pipeline", "Analytics"]
        current_nav = st.session_state.nav_page
        nav_idx = nav_items.index(current_nav) if current_nav in nav_items else 0

        selected = st.radio(
            "Navigation",
            options=nav_items,
            index=nav_idx,
            label_visibility="collapsed",
            key="main_nav_radio"
        )

        if selected != st.session_state.nav_page:
            st.session_state.nav_page = selected
            if selected != "Practicals":
                st.session_state.selected_practical_id = None
            st.rerun()

        # If on Practicals page and a practical is open, show quick jump
        if st.session_state.nav_page == "Practicals" and st.session_state.selected_practical_id is not None:
            st.markdown(
                f"<div style='font-size: 0.75rem; font-weight: 700; color: {THEME['text_muted']}; text-transform: uppercase; margin: 1.2rem 0 0.4rem 0;'>Jump to Practical:</div>",
                unsafe_allow_html=True
            )
            for p in PRACTICAL_INDEX:
                p_id = p["id"]
                is_curr = (st.session_state.selected_practical_id == p_id)
                prefix = "▶ " if is_curr else "  "
                if st.button(f"{prefix}{p['number_str']}", key=f"sb_jump_{p_id}", use_container_width=True):
                    st.session_state.selected_practical_id = p_id
                    st.rerun()

        # Sidebar Footer
        st.markdown(
            f"""
            <div style="margin-top: 3.5rem; padding-top: 1rem; border-top: 1px solid rgba(255,255,255,0.08); font-size: 0.75rem; color: {THEME['text_muted']};">
                <div style="font-weight: 700; color: {THEME['text_secondary']};">Rox • Log Intelligence</div>
                <div>Engine: Practical 10 Pipeline</div>
                <div style="color: {THEME['success']}; margin-top: 0.3rem;">● Threat Detection Active</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # Router Handlers
    def handle_navigate(page_name: str):
        st.session_state.nav_page = page_name
        st.session_state.selected_practical_id = None
        st.rerun()

    def handle_select_practical(p_id):
        st.session_state.nav_page = "Practicals"
        st.session_state.selected_practical_id = p_id
        st.rerun()

    # Main Area Router
    if st.session_state.nav_page == "Overview":
        render_overview_view(on_navigate=handle_navigate, on_select_practical=handle_select_practical)

    elif st.session_state.nav_page == "Practicals":
        render_practicals_view(
            selected_practical_id=st.session_state.selected_practical_id,
            on_select_practical=handle_select_practical
        )

    elif st.session_state.nav_page == "Log Analyzer":
        render_rox_view()

    elif st.session_state.nav_page == "Pipeline":
        render_pipeline_view()

    elif st.session_state.nav_page == "Analytics":
        render_analytics_view()


if __name__ == "__main__":
    main()
