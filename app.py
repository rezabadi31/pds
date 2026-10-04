"""app.py
ROX — Log Intelligence Platform
Clean, error-free, Streamlit-deployable Master Entry Point.
Fully portable across Local Streamlit and Streamlit Community Cloud without absolute paths.
"""

import sys
from pathlib import Path
import streamlit as st

# Ensure repository root is on sys.path portably
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import THEME, PRACTICAL_INDEX
from src.gui.overview import render_overview_view
from src.gui.rox import render_rox_view
from src.gui.practicals import render_practicals_view
from src.gui.pipeline_view import render_pipeline_view


# Page Configuration
st.set_page_config(
    page_title="ROX — Log Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def load_stylesheet():
    """Injects the dark cybersecurity stylesheet portably."""
    css_path = PROJECT_ROOT / "assets" / "dark_theme.css"
    if css_path.exists():
        with open(css_path, "r", encoding="utf-8") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)


def init_session_state():
    """Initializes router and session state."""
    if "nav_page" not in st.session_state:
        st.session_state.nav_page = "Overview"
    if "selected_practical_id" not in st.session_state:
        st.session_state.selected_practical_id = None
    if "sessions_history" not in st.session_state:
        st.session_state.sessions_history = []


def main():
    """Main application controller."""
    load_stylesheet()
    init_session_state()

    # -------------------------------------------------------------
    # SIDEBAR — FOLLOW REFERENCE IMAGE
    # -------------------------------------------------------------
    with st.sidebar:
        # Top Branding
        st.markdown(
            f"""
            <div style="display: flex; align-items: center; gap: 0.75rem; padding: 0.5rem 0 1.2rem 0; border-bottom: 1px solid rgba(120, 180, 255, 0.12); margin-bottom: 1rem;">
                <div style="width: 38px; height: 38px; border-radius: 50%; background: linear-gradient(135deg, #1687FF 0%, #22D3EE 100%); display: flex; align-items: center; justify-content: center; font-size: 1.25rem;">
                    🤖
                </div>
                <div>
                    <div style="font-size: 1.25rem; font-weight: 800; color: #FFFFFF; line-height: 1.1; letter-spacing: -0.01em;">
                        ROX
                    </div>
                    <div style="font-size: 0.72rem; color: {THEME['accent_cyan']}; font-weight: 600; letter-spacing: 0.05em; text-transform: uppercase;">
                        Log Intelligence
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # "+ New Analysis" Action
        if st.button("＋ New Analysis", key="btn_sb_new_analysis", use_container_width=True, type="primary"):
            st.session_state.nav_page = "ROX"
            st.session_state.analysis_result = None
            st.session_state.current_file_bytes = None
            st.session_state.current_filename = ""
            st.session_state.chat_history = []
            st.rerun()

        st.markdown("<div style='height: 0.8rem;'></div>", unsafe_allow_html=True)

        # Primary Navigation
        nav_options = ["⌂ Overview", "🤖 ROX (Live Analyzer)", "▣ Practicals", "◇ Pipeline"]
        nav_keys = {
            "⌂ Overview": "Overview",
            "🤖 ROX (Live Analyzer)": "ROX",
            "▣ Practicals": "Practicals",
            "◇ Pipeline": "Pipeline",
        }
        reverse_keys = {v: k for k, v in nav_keys.items()}

        current_nav_display = reverse_keys.get(st.session_state.nav_page, "⌂ Overview")
        current_idx = nav_options.index(current_nav_display) if current_nav_display in nav_options else 0

        selected_nav = st.radio(
            "Navigation",
            options=nav_options,
            index=current_idx,
            label_visibility="collapsed",
            key="sb_nav_radio",
        )

        target_page = nav_keys.get(selected_nav, "Overview")
        if target_page != st.session_state.nav_page:
            st.session_state.nav_page = target_page
            if target_page != "Practicals":
                st.session_state.selected_practical_id = None
            st.rerun()

        # If on Practicals page and a practical is open, show quick jump
        if st.session_state.nav_page == "Practicals" and st.session_state.selected_practical_id is not None:
            st.markdown(
                f"<div style='font-size: 0.72rem; font-weight: 700; color: {THEME['text_secondary']}; text-transform: uppercase; margin: 1.5rem 0 0.5rem 0;'>Jump to Practical:</div>",
                unsafe_allow_html=True
            )
            for p in PRACTICAL_INDEX:
                p_id = p["id"]
                is_curr = (st.session_state.selected_practical_id == p_id)
                prefix = "▶ " if is_curr else "  "
                if st.button(f"{prefix}{p['number_str']}", key=f"sb_jump_{p_id}", use_container_width=True):
                    st.session_state.selected_practical_id = p_id
                    st.rerun()

        # Saved Log Sessions in current runtime session
        current_file = st.session_state.get("current_filename", "")
        if current_file:
            st.markdown(
                f"""
                <div style="font-size: 0.72rem; font-weight: 700; color: {THEME['text_secondary']}; text-transform: uppercase; margin: 1.5rem 0 0.4rem 0;">
                    Active Session:
                </div>
                <div style="background: {THEME['card_elevated']}; border: 1px solid {THEME['border']}; border-radius: 6px; padding: 0.4rem 0.7rem; font-size: 0.78rem; color: {THEME['accent_cyan']}; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                    📄 {current_file}
                </div>
                """,
                unsafe_allow_html=True
            )

        # Sidebar Bottom Footer
        st.markdown(
            f"""
            <div style="margin-top: 4rem; padding-top: 1rem; border-top: 1px solid rgba(120, 180, 255, 0.12); font-size: 0.75rem; color: {THEME['text_secondary']};">
                <div style="font-weight: 700; color: {THEME['text_primary']};">Pipeline Status</div>
                <div style="color: {THEME['success']}; margin-top: 0.2rem; font-weight: 600;">● Ready</div>
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
        render_overview_view(on_navigate=handle_navigate)

    elif st.session_state.nav_page == "ROX":
        render_rox_view()

    elif st.session_state.nav_page == "Practicals":
        render_practicals_view(
            selected_practical_id=st.session_state.selected_practical_id,
            on_select_practical=handle_select_practical
        )

    elif st.session_state.nav_page == "Pipeline":
        render_pipeline_view()


if __name__ == "__main__":
    main()
