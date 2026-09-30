"""src/gui/practicals.py
Practicals Explorer View — Product Style
Presents the 10 interactive practical cards and the detailed product-style view:
AIM, INPUT, PROCESS, TECHNIQUES / TOOLS, ALGORITHM / METHOD, OBSERVATION, OUTPUT with real charts.
"""

from pathlib import Path
from typing import Dict, Any, Callable, Optional
import streamlit as st
import pandas as pd
from PIL import Image

from config import THEME, PRACTICAL_INDEX
from utils.practicals_data import PRACTICALS_DATA
from utils.data_loader import (
    read_text_file,
    load_csv_preview,
    load_parquet_preview,
    get_file_info,
    load_image,
    get_all_practical_plots,
    resolve_file_path,
)
from src.gui.charts import (
    plot_class_distribution_dark,
    plot_balancing_comparison_dark,
    plot_model_comparison_experiments_dark,
    plot_feature_importance_dark,
    plot_pipeline_stage_durations_dark,
)


def render_practicals_view(
    selected_practical_id: Optional[int],
    on_select_practical: Callable[[Optional[int]], None]
):
    """Renders either the 10-card practicals grid or a selected practical's detail view."""
    
    if selected_practical_id is not None:
        render_practical_detail(selected_practical_id, on_back=lambda: on_select_practical(None))
    else:
        render_practicals_grid(on_open=on_select_practical)


def render_practicals_grid(on_open: Callable[[int], None]):
    """Renders the 10 interactive practical cards in a responsive dark-themed grid."""
    
    st.markdown(
        f"""
        <div style="margin-bottom: 1.5rem;">
            <div class="product-hero-eyebrow">
                <span>📚</span> Laboratory Implementation &amp; Analytics Portfolio
            </div>
            <h1 style="font-size: 2.2rem; font-weight: 800; color: #FFFFFF; margin: 0.2rem 0 0.5rem 0;">
                Practicals Explorer
            </h1>
            <div style="font-size: 1.05rem; color: {THEME['text_secondary']}; line-height: 1.5;">
                Explore the actual implementations, data transformations, algorithms, and generated outputs across Practicals 1 to 10.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Render cards in 2 columns
    cols_per_row = 2
    rows = [PRACTICAL_INDEX[i:i + cols_per_row] for i in range(0, len(PRACTICAL_INDEX), cols_per_row)]

    for row in rows:
        cols = st.columns(cols_per_row)
        for idx, practical in enumerate(row):
            with cols[idx]:
                p_id = practical["id"]
                num_str = practical["number_str"]
                title = practical["title"]
                one_liner = practical["one_liner"]
                icon = practical["icon"]
                stage = practical["stage"]
                badge_color = practical.get("badge_color", THEME["accent"])

                card_html = f"""
                <div class="product-card">
                    <div class="product-card-top">
                        <span class="product-pill" style="color: {badge_color}; border-color: {badge_color}40; background: {badge_color}15;">
                            {num_str} • {stage}
                        </span>
                        <span class="status-badge-completed">VERIFIED</span>
                    </div>
                    <div class="product-card-title">{icon} {title}</div>
                    <div class="product-card-desc">{one_liner}</div>
                </div>
                """
                st.markdown(card_html, unsafe_allow_html=True)
                if st.button(f"Open {num_str} →", key=f"btn_open_{p_id}", use_container_width=True):
                    on_open(p_id)
                    st.rerun()
                st.write("")


def render_practical_detail(practical_id: int, on_back: Callable[[], None]):
    """Renders the detailed product-style practical view."""
    p_data = PRACTICALS_DATA.get(practical_id)
    if not p_data:
        st.error(f"Practical {practical_id} metadata not found.")
        if st.button("← Back to Practicals"):
            on_back()
        return

    # Top Navigation Row
    top_col1, top_col2 = st.columns([1, 4])
    with top_col1:
        if st.button("← Back to Practicals", key="btn_back_detail"):
            on_back()
            st.rerun()

    # Practical Header
    st.markdown(
        f"""
        <div style="margin-top: 0.6rem; margin-bottom: 1.5rem;">
            <div style="font-size: 0.85rem; font-weight: 700; color: {THEME['accent_secondary']}; letter-spacing: 0.12em; text-transform: uppercase;">
                {p_data['number_str']}
            </div>
            <h1 style="font-size: 2.3rem; font-weight: 800; color: #FFFFFF; margin-top: 0.2rem; margin-bottom: 0.4rem;">
                {p_data['short_title']}
            </h1>
            <div style="font-size: 1rem; color: {THEME['text_secondary']};">
                {p_data.get('official_title', '')}
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # 1. AIM
    with st.container():
        st.markdown(
            f"""
            <div class="detail-section">
                <div class="detail-section-title">
                    <span>🎯</span> AIM
                </div>
                <div style="font-size: 1.05rem; line-height: 1.6; color: #FFFFFF; font-weight: 500;">
                    {p_data['aim']}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # 2. INPUT DATASET
    inp_info = p_data.get("input_data", {})
    before_info = p_data.get("what_was_present_before", {})
    with st.container():
        st.markdown(
            f"""
            <div class="detail-section">
                <div class="detail-section-title">
                    <span>📥</span> INPUT / DATASET BEFORE PROCESSING
                </div>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 1rem;">
                    <div style="background: #10151F; padding: 0.85rem 1.1rem; border-radius: 8px; border: 1px solid rgba(255,255,255,0.06);">
                        <div style="font-size: 0.75rem; text-transform: uppercase; color: {THEME['text_muted']}; font-weight: 600;">Source File</div>
                        <div style="font-family: monospace; font-size: 0.85rem; color: {THEME['accent_cyan']}; margin-top: 0.2rem; word-break: break-all;">
                            {inp_info.get("source_path", "N/A")}
                        </div>
                    </div>
                    <div style="background: #10151F; padding: 0.85rem 1.1rem; border-radius: 8px; border: 1px solid rgba(255,255,255,0.06);">
                        <div style="font-size: 0.75rem; text-transform: uppercase; color: {THEME['text_muted']}; font-weight: 600;">Data Format</div>
                        <div style="font-size: 0.95rem; font-weight: 600; color: #FFFFFF; margin-top: 0.2rem;">
                            {inp_info.get("format", "N/A")}
                        </div>
                    </div>
                    <div style="background: #10151F; padding: 0.85rem 1.1rem; border-radius: 8px; border: 1px solid rgba(255,255,255,0.06);">
                        <div style="font-size: 0.75rem; text-transform: uppercase; color: {THEME['text_muted']}; font-weight: 600;">Record Volume</div>
                        <div style="font-size: 0.95rem; font-weight: 600; color: #FFFFFF; margin-top: 0.2rem;">
                            {inp_info.get("records_count", inp_info.get("total_records", "N/A"))}
                        </div>
                    </div>
                </div>
                <div style="font-size: 0.92rem; color: {THEME['text_secondary']}; line-height: 1.6;">
                    {before_info.get("details", "")}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # 3. PROCESS / PIPELINE
    with st.container():
        steps = p_data.get("workflow_steps", [])
        st.markdown(
            f"""
            <div class="detail-section">
                <div class="detail-section-title">
                    <span>🔁</span> ACTUAL PROCESSING FLOW
                </div>
            """,
            unsafe_allow_html=True
        )
        for s in steps:
            st.markdown(
                f"""
                <div style="display: flex; align-items: flex-start; margin-bottom: 0.6rem;">
                    <span style="color: {THEME['accent']}; font-weight: bold; margin-right: 0.6rem;">➔</span>
                    <span style="font-size: 0.92rem; color: {THEME['text_primary']}; line-height: 1.5;">{s}</span>
                </div>
                """,
                unsafe_allow_html=True
            )
        st.markdown("</div>", unsafe_allow_html=True)

    # 4. TECHNIQUES / TOOLS & ALGORITHMS / METHODS
    methods = p_data.get("methods", [])
    with st.container():
        st.markdown(
            f"""
            <div class="detail-section">
                <div class="detail-section-title">
                    <span>⚙️</span> TECHNIQUES, ALGORITHMS &amp; TOOLS USED
                </div>
            """,
            unsafe_allow_html=True
        )
        m_cols = st.columns(2)
        for idx, m in enumerate(methods):
            with m_cols[idx % 2]:
                st.markdown(
                    f"""
                    <div style="background: #10151F; border: 1px solid rgba(255,255,255,0.06); border-radius: 8px; padding: 1rem; margin-bottom: 0.8rem;">
                        <div style="font-weight: 700; color: {THEME['accent_cyan']}; font-size: 0.95rem; margin-bottom: 0.3rem;">
                            📌 {m['name']}
                        </div>
                        <div style="font-size: 0.85rem; color: {THEME['text_secondary']}; line-height: 1.45;">
                            {m['desc']}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
        st.markdown("</div>", unsafe_allow_html=True)

    # 5. OBSERVATIONS & KEY NUMERICAL RESULTS
    results = p_data.get("results", {})
    with st.container():
        st.markdown(
            f"""
            <div class="detail-section">
                <div class="detail-section-title">
                    <span>📈</span> OBSERVATIONS &amp; KEY NUMERICAL RESULTS
                </div>
            """,
            unsafe_allow_html=True
        )

        kpis = results.get("kpis", [])
        if kpis:
            k_cols = st.columns(min(len(kpis), 4))
            for i, kpi in enumerate(kpis):
                with k_cols[i % len(k_cols)]:
                    st.metric(kpi["label"], kpi["value"])
            st.write("")

        # Visuals for specific practicals
        if practical_id == 6:
            st.markdown("#### Balancing Method Comparison (Training Fold)")
            st.plotly_chart(plot_balancing_comparison_dark(), use_container_width=True)
            comp_table = results.get("comparison_table", [])
            if comp_table:
                st.dataframe(pd.DataFrame(comp_table), use_container_width=True, hide_index=True)
            st.info("ℹ️ **Selected final balancing method in this implementation: SMOTE** (60,000 balanced records on training split; 298,437 test records preserved untouched).")

        elif practical_id == 9:
            st.markdown("#### Attack Classifier Comparison")
            st.plotly_chart(plot_model_comparison_experiments_dark(), use_container_width=True)
            tab_a, tab_b, tab_feat = st.tabs(["Experiment A (Natural Split)", "Experiment B (SMOTE Balanced)", "Feature Importance"])
            with tab_a:
                exp_a = results.get("experiment_a", {})
                st.caption(exp_a.get("dataset_desc", ""))
                st.dataframe(pd.DataFrame(exp_a.get("metrics", [])), use_container_width=True, hide_index=True)
            with tab_b:
                exp_b = results.get("experiment_b", {})
                st.caption(exp_b.get("dataset_desc", ""))
                st.dataframe(pd.DataFrame(exp_b.get("metrics", [])), use_container_width=True, hide_index=True)
                st.success(f"🎯 {exp_b.get('note', '')}")
            with tab_feat:
                st.plotly_chart(plot_feature_importance_dark(12), use_container_width=True)

        elif practical_id == 10:
            st.markdown("#### Reusable Pipeline Execution Timings")
            st.plotly_chart(plot_pipeline_stage_durations_dark(), use_container_width=True)

        elif practical_id == 4:
            st.markdown("#### Ground-Truth Label Distribution")
            st.plotly_chart(plot_class_distribution_dark(log_scale=True), use_container_width=True)

        # Observations bullets
        obs = results.get("observations", [])
        if obs:
            st.markdown("<div style='margin-top: 1rem; font-weight: 700; color: #FFFFFF;'>Empirical Observations:</div>", unsafe_allow_html=True)
            for ob in obs:
                st.markdown(f"- {ob}")

        st.markdown("</div>", unsafe_allow_html=True)

    # 6. OUTPUT ARTIFACTS & GENERATED CHARTS
    with st.container():
        st.markdown(
            f"""
            <div class="detail-section">
                <div class="detail-section-title">
                    <span>🖼️</span> OUTPUT ARTIFACTS &amp; GENERATED PLOTS
                </div>
            """,
            unsafe_allow_html=True
        )

        output_files = p_data.get("output_files", [])
        csv_files = [f for f in output_files if f["type"] in ("csv", "parquet")]
        report_files = [f for f in output_files if f["type"] in ("report", "text", "json")]
        plot_items = get_all_practical_plots(practical_id)

        t_plots, t_rep, t_csv = st.tabs([
            f"🖼️ Generated Plots ({len(plot_items)})",
            f"📄 Technical Reports ({len(report_files)})",
            f"📊 Data Outputs ({len(csv_files)})"
        ])

        with t_plots:
            if not plot_items:
                st.info("No generated plot images found for this practical.")
            else:
                p_cols = st.columns(2)
                for idx, plot in enumerate(plot_items):
                    with p_cols[idx % 2]:
                        img = load_image(str(plot["path"]))
                        if img:
                            st.image(img, caption=f"{plot['title']} ({plot['size_str']})", use_container_width=True)

        with t_rep:
            if not report_files:
                st.info("No reports registered for this practical.")
            else:
                sel_rep = st.selectbox("Select report to view:", [f["name"] for f in report_files], key=f"pr_rep_{practical_id}")
                ch_rep = next(f for f in report_files if f["name"] == sel_rep)
                content = read_text_file(ch_rep["path"], max_lines=300)
                st.code(content, language="text")

        with t_csv:
            if not csv_files:
                st.info("No data outputs registered for this practical.")
            else:
                sel_csv = st.selectbox("Select data output to preview:", [f["name"] for f in csv_files], key=f"pr_csv_{practical_id}")
                ch_csv = next(f for f in csv_files if f["name"] == sel_csv)
                if ch_csv["type"] == "parquet":
                    df_p = load_parquet_preview(ch_csv["path"], nrows=30)
                else:
                    df_p = load_csv_preview(ch_csv["path"], nrows=30)
                if not df_p.empty:
                    st.dataframe(df_p, use_container_width=True)

        st.markdown("</div>", unsafe_allow_html=True)

    # 7. VALIDATION STATUS
    val_checks = p_data.get("validation", [])
    if val_checks:
        with st.container():
            st.markdown(
                f"""
                <div class="detail-section">
                    <div class="detail-section-title">
                        <span>✅</span> VALIDATION STATUS
                    </div>
                """,
                unsafe_allow_html=True
            )
            for v in val_checks:
                st.markdown(
                    f"""
                    <div style="display: flex; justify-content: space-between; align-items: center; background: #10151F; border: 1px solid rgba(255,255,255,0.06); padding: 0.75rem 1rem; border-radius: 6px; margin-bottom: 0.5rem;">
                        <div>
                            <strong style="color: #FFFFFF; font-size: 0.92rem;">{v['check']}</strong>
                            <div style="font-size: 0.82rem; color: {THEME['text_secondary']};">{v['details']}</div>
                        </div>
                        <span style="background: rgba(57, 217, 138, 0.15); color: {THEME['success']}; border: 1px solid rgba(57, 217, 138, 0.3); font-weight: 700; font-size: 0.75rem; padding: 0.2rem 0.6rem; border-radius: 4px;">
                            {v['status']}
                        </span>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            st.markdown("</div>", unsafe_allow_html=True)
