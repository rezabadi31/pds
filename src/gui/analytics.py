"""src/gui/analytics.py
Analytics View — Deep Security Intelligence & Machine Learning Benchmarks
Presents EDA telemetry, feature correlation heatmaps, class balancing dynamics, and ML classification benchmarks.
"""

from pathlib import Path
import streamlit as st
import pandas as pd
from PIL import Image

from config import THEME
from src.gui.charts import (
    plot_class_distribution_dark,
    plot_balancing_comparison_dark,
    plot_model_comparison_experiments_dark,
    plot_feature_importance_dark,
)
from utils.data_loader import load_image, get_all_practical_plots, resolve_file_path


def render_analytics_view():
    """Renders the Analytics dashboard."""

    st.markdown(
        f"""
        <div style="margin-bottom: 1.5rem;">
            <div class="product-hero-eyebrow">
                <span>📊</span> Deep Telemetry &amp; Model Intelligence
            </div>
            <h1 style="font-size: 2.2rem; font-weight: 800; color: #FFFFFF; margin: 0.2rem 0 0.5rem 0;">
                Security Analytics &amp; ML Benchmarks
            </h1>
            <div style="font-size: 1.05rem; color: {THEME['text_secondary']}; line-height: 1.5;">
                Comprehensive exploratory data analysis, feature correlations, class balancing evaluation, and classification performance.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    tab_ml, tab_eda, tab_bal = st.tabs([
        "🛡️ Attack Classifier Benchmarks (Practical 09)",
        "📈 Exploratory Visual Telemetry (Practical 08)",
        "⚖️ Class Balancing Analytics (Practical 06)"
    ])

    with tab_ml:
        st.markdown("### Dual Experiment Classifier Evaluation")
        st.plotly_chart(plot_model_comparison_experiments_dark(), use_container_width=True)

        col_m1, col_m2 = st.columns(2)
        with col_m1:
            st.markdown(
                f"""
                <div style="background: #10151F; border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 1.2rem;">
                    <div style="font-weight: 700; color: {THEME['accent_cyan']}; font-size: 1rem; margin-bottom: 0.5rem;">
                        Experiment A: Natural Imbalanced Split (80/20)
                    </div>
                    <div style="font-size: 0.85rem; color: {THEME['text_secondary']}; margin-bottom: 0.8rem;">
                        Trained on 1,193,745 records; evaluated on 298,437 untouched test records.
                    </div>
                """,
                unsafe_allow_html=True
            )
            df_exp_a = pd.DataFrame([
                {"Model": "Logistic Regression", "Accuracy": "97.07%", "Macro Recall": "98.45%", "Macro F1": "45.18%", "Weighted F1": "98.29%"},
                {"Model": "Random Forest (100 Trees)", "Accuracy": "99.97%", "Macro Recall": "97.63%", "Macro F1": "95.26%", "Weighted F1": "99.97%"}
            ])
            st.dataframe(df_exp_a, use_container_width=True, hide_index=True)
            st.markdown("</div>", unsafe_allow_html=True)

        with col_m2:
            st.markdown(
                f"""
                <div style="background: #10151F; border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 1.2rem;">
                    <div style="font-weight: 700; color: {THEME['success']}; font-size: 1rem; margin-bottom: 0.5rem;">
                        Experiment B: SMOTE Balanced Training
                    </div>
                    <div style="font-size: 0.85rem; color: {THEME['text_secondary']}; margin-bottom: 0.8rem;">
                        Trained on 60,000 SMOTE records; evaluated strictly on 298,437 untouched test records.
                    </div>
                """,
                unsafe_allow_html=True
            )
            df_exp_b = pd.DataFrame([
                {"Model": "Logistic Regression", "Accuracy": "96.72%", "Macro Recall": "98.82%", "Macro F1": "42.81%", "Weighted F1": "98.10%"},
                {"Model": "Random Forest (100 Trees)", "Accuracy": "99.54%", "Macro Recall": "99.24%", "Macro F1": "69.18%", "Weighted F1": "99.65%"}
            ])
            st.dataframe(df_exp_b, use_container_width=True, hide_index=True)
            st.markdown("</div>", unsafe_allow_html=True)

        st.write("")
        st.markdown("### Top Predictive Features (Random Forest Gini Importance)")
        st.plotly_chart(plot_feature_importance_dark(15), use_container_width=True)

        # Confusion matrix visual images
        rf_cm = load_image("Practical 9/outputs/plots/random_forest_confusion_matrix.png")
        lr_cm = load_image("Practical 9/outputs/plots/logistic_regression_confusion_matrix.png")

        c_cm1, c_cm2 = st.columns(2)
        with c_cm1:
            if rf_cm:
                st.image(rf_cm, caption="Random Forest Confusion Matrix (Experiment A)", use_container_width=True)
        with c_cm2:
            if lr_cm:
                st.image(lr_cm, caption="Logistic Regression Confusion Matrix (Experiment A)", use_container_width=True)

    with tab_eda:
        st.markdown("### 15 Exploratory Telemetry Figures (Practical 08)")
        p8_plots = get_all_practical_plots(8)
        if p8_plots:
            cols = st.columns(2)
            for idx, p in enumerate(p8_plots):
                with cols[idx % 2]:
                    img = load_image(str(p["path"]))
                    if img:
                        st.image(img, caption=f"{p['title']} ({p['size_str']})", use_container_width=True)

    with tab_bal:
        st.markdown("### Class Imbalance & Resampling Comparison (Practical 06)")
        st.plotly_chart(plot_balancing_comparison_dark(), use_container_width=True)

        st.markdown(
            f"""
            <div style="background: #10151F; border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 1.2rem; margin-top: 1rem;">
                <div style="font-weight: 700; color: #FFFFFF; font-size: 1rem; margin-bottom: 0.5rem;">
                    Key Balancing Methodology Comparison
                </div>
                <div style="font-size: 0.88rem; color: {THEME['text_secondary']}; line-height: 1.6;">
                    • <strong>Original Training Set (1,193,745 records)</strong>: Imbalance ratio of 9,298:1 between benign (1.19M) and sqli (128).<br>
                    • <strong>Random Undersampling (768 records)</strong>: Downsampled to 128 per class. Fast, but discards over 99.9% of benign pattern diversity.<br>
                    • <strong>Random Oversampling (60,000 records)</strong>: Duplicated minority samples with replacement. Risks decision boundary memorization.<br>
                    • <strong>SMOTE (60,000 records) — Selected Final Method</strong>: Synthesizes novel feature vectors along k-NN (k=5) line segments, creating smooth decision manifolds.<br>
                    • <strong>Untouched Test Set (298,437 records)</strong>: Preserved strictly without resampling for realistic real-world evaluation.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        p6_plots = get_all_practical_plots(6)
        if p6_plots:
            st.write("")
            st.markdown("### Balancing Visual Artifacts")
            cols = st.columns(2)
            for idx, p in enumerate(p6_plots[:4]):
                with cols[idx % 2]:
                    img = load_image(str(p["path"]))
                    if img:
                        st.image(img, caption=p["title"], use_container_width=True)
