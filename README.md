# Rox — Log Intelligence Platform

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://streamlit.io/cloud)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.3+-orange.svg)](https://scikit-learn.org/)
[![Apache Parquet](https://img.shields.io/badge/Apache-Parquet-blueviolet.svg)](https://parquet.apache.org/)
[![Pipeline Engine](https://img.shields.io/badge/Pipeline-Production%20Ready-success.svg)]()

A modern, dark-themed **Log Analysis & Security Intelligence Platform** featuring an integrated AI assistant named **Rox**.

The platform is designed around two core functions:
1. **Practicals Explorer**: An interactive, visual product-style interface presenting what was actually implemented across Practical 1 to 10 using empirical project outputs, charts, and metrics.
2. **Rox Live Log Analysis Assistant**: An interactive log processing engine where users can upload new server access logs (`.log`, `.txt`, `.csv`) and execute the automated 7-stage pipeline to classify threats, detect suspicious behavior, inspect features, chat with Rox, and download processed datasets.

---

## 🌟 Platform Capabilities

- **Overview Dashboard**: High-level cybersecurity intelligence overview with real project statistics (2.06M raw records, 570k deduplicated entries, 6 multi-class threat categories, 66 numerical features).
- **Practicals Explorer (1 to 10)**: 10 interactive cards with subtle hover effects and detailed product views:
  - **Aim**: Target objective of the data science operation.
  - **Input / Dataset**: Source file, record count, attributes, and uncleaned baseline state.
  - **Process**: Visual stage flow from raw telemetry to ML-ready features.
  - **Techniques & Tools**: Strictly the tools actually used (Python, Pandas, Scikit-learn, imbalanced-learn, Matplotlib, Seaborn, Plotly, tsfresh, Featuretools, PyArrow).
  - **Algorithm / Method**: Specific algorithms (e.g. streaming generators, regex signatures, SMOTE, Random Forest).
  - **Observation**: Empirical results extracted directly from project outputs.
  - **Output**: Actual generated plots, technical reports, and CSV samples.
- **Rox — Live Log Analysis Assistant**:
  - Upload `.log`, `.txt`, or `.csv` files or test using the one-click demo honeypot sample.
  - Executes the automated Practical 10 pipeline: `Load → Parse → Structure → Preprocess → Label → Feature Engineer → Analyze → Export`.
  - Displays traffic classifications (benign, brute force, sqli, path traversal, xss, command injection), suspicious IPs, burst traffic, and high-entropy URLs.
  - Features an interactive conversational assistant to ask natural forensic questions (e.g., *"What attacks were detected?"*, *"Which IP generated the most suspicious requests?"*).
  - One-click downloads for processed CSV, Parquet, and JSON analysis summaries.
- **Reusable Pipeline View**: Step-by-step breakdown of the 8 automated production stages (01 Load, 02 Parse, 03 Structure, 04 Preprocess, 05 Label, 06 Engineer Features, 07 Validate, 08 Export) with timing metrics.
- **Security Analytics**: Cross-telemetry exploratory data analysis, 15 security visualization figures, Pearson feature correlation heatmaps, class balancing dynamics (SMOTE vs RUS/ROS), and ML classifier benchmarks.

---

## 🛠️ Technology Stack

- **Core Framework**: Streamlit (with custom dark cybersecurity CSS)
- **Data Engineering**: Pandas, NumPy
- **High-Performance Columnar Storage**: Apache Arrow / PyArrow (Snappy-compressed Parquet)
- **Machine Learning**: Scikit-Learn (Random Forest: 99.97% Acc, 95.26% Macro F1; Logistic Regression baseline)
- **Dataset Balancing**: Imbalanced-Learn (SMOTE 60k balanced training partition)
- **Feature Extraction**: Featuretools, tsfresh, Shannon entropy
- **Visual Analytics**: Matplotlib, Seaborn, Plotly Express

---

## 🚀 Quickstart & Local Execution

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/rezabadi31/pds.git
   cd pds
   ```

2. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Launch the Platform:**
   ```bash
   streamlit run app.py
   ```

The application opens at `http://localhost:8501`.

---

## 📁 Project Architecture

```text
pds/
├── app.py                      # Master Streamlit entry point
├── config.py                   # Central dark theme tokens, paths, baseline metrics
├── requirements.txt            # Unified dependencies
├── README.md                   # Platform documentation
│
├── assets/
│   └── dark_theme.css          # Dark cybersecurity stylesheet
│
├── src/
│   ├── pipeline/
│   │   └── pipeline_runner.py  # Rox live pipeline executor & chat logic
│   └── gui/
│       ├── overview.py         # Platform overview & KPI hero banner
│       ├── practicals.py       # 10 practical cards & detailed product views
│       ├── rox.py              # Rox assistant & live log analyzer
│       ├── pipeline_view.py    # Interactive 8-stage pipeline visualizer
│       ├── analytics.py        # Deep telemetry & model benchmarks
│       └── charts.py           # Dark-themed Plotly charts
│
├── utils/
│   ├── practicals_data.py      # Verified practical metadata & 10-stage facts
│   └── data_loader.py          # Memory-safe cached loaders (previews & plot locator)
│
├── data/
│   └── sample_honeypot.log     # Demo honeypot sample for Rox testing
│
└── Practical 1 to 10/          # Source practical implementations, models & outputs
```

---

## 🛡️ Empirical Integrity Guarantee

- **Zero Fabricated Results**: Every metric, record count, accuracy score, and distribution is read directly from verified output files and logs in `Practical 1` to `Practical 10`.
- **Dual Experiment Separation**: Experiment A (natural imbalanced split) and Experiment B (SMOTE-balanced train evaluated on untouched test) are preserved strictly separate.
- **Memory Safety**: Large datasets (multi-hundred MB CSVs) are previewed using cached head-sampling (`@st.cache_data`) to prevent RAM exhaustion.
