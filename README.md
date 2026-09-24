# Web Honeypot Log Analysis and Attack Detection (Practicals 1 to 10)

Production-grade cybersecurity log analysis, feature engineering, and machine learning attack detection platform developed for the Python for Data Science (PDS) laboratory course.

---

## Streamlit Community Cloud Deployment

To deploy this project to [Streamlit Community Cloud](https://streamlit.io/cloud):

1. **Repository**: `rezabadi31/pds`
2. **Branch**: `main`
3. **Main file path**: `app.py` (or `PDS_GUI/app.py`)
4. **Python Version**: `3.10` / `3.11` / `3.12` / `3.13`

The application will launch directly into the presentation dashboard without needing external services or large raw log downloads.

---

## Repository Structure

```text
.
├── app.py                     # Root Streamlit entry point for Streamlit Cloud
├── requirements.txt           # Unified dependency specification
├── .gitignore                 # Excludes cache and multi-hundred MB raw files
├── README.md                  # Project overview and deployment guide
│
├── PDS_GUI/                   # Master Presentation & Analytics Dashboard
│   ├── app.py                 # Streamlit dashboard application
│   ├── config.py              # Path definitions & baseline metrics
│   ├── requirements.txt       # GUI dependencies
│   ├── README.md              # GUI specific documentation
│   └── utils/
│       ├── charts.py          # Interactive Plotly chart builders
│       ├── data_loader.py     # Safe, cached data loaders with sample fallback
│       ├── metrics.py         # Empirical metric synthesizers
│       └── practical_info.py  # Technical descriptions & Defense Q&As
│
├── Practical 1/               # Data Inspection (2.06M records, schema audit)
├── Practical 2/               # Log Parsing & Structuring (13-column schema)
├── Practical 3/               # Cleaning & Deduplication (-570k duplicates)
├── Practical 4/               # Deterministic Attack Labeling (6 classes)
├── Practical 5/               # Feature Engineering (66 ML features)
├── Practical 6/               # Dataset Balancing (SMOTE 60k balanced train set)
├── Practical 7/               # Multi-Dimensional Wrangling & IP Profiling
├── Practical 8/               # Exploratory Data Analysis (15 analytical charts)
├── Practical 9/               # Machine Learning Classifiers (Random Forest 99.97% Acc, 95.26% F1)
│   └── outputs/
│       ├── models/
│       │   ├── random_forest.joblib        # 100 Trees Ensemble (19.98 MB)
│       │   └── logistic_regression.joblib  # Linear Baseline (0.01 MB)
│       ├── data/
│       │   └── model_comparison.csv
│       ├── plots/
│       └── reports/
└── Practical 10/              # Reusable 7-Stage Pipeline (Apache Parquet export)
    ├── data/processed/
    │   └── feature_engineered_logs.parquet # 97.8% Compressed Parquet Dataset (9.46 MB)
    ├── pipeline/
    ├── reports/
    └── run_pipeline.py
```

---

## Core System Architecture & Results

- **Ingestion & Structuring**: 2,061,431 raw honeypot connection records parsed into 13 canonical attributes.
- **Cleaning**: 570,179 exact duplicate records removed (-27.6% redundancy).
- **Ground-Truth Labeling**: 6 deterministic classes (benign, brute_force, path_traversal, xss, command_injection, sqli) with zero circular ML dependence.
- **Feature Space**: 66 numerical features capturing request rates, Shannon entropies, lexical ratios, and temporal intervals.
- **Class Balancing**: Mitigated 9,298:1 class imbalance using SMOTE on training partition only (60,000 balanced rows); 298,437 test records preserved untouched.
- **Best Model**: Random Forest (100 trees) achieving **99.97% Accuracy** and **95.26% Macro F1**.
- **Reusable Pipeline**: Practical 10 automated CLI pipeline with Apache Parquet storage yielding **97.8% file size reduction** over CSV.

---

## Local Execution

To run the Streamlit dashboard locally:

```powershell
streamlit run app.py
```
