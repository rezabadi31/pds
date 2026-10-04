# ROX — Log Intelligence Platform

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://streamlit.io/cloud)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![Pipeline Status](https://img.shields.io/badge/Pipeline-Ready-success.svg)]()

ROX is a production-grade, dark-themed **Log Intelligence Platform** and autonomous security assistant. It transforms raw server access telemetry into structured, labeled, feature-engineered datasets and delivers instant forensic insights.

```
                    ROX
                     │
        ┌────────────┴────────────┐
        │                         │
 PRACTICAL STORY             LIVE ANALYZER
        │                         │
  Actual P1 → P10             Upload Log
  screenshots                     │
  actual outputs                  ▼
  actual results               LOAD
                                ↓
                              PARSE
                                ↓
                             CLEAN
                                ↓
                             LABEL
                                ↓
                       FEATURE ENGINEERING
                       ├─ Domain Features
                       ├─ Featuretools
                       └─ tsfresh
                                ↓
                        Anomaly Detection
                                ↓
                         Security Results
                                ↓
                           Ask ROX
```

---

## 🚀 Quickstart (Local Execution)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/rezabadi31/pds.git
   cd pds
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Launch the application:**
   ```bash
   streamlit run app.py
   ```

---

## ☁️ Streamlit Community Cloud Deployment

ROX is fully configured for zero-configuration deployment to **Streamlit Community Cloud**:

1. Push this repository to GitHub.
2. Log into [share.streamlit.io](https://share.streamlit.io/).
3. Click **New app**.
4. Select your repository, branch (`main`), and set **Main file path** to:
   ```text
   app.py
   ```
5. Click **Deploy**.

> **Note**: ROX operates 100% deterministically and does not require paid LLM API keys. All asset references and pipeline modules use relative paths that work automatically in the cloud environment.

---

## 📂 Project Architecture

```text
pds/
├── app.py                     # Master Streamlit entry point
├── requirements.txt           # Cloud-compatible dependency manifest
├── README.md                  # Project documentation & deployment guide
├── config.py                  # Theme tokens, baseline metrics & relative paths
│
├── src/
│   ├── pipeline/              # Reusable data engineering pipeline
│   │   ├── loader.py          # Multi-format log loader (.log, .txt, .csv, .json)
│   │   ├── parser.py          # Schema parsing & canonical harmonization
│   │   ├── preprocessing.py   # Cleaning, normalization & deduplication
│   │   ├── labeling.py        # Practical 04 deterministic attack attribution
│   │   ├── feature_engineering.py # Domain, Featuretools & tsfresh features
│   │   ├── anomaly_detection.py   # Practical 05 Isolation Forest detector
│   │   ├── pipeline.py        # Master pipeline coordinator & offline Q&A
│   │   └── pipeline_runner.py # Backward-compatible adapter
│   │
│   └── gui/                   # Dark cybersecurity UI views
│       ├── overview.py        # Clean landing screen & quick actions
│       ├── rox.py             # Live Analyzer workspace, chat & downloads
│       ├── practicals.py      # Practical Story (P01-P10) cards & evidence
│       ├── pipeline_view.py   # Reusable pipeline flow & 14 verified checks
│       └── charts.py          # Clean Plotly dark charts
│
├── assets/
│   ├── dark_theme.css         # Dark navy & cyan design stylesheet
│   └── practicals/            # 51 generated plots from Practicals 01 to 09
│
├── metadata/
│   └── practicals.json        # Verified empirical metrics & practical summaries
│
└── data/
    └── sample_honeypot.log    # Verified sample honeypot access log for testing
```

---

## 🛡️ Core Capabilities

- **ROX Live Analyzer**: Upload raw access logs (`.log`, `.txt`, `.csv`, `.json`) or test with the built-in demo sample. Executes real pipeline stages: `Load → Parse → Structure → Preprocess → Label → Feature Engineer → Anomaly Detection → Export`.
- **Attack Classification**: Deterministic attribution across 6 security classes (`benign`, `brute_force`, `path_traversal`, `xss`, `command_injection`, `sqli`).
- **Feature Engineering**: Generates request behavioral rates, inter-arrival times, URL Shannon entropy, Featuretools relational aggregations, and tsfresh time-series metrics.
- **Unsupervised Anomaly Detection**: Isolation Forest scoring (`Normal` vs `Anomalous`) evaluated independently of rule-based attacks.
- **Ask ROX**: 100% offline, fact-grounded forensic Q&A interface grounded strictly in the processed telemetry.
- **Practical Story (P01 → P10)**: 10 compact cards detailing AIM, INPUT, PROCESS, METHODS/TOOLS, RESULTS, and 51 actual generated screenshot artifacts.
