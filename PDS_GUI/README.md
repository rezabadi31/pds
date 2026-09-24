# PDS Log Analytics & Attack Detection System (PDS_GUI)

## Project Title
**"Web Honeypot Log Analysis and Attack Detection — Practical 1 to Practical 10"**

## Laboratory Course
**Python for Data Science (PDS)**

---

## 1. Overview & Purpose
The **PDS_GUI** is a presentation and analytical control center developed for demonstrating the entire end-to-end PDS cybersecurity log analysis project (Practicals 1 to 10) for technical evaluation and defense.

**Key Architecture Principles:**
- **Zero Expensive Re-computation on Startup**: Does not re-run expensive 2-million record practicals on launch. Reads and visualizes the existing evidence, reports, tables, plots, models, and Parquet files.
- **Fail-Safe Robustness**: Never crashes if an optional output is missing; displays clean `AVAILABLE` / `NOT FOUND` status indicators.
- **Memory Optimized**: Uses Streamlit `@st.cache_data` and sample previews (`nrows=1000`) to avoid loading gigabyte CSV files into RAM simultaneously.
- **100% Local & Free Open-Source**: Requires zero cloud services, external databases, or paid APIs.

---

## 2. Directory Structure

```text
D:\Pds Practicals\PDS_GUI\
│
├── app.py                     # Master Streamlit presentation application
├── config.py                  # Practical directories, expected outputs, constants
├── requirements.txt           # Python dependency requirements
├── README.md                  # GUI guide & documentation
│
├── utils\
│   ├── __init__.py            # Package marker
│   ├── data_loader.py         # Safe, cached CSV/Parquet/report loaders
│   ├── metrics.py             # Metric synthesizers across practicals
│   ├── charts.py              # Interactive Plotly figures & diagnostic plots
│   └── practical_info.py      # Technical descriptions & 25 Defense Q&As
│
└── assets\                    # Static resources & styling
```

---

## 3. How to Run the GUI

Open PowerShell or Command Prompt:

```powershell
cd /d "D:\Pds Practicals\PDS_GUI"
& "C:\Users\ASUS\AppData\Local\Programs\Python\Python313\python.exe" -m streamlit run app.py
```

Or if Streamlit is in your PATH:

```powershell
cd /d "D:\Pds Practicals\PDS_GUI"
streamlit run app.py
```

The application is hosted locally at `http://localhost:8501`.

---

## 4. Key Dashboard Features

1. **Dashboard Overview**: 8 high-impact metric cards (2.06M raw records, 1.49M processed records, 6 classes, 66 features, 60k balanced train rows, 298k test rows, 99.97% Random Forest accuracy, 95.26% Macro F1), visual execution pipeline, and interactive class distribution & model comparison charts.
2. **Project Architecture**: System dataflow documentation spanning data engineering, threat intelligence, and machine learning branches.
3. **Practical Pages (1 to 10)**: Dedicated pages for each practical detailing Aim, Objective, Input, Output, Technical Approach, System Rationale, Empirical Results, data preview, charts, and text report downloads.
4. **Model Evaluation Analysis**: Side-by-side comparison of Logistic Regression vs. Random Forest, multiclass confusion matrices, Top 20 Gini feature importances, and Part 13 balanced-data validation metrics.
5. **Dataset Explorer**: Interactive, memory-safe viewer for structured, preprocessed, labeled, feature-engineered, and Parquet datasets.
6. **Technical Defense Q&A**: 25 comprehensive, realistic technical defense questions and answers tailored directly to dataset metrics and engineering methodologies.
7. **Technical Project Report**: Automated generation and instant download of `PDS_Project_Summary.txt` and `PDS_Project_Summary.html`.
