# Practical 8: Data Visualization and Exploratory Data Analysis (EDA)

## Project Title
**"To use the visual tools or by using Python for the Data Visualization and EDA"**

## Laboratory Course
**Python for Data Science (PDS) — Cybersecurity Analytics Practicals**

---

## 1. Objective & Scope
The objective of Practical 8 is to employ exploratory data analysis (EDA) and visualization methodologies to investigate attack patterns, client-IP behaviors, HTTP method distributions, status code error rates, and security feature correlations from the cybersecurity access-log telemetry (`Practical 7/data/processed/wrangled_filtered_dataset.csv`).

All visual analytics are conducted exclusively using free, open-source Python libraries:
- **Matplotlib**: Standard temporal and comparative charts.
- **Seaborn**: Heatmaps, statistical feature distributions, and categorical comparisons.
- **Plotly**: Local interactive exploration and multi-panel dashboards.

No paid or proprietary tools (Tableau, Power BI, Alteryx, DataRobot) are used. Everything runs 100% locally.

---

## 2. Directory Structure

```text
Practical 8
│
├── data\
│   ├── top10_attacking_ips.csv                  # Table of top 10 attack sources
│   ├── attack_categories_over_time.csv          # Daily temporal attack matrix
│   ├── status_code_groups.csv                   # Breakdown of status codes into 2xx/3xx/4xx/5xx
│   └── ip_vs_request_type.csv                   # Crosstab table for top 20 client IPs
│
├── outputs\
│   ├── plots\
│   │   ├── 01_requests_per_hour.png             # Requests per hour line chart
│   │   ├── 02_top10_attacking_ips.png           # Top 10 attacking IPs horizontal bar chart
│   │   ├── 03_attack_categories_over_time.png   # Multi-line temporal attack category trends
│   │   ├── 04_status_code_distribution.png      # HTTP status code frequency distribution
│   │   ├── 05_status_code_group_distribution.png# Status code category group distribution
│   │   ├── 06_ip_vs_request_type_heatmap.png    # Top 20 client IP × request method heatmap
│   │   ├── 07_attack_category_distribution.png  # Traffic class and attack category distribution
│   │   ├── 08_request_type_distribution.png     # HTTP request method frequency distribution
│   │   ├── 09_bot_vs_nonbot.png                 # Bot vs human volume & attack rate comparison
│   │   ├── 10_internal_vs_external.png          # Internal vs external IPv4 traffic share
│   │   ├── 11_url_length_distribution.png       # URL character length distribution (Seaborn)
│   │   ├── 12_payload_length_distribution.png   # Payload character length distribution (Seaborn)
│   │   ├── 13_requests_per_ip_distribution.png  # Requests per client IP log-scale distribution
│   │   ├── 14_inter_request_time_distribution.png # Inter-request time interval distribution
│   │   └── 15_feature_correlation_heatmap.png   # Pearson correlation matrix of security attributes
│   │
│   ├── interactive\
│   │   ├── 01_requests_per_hour.html            # Interactive hourly time series
│   │   ├── 02_top10_attacking_ips.html          # Interactive top attacking IPs bar chart
│   │   ├── 03_attack_categories_over_time.html  # Interactive temporal attack category trends
│   │   ├── 04_status_code_distribution.html     # Interactive status code explorer
│   │   ├── 07_attack_category_distribution.html # Interactive categorical label breakdown
│   │   └── eda_dashboard.html                   # 6-panel comprehensive interactive HTML dashboard
│   │
│   └── reports\
│       ├── eda_summary.txt                      # Factual empirical observations from dataset
│       └── visualization_report.txt             # Technical EDA and visualization findings report
│
├── src\
│   ├── __init__.py
│   ├── config.py                                # Paths, security feature lists, and export targets
│   ├── inspector.py                             # Part 1: Dataset ingestion and schema inspection
│   ├── visualizer.py                            # Parts 2–10: Static Matplotlib & Seaborn plots
│   ├── additional_eda.py                        # Parts 11 & 12: Feature distributions & correlation heatmap
│   ├── interactive.py                           # Parts 2, 3, 4, 5, 7 & 13: Interactive Plotly dashboards
│   ├── reporter.py                              # Part 14: Technical report and factual EDA generator
│   ├── run_practical8.py                        # Master pipeline orchestrator
│   └── verify_visualization.py                  # Part 15: Quality validation & assertion suite
│
├── run_practical8.py                            # Root launcher
├── verify_visualization.py                      # Root verification launcher
├── requirements.txt                             # Open-source dependencies
└── README.md                                    # Project documentation
```

---

## 3. Analytical Components

1. **Part 1 — Ingestion & Schema Inspection**: Loads the primary filtered telemetry (`wrangled_filtered_dataset.csv`) or fallback balanced dataset, extracts structural metrics, and prints the required `EDA DATASET INFORMATION` block.
2. **Part 2 — Requests per Hour**: Visualizes total, benign, and attack requests per hour over the complete time range (`01_requests_per_hour.png` & interactive HTML).
3. **Part 3 — Top 10 Attacking IPs**: Identifies the highest observed attack-volume hosts without unfounded malice assumptions (`02_top10_attacking_ips.png` & interactive HTML).
4. **Part 4 — Temporal Attack Trends**: Multi-line visualization tracking distinct attack categories across calendar dates (`03_attack_categories_over_time.png` & interactive HTML).
5. **Part 5 — HTTP Status Code Analysis**: Explores status code counts and groups into 2xx, 3xx, 4xx, 5xx classes (`04_status_code_distribution.png` & `05_status_code_group_distribution.png`).
6. **Part 6 — IP vs Request Type Crosstab**: High-clarity Seaborn heatmap restricted to the top 20 client IPs to avoid visual illegibility (`06_ip_vs_request_type_heatmap.png`).
7. **Part 7 — Category Distributions**: Audits class balance across benign and attack categories (`07_attack_category_distribution.png` & interactive HTML).
8. **Part 8 — Request Types**: Frequency distribution of HTTP methods (`08_request_type_distribution.png`).
9. **Part 9 & 10 — Bot & IP Demarcations**: Compares bot vs human and internal vs external traffic characteristics (`09_bot_vs_nonbot.png` & `10_internal_vs_external.png`).
10. **Part 11 & 12 — Feature Distributions & Correlation**: Plots statistical distributions of URL lengths, payload lengths, request frequencies, and inter-request intervals. Computes a Pearson correlation matrix across numeric security features (`15_feature_correlation_heatmap.png`).
11. **Part 13 — Standalone Interactive Dashboard**: Produces `eda_dashboard.html`, a multi-panel Plotly interactive dashboard that runs entirely locally in any standard web browser.
12. **Part 14 & 15 — Reporting & Automated Validation**: Generates `eda_summary.txt`, `visualization_report.txt`, and verifies all 12 assertion criteria via `verify_visualization.py`.

---

## 4. Execution Commands

### Execute the Complete Pipeline
```bash
& "C:\Users\ASUS\AppData\Local\Programs\Python\Python313\python.exe" run_practical8.py
```

### Run Quality Verification Suite Independently
```bash
& "C:\Users\ASUS\AppData\Local\Programs\Python\Python313\python.exe" verify_visualization.py
```
