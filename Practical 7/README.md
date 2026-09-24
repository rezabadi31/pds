# Practical 7: Data Wrangling for Aggregated Analysis

## Project Title
**"To do the Data Wrangling for Aggregated Analysis on the balanced dataset."**

## Laboratory Course
**Python for Data Science (PDS) — Cybersecurity Analytics Practicals**

---

## 1. Objective & Scope
The primary objective of Practical 7 is to perform rigorous data wrangling, aggregation, filtering, reshaping, and time-series analysis on the balanced cybersecurity honeypot access-log dataset (`Practical 6/data/processed/balanced_training_dataset.csv`). This process extracts behavioral signals across IP frequency, temporal diurnal trends, protocol request methods, error status distributions, and automated bot vs. human activity.

All processing is executed exclusively using free, open-source Python tools (`pandas`, `numpy`, `matplotlib`, `ipaddress`). No paid, cloud, or proprietary software (Power BI, Tableau, Alteryx, DataRobot) is used.

---

## 2. Directory Structure

```text
Practical 7
│
├── data
│   └── processed
│       └── wrangled_filtered_dataset.csv        # Final wrangled dataset excluding bots & internal IPs
│
├── outputs
│   ├── aggregated
│   │   ├── ip_attack_frequency.csv              # Full IP-level traffic, attack count, and diversity metrics
│   │   ├── top_attack_ips.csv                   # Top 20 attack sources by volume
│   │   ├── ip_attack_type_matrix.csv            # IP × attack label crosstab frequency matrix
│   │   ├── ip_attack_type_percentage.csv        # IP × attack label percentage distribution
│   │   ├── hourly_traffic.csv                   # Resampled hourly telemetry (total, benign, attack, 4xx, 5xx)
│   │   ├── daily_traffic.csv                    # Resampled daily telemetry (total, attack rate, unique IPs)
│   │   ├── daily_attack_types.csv               # Daily breakdown by attack classification
│   │   ├── request_type_label_pivot.csv         # HTTP method × label crosstab pivot table
│   │   ├── request_type_label_percentage.csv    # HTTP method × label percentage matrix
│   │   ├── status_code_label_pivot.csv          # HTTP status code × label pivot table
│   │   ├── bot_filtered_dataset.csv             # Telemetry excluding likely automated bots
│   │   ├── bot_traffic_summary.csv              # Bot traffic distribution by label
│   │   ├── external_ip_dataset.csv              # Telemetry excluding internal/private/loopback IPs
│   │   ├── internal_external_summary.csv        # Internal vs external volume comparison
│   │   └── filtered                             # Key aggregations regenerated on filtered telemetry
│   │       ├── ip_attack_frequency.csv
│   │       ├── top_attack_ips.csv
│   │       ├── hourly_traffic.csv
│   │       ├── daily_traffic.csv
│   │       ├── daily_attack_types.csv
│   │       ├── request_type_label_pivot.csv
│   │       ├── request_type_label_percentage.csv
│   │       └── status_code_label_pivot.csv
│   │
│   ├── plots
│   │   ├── 1_top_attack_ips.png                 # Horizontal bar chart of top 20 attack IPs
│   │   ├── 2_hourly_traffic.png                 # Hourly time-series trend of total, benign, attack traffic
│   │   ├── 3_daily_attack_traffic.png           # Daily attack request volume & attack rate dual-axis plot
│   │   ├── 4_attack_type_distribution.png       # Class distribution in balanced telemetry
│   │   ├── 5_request_type_label_heatmap.png     # Heatmap of request types vs attack categories
│   │   ├── 6_bot_vs_nonbot.png                  # Bot vs non-bot traffic share and volume comparison
│   │   └── 7_internal_vs_external.png           # Internal vs external IPv4 classification comparison
│   │
│   └── reports
│       ├── data_inspection_report.txt           # Initial dataset dimensions, schema, and unique counts
│       └── wrangling_report.txt                 # Comprehensive empirical technical report
│
├── src
│   ├── __init__.py
│   ├── config.py                                # Paths, bot keyword patterns, RFC 1918 constants
│   ├── inspector.py                             # Part 1: Loading, timestamp parsing, schema inspection
│   ├── ip_analyzer.py                           # Parts 2 & 3: IP frequency metrics and crosstab matrix
│   ├── time_series.py                           # Parts 4 & 5: Hourly and daily time-series resampling
│   ├── pivots.py                                # Parts 6 & 7: Request type and status code pivot tables
│   ├── filters.py                               # Parts 8–11: Bot, internal IP, combined filtering & re-aggregation
│   ├── plots.py                                 # Part 12: High-resolution matplotlib visualizations
│   ├── reporter.py                              # Part 14: Automated technical wrangling report generator
│   └── verify_wrangling.py                      # Part 13: Data quality and verification suite
│
├── run_practical7.py                            # Master orchestrator producing required terminal summary
├── requirements.txt                             # Python open-source dependencies
└── README.md                                    # Project documentation
```

---

## 3. Core Analytical Workflow

### Part 1: Data Ingestion & Schema Inspection
- Loads the primary balanced dataset (`Practical 6/data/processed/balanced_training_dataset.csv`).
- Converts `timestamp` into timezone-aware pandas datetime objects (`pd.to_datetime(..., errors="coerce")`).
- Computes structural metrics: record counts, schema attributes, nulls, duplicates, and entity uniqueness.
- Exports `outputs/reports/data_inspection_report.txt`.

### Part 2 & 3: Client-IP Attack Frequency & Crosstab Reshaping
- Calculates IP-level statistics: `total_requests`, `attack_requests`, `benign_requests`, `attack_rate`, and unique diversity counts (`unique_attack_types`, `unique_request_types`, `unique_resources`, `unique_user_agents`).
- Exports `ip_attack_frequency.csv` and `top_attack_ips.csv`.
- Reshapes traffic into an IP × attack-label contingency matrix (`ip_attack_type_matrix.csv`, `ip_attack_type_percentage.csv`).
- **Analytical Rule**: An IP with high attack count is NOT automatically labeled malicious; multi-tenant proxies, shared gateways, and infected endpoints require context.

### Part 4 & 5: Hourly & Daily Time-Series Resampling
- Uses `timestamp` as the temporal index without modifying the underlying dataset.
- Aggregates traffic hourly: `hourly_traffic.csv` tracking total, benign, attack, 4xx, and 5xx traffic.
- Resamples daily: `daily_traffic.csv` and `daily_attack_types.csv` tracking day-over-day attack rates.

### Part 6 & 7: Pivot Tables & Error Distributions
- Pivot analysis on `request_type × label` (`request_type_label_pivot.csv` and percentage version).
- Pivot analysis on `status_code × label` (`status_code_label_pivot.csv`), calculating overall 4xx client and 5xx server error rates.

### Part 8, 9, 10 & 11: Rule-Based Telemetry Filtering
- **Bot Filtering**: Explicit case-insensitive matching on user-agent strings against common automated tools (`bot`, `crawler`, `spider`, `slurp`, `wget`, `curl`, `python-requests`, `scrapy`, `scanner`). Saved to `bot_filtered_dataset.csv`.
- **Internal IP Filtering**: Validates IPv4 addresses against private RFC 1918 allocations (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and loopback (`127.0.0.0/8`) via Python's standard `ipaddress` library. Saved to `external_ip_dataset.csv`.
- **Combined Filtering**: Isolates clean external human/non-bot traffic into `data/processed/wrangled_filtered_dataset.csv`.
- **Filtered Aggregations**: Re-runs IP frequency, time series, and pivots on the filtered dataset under `outputs/aggregated/filtered/`.

### Part 12: Visualizations
Produces 7 publication-ready figures in `outputs/plots/` at 300 DPI:
1. `1_top_attack_ips.png`
2. `2_hourly_traffic.png`
3. `3_daily_attack_traffic.png`
4. `4_attack_type_distribution.png`
5. `5_request_type_label_heatmap.png`
6. `6_bot_vs_nonbot.png`
7. `7_internal_vs_external.png`

### Part 13 & 14: Quality Assurance & Reporting
- Automated verification via `src/verify_wrangling.py` checking 11 assertions.
- Mathematical invariants verified: non-negative counts, valid percentage ranges (0.0% to 100.0%), additive sum consistency (`attack + benign == total`), zero impossible timestamps, and strict non-modification of Practical 6 input.
- Detailed technical report exported to `outputs/reports/wrangling_report.txt`.

---

## 4. Execution Instructions

### Run the Complete Pipeline
```bash
python run_practical7.py
```

### Run Quality Verification Suite Independently
```bash
python src/verify_wrangling.py
```
