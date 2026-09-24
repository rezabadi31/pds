# Practical 5 — Feature Engineering for Anomaly & Suspicious Activity Detection

## Title
**"To do the feature engineering for the anomaly detection or any suspicious activity."**

## Course
Predictive Data Science (PDS)

---

## 1. Objective
The primary objective of Practical 5 is to design and implement a comprehensive, scalable, and reproducible feature-engineering pipeline that extracts domain-specific behavioral, temporal, lexical, and structural features from honeypot access logs. The engineered feature matrix provides rich mathematical representations for unsupervised anomaly detection (e.g., Isolation Forest) and suspicious-activity classification without introducing target leakage.

---

## 2. Input Telemetry & Data Integrity Guarantees
- **Primary Input:** `D:\Pds Practicals\Practical 4\data\processed\labeled_access_logs.csv` (1,492,182 records × 16 columns)
- **Fallback Ingestion:** If Practical 4 is absent, automatically ingests `preprocessed_access_logs.csv` from Practical 3 and explicitly logs that Practical 4 data was unavailable.
- **Data Protection:** Neither Practical 3 nor Practical 4 files are ever modified or overwritten.
- **Zero Target Leakage:** Columns `label` and `label_reason` are strictly excluded from all feature calculations and the ML-ready matrix. They are used exclusively for separate supervised validation.
- **Record Integrity:** 100% of the original records are preserved in their exact order without random deletions or synthetic data fabrication.

---

## 3. Directory Structure
```text
D:\Pds Practicals\Practical 5\
│
├── data\
│   └── processed\
│       ├── feature_engineered_access_logs.csv   # All 16 original columns + raw engineered features
│       └── ml_ready_features.csv               # Imputed, encoded, and RobustScaler-normalized numeric matrix
│
├── outputs\
│   ├── reports\
│   │   ├── feature_engineering_report.txt      # Full technical, statistical, and execution report
│   │   └── tool_comparison_report.txt          # In-depth comparison of Python, TPOT, DataRobot, Alteryx, H2O
│   ├── features\
│   │   ├── feature_dictionary.csv              # Feature catalog: Name, Type, Description, Source, Anomaly Relevance
│   │   ├── feature_statistics.csv              # Summary statistics (mean, std, min, percentiles, max)
│   │   ├── feature_correlation.csv             # Pairwise Pearson correlation matrix
│   │   └── top_features.csv                    # Top features ranked by discriminative importance
│   ├── samples\
│   │   └── feature_engineered_sample.csv       # 10,000 representative records covering all classes
│   ├── plots\
│   │   ├── 1_requests_per_ip_distribution.png     # Log-scale request volume per IP
│   │   ├── 2_inter_request_time_distribution.png  # Inter-arrival delta distribution (<300s)
│   │   ├── 3_url_entropy_distribution.png         # Shannon entropy distribution
│   │   ├── 4_status_404_ratio_distribution.png    # Status code / error ratio distribution
│   │   ├── 5_user_agent_category_distribution.png # User-Agent taxonomy distribution (Log scale)
│   │   ├── 6_top10_feature_importance.png         # Validation Random Forest top-10 bar chart
│   │   └── 7_anomaly_score_distribution.png       # Isolation Forest decision score distribution
│   └── automl\
│       ├── tpot_pipeline.txt                   # TPOT genetic search optimization results
│       ├── datarobot_feature_report.txt        # DataRobot environment status & architectural analysis
│       ├── practical5_feature_engineering.yxmd # Valid Alteryx Designer workflow XML
│       └── h2o_feature_report.txt              # H2O Driverless AI status & architectural analysis
│
├── src\
│   ├── __init__.py
│   ├── config.py                               # Centralized directory paths and hyperparameters
│   ├── inspector.py                            # Step 1: Automated schema and distribution inspector
│   ├── time_features.py                        # Step 2: Temporal and diurnal features (is_night)
│   ├── ip_features.py                          # Features 1 & 2: IP frequency, windows, and inter-arrival timing
│   ├── status_features.py                      # Feature 3: Status code ratios, error rates, and 404 flags
│   ├── user_agent.py                           # Feature 4: User-agent taxonomy, tool detection, and diversity
│   ├── entropy_url.py                          # Feature 5: Shannon entropy and lexical URL metrics
│   ├── security_features.py                    # Additional security heuristics & compound triggers
│   ├── preprocessor.py                         # Missing value imputation, one-hot encoding, and RobustScaler
│   ├── anomaly.py                              # Isolation Forest anomaly detection & RF validation
│   ├── automl_runner.py                        # TPOT pipeline optimizer and commercial tool reporter
│   └── plots.py                                # Diagnostic visualization generator (300 DPI)
│
├── run_practical5.py                           # Master pipeline entrypoint with standard terminal output
├── verify_features.py                          # Automated 10-point test verification suite
├── requirements.txt                            # Python dependencies
└── README.md                                   # Comprehensive documentation & viva preparation guide
```

---

## 4. Feature Taxonomy & Engineering Methodology

### A. Temporal & Diurnal Features
| Feature Name | Type | Definition & Operational Relevance |
| :--- | :---: | :--- |
| `request_hour` | Int (0–23) | Hour of the day when the HTTP request arrived. |
| `request_day_of_week` | Int (0–6) | Day of week (0 = Monday, 6 = Sunday). Identifies weekend vs. weekday traffic shifts. |
| `request_day` | Int (1–31) | Calendar day of the month. |
| `request_month` | Int (1–12) | Calendar month. |
| `is_night` | Binary (0/1) | **Strict Rule:** Set to `1` if `00:00 <= hour < 06:00`, else `0`. Highlights off-peak hours when human traffic is minimal and automated scans dominate. |

### B. Client IP Volume, Inter-Arrival & Traffic Windows
| Feature Name | Type | Definition & Operational Relevance |
| :--- | :---: | :--- |
| `requests_per_ip` | Int | Total number of requests originated from the client IP across the entire dataset. |
| `ip_request_rank` | Int | Dense ordinal rank of client IP by traffic volume (Rank 1 = heaviest traffic generator). |
| `time_since_previous_request` | Float (s) | Elapsed seconds between consecutive requests from the same IP (sorted chronologically). First request has `NaN` (imputed with 999.0s sentinel for ML). |
| `mean_inter_request_time_ip` | Float (s) | Mean inter-arrival time per IP. Distinguishes rapid automated scrapers from human navigation. |
| `median_inter_request_time_ip` | Float (s) | Median inter-arrival time per IP. Outlier-resistant measure of client request pacing. |
| `min_inter_request_time_ip` | Float (s) | Minimum inter-arrival interval per IP. Identifies concurrent connection flooding. |
| `rapid_request_flag` | Binary (0/1) | Set to `1` if `time_since_previous_request <= 1.0` second, else `0`. Direct burst indicator. |
| `requests_per_ip_1min` | Int | Rolling count of requests from the same IP in the preceding 60-second window. |
| `requests_per_ip_5min` | Int | Rolling count of requests from the same IP in the preceding 300-second window. |
| `requests_per_ip_10min` | Int | Rolling count of requests from the same IP in the preceding 600-second window. |
| `unique_urls_per_ip` | Int | Count of distinct endpoints visited by client IP. High values indicate broad site crawling. |
| `unique_ports_per_ip` | Int | Count of distinct client ephemeral ports used. Flags multi-socket scanning tools. |
| `unique_user_agents_per_ip` | Int | Count of distinct User-Agent headers emitted by same IP. Flags header rotation evasion. |

### C. Status Code Frequency & Documented Observations
- **Schema Inspection:** The input schema contains `status_code` with constant value `0` across all records (standard in raw packet-capture honeypots without an active web server returning HTTP responses).
- **Integrity Rule:** In accordance with academic guidelines, values are not fabricated.
- **Computed Metrics:**
  - `status_404_count_ip`: Total 404 responses per IP.
  - `status_404_ratio_ip`: Ratio of 404 responses to total IP requests.
  - `status_403_count_ip`, `status_500_count_ip`, `error_status_ratio_ip`.
  - `high_404_activity_flag`: Binary alert set to `1` if `status_404_ratio_ip >= 0.50` OR `status_404_count_ip >= 20`.

### D. User-Agent Parsing & Tool Profiling
- **Taxonomy:** Clients are categorized into `browser`, `bot`, `scanner`, `script`, or `unknown`.
- **Known Security Scanners:** `gobuster`, `dirbuster`, `nikto`, `sqlmap`, `nmap`, `masscan`, `zgrab`, `censys`, `shodan`, `acunetix`, `nessus`, `wpscan`, `hydra`.
- **Automated Scripts & Libraries:** `curl`, `wget`, `python-requests`, `requests`, `aiohttp`, `urllib`, `httpx`, `httpclient`, `libwww-perl`, `go-http-client`.
- **Search & Index Bots:** `googlebot`, `bingbot`, `yandex`, `slurp`, `crawler`, `spider`.
- **Browsers:** `Mozilla`, `Chrome`, `Safari`, `Firefox`, `Edge`, `Opera`.
- **Flags:** `is_bot` (1 if bot, script, or scanner), `is_scanner` (1 if dedicated scanner), `user_agent_length`.

### E. Shannon Entropy & URL Lexical Analysis
- **Character-Level Shannon Entropy Formula:**
  $$H(X) = -\sum_{i=1}^{n} p(x_i) \log_2 p(x_i)$$
  Quantifies the degree of randomness in bits per character. Applied directly to `normalized_resource`.
- **Lexical Structural Features:**
  - `url_length`: Character length of the URL path.
  - `path_depth`: Count of `/` delimiters in the path.
  - `number_of_query_parameters`: Count of `&` parameter separators.
  - `special_character_count`: Non-alphanumeric character count.
  - `digit_ratio`: `digits / url_length`.
  - `letter_ratio`: `letters / url_length`.

### F. Additional Security & Payload Indicators
- `payload_length`: Length of POST/request payload body.
- `payload_entropy`: Character-level Shannon entropy of the payload string.
- `contains_sql_keyword`: Regex flag for SQL injection keywords (`UNION`, `SELECT`, `--`, `OR 1=1`).
- `contains_path_traversal`: Regex flag for directory climbing (`../`, `..\`, `/etc/passwd`, `win.ini`).
- `contains_script_tag`: Regex flag for XSS syntax (`<script>`, `alert`, `document.cookie`).
- `contains_command_separator`: Regex flag for shell separators (`; ls`, `| id`, `&&`, `` ` ``).
- `request_rate_1min`: `requests_per_ip_1min / 60.0` (instantaneous requests/sec).
- `request_rate_5min`: `requests_per_ip_5min / 300.0` (sustained requests/sec).
- `failed_pattern_count`: Compound integer tally (0–4) of security pattern triggers.

---

## 5. Feature Scaling & ML-Ready Dataset Preparation

### RobustScaler Transformation
Because access-log telemetry exhibits heavy skewness, extreme bursts (e.g., scanners issuing tens of thousands of requests in seconds), and long tails, standard z-score normalization (`StandardScaler`) is susceptible to distortion by extreme outliers. We employ **`RobustScaler`**:
$$x_{scaled} = \frac{x - Q_2(x)}{Q_3(x) - Q_1(x)}$$
This centers features by the median and scales by the Interquartile Range (IQR), making the scaled matrix resilient to extreme outlier values.

### Handling Missing Values
- `time_since_previous_request`: The first request for every client IP has an undefined inter-arrival delta. To preserve record integrity without deleting rows, NaNs are imputed with `999.0` seconds (representing an idle, non-burst baseline).
- Any remaining feature NaNs are imputed using the feature's column median.

---

## 6. Automated Feature Engineering & Tool Comparison

| Criterion | Custom Python Pipeline | TPOT | DataRobot | Alteryx Designer | H2O Driverless AI |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Category** | Code-First Domain Pipeline | AutoML Genetic Search | Enterprise Cloud AutoML | Visual ETL / Analytics | Enterprise Automated AI |
| **Licensing** | Free / Open-Source | Free / Open-Source | Commercial / Proprietary | Commercial / Proprietary | Commercial / Proprietary |
| **Execution Status** | **EXECUTED & COMPLETED** | **EXECUTED & COMPLETED** | **NOT EXECUTED (No License)** | **WORKFLOW CREATED (.yxmd)** | **NOT EXECUTED (No License)** |
| **Dataset Scale Handling** | 1.49M records in <60s | Sampled (5k–50k records) | Requires sampling or cluster | Multi-threaded local engine | GPU-accelerated cluster |
| **Domain Cybersecurity Features** | **Highest:** Custom Shannon entropy, rolling auth windows, payload signatures | **Low:** General mathematical transforms, polynomial features | **High:** Automated time-series windows & text embeddings | **High:** Visual formula tools, regex, spatial & group stats | **Very High:** Genetic text transformers, target encoding |
| **Target Leakage Control** | Fully explicit & auditable | Handled via CV splits | Automated guardrails | Manual workflow layout | Automated leakage detection |

### Notes on Tool Integrity
- **TPOT:** Executed on a representative sample of 5,000 records with `generations=3` and `population_size=10`. Best discovered pipeline saved to `outputs/automl/tpot_pipeline.txt`.
- **DataRobot & H2O Driverless AI:** In strict adherence to academic integrity, neither synthetic results nor mock benchmark scores are fabricated. Reports document the absence of enterprise environments and provide an architectural evaluation of their capabilities.
- **Alteryx Designer:** A syntactically valid `.yxmd` XML workflow was created at `outputs/automl/practical5_feature_engineering.yxmd` connecting Input Data, Auto Field, Formula transformations, Summarize aggregates, and Output File nodes.

---

## 7. Unsupervised Anomaly Detection (Isolation Forest)

### Model Configuration
- **Algorithm:** `IsolationForest`
- **Hyperparameters:** `n_estimators=100`, `contamination="auto"`, `random_state=42`, `n_jobs=-1`
- **Output Columns:**
  - `anomaly_score`: Continuous decision function value (lower values indicate higher isolation and greater abnormality).
  - `anomaly_flag`: Discrete indicator (`-1` = anomalous, `1` = normal).
- **Core Principle:** Anomaly detection identifies statistical outliers in multi-dimensional feature space. An anomaly is **not** automatically an attack; it flags unusual behavioral patterns for security analyst investigation.

---

## 8. Verification Suite & Quality Assurance

Run the automated test suite:
```powershell
python verify_features.py
```
Validates:
1. `[PASS]` Input & Feature dataset saved and readable (`feature_engineered_access_logs.csv`).
2. `[PASS]` Timestamp features created (`request_hour`, `request_day_of_week`, `request_day`, `request_month`, `is_night`).
3. `[PASS]` Requests-per-IP features created (`requests_per_ip`, `ip_request_rank`, rolling windows).
4. `[PASS]` Inter-request-time features created (`time_since_previous_request`, `mean_inter_request_time_ip`, `rapid_request_flag`).
5. `[PASS]` Status-code features created and documented (`status_404_count_ip`, `status_404_ratio_ip`, `high_404_activity_flag`).
6. `[PASS]` User-agent features created (`user_agent_type`, `is_bot`, `is_scanner`, `user_agent_length`).
7. `[PASS]` URL entropy calculated (`url_entropy` in bits).
8. `[PASS]` URL-derived features created (`url_length`, `path_depth`, `number_of_query_parameters`, `special_character_count`, `digit_ratio`, `letter_ratio`).
9. `[PASS]` No target leakage (`label` and `label_reason` excluded from `ml_ready_features.csv`).
10. `[PASS]` ML-ready dataset saved, properly scaled, with 0 NaNs and 0 infinite values.

---

## 9. Viva Voce Questions & Answers

**Q1: Why is character-level Shannon entropy valuable for web anomaly detection?**  
*Answer:* Shannon entropy measures information density and randomness. Standard web application paths have predictable English/alphanumeric vocabulary with low to moderate entropy (typically 2.0–3.5 bits). Exploitation attempts (e.g., base64-encoded shellcodes, randomized directory fuzzing hashes, or hex-encoded SQL injections) exhibit significantly higher entropy (4.0–6.0+ bits). This makes entropy a powerful numerical indicator for detecting unseen zero-day attacks without predefined signature rules.

**Q2: What is target leakage, and how does Practical 5 prevent it?**  
*Answer:* Target leakage occurs when ground-truth labels or information derived from the target variable are inadvertently included in the feature set during feature engineering or model training, causing overly optimistic evaluation metrics that fail in production. Practical 5 prevents target leakage by strictly excluding `label` and `label_reason` from the feature matrix and computing all behavioral, temporal, and lexical metrics purely from raw HTTP request attributes. Labels are used solely for separate validation.

**Q3: Why was RobustScaler chosen over StandardScaler for normalising the ML-ready dataset?**  
*Answer:* Web honeypot telemetry contains extreme outliers (e.g., vulnerability scanners issuing thousands of requests in seconds or single IPs accounting for 80,000+ requests). `StandardScaler` calculates the mean and standard deviation, both of which are severely distorted by extreme values, compressing normal variations toward zero. `RobustScaler` uses the median and Interquartile Range ($IQR = Q_3 - Q_1$), which are statistically robust to outliers and preserve variance among normal and moderately anomalous records.

**Q4: Why does an anomaly detected by Isolation Forest not necessarily equal a malicious attack?**  
*Answer:* Isolation Forest is an unsupervised algorithm that isolates observations by randomly selecting features and splitting values. Points that isolate quickly (few splits) are statistically anomalous. However, benign events can also be statistically anomalous—such as an administrator performing an unusual late-night database backup or a surge in traffic from a legitimate partner API. Therefore, anomaly detection serves as a prioritization mechanism for triage rather than a deterministic attack verdict.

**Q5: What are the trade-offs between automated feature engineering tools (like TPOT or H2O) versus domain-specific feature engineering in cybersecurity?**  
*Answer:* Automated tools excel at mathematical combinations (polynomial features, PCA, interaction terms), but they lack domain context. They cannot autonomously formulate concepts like directory traversal climbing patterns (`../`), login brute-force sliding windows, or SQL comment evasion (`/**/`). The most effective architecture uses domain-specific feature engineering to create meaningful security indicators, followed by AutoML for pipeline optimization and feature selection.
