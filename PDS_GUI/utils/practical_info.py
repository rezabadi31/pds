"""practical_info.py
Authoritative Academic Descriptions, Methodology Summaries, and Technical Q&A
Tailored for technical project defense and comprehensive system evaluation.
"""

from typing import Dict, Any, List

PRACTICAL_DETAILS: Dict[int, Dict[str, Any]] = {
    1: {
        "title": "Data Inspection",
        "aim": "To load, inspect, and explore the unstructured web honeypot access log data.",
        "objective": "Understand the schema, size, raw formatting, and character encoding of the access log dataset before applying any data transformations.",
        "what_i_did": "I inspected the raw log file (cj.log), verified its size (215.40 MB) and physical line count (2,061,431), identified that lines were serialized JSON arrays, and checked for malformed or concatenated entries.",
        "why_required": "Raw log telemetry cannot be ingested blindly; inspecting the raw structure reveals delimiter variations and prevents pipeline crashes during parsing.",
        "input": "Practical 1/data/raw/cj.log",
        "process": "1. Safe streaming line generator with UTF-8 decoding.\n2. Concatenated array splitting on ']['.\n3. Regex pattern matching against Honeypot JSON array and Common Log formats.\n4. Auditing column schema and non-blank lines.",
        "output": "outputs/reports/inspection_report.txt and exploratory statistics.",
        "result": "Identified 2,061,431 raw records capturing 8 core attributes with zero fatal decoding errors.",
        "key_stats": {
            "Raw File Size": "215.40 MB",
            "Physical Lines": "2,061,431",
            "Detected Schema": "8-Element JSON Array",
            "Decoding Errors": "0",
        },
    },
    2: {
        "title": "Log Parsing & Structuring",
        "aim": "To convert the unstructured raw log data into a structured tabular dataset.",
        "objective": "Extract the raw JSON elements into a clean 13-column Pandas DataFrame adhering to canonical web telemetry schemas.",
        "what_i_did": "I built a streaming JSON parsing engine that mapped the 8 available source attributes and aligned 5 standard HTTP fields, generating structured_access_logs.csv.",
        "why_required": "Machine learning algorithms and data analysis tools require structured tabular inputs rather than unstructured string blobs.",
        "input": "Practical 1 raw cj.log",
        "process": "1. Stream line-by-line reading.\n2. Handle multiple JSON records per buffer line.\n3. Safe json.loads extraction.\n4. Map into 13 structured fields (category_type, payload, timestamp, client_ip, client_port, user_agent, accept_language, proxy_ip, request_type, status_code, resource_requested, bytes_sent, referrer).\n5. Stream directly to CSV.",
        "output": "data/processed/structured_access_logs.csv (2,062,226 rows × 13 columns).",
        "result": "100% parsing success rate; 0 malformed records.",
        "key_stats": {
            "Records Parsed": "2,062,226",
            "Structured Columns": "13",
            "Parsing Success": "100.0%",
            "Malformed Records": "0",
        },
    },
    3: {
        "title": "Data Cleaning & Preprocessing",
        "aim": "To clean, standardize, and preprocess the structured dataset for machine learning readiness.",
        "objective": "Handle missing values, parse timestamps, normalize resource paths, and remove exact duplicate records without corrupting security signals.",
        "what_i_did": "I converted timestamps to datetime64[ns], eliminated 570,179 exact duplicate records, imputed missing values using domain-justified strategies, and normalized web resource paths into 'normalized_resource'.",
        "why_required": "Exact duplicates artificially skew traffic volumes and model evaluation. Normalizing paths (/index.html -> /index) groups identical endpoints for reliable behavioral profiling.",
        "input": "Practical 2 structured_access_logs.csv",
        "process": "1. Convert timestamps with errors='coerce'.\n2. Deduplicate exact duplicate rows across all attributes.\n3. Domain-specific missing value imputation ('unknown', 'none', 0).\n4. Regex path normalization into normalized_resource.\n5. Cast numeric datatypes.",
        "output": "data/processed/preprocessed_access_logs.csv (1,492,047 rows × 14 columns).",
        "result": "Removed 570,179 exact duplicates; resolved 18.4 million missing values with zero residual NaNs or invalid timestamps.",
        "key_stats": {
            "Records Before": "2,062,226",
            "Exact Duplicates Removed": "570,179",
            "Records After": "1,492,047",
            "Missing Values Remaining": "0",
        },
    },
    4: {
        "title": "Attack Labeling",
        "aim": "To classify web requests into benign and attack categories using deterministic rule-based detection.",
        "objective": "Create ground-truth multi-class labels ('label') and human-readable audit explanations ('label_reason') based on observable attack patterns without using ML.",
        "what_i_did": "I engineered a prioritized deterministic rule engine that scanned payloads and normalized resources for SQL injection, path traversal, command injection, XSS, and sliding-window brute-force authentication attempts.",
        "why_required": "Supervised machine learning requires accurate, auditable ground-truth labels. Rule-based labeling ensures complete transparency before model training.",
        "input": "Practical 3 preprocessed_access_logs.csv",
        "process": "1. Build consolidated searchable text from payload, resource, and category.\n2. Evaluate brute-force attacks (>=10 login attempts in 10-minute sliding window per IP).\n3. Match regex signatures for XSS, Command Injection, Path Traversal, and SQLi.\n4. Apply strict priority: SQLi > Traversal > CMDi > XSS > Brute Force > Benign.\n5. Populate label and label_reason.",
        "output": "data/processed/labeled_access_logs.csv (1,492,047 rows × 16 columns).",
        "result": "Identified 4,365 malicious attacks across 5 distinct classes, alongside 1,487,682 benign requests.",
        "key_stats": {
            "Benign Traffic": "1,487,682 (99.71%)",
            "Brute Force": "1,342",
            "Path Traversal": "1,098",
            "XSS": "960",
            "Command Injection": "805",
            "SQL Injection": "160",
        },
    },
    5: {
        "title": "Feature Engineering",
        "aim": "To engineer numerical behavioral, lexical, and structural features for cybersecurity attack detection.",
        "objective": "Transform raw text and timestamps into 66 discriminative numeric features capturing request rates, Shannon entropies, path depths, and temporal dynamics.",
        "what_i_did": "I computed client-IP request densities over 1-min and 5-min rolling windows, calculated Shannon entropy of URLs and payloads, extracted lexical ratios, and generated automated Featuretools and tsfresh temporal features.",
        "why_required": "Machine learning algorithms cannot directly ingest raw strings or timestamps; numerical features represent behavioral patterns mathematically.",
        "input": "Practical 4 labeled_access_logs.csv",
        "process": "1. IP-level aggregation: requests_per_ip, ip_request_rank.\n2. Temporal dynamics: inter_request_time, 1m/5m/10m rolling request counts using vectorized np.searchsorted.\n3. Lexical & Shannon entropy on URLs and payloads.\n4. Security heuristic indicators (SQL keywords, directory climbing, shell separators).\n5. Automated feature synthesis.",
        "output": "data/processed/feature_engineered_access_logs.csv (1,492,182 rows × 80 columns, 66 numeric ML features).",
        "result": "Constructed a 66-dimensional numeric feature matrix with zero target leakage.",
        "key_stats": {
            "Total Engineered Features": "66 ML Features",
            "Primary Indicators": "Entropy, Request Rates, Lexical Ratios",
            "Rolling Windows": "1-min, 5-min, 10-min",
            "Target Leakage": "0% (Strictly Excluded)",
        },
    },
    6: {
        "title": "Dataset Balancing",
        "aim": "To address severe class imbalance in cybersecurity telemetry using sampling strategies.",
        "objective": "Mitigate the 9,298:1 benign-to-attack imbalance using SMOTE and oversampling on the training partition while keeping the test set untouched.",
        "what_i_did": "I isolated an untouched 20% test partition (298,437 rows), then applied SMOTE to the 80% training partition, synthesizing minority attack samples to produce a balanced 60,000-record training dataset (10,000 per class).",
        "why_required": "Training directly on imbalanced data causes models to predict only the majority benign class. Balancing the training partition forces models to learn attack decision boundaries.",
        "input": "Practical 5 feature_engineered_access_logs.csv",
        "process": "1. Stratified 80/20 train/test split.\n2. Export untouched test partition to test_dataset.csv.\n3. Cap benign class in training partition.\n4. Apply SMOTE to synthesize minority samples (SQLi, CMDi, XSS, Traversal, Brute Force).\n5. Verify zero test-set contamination.",
        "output": "data/processed/balanced_training_dataset.csv (60,000 rows) and test_dataset.csv (298,437 rows).",
        "result": "Created balanced training set with exactly 10,000 samples per class while preserving test distribution.",
        "key_stats": {
            "Original Imbalance Ratio": "9,298.89 : 1",
            "Balanced Train Dataset": "60,000 records (10k / class)",
            "Untouched Test Dataset": "298,437 records",
            "Balancing Algorithm": "SMOTE + Controlled Resampling",
        },
    },
    7: {
        "title": "Data Wrangling",
        "aim": "To perform multi-dimensional data wrangling, aggregation, and behavioral profiling.",
        "objective": "Extract threat intelligence insights by grouping telemetry by client IP, temporal intervals, HTTP methods, and status codes.",
        "what_i_did": "I aggregated request frequencies by client IP, analyzed attack distribution by hour and day, cross-tabulated status codes against attack categories, and separated internal vs. external IP behaviors.",
        "why_required": "Data wrangling bridges raw feature tables and high-level security insights, revealing attacker origins and reconnaissance campaigns.",
        "input": "Practical 5 feature_engineered_access_logs.csv",
        "process": "1. Pivot tables of top attacking IPs.\n2. Hourly and daily time-series resamplings.\n3. Correlation matrices between error ratios and attack flags.\n4. Export wrangled summary tables.",
        "output": "data/processed/wrangled_filtered_dataset.csv, summary tables, and analytical reports.",
        "result": "Identified top 10 threat actor IPs responsible for over 80% of automated probe bursts.",
        "key_stats": {
            "Aggregated Tables": "8 Profiling Views",
            "Top Threat IPs": "10 Key Botnet Hosts",
            "Temporal Grouping": "Hourly & Daily Trends",
            "Wrangled Records": "1,492,182",
        },
    },
    8: {
        "title": "Data Visualization & EDA",
        "aim": "To conduct exploratory data analysis and visualize attack patterns and feature distributions.",
        "objective": "Produce publication-quality visual diagnostics illustrating attack trends, IP behaviors, and statistical feature distributions.",
        "what_i_did": "I generated 15 comprehensive visualization charts using Matplotlib and Seaborn, and interactive HTML dashboards using Plotly, covering traffic volume by hour, top attacking IPs, and correlation heatmaps.",
        "why_required": "Visual analytics allow security analysts and evaluators to immediately perceive attack surges, anomalous payload lengths, and error rate spikes.",
        "input": "Practical 7 wrangled_filtered_dataset.csv",
        "process": "1. Requests-per-hour temporal line charts.\n2. Horizontal bar charts of top malicious IPs.\n3. Log-scale attack category distributions.\n4. Correlation heatmap of numeric security features.\n5. Interactive Plotly dashboards.",
        "output": "outputs/plots/ (15 PNG figures) and outputs/interactive/ (HTML dashboards).",
        "result": "Clearly demonstrated temporal clustering of brute-force attacks and high entropy in SQLi payloads.",
        "key_stats": {
            "Total Static Charts": "15 PNG Plots",
            "Interactive Dashboards": "Plotly HTML Views",
            "Key Insights": "Night-time attack spikes, high payload entropy",
            "Tools": "Matplotlib, Seaborn, Plotly",
        },
    },
    9: {
        "title": "Simple Attack Classifier",
        "aim": "To build, train, and evaluate machine learning classifiers for automated cyberattack detection.",
        "objective": "Compare linear (Logistic Regression) vs. non-linear ensemble (Random Forest) models using rigorous multi-class metrics (Accuracy, Macro Precision, Recall, and Macro F1).",
        "what_i_did": "I trained Logistic Regression (with StandardScaler) and Random Forest (100 trees) on 1,193,745 training records, evaluated them on 298,437 untouched test records, and analyzed confusion matrices and Gini feature importances.",
        "why_required": "Rule-based systems cannot generalize to new variations; machine learning models detect complex multi-feature attack combinations automatically.",
        "input": "Practical 5 feature_engineered_access_logs.csv",
        "process": "1. Stratified 80/20 train/test partition.\n2. Fit StandardScaler strictly on X_train for Logistic Regression.\n3. Train Logistic Regression (max_iter=300, class_weight='balanced').\n4. Train Random Forest (n_estimators=100, class_weight='balanced').\n5. Generate multiclass confusion matrices and classification reports.\n6. Extract top 20 Gini feature importances.",
        "output": "outputs/models/ (joblib files), confusion matrices, and model_comparison.csv.",
        "result": "Random Forest achieved 99.97% Accuracy and 95.26% Macro F1, outperforming Logistic Regression (97.07% Accuracy, 45.18% Macro F1).",
        "key_stats": {
            "Random Forest Accuracy": "99.97%",
            "Random Forest Macro F1": "95.26%",
            "Logistic Regression Accuracy": "97.07%",
            "Logistic Regression Macro F1": "45.18%",
            "Test Set Evaluation": "298,437 Untouched Records",
        },
    },
    10: {
        "title": "Reusable Data Pipeline",
        "aim": "To integrate Practicals 1–5 into an automated, modular, and reusable Python data pipeline.",
        "objective": "Build a production-grade LogProcessingPipeline class supporting CLI arguments (--input, --output, --format) and exporting CSV and Apache Parquet datasets.",
        "what_i_did": "I combined loading, structuring, preprocessing, labeling, feature engineering, and 14 automated validation checks into a reusable class that processed 2.06M records in under 2 minutes.",
        "why_required": "Running manual scripts step-by-step is error-prone; an automated pipeline enables continuous security log processing for live production environments.",
        "input": "Default cj.log or custom input specified via CLI.",
        "process": "1. [1/7] Safe streaming ingestion.\n2. [2/7] JSON structuring into 13 fields.\n3. [3/7] Cleaning, deduplication, path normalization.\n4. [4/7] Prioritized rule labeling with label_reason.\n5. [5/7] Vectorized feature engineering (26 numeric features).\n6. [6/7] 14 automated validation checks.\n7. [7/7] Multi-format export (CSV and Parquet).",
        "output": "feature_engineered_logs.csv, feature_engineered_logs.parquet (97.8% compression), and audit reports.",
        "result": "14/14 validation checks passed; pipeline executes end-to-end without manual intervention.",
        "key_stats": {
            "Pipeline Execution Time": "~116 Seconds",
            "Parquet File Size": "9.46 MB (97.8% Compression)",
            "Automated Validations": "14/14 PASS",
            "CLI Support": "--input, --output, --format",
        },
    },
}

VIVA_QUESTIONS: List[Dict[str, str]] = [
    {
        "q": "1. What is the overarching objective of this project?",
        "a": "This project builds an end-to-end data science and machine learning pipeline that ingests raw, unstructured web honeypot access logs, cleans and structures them, detects cyberattacks via deterministic rule-based labeling, engineers domain-specific behavioral features, addresses severe class imbalance, evaluates machine learning classifiers, and packages the entire workflow into a reusable data engineering pipeline.",
    },
    {
        "q": "2. What raw dataset was used, and what was its original format?",
        "a": "The primary dataset is cj.log (215.40 MB, 2,061,431 records), which captures web honeypot connection telemetry. Each record is serialized as an 8-element JSON array containing: category_type, payload, timestamp, client_ip, client_port, user_agent, accept_language, and proxy_ip.",
    },
    {
        "q": "3. Why was it necessary to parse the raw log into a 13-column structured schema?",
        "a": "Raw logs are stored as unstructured text lines. To enable standardized filtering, Pandas vectorized operations, and machine learning, the 8 available source attributes were extracted and aligned with 5 standard web server HTTP fields (request_type, status_code, resource_requested, bytes_sent, referrer), setting unavailable fields safely to neutral null values.",
    },
    {
        "q": "4. Why did you remove exact duplicate records in Practical 3, and how many were removed?",
        "a": "We removed 570,179 exact duplicate records (dropping row count from 2,062,226 to 1,492,047). In high-volume honeypots, exact identical logs occur due to buffer re-flushes and network retransmissions. Removing exact duplicates prevents artificial inflation of traffic volumes while preserving legitimate repeated requests that differ by timestamp or port.",
    },
    {
        "q": "5. What is the purpose of URL path normalization, and how does it work?",
        "a": "Web clients and scanners request identical resources using varying syntaxes (e.g., /index.html, /INDEX.HTML, /index/, //index). Path normalization converts strings to lowercase, strips trailing slashes, collapses double slashes, and removes redundant .html/.htm extensions, standardizing them into a canonical 'normalized_resource' column.",
    },
    {
        "q": "6. How were ground-truth attack labels created in Practical 4? Did you use an ML model?",
        "a": "No, machine learning was deliberately NOT used for labeling. Ground-truth labels were generated using deterministic rule-based pattern matching based on observable security signatures. This prevents circular logic and ensures auditable ground truth.",
    },
    {
        "q": "7. What attack classes are identified by your rule-based engine?",
        "a": "Six distinct classes: benign (normal traffic), sqli (SQL Injection), path_traversal (directory climbing), command_injection (OS shell execution), xss (Cross-Site Scripting), and brute_force (repeated authentication bursts).",
    },
    {
        "q": "8. What priority order was used for resolving multi-pattern matches during labeling?",
        "a": "The strict deterministic priority order is: (1) SQL Injection > (2) Path Traversal > (3) Command Injection > (4) Cross-Site Scripting > (5) Brute Force > (6) Benign. This ensures severe injection vulnerabilities take precedence over generic anomalies.",
    },
    {
        "q": "9. How did you define and detect brute-force attacks without session cookies?",
        "a": "Brute force was detected temporally: requests targeting authentication or login endpoints (e.g., /login, /admin/login, /wp-login, author queries) were grouped by client_ip and evaluated using a 10-minute sliding window. Any client IP initiating >= 10 login requests within 10 minutes was flagged as brute_force.",
    },
    {
        "q": "10. Why is feature engineering critical in this project?",
        "a": "Machine learning models cannot directly process raw timestamps, IP strings, or text payloads. Feature engineering translates raw logs into numeric representations—such as request rates per second, Shannon entropy of URLs and payloads, and inter-arrival intervals—that reflect suspicious behavior mathematically.",
    },
    {
        "q": "11. What is Shannon Entropy, and how does it indicate a cyberattack?",
        "a": "Shannon entropy measures the informational randomness and character diversity of a string: H(X) = -sum(p(x) * log2(p(x))). Normal URLs have low entropy due to structured English keywords. Attack payloads (e.g., SQL hex encodings, Base64 payloads, obfuscated shell commands) exhibit significantly higher entropy.",
    },
    {
        "q": "12. What was the class imbalance ratio in Practical 6, and why was it a major challenge?",
        "a": "The dataset exhibited extreme class imbalance: 1,487,823 benign records vs. only 160 SQLi records (an imbalance ratio of 9,298.89 : 1). Over 99.7% of all traffic was benign. A naive classifier predicting 'benign' 100% of the time would achieve 99.7% accuracy while completely failing to detect every single cyberattack.",
    },
    {
        "q": "13. How did you resolve the class imbalance problem?",
        "a": "We applied SMOTE (Synthetic Minority Over-sampling Technique) combined with controlled benign downsampling to the training partition only. This synthesized minority attack records using k-nearest neighbors in feature space, creating a balanced training dataset of 60,000 records (10,000 per class).",
    },
    {
        "q": "14. Did you apply SMOTE or balancing to the test dataset? Why or why not?",
        "a": "Absolutely NOT. The 20% test partition (298,437 records) was kept strictly untouched in its natural, imbalanced distribution. Balancing the test set would artificially distort evaluation and cause data snooping / data contamination.",
    },
    {
        "q": "15. What machine learning models did you train in Practical 9?",
        "a": "We trained two contrasting architectures: (1) Multinomial Logistic Regression with L2 regularization (a linear baseline model trained with StandardScaler), and (2) Random Forest Classifier with 100 decision trees (a non-linear ensemble). Both utilized class_weight='balanced'.",
    },
    {
        "q": "16. What evaluation metrics did you use, and why is accuracy insufficient?",
        "a": "We evaluated Accuracy, Macro Precision, Macro Recall, Macro F1, and Weighted F1. Accuracy is misleading in imbalanced domains because classifying all samples as benign yields 99.7% accuracy. Macro F1 gives equal weight to all six classes regardless of sample size, making it the true metric of attack detection capability.",
    },
    {
        "q": "17. What were the exact comparative results between Logistic Regression and Random Forest?",
        "a": "Random Forest achieved 99.97% Accuracy, 93.08% Macro Precision, 97.63% Macro Recall, and 95.26% Macro F1. Logistic Regression achieved 97.07% Accuracy, 38.67% Macro Precision, 98.45% Macro Recall, and 45.18% Macro F1.",
    },
    {
        "q": "18. Why did Logistic Regression achieve high recall (98.45%) but lower precision (38.67%)?",
        "a": "With class_weight='balanced', the linear decision boundary is penalized heavily for missing any attack instance, forcing it to aggressively flag suspicious requests. Because linear hyperplanes cannot easily separate overlapping high-dimensional clusters, it misclassified several thousand benign requests as attacks, reducing precision.",
    },
    {
        "q": "19. Which features had the highest Gini importance in the Random Forest model?",
        "a": "The top discriminative features were: (1) payload_entropy, (2) payload_length, (3) requests_per_ip, (4) failed_pattern_count, (5) path_depth, (6) requests_per_ip_1min, (7) special_character_count, and (8) url_length.",
    },
    {
        "q": "20. What is Practical 10, and how does it differ from Practical 5?",
        "a": "Practical 5 focused specifically on feature engineering experimentation. Practical 10 is an automated, reusable, production-ready pipeline that integrates loading, parsing, cleaning, labeling, feature engineering, and 14 automated validation checks into a single command-line interface supporting CSV and Parquet export.",
    },
    {
        "q": "21. Why did you include Apache Parquet export in Practical 10, and what advantage did it provide?",
        "a": "Apache Parquet is a columnar, compressed storage format optimized for big data queries. In Practical 10, the final dataset was 429.8 MB in CSV format, but compressed down to just 9.46 MB in Parquet—a 97.8% file size reduction with significantly faster read/write speeds.",
    },
    {
        "q": "22. How did you ensure zero data leakage throughout the machine learning workflow?",
        "a": "We enforced strict isolation: (1) 'label' and 'label_reason' were excluded from feature matrices, (2) StandardScaler was fitted strictly on X_train and only transformed on X_test, (3) train/test split was performed prior to scaling or balancing, and (4) test sets remained un-augmented.",
    },
    {
        "q": "23. What are the practical limitations of this system in a real-world enterprise SOC?",
        "a": "Key limitations include: (1) Adversarial evasion (attackers using payload fragmentation or deliberate slow-rate probing), (2) Concept drift (new zero-day attack patterns require updated training data), and (3) Honeypot schema constraints (status codes and body byte counts were unavailable in the raw source).",
    },
    {
        "q": "24. Can your pipeline process new, incoming log files automatically?",
        "a": "Yes. Practical 10 provides a reusable CLI command: python run_pipeline.py --input <path_to_log> --format parquet, allowing any compatible web log file to be ingested, preprocessed, labeled, and converted to features automatically.",
    },
    {
        "q": "25. Were any paid tools, cloud services, or external APIs used anywhere in the project?",
        "a": "No. The entire project was implemented 100% locally on Windows using free, open-source Python libraries (Pandas, NumPy, Scikit-learn, Matplotlib, Seaborn, Plotly, PyArrow, Streamlit, Joblib).",
    },
]
