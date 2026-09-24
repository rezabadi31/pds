# Practical 1 — Access Log Data Exploration

## Aim
The primary objective of Practical 1 is **To Load and Explore the Unstructured Access Log Data**. Server access logs are continuous, high-volume records generated in raw, unstructured formats. Before applying downstream machine learning, statistical modeling, or cybersecurity intrusion detection, data scientists must master:
1. Safely loading raw access log files without silent data truncation or memory exhaustion.
2. Inspecting raw log entries and identifying format patterns.
3. Formulating robust regular expressions to parse unstructured lines into structured attributes.
4. Handling edge cases such as buffer concatenation (`][`), blank lines, and malformed strings.
5. Ingesting records into a structured Pandas DataFrame and saving as CSV.
6. Conducting exploratory data analysis (EDA) to profile client traffic, scanner tools, and temporal trends.

---

## Dataset
- **File Name:** `cj.log`
- **Location:** `data/raw/cj.log`
- **Archive Origin:** `D:\Logs.rar` (Untouched original archive)
- **File Size:** 225,867,389 bytes (215.40 MB)
- **Total Raw Lines:** 2,062,365
- **Blank Lines:** 934
- **Concatenated Entries:** 911 lines exhibiting `][` multi-record logging artifacts
- **Total Extracted Records:** 2,062,361
- **Successfully Parsed:** 2,062,330 entries
- **Failed Records:** 31 entries
- **Parsing Success Rate:** 99.9985%
- **Time Range:** 2023-01-08 08:07:15 UTC to 2024-02-19 21:44:01 UTC (~407 days, 13 hours)

---

## Log Format
Inspection of the actual raw data reveals that rather than traditional Apache/Nginx Common Log Format (CLF), the data was collected by a **Web Honeypot / Intrusion Detection System Sensor** logging requests as serialized 8-element JSON arrays:

```text
[category_type, payload, timestamp, client_ip, client_port, user_agent, accept_language, proxy_ip]
```

### Extracted Fields:
1. `category_type` (String): Attack category or probe command identifier (e.g., `"auto"`, `"vars"`, `"lang"`, or `null`).
2. `payload` (String): Specific parameter payload or command argument (e.g., `"ps"`, `adminisp`, or `null`).
3. `timestamp` (Datetime): Request arrival timestamp in ISO format (`"YYYY-MM-DD HH:MM:SS"`).
4. `client_ip` (String): Source IPv4/IPv6 client address.
5. `client_port` (Integer): Client ephemeral source TCP port.
6. `user_agent` (String): HTTP User-Agent request header string identifying client tool or browser.
7. `accept_language` (String): HTTP Accept-Language header.
8. `proxy_ip` (String): Forwarded IP reported by reverse proxy or Cloudflare CDN.

---

## Project Structure

```text
D:\Pds Practicals\Practical 1\
│
├── data\
│   ├── raw\
│   │   └── cj.log                       # Actual raw access log (225.87 MB)
│   └── processed\
│       └── parsed_sample.csv            # Structured sample for fast notebook EDA
│
├── notebooks\
│   └── Practical_1_Access_Log_Exploration.ipynb   # 22-section academic Jupyter notebook
│
├── outputs\
│   ├── parsed_logs.csv                 # Complete structured CSV (2,062,330 rows, 161.2 MB)
│   ├── random_samples.txt              # 10 reproducible random sample entries (seed=42)
│   ├── log_structure_report.txt        # Full structure, schema, and quality report
│   ├── exploration_summary.txt         # 15-point analytical findings summary
│   └── plots\
│       ├── top_10_ips.png              # Top 10 client IP traffic distribution
│       ├── top_10_requests.png         # Top 10 requested categories & attack probes
│       └── request_volume_over_time.png# Monthly server request volume timeline
│
├── src\
│   ├── __init__.py
│   └── log_parser.py                   # Reusable parser module
│
├── run_practical1.py                   # Automated end-to-end execution script
├── requirements.txt                    # Project dependencies
└── README.md                           # Documentation and practical report
```

---

## Technologies
- **Python 3.11+**
- **Standard Library Modules:** `re`, `random`, `datetime`, `collections.Counter`, `pathlib.Path`, `csv`, `json`
- **Third-Party Libraries:**
  - `pandas`: Tabular data structures and data manipulation.
  - `numpy`: Numerical operations.
  - `matplotlib`: Publication-quality statistical visualizations.
  - `jupyter`: Interactive notebook environment.

---

## Installation

```bash
# Navigate to the project directory
cd "D:\Pds Practicals\Practical 1"

# Create a virtual environment (optional)
python -m venv .venv

# Activate the virtual environment
.venv\Scripts\activate

# Install required dependencies
pip install -r requirements.txt
```

---

## Running the Practical

Execute the main pipeline directly from the terminal:

```bash
cd "D:\Pds Practicals\Practical 1"
python run_practical1.py
```

### Execution Flow:
```text
============================================================
PRACTICAL 1
ACCESS LOG DATA EXPLORATION
============================================================

[1/8] Locating dataset...
[2/8] Inspecting raw log...
[3/8] Extracting random samples...
[4/8] Detecting log format...
[5/8] Parsing log entries...
[6/8] Creating DataFrame...
[7/8] Generating analysis and visualizations...
[8/8] Saving outputs...

============================================================
FINAL RESULTS
============================================================
Dataset:          cj.log
Log Format:       Web Honeypot / Intrusion Detection Access Log (JSON Array)
Total Entries:    2,062,361
Parsed:           2,062,330
Malformed:        31
Parsing Success:  99.9985%
Fields:           category_type, payload, timestamp, client_ip, client_port, user_agent, accept_language, proxy_ip
Output Directory: outputs/
STATUS: SUCCESS
============================================================
```

---

## Running the Notebook

Open and run the academic practical notebook:

```bash
cd "D:\Pds Practicals\Practical 1"
jupyter notebook notebooks/Practical_1_Access_Log_Exploration.ipynb
```
Or open the folder directly in VS Code / Cursor and select the Python kernel.

### Notebook Sections:
1. **AIM**: Practical objective.
2. **OBJECTIVES**: Learning outcomes.
3. **IMPORT LIBRARIES**: Minimal required imports.
4. **DATASET LOCATION**: Dynamic project-root path resolution.
5. **LOAD RAW ACCESS LOG**: Streaming line reader demonstration.
6. **FIRST 5 RAW LOG ENTRIES**: Raw unstructured line display.
7. **LAST 5 RAW LOG ENTRIES**: Trailing log line display.
8. **RANDOM 10 LOG ENTRIES**: Reproducible sampling with `seed=42`.
9. **UNDERSTANDING LOG STRUCTURE**: 8-field identification table.
10. **REGEX PARSING**: Anchored pattern explanation and single-line parsing demo.
11. **PARSE COMPLETE DATASET**: Parsing metrics and audit report.
12. **CREATE DATAFRAME**: `df.head(10)`, `df.shape`, `df.info()`.
13. **DATA QUALITY**: Missing values and type breakdown.
14. **HTTP METHOD ANALYSIS**: Explanation of schema format characteristics.
15. **STATUS CODE ANALYSIS**: Explanation of schema format characteristics.
16. **TOP IP ADDRESSES**: Frequency table and horizontal bar chart.
17. **TOP REQUESTED RESOURCES**: Category frequency table and horizontal bar chart.
18. **USER-AGENT ANALYSIS**: Automated scanner vs. browser analysis and chart.
19. **TIME ANALYSIS**: Time span and daily request volume trend chart.
20. **IDENTIFY USEFUL FIELDS**: Academic table for downstream practicals.
21. **OBSERVATIONS**: Data-driven analytical findings.
22. **CONCLUSION**: Academic takeaway.

---

## Outputs

- **`outputs/random_samples.txt`**: Exactly 10 reproducible random lines extracted with `seed=42`.
- **`outputs/log_structure_report.txt`**: Comprehensive audit report with file sizes, line counts, missing value percentages, and field explanations.
- **`outputs/parsed_logs.csv`**: Full structured dataset containing all 2,062,330 parsed records (161.2 MB).
- **`outputs/exploration_summary.txt`**: 15-point analytical findings summary.
- **`outputs/plots/top_10_ips.png`**: Publication-quality horizontal bar chart of the top 10 client IP addresses.
- **`outputs/plots/top_10_requests.png`**: Horizontal bar chart of the top 10 requested attack categories / probes.
- **`outputs/plots/request_volume_over_time.png`**: Monthly request volume trend graph covering Jan 2023 – Feb 2024.

---

## Results & Key Findings
1. **Automated Security Tools:** More than **87%** of all 2.06 million server requests were generated by automated directory fuzzing and scanning tools:
   - `gobuster/3.6`: 1,395,592 requests (67.67%)
   - `OWASP DirBuster 1.0-RC1`: 398,116 requests (19.30%)
2. **Attacker Traffic Concentration:**
   - Client IP `212.60.12.161` accounted for 612,203 requests (29.69% of all traffic).
   - The top 5 client IPs combined accounted for over 1.57 million requests (~76% of total traffic).
3. **Attack Signatures:** While 98.68% of entries represent unclassified directory brute-force probes (`null` category), targeted exploit scans hit categories such as `auto` (9,684), `lang` (4,692), `author` (1,325), `XDEBUG_SESSION_START` (593), and PHP remote file inclusion probes.
4. **Data Integrity & Robustness:** Handled 911 concatenated `][` logging lines and 934 blank lines without program crashes, achieving a **99.9985%** parsing success rate.

---

## Conclusion
Practical 1 successfully demonstrated how to inspect, decode, pattern-identify, and parse raw unstructured server access log data into high-quality structured datasets. By utilizing anchored regular expressions, stream-processing generators, and reproducible statistical sampling, over 2.06 million log entries were structured with minimal memory footprint. The resulting structured dataset (`outputs/parsed_logs.csv`) is verified and ready for downstream analytical practicals.
