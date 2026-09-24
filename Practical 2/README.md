# Practical 2 — Converting Unstructured Log Data into a Structured Dataset

## Objective
The primary objective of Practical 2 is **To Convert the Unstructured Log Data into a Structured Dataset**. Server log telemetry is continually emitted as semi-structured or raw serialized strings. In this practical, we:
1. Stream and parse the raw log file without loading the entire 215 MB dataset into memory simultaneously.
2. Extract all fields supported by the source log format into clean typed attributes.
3. Formulate a 13-column tabular dataset incorporating both source-available security attributes and standard web access log columns.
4. Correctly represent unavailable Apache/Nginx fields as `NaN` without manufacturing false values.
5. Ingest the records into a structured Pandas DataFrame, convert timestamps and ports to proper data types, and export the complete dataset to CSV (`data/processed/structured_access_logs.csv`).
6. Validate data quality, cardinalities, missing values, and generate analytical reports and visualizations for practical submission.

---

## Input Dataset
- **Authoritative Source File:** `D:\Pds Practicals\Practical 1\data\raw\cj.log`
- **File Size:** 225,867,389 bytes (215.40 MB)
- **Total Physical Lines:** 2,062,365
- **Blank Lines:** 934
- **Multi-Record Concatenated Lines (`][`):** 911 lines (expanding into 1,841 entries)
- **Total Individual Log Records:** 2,062,361
- **Successfully Parsed Records:** 2,062,361 (100.0000%)
- **Malformed Records:** 0
- **Data Protection:** The original raw log file in Practical 1 is accessed in read-only streaming mode and remains completely untouched.

---

## Log Format
The dataset was produced by a **Web Honeypot / Intrusion Detection System Sensor** logging requests as serialized 8-element JSON arrays:

```text
[category_type, payload, timestamp, client_ip, client_port, user_agent, accept_language, proxy_ip]
```

### Important Academic Distinction:
This is **not** a standard Apache/Nginx Combined Log Format file. Consequently, fields such as HTTP Request Method (`GET`, `POST`), HTTP Status Code (`200`, `404`), Resource URI, Bytes Sent, and Referrer do not exist as distinct standalone fields in the raw records. In accordance with rigorous scientific practices, these 5 columns are maintained as `NaN` (missing values) to preserve schema compatibility without inventing false data.

---

## Tools and Libraries
- **Language:** Python 3.11+
- **Standard Library Modules:** `json`, `pathlib.Path`, `collections.Counter`, `datetime`, `csv`, `re`
- **Third-Party Data Science Stack:**
  - `pandas`: Tabular DataFrame operations, datetime coercion, and CSV generation.
  - `numpy`: Numerical operations and missing value representation (`np.nan`).
  - `matplotlib`: Publication-quality statistical visualizations.
  - `jupyter`: Interactive notebook environment.

---

## Field Mapping

| Raw Array Position | Structured Column | Data Type | Description & Purpose |
| :--- | :--- | :--- | :--- |
| **Index 0** | `category_type` | String | Attack classification or command probe identifier |
| **Index 1** | `payload` | String | Exploit argument, parameter value, or injected command |
| **Index 2** | `timestamp` | Datetime | Request arrival timestamp (UTC, ISO format) |
| **Index 3** | `client_ip` | String | Source IPv4/IPv6 client address |
| **Index 4** | `client_port` | Int64 | Source TCP ephemeral port (converted to integer) |
| **Index 5** | `user_agent` | String | HTTP User-Agent request header |
| **Index 6** | `accept_language` | String | HTTP Accept-Language preference header |
| **Index 7** | `proxy_ip` | String | Secondary or CDN (Cloudflare) forwarded IP address |
| *Unavailable* | `request_type` | Float64 (NaN) | HTTP request method (unavailable in honeypot schema) |
| *Unavailable* | `status_code` | Float64 (NaN) | HTTP response status code (unavailable in honeypot schema) |
| *Unavailable* | `resource_requested` | Float64 (NaN) | URL request path (unavailable in honeypot schema) |
| *Unavailable* | `bytes_sent` | Float64 (NaN) | HTTP response body bytes (unavailable in honeypot schema) |
| *Unavailable* | `referrer` | Float64 (NaN) | HTTP Referer header (unavailable in honeypot schema) |

---

## Parsing Method
1. **Streaming File Reading:** Lines are yielded one by one using a generator with UTF-8 replacement decoding.
2. **Buffer Flush Decomposition (`][`):** 911 lines containing multiple concatenated JSON arrays from logging buffer flushes are split and enclosed in valid brackets (`[...]`).
3. **JSON Parsing:** Native C-accelerated `json.loads` parses each array in ~6.8 seconds with 100% accuracy.
4. **Type Coercion:** Port numbers are cast to integers, timestamps are converted to ISO strings and Pandas datetime, and missing values are mapped to `None` / `NaN`.
5. **Incremental CSV Export:** Records are written directly to disk via `csv.DictWriter`, keeping memory overhead strictly below 150 MB throughout the 2.06M row processing.

---

## DataFrame Structure
```text
<class 'pandas.DataFrame'>
RangeIndex: 2062361 entries, 0 to 2062360
Data columns (total 13 columns):
 #   Column              Non-Null Count    Dtype         
---  ------              --------------    -----         
 0   category_type       27277 non-null    object        
 1   payload             16162 non-null    object        
 2   timestamp           2062361 non-null  datetime64[ns]
 3   client_ip           2062361 non-null  object        
 4   client_port         2062361 non-null  int64         
 5   user_agent          2036208 non-null  object        
 6   accept_language     61677 non-null    object        
 7   proxy_ip            47915 non-null    object        
 8   request_type        0 non-null        float64 (NaN) 
 9   status_code         0 non-null        float64 (NaN) 
 10  resource_requested  0 non-null        float64 (NaN) 
 11  bytes_sent          0 non-null        float64 (NaN) 
 12  referrer            0 non-null        float64 (NaN) 
dtypes: datetime64[ns](1), float64(5), int64(1), object(6)
```

---

## Project Structure

```text
D:\Pds Practicals\Practical 2\
│
├── data\
│   ├── raw\                             # Reference to input data
│   └── processed\
│       ├── structured_access_logs.csv   # Complete structured CSV (2,062,361 rows, 171.02 MB)
│       └── structured_sample.csv        # 10,000-row sample for fast notebook EDA
│
├── notebooks\
│   └── Practical_2_Log_Structuring.ipynb   # Complete academic practical notebook
│
├── outputs\
│   ├── plots\
│   │   ├── top_10_ips.png               # Top 10 client IP traffic bar chart
│   │   ├── top_user_agents.png          # Top 10 user agents bar chart
│   │   ├── records_over_time.png        # Monthly record volume timeline trend
│   │   ├── missing_values.png           # Missing values by column distribution
│   │   └── top_categories.png           # Top attack categories / probes bar chart
│   └── reports\
│       ├── parsing_report.txt           # Official parsing audit and reconciliation report
│       ├── field_mapping_report.txt     # Complete raw-to-structured schema mapping
│       ├── data_quality_report.txt      # Missing values, cardinalities, temporal coverage
│       └── structured_sample.txt        # First 10 structured records for report screenshots
│
├── src\
│   ├── __init__.py                      # Package init
│   └── log_parser.py                    # Streaming JSON parser and structuring engine
│
├── practical_2.py                       # Core implementation module
├── run_practical2.py                    # Executable entry point
├── requirements.txt                     # Dependencies
└── README.md                            # Documentation and project report
```

---

## Output Files
- **`data/processed/structured_access_logs.csv`**: The complete structured dataset (2,062,361 rows, 171.02 MB).
- **`outputs/reports/parsing_report.txt`**: Standard parsing audit report.
- **`outputs/reports/field_mapping_report.txt`**: Detailed transformation documentation.
- **`outputs/reports/data_quality_report.txt`**: Cardinality, missing values, and time span report.
- **`outputs/reports/structured_sample.txt`**: Clean formatted sample for Word report screenshots.
- **`outputs/plots/*.png`**: 5 high-resolution visualization charts.

---

## Data Quality
- **Completeness:** 100% of parsed records contain valid timestamps, client IPs, and source TCP ports.
- **Cardinality:** 1,029 unique client IP addresses and 6,290 unique User-Agent strings.
- **Timeline:** Continuous coverage from **2023-01-08 08:07:15 UTC** to **2024-02-19 21:44:01 UTC** (~407 days).
- **Security Insights:** Over **87%** of requests originate from automated scanners (`gobuster/3.6` and `OWASP DirBuster`), with the top IP (`212.60.12.161`) accounting for 29.69% of all traffic.

---

## Limitations
1. **Unavailable Standard Web Fields:** HTTP method, status code, URL path, response bytes, and referrer are not logged by this honeypot sensor and are correctly set to `NaN`.
2. **Category Sparsity:** 98.68% of entries have `null` category types because the honeypot records general port scans and directory brute-force probes without specific exploit payloads.

---

## How to Run

```bash
# Navigate to the Practical 2 directory
cd "D:\Pds Practicals\Practical 2"

# Execute the complete practical pipeline
python run_practical2.py
```

### Running the Notebook:
```bash
cd "D:\Pds Practicals\Practical 2"
jupyter notebook notebooks/Practical_2_Log_Structuring.ipynb
```
