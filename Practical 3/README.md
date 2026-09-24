# Practical 3 — Data Cleaning and Preprocessing for Access Log Telemetry

## Title
**"To clean the data and Preprocessing for further process of dataset."**

## Course
Predictive Data Science (PDS)

---

## 1. Objective
The primary objective of Practical 3 is to systematically clean, sanitize, and preprocess the structured honeypot and web access-log telemetry generated in Practical 2. Raw logs frequently contain duplicate observations, unrecorded network fields, non-standardized string representations, malformed timestamps, and unnormalized resource paths. 

By applying rigorous, domain-justified preprocessing techniques, this practical transforms the 13-column dataset into a reliable, consistent, and machine-learning-ready format without fabricating false telemetry or compromising original data integrity.

---

## 2. Input Dataset & Integrity Rules
- **Input Reference Path:** `D:\Pds Practicals\Practical 3\data\input\structured_access_logs.csv`
- **Original Source Path:** `D:\Pds Practicals\Practical 2\data\processed\structured_access_logs.csv`
- **Integrity Rule 1:** The Practical 2 dataset is strictly treated as read-only and is never modified or overwritten.
- **Integrity Rule 2:** Missing timestamps are never fabricated with fake dates; invalid timestamps are set to `pd.NaT` using `errors="coerce"`.
- **Integrity Rule 3:** Missing values in categorical fields are imputed with standardized domain placeholders (`unknown` or `none`), preserving their semantic absence.
- **Integrity Rule 4:** URL/path normalization preserves reserved URI query parameters and characters (`/ ? = & : . - _ %`).

---

## 3. Directory Structure
```text
D:\Pds Practicals\Practical 3\
│
├── data\
│   ├── input\
│   │   └── structured_access_logs.csv        # Input reference from Practical 2
│   └── processed\
│       └── preprocessed_access_logs.csv       # Cleaned & normalized output dataset
│
├── outputs\
│   ├── reports\
│   │   ├── preprocessing_report.txt          # Detailed academic execution report
│   │   ├── preprocessing_summary.csv         # Per-column missing handling summary
│   │   └── before_after_comparison.csv       # Pre vs Post preprocessing statistics
│   └── samples\
│       └── preprocessed_sample.csv           # 10,000-row representative verification sample
│
├── src\
│   ├── __init__.py
│   └── preprocessor.py                       # Modular cleaning & normalization routines
│
├── run_practical3.py                         # End-to-end pipeline execution entrypoint
├── verify_preprocessing.py                   # Automated 10-point test verification suite
├── requirements.txt                          # Python dependencies
└── README.md                                 # Complete documentation and viva guide
```

---

## 4. Preprocessing Methodology

### Step 1: Timestamp Conversion
- The `timestamp` column is converted using `pd.to_datetime(..., errors="coerce")`.
- All 2,062,361 timestamps are verified to adhere to standard ISO format (`YYYY-MM-DD HH:MM:SS`).
- Original object string type is cast to native 64-bit datetime (`datetime64[ns]`).

### Step 2: Exact Duplicate Deduplication
- Server logs in high-concurrency environments often record identical network packets across duplicate buffer writes.
- 570,179 exact duplicate rows (identical timestamp, IP, port, payload, and user-agent) are identified and pruned.
- Legitimate repeat visits having distinct timestamps or ephemeral client ports are strictly preserved.

### Step 3: Domain-Justified Missing Value Imputation
Blindly filling missing values with zero corrupts categorical features. Instead, each attribute is treated according to its operational semantics:

| Column Name | Semantic Role | Imputation Strategy | Justification |
| :--- | :--- | :--- | :--- |
| `timestamp` | Temporal | `pd.NaT` (retain) | Fabricating fake timestamps destroys temporal ordering. |
| `client_ip` | Network ID | `'unknown'` | Preserves missing client identity without collision. |
| `client_port` | Transport Port | `0` (int64) | Standard sentinel for unrecorded ephemeral TCP port. |
| `category_type` | Threat Category | `'unknown'` | Benign/unclassified connection attempts produce no category. |
| `payload` | Exploit Data | `'none'` | Standard requests without exploit payload contain no body. |
| `user_agent` | Client Software | `'unknown'` | Missing HTTP User-Agent header (common in raw TCP probes). |
| `accept_language` | Browser Locale | `'unknown'` | Absent in automated network crawlers. |
| `proxy_ip` | CDN / Proxy | `'none'` | Indicates direct client-to-server connection without proxy. |
| `request_type` | HTTP Method | `'unknown'` | Unrecorded HTTP verb in honeypot socket telemetry. |
| `status_code` | HTTP Status | `0` (int64) | 0 denotes unrecorded status code or dropped TCP socket. |
| `resource_requested` | URI Endpoint | Derived / `'/unknown'` | Extracted from payload if path exists, otherwise `'/unknown'`. |
| `bytes_sent` | Body Size | `0` (int64) | 0 bytes sent indicates no response body delivered. |
| `referrer` | HTTP Referer | `'none'` | Indicates direct traffic without referral origin. |

### Step 4: String Sanitization & Lowercasing
- Leading, trailing, and redundant internal whitespace characters are eliminated across all text attributes.
- Categorical attributes (`category_type`, `accept_language`, `request_type`, `referrer`, `proxy_ip`) are converted to lowercase.
- All RFC-reserved URL punctuation (`/ ? = & : . - _ %`) is retained.

### Step 5: URL Path Normalization (`normalized_resource`)
A dedicated normalization function `normalize_url_path()` standardizes endpoints into a consistent feature:
- Trims whitespace.
- Lowercases path components.
- Strips redundant trailing slashes (`/products/` -> `/products`).
- Strips redundant `.html` and `.htm` file extensions:
  - `/index.html` -> `/index`
  - `/login.html` -> `/login`
  - `/about.htm`  -> `/about`
- Preserves query parameters and URL fragments:
  - `/index.html?ref=google` -> `/index?ref=google`

---

## 5. Verification & Quality Assurance
The verification suite (`verify_preprocessing.py`) executes 10 automated assertions:
1. `[PASS]` Timestamp is valid `datetime64[ns]`.
2. `[PASS]` Missing values handled with zero unhandled nulls.
3. `[PASS]` Text fields lowercased where expected.
4. `[PASS]` Leading/trailing whitespace stripped.
5. `[PASS]` URL path normalization rules verified.
6. `[PASS]` Duplicate handling completed.
7. `[PASS]` Numeric columns typed as `int64`.
8. `[PASS]` Important columns preserved (14 total columns).
9. `[PASS]` Output CSV loadable and valid.
10. `[PASS]` Resulting dataset is ML-ready.

---

## 6. Viva Voce Questions & Answers

**Q1: Why should timestamps be converted to datetime objects rather than kept as strings?**  
*Answer:* Datetime objects enable temporal indexing, time-series aggregation, extraction of temporal components (hour of day, day of week), interval arithmetic, and windowed feature engineering which are computationally infeasible with raw string comparisons.

**Q2: Why is it dangerous to fill all missing values with 0?**  
*Answer:* In categorical attributes like IP addresses, User-Agents, or URLs, replacing missing values with 0 falsely treats missing metadata as a numerical quantity, distorting statistical distributions and corrupting encoding steps (e.g. One-Hot or Target Encoding).

**Q3: What is the purpose of URL path normalization like `/index.html` -> `/index`?**  
*Answer:* Web servers often serve the identical resource through multiple aliases (`/index`, `/index.html`, `/index/`). Normalization prevents artificial cardinality explosion, ensuring machine learning models treat requests to the same endpoint as identical observations.

**Q4: Under what conditions should duplicate rows be dropped in access logs?**  
*Answer:* Only exact duplicate rows (where timestamp, IP, port, payload, and client headers are 100% identical) should be removed as logging artifacts. Repeated requests from the same IP at different timestamps or ports represent valid separate visits and must be preserved.
