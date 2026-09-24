# Practical 4 — Basic Request Classification (Benign vs. Attack)

## Title
**"To label the requests as Benign or Attack (Basic Classification) from the dataset."**

## Course
Predictive Data Science (PDS)

---

## 1. Objective
The primary objective of Practical 4 is to build a deterministic, pattern-based security classification engine that assigns ground-truth operational and attack labels to web telemetry without using machine learning. By inspecting request URIs, query parameters, payloads, and client authentication patterns, requests are classified as `benign`, `sqli`, `path_traversal`, `command_injection`, `xss`, or `brute_force`.

---

## 2. Input Dataset & Data Protection
- **Source Input Path:** `D:\Pds Practicals\Practical 3\data\processed\preprocessed_access_logs.csv`
- **Integrity Rule 1:** The Practical 3 preprocessed dataset is accessed strictly in read-only mode and remains completely untouched.
- **Integrity Rule 2:** All 14 original columns from Practical 3 are preserved in their original positions.
- **Integrity Rule 3:** Two new columns are appended: `label` (class name) and `label_reason` (human-readable explanation of why the rule fired).

---

## 3. Directory Structure
```text
D:\Pds Practicals\Practical 4\
│
├── data\
│   └── processed\
│       └── labeled_access_logs.csv           # Final labeled dataset (1.49M rows × 16 columns)
│
├── outputs\
│   ├── reports\
│   │   ├── labeling_report.txt               # Complete technical & academic report
│   │   ├── label_distribution.csv            # Counts and percentages per class
│   │   └── attack_pattern_summary.csv        # Detailed rule definitions & priorities
│   ├── samples\
│   │   └── labeled_samples.csv               # 10,000 representative labeled records
│   └── plots\
│       └── label_distribution.png            # Logarithmic distribution chart (300 DPI)
│
├── src\
│   ├── __init__.py
│   └── labeler.py                            # Modular rule engine & labeling routines
│
├── run_practical4.py                         # Full pipeline execution entrypoint
├── verify_labeling.py                        # Automated 10-point test verification suite
├── requirements.txt                          # Python dependencies
└── README.md                                 # Documentation & viva preparation guide
```

---

## 4. Rule Engine Architecture & Attack Specifications

### Rule 1: SQL Injection (`sqli`) — Priority 1
Detects attempts to manipulate database queries via URL parameters and POST payloads:
- Boolean tautologies: `' OR 1=1`, `' OR '1'='1'`, `OR 1=1 --`
- Keyword combinations: `UNION SELECT`, `UNION ALL SELECT`, `SELECT ... FROM`
- Inline evasion comments: `UNION/**/ALL/**/SELECT`
- DDL / DML operations: `DROP TABLE`, `INSERT INTO`, `UPDATE ... SET`, `DELETE FROM`
- Time-based blind SQLi: `SLEEP(`, `WAITFOR DELAY`
- Administrative procedures: `xp_cmdshell`

### Rule 2: Path Traversal (`path_traversal`) — Priority 2
Detects attempts to access unauthorized files or directories outside the web root:
- Directory climbing: `../`, `..\`
- URL-encoded climbing: `%2e%2e%2f`, `%2e%2e/`, `..%2f`, `%2f..%2f`
- Sensitive targets: `/etc/passwd`, `winnt/win.ini`, `windows/win.ini`, `boot.ini`, `etc/hosts`

### Rule 3: Command Injection (`command_injection`) — Priority 3
Detects attempts to execute arbitrary shell commands on the host operating system:
- Command separators followed by system binaries: `;ls`, `|whoami`, `&&cat /etc/passwd`, `;id`, `|id|`
- Direct shell binary paths: `/bin/sh`, `/bin/bash`
- Malware downloaders & droppers: `wget ... /tmp/jaws`, `sh /tmp/`

### Rule 4: Cross-Site Scripting (`xss`) — Priority 4
Detects client-side script injection in web parameters:
- Script tags: `<script>`, `</script>`
- Protocol handlers: `javascript:`
- DOM event handlers: `onerror=`, `onload=`
- Cookie theft payloads: `alert(document.cookie)`

### Rule 5: Brute Force (`brute_force`) — Priority 5
Detects rapid credential guessing or account enumeration attempts:
- Authentication endpoints: `/login`, `/signin`, `/sign-in`, `/auth`, `/authenticate`, `/wp-login`, `/admin/login`, `logout`, `author`
- Aggregated by `client_ip` and ordered chronologically by `timestamp`.
- Threshold: `>= 10` login attempts within a `10-minute` rolling time window.
- Isolated or benign single login visits from benign users are not flagged as brute force.

### Deterministic Priority Order
When a request matches multiple attack rules, the deterministic hierarchy resolves collisions:
```text
sqli > path_traversal > command_injection > xss > brute_force > benign
```

---

## 5. Verification Suite & Quality Assurance
Run automated verification:
```powershell
python verify_labeling.py
```
Validates:
1. `[PASS]` Output dataset readable and correctly formatted.
2. `[PASS]` `label` and `label_reason` columns created.
3. `[PASS]` No missing labels (0 nulls).
4. `[PASS]` Only approved labels assigned.
5. `[PASS]` All 14 original columns preserved.
6. `[PASS]` SQLi rule applied and verified.
7. `[PASS]` Path traversal rule applied and verified.
8. `[PASS]` Brute force rule evaluated and verified.
9. `[PASS]` Mathematical total consistency: Total = Benign + All Attack Categories.
10. `[PASS]` Real log examples extracted directly from dataset observations.

---

## 6. Viva Voce Questions & Answers

**Q1: Why is rule-based labeling preferred over machine learning at this stage of the pipeline?**  
*Answer:* Unsupervised or semi-supervised ML models can hallucinate classifications without ground-truth labels. Rule-based labeling uses explicit, verifiable security signatures to establish high-confidence ground truth labels, which can subsequently be used for supervised training and model evaluation.

**Q2: How does the pipeline prevent false positives in brute-force detection?**  
*Answer:* Simply counting total requests per IP would incorrectly flag high-traffic benign users. The pipeline first filters strictly for authentication endpoints (`/login`, `/auth`, `wp-login`), sorts by timestamp, and requires at least 10 attempts within a tight 10-minute rolling window from the same IP.

**Q3: What is deterministic label priority, and why is it necessary?**  
*Answer:* Sophisticated exploit payloads often combine multiple techniques (e.g., a SQL injection that includes shell commands or directory climbing). A deterministic hierarchy prevents non-deterministic race conditions and ensures repeatable classification across all runs.

**Q4: How were evasion techniques like inline comments handled in SQL injection detection?**  
*Answer:* Attackers frequently insert SQL comment blocks such as `/**/` (e.g. `UNION/**/ALL/**/SELECT/**/`) to bypass simple whitespace-based filters. The regex engine accommodates flexible whitespace and inline comment patterns `(?:\s+|/\*.*?\*/)+` to ensure complete coverage.
