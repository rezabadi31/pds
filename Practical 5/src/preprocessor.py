"""preprocessor.py
Feature Scaling, Imputation, and ML-Ready Matrix Preparation
Transforms engineered features into an outlier-robust, machine-learning-ready matrix.
"""

from typing import Tuple, List, Dict
import pandas as pd
import numpy as np
from sklearn.preprocessing import RobustScaler
from src.config import (
    FEATURE_DICT_CSV,
    FEATURE_STATS_CSV,
    FEATURE_CORR_CSV,
    ML_READY_CSV,
    FEATURE_ENGINEERED_CSV,
    FEATURE_SAMPLE_CSV,
    SAMPLE_SIZE_EXPORT,
    RANDOM_STATE,
)

FEATURE_METADATA: List[Dict[str, str]] = [
    {
        "Feature": "request_hour",
        "Type": "Numerical (Discrete)",
        "Description": "Hour of the day (0-23) when the HTTP request arrived",
        "Source Column": "timestamp",
        "Anomaly Relevance": "Off-peak hours may correlate with automated intrusion scans",
    },
    {
        "Feature": "request_day_of_week",
        "Type": "Numerical (Discrete)",
        "Description": "Day of the week (0=Mon to 6=Sun)",
        "Source Column": "timestamp",
        "Anomaly Relevance": "Weekend vs weekday behavioral variance",
    },
    {
        "Feature": "is_night",
        "Type": "Binary Flag",
        "Description": "Indicator (1) if request arrived during 00:00-06:00, else (0)",
        "Source Column": "timestamp",
        "Anomaly Relevance": "Probes concentrated during low human operator supervision hours",
    },
    {
        "Feature": "requests_per_ip",
        "Type": "Numerical (Discrete)",
        "Description": "Total volume of requests originated from this client IP",
        "Source Column": "client_ip",
        "Anomaly Relevance": "Extreme volumes indicate aggressive scanning or DoS",
    },
    {
        "Feature": "ip_request_rank",
        "Type": "Numerical (Discrete)",
        "Description": "Dense ordinal rank of client IP by total traffic volume (1 = top)",
        "Source Column": "client_ip",
        "Anomaly Relevance": "Prioritizes heavy traffic sources in volume distribution",
    },
    {
        "Feature": "time_since_previous_request",
        "Type": "Numerical (Continuous)",
        "Description": "Elapsed time in seconds since previous request from same IP",
        "Source Column": "client_ip, timestamp",
        "Anomaly Relevance": "Sub-second deltas suggest automated tool scraping",
    },
    {
        "Feature": "mean_inter_request_time_ip",
        "Type": "Numerical (Continuous)",
        "Description": "Average inter-arrival interval for client IP in seconds",
        "Source Column": "client_ip, timestamp",
        "Anomaly Relevance": "Distinguishes high-speed automation from manual human browsing",
    },
    {
        "Feature": "median_inter_request_time_ip",
        "Type": "Numerical (Continuous)",
        "Description": "Median inter-arrival interval for client IP in seconds",
        "Source Column": "client_ip, timestamp",
        "Anomaly Relevance": "Robust measure of pacing unaffected by idle pauses",
    },
    {
        "Feature": "min_inter_request_time_ip",
        "Type": "Numerical (Continuous)",
        "Description": "Minimum observed inter-arrival interval for client IP in seconds",
        "Source Column": "client_ip, timestamp",
        "Anomaly Relevance": "Detects bursts and concurrent socket flooding",
    },
    {
        "Feature": "rapid_request_flag",
        "Type": "Binary Flag",
        "Description": "1 if time since previous request <= 1.0 second, else 0",
        "Source Column": "time_since_previous_request",
        "Anomaly Relevance": "Identifies rapid successive calls characteristic of automated scripts",
    },
    {
        "Feature": "requests_per_ip_1min",
        "Type": "Numerical (Discrete)",
        "Description": "Rolling count of requests from same IP in the preceding 60 seconds",
        "Source Column": "client_ip, timestamp",
        "Anomaly Relevance": "Detects immediate rate spikes and burst probing",
    },
    {
        "Feature": "requests_per_ip_5min",
        "Type": "Numerical (Discrete)",
        "Description": "Rolling count of requests from same IP in the preceding 5 minutes",
        "Source Column": "client_ip, timestamp",
        "Anomaly Relevance": "Detects sustained medium-window brute force campaigns",
    },
    {
        "Feature": "requests_per_ip_10min",
        "Type": "Numerical (Discrete)",
        "Description": "Rolling count of requests from same IP in the preceding 10 minutes",
        "Source Column": "client_ip, timestamp",
        "Anomaly Relevance": "Evaluates long-window crawl volume",
    },
    {
        "Feature": "status_404_count_ip",
        "Type": "Numerical (Discrete)",
        "Description": "Total 404 Not Found HTTP responses received by client IP",
        "Source Column": "status_code",
        "Anomaly Relevance": "High 404 counts indicate directory or file fuzzing",
    },
    {
        "Feature": "status_404_ratio_ip",
        "Type": "Numerical (Continuous)",
        "Description": "Proportion of total requests from IP that resulted in 404 (0.0-1.0)",
        "Source Column": "status_code",
        "Anomaly Relevance": "Ratios >0.5 strongly correlate with scanning behavior",
    },
    {
        "Feature": "error_status_ratio_ip",
        "Type": "Numerical (Continuous)",
        "Description": "Proportion of requests yielding 4xx/5xx error status codes",
        "Source Column": "status_code",
        "Anomaly Relevance": "General measure of client error-generation propensity",
    },
    {
        "Feature": "high_404_activity_flag",
        "Type": "Binary Flag",
        "Description": "1 if 404 ratio >= 0.50 OR 404 count >= 20, else 0",
        "Source Column": "status_404_ratio_ip",
        "Anomaly Relevance": "Discrete alert trigger for directory brute-forcing",
    },
    {
        "Feature": "user_agent_type",
        "Type": "Categorical",
        "Description": "Taxonomy classification: browser, bot, scanner, script, unknown",
        "Source Column": "user_agent",
        "Anomaly Relevance": "Differentiates genuine interactive clients from tool suites",
    },
    {
        "Feature": "is_bot",
        "Type": "Binary Flag",
        "Description": "1 if client is an identified bot, spider, or script, else 0",
        "Source Column": "user_agent",
        "Anomaly Relevance": "Flags non-interactive automation engines",
    },
    {
        "Feature": "is_scanner",
        "Type": "Binary Flag",
        "Description": "1 if client matches known vulnerability/dir scanner signatures, else 0",
        "Source Column": "user_agent",
        "Anomaly Relevance": "High-confidence signature of reconnaissance tools",
    },
    {
        "Feature": "user_agent_length",
        "Type": "Numerical (Discrete)",
        "Description": "Character length of the User-Agent header string",
        "Source Column": "user_agent",
        "Anomaly Relevance": "Abnormally short or long headers suggest spoofing",
    },
    {
        "Feature": "unique_user_agents_per_ip",
        "Type": "Numerical (Discrete)",
        "Description": "Count of distinct User-Agent headers emitted by same client IP",
        "Source Column": "client_ip, user_agent",
        "Anomaly Relevance": "User-agent rotation used by evading scanners or proxies",
    },
    {
        "Feature": "unique_urls_per_ip",
        "Type": "Numerical (Discrete)",
        "Description": "Count of distinct resource paths requested by client IP",
        "Source Column": "client_ip, normalized_resource",
        "Anomaly Relevance": "Broad endpoint sweeps characteristic of web crawlers",
    },
    {
        "Feature": "unique_ports_per_ip",
        "Type": "Numerical (Discrete)",
        "Description": "Count of distinct client ephemeral ports utilized",
        "Source Column": "client_ip, client_port",
        "Anomaly Relevance": "Port cycling or single-port persistence metrics",
    },
    {
        "Feature": "url_entropy",
        "Type": "Numerical (Continuous)",
        "Description": "Character-level Shannon entropy of normalized resource path",
        "Source Column": "normalized_resource",
        "Anomaly Relevance": "High entropy flags random hashes, obfuscated injections",
    },
    {
        "Feature": "url_length",
        "Type": "Numerical (Discrete)",
        "Description": "Character length of the requested resource path",
        "Source Column": "normalized_resource",
        "Anomaly Relevance": "Excessive lengths indicate buffer overflow or deep traversal",
    },
    {
        "Feature": "path_depth",
        "Type": "Numerical (Discrete)",
        "Description": "Number of '/' hierarchy delimiters in resource path",
        "Source Column": "normalized_resource",
        "Anomaly Relevance": "Directory tree traversal depth indicator",
    },
    {
        "Feature": "number_of_query_parameters",
        "Type": "Numerical (Discrete)",
        "Description": "Count of key-value query parameters attached to URL",
        "Source Column": "normalized_resource",
        "Anomaly Relevance": "Parameter fuzzing and complex payload delivery",
    },
    {
        "Feature": "special_character_count",
        "Type": "Numerical (Discrete)",
        "Description": "Count of non-alphanumeric characters in URL string",
        "Source Column": "normalized_resource",
        "Anomaly Relevance": "High symbol density flags encoding, quotes, and punctuation attacks",
    },
    {
        "Feature": "digit_ratio",
        "Type": "Numerical (Continuous)",
        "Description": "Ratio of numeric digits to total URL length",
        "Source Column": "normalized_resource",
        "Anomaly Relevance": "Numeric IDs vs hex-encoded shellcode",
    },
    {
        "Feature": "letter_ratio",
        "Type": "Numerical (Continuous)",
        "Description": "Ratio of alphabetic characters to total URL length",
        "Source Column": "normalized_resource",
        "Anomaly Relevance": "Low letter ratio indicates symbol-heavy or binary payloads",
    },
    {
        "Feature": "payload_length",
        "Type": "Numerical (Discrete)",
        "Description": "Character length of the request payload body",
        "Source Column": "payload",
        "Anomaly Relevance": "Unusually large payloads indicate injection attempts",
    },
    {
        "Feature": "payload_entropy",
        "Type": "Numerical (Continuous)",
        "Description": "Character-level Shannon entropy of the payload",
        "Source Column": "payload",
        "Anomaly Relevance": "High entropy highlights encrypted or encoded attack payloads",
    },
    {
        "Feature": "contains_sql_keyword",
        "Type": "Binary Flag",
        "Description": "1 if payload contains SQL injection syntax (UNION, SELECT, --), else 0",
        "Source Column": "payload",
        "Anomaly Relevance": "Syntactic signature of database manipulation attempts",
    },
    {
        "Feature": "contains_path_traversal",
        "Type": "Binary Flag",
        "Description": "1 if URL/payload contains traversal sequences (../, /etc/passwd), else 0",
        "Source Column": "payload, normalized_resource",
        "Anomaly Relevance": "Directory climbing and sensitive file access signature",
    },
    {
        "Feature": "contains_script_tag",
        "Type": "Binary Flag",
        "Description": "1 if payload contains XSS markers (<script>, alert, cookie), else 0",
        "Source Column": "payload",
        "Anomaly Relevance": "Client-side script execution signature",
    },
    {
        "Feature": "contains_command_separator",
        "Type": "Binary Flag",
        "Description": "1 if payload contains shell separators (; ls, | id, &&), else 0",
        "Source Column": "payload",
        "Anomaly Relevance": "OS command execution signature",
    },
    {
        "Feature": "request_rate_1min",
        "Type": "Numerical (Continuous)",
        "Description": "Instantaneous request arrival rate (requests/sec) in 1-min window",
        "Source Column": "requests_per_ip_1min",
        "Anomaly Relevance": "Direct measurement of burst traffic intensity",
    },
    {
        "Feature": "request_rate_5min",
        "Type": "Numerical (Continuous)",
        "Description": "Sustained request arrival rate (requests/sec) in 5-min window",
        "Source Column": "requests_per_ip_5min",
        "Anomaly Relevance": "Direct measurement of sustained attack throughput",
    },
    {
        "Feature": "failed_pattern_count",
        "Type": "Numerical (Discrete)",
        "Description": "Aggregate count of triggered security heuristic patterns (0-4)",
        "Source Column": "Multiple heuristic flags",
        "Anomaly Relevance": "Compound anomaly intensity score",
    },
]


def prepare_ml_ready_features(
    df: pd.DataFrame,
) -> Tuple[pd.DataFrame, pd.DataFrame, List[str]]:
    """Encodes categoricals, handles missing values, and applies RobustScaler.
    
    Generates dictionary, statistics, correlation matrices, and saves ML datasets.
    Strictly avoids using 'label' or 'label_reason' in the feature matrix.
    """
    print("\n" + "=" * 60)
    print("STEP 6 - FEATURE SCALING & ML-READY DATASET PREPARATION")
    print("=" * 60)

    # 1. Export Feature Dictionary
    dict_df = pd.DataFrame(FEATURE_METADATA)
    dict_df.to_csv(FEATURE_DICT_CSV, index=False)
    print(f"Saved feature dictionary ({len(dict_df)} features) to: {FEATURE_DICT_CSV.name}")

    # 2. Select Candidate Features (exclude target labels and raw text)
    # Numerical features to scale
    numeric_features = [
        "request_hour",
        "request_day_of_week",
        "request_day",
        "request_month",
        "is_night",
        "requests_per_ip",
        "ip_request_rank",
        "time_since_previous_request",
        "mean_inter_request_time_ip",
        "median_inter_request_time_ip",
        "min_inter_request_time_ip",
        "rapid_request_flag",
        "requests_per_ip_1min",
        "requests_per_ip_5min",
        "requests_per_ip_10min",
        "status_404_count_ip",
        "status_404_ratio_ip",
        "error_status_ratio_ip",
        "high_404_activity_flag",
        "is_bot",
        "is_scanner",
        "user_agent_length",
        "unique_user_agents_per_ip",
        "unique_urls_per_ip",
        "unique_ports_per_ip",
        "url_entropy",
        "url_length",
        "path_depth",
        "number_of_query_parameters",
        "special_character_count",
        "digit_ratio",
        "letter_ratio",
        "payload_length",
        "payload_entropy",
        "contains_sql_keyword",
        "contains_path_traversal",
        "contains_script_tag",
        "contains_command_separator",
        "request_rate_1min",
        "request_rate_5min",
        "failed_pattern_count",
    ]

    # Verify presence in dataframe
    candidate_features = [f for f in numeric_features if f in df.columns]

    # 3. Handle Missing Values in Features (e.g. time_since_previous_request first request)
    # We impute NaNs in time_since_previous_request with the IP mean or a neutral sentinel (e.g. 999.0s)
    df_imputed = df[candidate_features].copy()
    if "time_since_previous_request" in df_imputed.columns:
        # Fill first-request NaN with 999.0s (representing no prior recent burst)
        df_imputed["time_since_previous_request"] = df_imputed["time_since_previous_request"].fillna(999.0)

    # Impute any remaining NaNs with column median
    df_imputed = df_imputed.fillna(df_imputed.median())

    # 4. One-Hot Encode user_agent_type if present
    if "user_agent_type" in df.columns:
        ua_dummies = pd.get_dummies(df["user_agent_type"], prefix="ua", dtype=int)
        df_encoded = pd.concat([df_imputed, ua_dummies], axis=1)
    else:
        df_encoded = df_imputed

    all_ml_cols = list(df_encoded.columns)

    # 5. Compute Feature Statistics & Correlations
    stats_df = df_encoded.describe().T.reset_index()
    stats_df.rename(columns={"index": "feature"}, inplace=True)
    stats_df.to_csv(FEATURE_STATS_CSV, index=False)
    print(f"Saved feature statistics to: {FEATURE_STATS_CSV.name}")

    # Compute correlation on candidate numeric features
    corr_df = df_imputed.corr()
    corr_df.to_csv(FEATURE_CORR_CSV)
    print(f"Saved feature correlation matrix to: {FEATURE_CORR_CSV.name}")

    # 6. Apply RobustScaler (handles heavy-tailed distributions and extreme outliers)
    scaler = RobustScaler()
    scaled_matrix = scaler.fit_transform(df_encoded)
    ml_ready_df = pd.DataFrame(scaled_matrix, columns=all_ml_cols, index=df.index)

    # 7. Export Datasets
    print(f"\nSaving unscaled feature-engineered dataset ({len(df):,} rows x {len(df.columns)} cols)...")
    df.to_csv(FEATURE_ENGINEERED_CSV, index=False)
    print(f"  -> Saved: {FEATURE_ENGINEERED_CSV.name}")

    print(f"Saving ML-ready scaled matrix ({len(ml_ready_df):,} rows x {len(ml_ready_df.columns)} cols)...")
    ml_ready_df.to_csv(ML_READY_CSV, index=False)
    print(f"  -> Saved: {ML_READY_CSV.name}")

    # 8. Export Representative Sample (10,000 rows with all attack classes if available)
    if "label" in df.columns:
        attack_subset = df[df["label"] != "benign"]
        benign_needed = max(0, SAMPLE_SIZE_EXPORT - len(attack_subset))
        benign_subset = df[df["label"] == "benign"].head(benign_needed)
        sample_df = pd.concat([attack_subset, benign_subset]).sample(frac=1.0, random_state=RANDOM_STATE)
    else:
        sample_df = df.sample(n=min(SAMPLE_SIZE_EXPORT, len(df)), random_state=RANDOM_STATE)

    sample_df.to_csv(FEATURE_SAMPLE_CSV, index=False)
    print(f"Saved representative sample ({len(sample_df):,} records) to: {FEATURE_SAMPLE_CSV.name}")

    return df, ml_ready_df, all_ml_cols
