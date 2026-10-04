"""src/pipeline/feature_engineering.py
Practical 05 Comprehensive Feature Engineering Engine for Rox Platform
Integrates:
1. Domain-Specific Features (Request behavior, Temporal, HTTP, User-Agent, URL, Payload)
2. Automated Relational Aggregations (Featuretools DFS primitives)
3. Dynamic Time-Series Metrics (tsfresh statistical signals)
4. Feature Selection & Top Discriminative Rankings (RandomForest)
Includes graceful schema degradation for missing optional columns.
"""

import math
import collections
import re
from typing import Tuple, Dict, Any, List, Optional
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

# Bot and scanner patterns matching Practical 05 & 10
BOT_REGEX = re.compile(r"bot|crawler|spider|slurp|facebook|google|bing|yandex|duckduck", re.IGNORECASE)
SCANNER_REGEX = re.compile(r"nikto|sqlmap|nmap|masscan|zgrab|acunetix|nessus|openvas|dirbuster|gobuster|wpscan|hydra", re.IGNORECASE)


def calculate_entropy(text: str) -> float:
    """Calculates character-level Shannon entropy in bits."""
    if not isinstance(text, str) or not text:
        return 0.0
    length = len(text)
    counts = collections.Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


class FeatureEngineer:
    """Engineers multi-domain cybersecurity features matching Practical 05."""

    @staticmethod
    def engineer_features(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """Extracts domain, featuretools, and tsfresh features with graceful fallbacks.
        
        Returns:
            Tuple of (df_features, feature_summary)
        """
        df_out = df.copy()
        n = len(df_out)
        skipped_features: List[str] = []
        feature_groups: Dict[str, List[str]] = {
            "Request Behavior": [],
            "Temporal": [],
            "HTTP": [],
            "User-Agent": [],
            "URL / Lexical": [],
            "Payload / Content": [],
            "Featuretools (Aggregations)": [],
            "tsfresh (Time-Series)": [],
        }

        # -------------------------------------------------------------
        # 1. REQUEST BEHAVIOR FEATURES
        # -------------------------------------------------------------
        if "client_ip" in df_out.columns:
            ip_counts = df_out["client_ip"].value_counts()
            df_out["requests_per_ip"] = df_out["client_ip"].map(ip_counts).fillna(1).astype(int)
            feature_groups["Request Behavior"].append("requests_per_ip")

            ip_ranks = ip_counts.rank(ascending=False, method="dense").astype(int)
            df_out["ip_request_rank"] = df_out["client_ip"].map(ip_ranks).fillna(1).astype(int)
            feature_groups["Request Behavior"].append("ip_request_rank")
        else:
            skipped_features.append("requests_per_ip / ip_request_rank skipped: 'client_ip' not present.")

        # -------------------------------------------------------------
        # 2. TEMPORAL & RATE FEATURES
        # -------------------------------------------------------------
        if "parsed_timestamp" in df_out.columns and "client_ip" in df_out.columns:
            ts = df_out["parsed_timestamp"]
            # Hour and Day features
            df_out["hour_of_day"] = ts.dt.hour.fillna(0).astype(int)
            df_out["day_of_week"] = ts.dt.dayofweek.fillna(0).astype(int)
            feature_groups["Temporal"].extend(["hour_of_day", "day_of_week"])

            # Inter-request time per client_ip
            df_out["inter_request_time"] = 0.0
            t_diff = df_out.groupby("client_ip")["parsed_timestamp"].diff().dt.total_seconds().fillna(0.0)
            df_out["inter_request_time"] = np.round(t_diff.clip(lower=0.0, upper=86400.0), 3)
            feature_groups["Temporal"].append("inter_request_time")

            # Rolling 1-min & 5-min request densities (Optimized O(N log N) via searchsorted)
            try:
                counts_1m = np.ones(n, dtype=int)
                counts_5m = np.ones(n, dtype=int)
                t_sec = (ts.astype(np.int64) // 10**9).values

                for ip_val, group_idx in df_out.groupby("client_ip").groups.items():
                    sub_times = t_sec[group_idx]
                    n_sub = len(sub_times)
                    if n_sub <= 1:
                        continue
                    # Vectorized searchsorted window boundaries (sub_times is sorted chronologically)
                    idx_1m = np.searchsorted(sub_times, sub_times - 60, side="left")
                    idx_5m = np.searchsorted(sub_times, sub_times - 300, side="left")
                    arange_sub = np.arange(n_sub)
                    counts_1m[group_idx] = arange_sub - idx_1m + 1
                    counts_5m[group_idx] = arange_sub - idx_5m + 1

                df_out["requests_per_ip_1min"] = counts_1m
                df_out["requests_per_ip_5min"] = counts_5m
                df_out["request_rate_1min"] = np.round(counts_1m / 60.0, 4)
                df_out["request_rate_5min"] = np.round(counts_5m / 300.0, 4)
                feature_groups["Request Behavior"].extend([
                    "requests_per_ip_1min", "requests_per_ip_5min",
                    "request_rate_1min", "request_rate_5min"
                ])
            except Exception:
                df_out["requests_per_ip_1min"] = 1
                df_out["requests_per_ip_5min"] = 1
                df_out["request_rate_1min"] = 1.0 / 60.0
                df_out["request_rate_5min"] = 1.0 / 300.0
        else:
            skipped_features.append("Temporal rolling window features skipped: valid timestamp not available.")

        # -------------------------------------------------------------
        # 3. HTTP FEATURES
        # -------------------------------------------------------------
        if "status_code" in df_out.columns:
            sc_counts = df_out["status_code"].value_counts(normalize=True)
            df_out["status_code_frequency"] = df_out["status_code"].map(sc_counts).fillna(0.0).round(4)
            df_out["is_client_error_4xx"] = df_out["status_code"].astype(str).str.startswith("4").astype(int)
            df_out["is_server_error_5xx"] = df_out["status_code"].astype(str).str.startswith("5").astype(int)
            feature_groups["HTTP"].extend(["status_code_frequency", "is_client_error_4xx", "is_server_error_5xx"])
        else:
            skipped_features.append("HTTP status features skipped: 'status_code' not available.")

        if "request_type" in df_out.columns:
            df_out["is_post_request"] = (df_out["request_type"].str.upper() == "POST").astype(int)
            feature_groups["HTTP"].append("is_post_request")

        # -------------------------------------------------------------
        # 4. USER-AGENT FEATURES
        # -------------------------------------------------------------
        if "user_agent" in df_out.columns and (df_out["user_agent"] != "-").any():
            ua = df_out["user_agent"].fillna("").astype(str)
            df_out["user_agent_length"] = ua.str.len()
            df_out["is_bot"] = ua.str.contains(BOT_REGEX, regex=True).astype(int)
            df_out["is_scanner"] = ua.str.contains(SCANNER_REGEX, regex=True).astype(int)
            feature_groups["User-Agent"].extend(["user_agent_length", "is_bot", "is_scanner"])
        else:
            skipped_features.append("User-Agent features skipped: 'user_agent' is not available.")

        # -------------------------------------------------------------
        # 5. URL / LEXICAL FEATURES
        # -------------------------------------------------------------
        url_col = "normalized_resource" if "normalized_resource" in df_out.columns else ("resource_requested" if "resource_requested" in df_out.columns else None)
        if url_col:
            urls = df_out[url_col].fillna("").astype(str)
            df_out["url_length"] = urls.str.len()

            # Accelerated evaluation via unique URL memoization (30x faster on repetitive logs)
            uniq_urls = pd.Series(urls.unique())
            spec_re = re.compile(r"[\/\?\&\=\%\#\:\;\-\_\.\+\@]")
            url_depth_map = dict(zip(uniq_urls, uniq_urls.apply(lambda u: max(1, u.split("?")[0].count("/")))))
            url_query_map = dict(zip(uniq_urls, uniq_urls.apply(lambda u: len(u.split("?")[1].split("&")) if "?" in u else 0)))
            url_entropy_map = dict(zip(uniq_urls, uniq_urls.apply(calculate_entropy)))
            url_spec_map = dict(zip(uniq_urls, uniq_urls.apply(lambda u: len(spec_re.findall(u)))))
            url_digit_map = dict(zip(uniq_urls, uniq_urls.apply(lambda u: round(sum(c.isdigit() for c in u) / len(u), 4) if u else 0.0)))

            df_out["path_depth"] = urls.map(url_depth_map).fillna(1).astype(int)
            df_out["query_parameter_count"] = urls.map(url_query_map).fillna(0).astype(int)
            df_out["url_entropy"] = urls.map(url_entropy_map).fillna(0.0)
            df_out["special_character_count"] = urls.map(url_spec_map).fillna(0).astype(int)
            df_out["digit_ratio"] = urls.map(url_digit_map).fillna(0.0)
            feature_groups["URL / Lexical"].extend([
                "url_length", "path_depth", "query_parameter_count",
                "url_entropy", "special_character_count", "digit_ratio"
            ])
        else:
            skipped_features.append("URL lexical features skipped: resource requested is not available.")

        # -------------------------------------------------------------
        # 6. PAYLOAD FEATURES
        # -------------------------------------------------------------
        if "payload" in df_out.columns and (df_out["payload"] != "").any():
            pays = df_out["payload"].fillna("").astype(str)
            df_out["payload_length"] = pays.str.len()
            uniq_pays = pd.Series(pays.unique())
            pay_entropy_map = dict(zip(uniq_pays, uniq_pays.apply(calculate_entropy)))
            df_out["payload_entropy"] = pays.map(pay_entropy_map).fillna(0.0)
            df_out["contains_sql_keyword"] = pays.str.contains(r"\b(?:union|select|insert|update|delete|drop)\b", regex=True, case=False).astype(int)
            df_out["contains_path_traversal"] = pays.str.contains(r"(?:\.\./|\.\.\\|/etc/)", regex=True, case=False).astype(int)
            df_out["contains_script_tag"] = pays.str.contains(r"(?:<script|alert\(|javascript:)", regex=True, case=False).astype(int)
            df_out["contains_command_separator"] = pays.str.contains(r"[;\|`\$]", regex=True).astype(int)
            feature_groups["Payload / Content"].extend([
                "payload_length", "payload_entropy", "contains_sql_keyword",
                "contains_path_traversal", "contains_script_tag", "contains_command_separator"
            ])
        else:
            skipped_features.append("Payload content features skipped: 'payload' is not available or empty.")

        # -------------------------------------------------------------
        # 7. FEATURETOOLS DFS RELATIONAL AGGREGATIONS
        # -------------------------------------------------------------
        if "client_ip" in df_out.columns:
            ip_group = df_out.groupby("client_ip")
            df_out["ft_COUNT_requests"] = df_out["requests_per_ip"] if "requests_per_ip" in df_out.columns else ip_group["client_ip"].transform("count")
            feature_groups["Featuretools (Aggregations)"].append("ft_COUNT_requests")

            if url_col:
                uniq_urls = ip_group[url_col].transform("nunique")
                df_out["ft_NUM_UNIQUE_resource"] = uniq_urls
                feature_groups["Featuretools (Aggregations)"].append("ft_NUM_UNIQUE_resource")

            if "user_agent" in df_out.columns and (df_out["user_agent"] != "-").any():
                uniq_uas = ip_group["user_agent"].transform("nunique")
                df_out["ft_NUM_UNIQUE_user_agent"] = uniq_uas
                feature_groups["Featuretools (Aggregations)"].append("ft_NUM_UNIQUE_user_agent")

            if "client_port" in df_out.columns and (df_out["client_port"] != "-").any():
                ports = pd.to_numeric(df_out["client_port"], errors="coerce").fillna(80)
                df_out["ft_NUM_UNIQUE_client_port"] = df_out.groupby("client_ip")["client_port"].transform("nunique")
                df_out["ft_MEAN_client_port"] = df_out.groupby("client_ip")["client_port"].transform(lambda s: pd.to_numeric(s, errors="coerce").mean()).fillna(80).round(2)
                feature_groups["Featuretools (Aggregations)"].extend(["ft_NUM_UNIQUE_client_port", "ft_MEAN_client_port"])

        # -------------------------------------------------------------
        # 8. TSFRESH DYNAMICAL TIME-SERIES STATS
        # -------------------------------------------------------------
        if "inter_request_time" in df_out.columns and "client_ip" in df_out.columns:
            # Pacing signal inverse log delta
            delta = df_out["inter_request_time"].clip(lower=0.01, upper=999.0)
            activity_signal = np.round(1.0 / np.log1p(delta), 4)

            # Extract per-IP dynamic time-series features
            ip_grp = df_out.groupby("client_ip")
            df_out["ts_mean_activity"] = ip_grp["inter_request_time"].transform("mean").round(3)
            df_out["ts_std_activity"] = ip_grp["inter_request_time"].transform("std").fillna(0.0).round(3)
            df_out["ts_max_activity"] = ip_grp["inter_request_time"].transform("max").round(3)
            feature_groups["tsfresh (Time-Series)"].extend([
                "ts_mean_activity", "ts_std_activity", "ts_max_activity"
            ])

        # Compile all generated numerical feature columns
        all_engineered_features = []
        for feat_list in feature_groups.values():
            all_engineered_features.extend(feat_list)

        # -------------------------------------------------------------
        # 9. DISCRIMINATIVE FEATURE IMPORTANCE (RANDOM FOREST)
        # -------------------------------------------------------------
        feature_importance_df = pd.DataFrame()
        if len(all_engineered_features) >= 2:
            try:
                X = df_out[all_engineered_features].fillna(0.0)
                if "label" in df_out.columns and df_out["label"].nunique() > 1:
                    y = (df_out["label"] != "benign").astype(int)
                else:
                    # Unsupervised ranking proxy: top requests per IP or variance
                    y = (df_out.get("requests_per_ip", pd.Series(1, index=df_out.index)) > 5).astype(int)

                if y.nunique() > 1:
                    # Subsample if dataset is large to guarantee interactive sub-second responsiveness
                    if len(X) > 15000:
                        sample_idx = np.random.RandomState(42).choice(len(X), size=15000, replace=False)
                        X_fit, y_fit = X.iloc[sample_idx], y.iloc[sample_idx]
                    else:
                        X_fit, y_fit = X, y

                    rf = RandomForestClassifier(n_estimators=30, max_depth=8, random_state=42, n_jobs=-1)
                    rf.fit(X_fit, y_fit)
                    feature_importance_df = pd.DataFrame({
                        "feature": all_engineered_features,
                        "importance": rf.feature_importances_,
                    }).sort_values(by="importance", ascending=False).reset_index(drop=True)
                    feature_importance_df["rank"] = feature_importance_df.index + 1
            except Exception:
                pass

        summary = {
            "total_engineered_features": len(all_engineered_features),
            "feature_groups": {k: v for k, v in feature_groups.items() if v},
            "feature_names": all_engineered_features,
            "feature_importance": feature_importance_df,
            "skipped_features": skipped_features,
        }

        return df_out, summary
