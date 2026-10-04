"""src/pipeline/anomaly_detection.py
Unsupervised Anomaly Detection Module for Rox Platform
Implements Practical 05 Isolation Forest:
Calculates anomaly scores, flags statistically unusual behavior (Normal vs Anomalous),
and provides factual distinction between anomalies and security attacks.
"""

from typing import Tuple, Dict, Any, List
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

RANDOM_STATE = 42


class AnomalyDetector:
    """Unsupervised Isolation Forest detector for web telemetry anomalies."""

    @staticmethod
    def detect_anomalies(
        df: pd.DataFrame,
        feature_columns: List[str],
        contamination: float = 0.05,
    ) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """Fits an Isolation Forest model to score and flag anomalous behavior.
        
        Args:
            df: DataFrame containing engineered features
            feature_columns: list of numerical feature column names
            contamination: expected proportion of outliers (default 5%)
            
        Returns:
            Tuple of (df_with_anomaly_scores, anomaly_metrics)
        """
        df_out = df.copy()
        n = len(df_out)

        if n == 0 or not feature_columns:
            df_out["anomaly_score"] = 0.0
            df_out["anomaly_flag"] = 1
            df_out["anomaly_label"] = "Normal"
            return df_out, {
                "model": "Isolation Forest",
                "normal_count": 0,
                "anomalous_count": 0,
                "anomaly_percentage": 0.0,
                "mean_score": 0.0,
                "explanation": "No records or features provided for anomaly scoring.",
            }

        # Select numerical features and fill any NaNs safely
        X = df_out[feature_columns].select_dtypes(include=[np.number]).fillna(0.0)
        if X.shape[1] == 0:
            df_out["anomaly_score"] = 0.0
            df_out["anomaly_flag"] = 1
            df_out["anomaly_label"] = "Normal"
            return df_out, {
                "model": "Isolation Forest",
                "normal_count": n,
                "anomalous_count": 0,
                "anomaly_percentage": 0.0,
                "mean_score": 0.0,
                "explanation": "No numerical features available for anomaly scoring.",
            }

        # Subsample for fit if dataset is large, for sub-second interactive response
        sample_size = min(10000, n)
        if n > sample_size:
            fit_sample = X.sample(n=sample_size, random_state=RANDOM_STATE)
        else:
            fit_sample = X

        iso = IsolationForest(
            n_estimators=60,
            contamination=contamination,
            random_state=RANDOM_STATE,
            n_jobs=-1,
        )
        iso.fit(fit_sample)

        # Decision function: lower values mean more abnormal
        raw_scores = iso.decision_function(X)
        flags = np.where(raw_scores < 0, -1, 1)

        df_out["anomaly_score"] = np.round(raw_scores, 4)
        df_out["anomaly_flag"] = flags
        df_out["anomaly_label"] = np.where(flags == -1, "Anomalous", "Normal")

        anomalous_count = int((flags == -1).sum())
        normal_count = int((flags == 1).sum())
        anomaly_pct = round((anomalous_count / n) * 100, 2) if n > 0 else 0.0

        # Contrast with rule-based attack labels if present
        attack_overlap_info = ""
        if "label" in df_out.columns:
            attack_mask = df_out["label"] != "benign"
            total_attacks = int(attack_mask.sum())
            attacks_flagged = int(((flags == -1) & attack_mask).sum())
            if total_attacks > 0:
                det_rate = round((attacks_flagged / total_attacks) * 100, 1)
                attack_overlap_info = f"{attacks_flagged:,} of {total_attacks:,} attacks ({det_rate}%) were also flagged as anomalous."

        explanation = (
            "An anomaly indicates unusual behavior or statistical deviance from baseline traffic. "
            "It is not automatically a malicious attack. Rule-based attack classification and "
            "unsupervised anomaly detection operate independently."
        )

        metrics = {
            "model": "Isolation Forest",
            "normal_count": normal_count,
            "anomalous_count": anomalous_count,
            "anomaly_percentage": anomaly_pct,
            "mean_score": round(float(np.mean(raw_scores)), 4),
            "min_score": round(float(np.min(raw_scores)), 4),
            "max_score": round(float(np.max(raw_scores)), 4),
            "attack_overlap_info": attack_overlap_info,
            "explanation": explanation,
        }

        return df_out, metrics
