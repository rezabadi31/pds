"""time_features.py
Step 2: Temporal Feature Extraction for Web Access Logs
Extracts cyclical and operational time metrics for suspicious activity profiling.
"""

from typing import Tuple
import pandas as pd


def extract_time_features(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    """Extracts calendar and diurnal timing features from the timestamp column.
    
    Night window is strictly defined as 00:00:00 to 05:59:59 (00:00–06:00),
    representing typical low-traffic periods where automated intrusion probes stand out.
    """
    if "timestamp" not in df.columns:
        raise ValueError("Cannot extract time features: 'timestamp' column is missing.")

    # Parse datetime efficiently
    ts_dt = pd.to_datetime(df["timestamp"], errors="coerce")
    
    df["request_hour"] = ts_dt.dt.hour.fillna(-1).astype(int)
    df["request_day_of_week"] = ts_dt.dt.dayofweek.fillna(-1).astype(int)
    df["request_day"] = ts_dt.dt.day.fillna(-1).astype(int)
    df["request_month"] = ts_dt.dt.month.fillna(-1).astype(int)
    
    # is_night: 00:00 - 06:00 (i.e. hour >= 0 and hour < 6)
    df["is_night"] = ((df["request_hour"] >= 0) & (df["request_hour"] < 6)).astype(int)
    
    return df, ts_dt
