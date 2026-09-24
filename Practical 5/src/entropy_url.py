"""entropy_url.py
Part A (5): Shannon Entropy and Lexical Structural Features for URLs
Quantifies randomness, path complexity, and character distributions.
"""

from typing import Tuple, Dict, Any
import math
import collections
import pandas as pd


def calculate_shannon_entropy(text: str) -> float:
    """Calculates character-level Shannon entropy in bits:
    H(X) = -sum(p(x) * log2(p(x)))
    """
    if not isinstance(text, str) or not text:
        return 0.0
    
    length = len(text)
    counts = collections.Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def _compute_lexical_metrics(url_str: str) -> Dict[str, float]:
    """Computes all lexical, depth, and ratio features for a single URL string."""
    if not isinstance(url_str, str) or not url_str:
        return {
            "url_entropy": 0.0,
            "url_length": 0,
            "path_depth": 0,
            "query_parameter_count": 0,
            "special_character_count": 0,
            "digit_ratio": 0.0,
            "letter_ratio": 0.0,
        }

    s = url_str.strip()
    u_len = len(s)
    entropy = calculate_shannon_entropy(s)

    # Path depth: number of '/' characters
    path_depth = s.count("/")

    # Number of query parameters
    if "?" in s:
        query_part = s.split("?", 1)[1]
        num_query_params = query_part.count("&") + 1 if query_part else 0
    else:
        num_query_params = 0

    # Character distributions
    digits = sum(c.isdigit() for c in s)
    letters = sum(c.isalpha() for c in s)
    specials = sum(not c.isalnum() for c in s)

    digit_ratio = round(digits / u_len, 4) if u_len > 0 else 0.0
    letter_ratio = round(letters / u_len, 4) if u_len > 0 else 0.0

    return {
        "url_entropy": entropy,
        "url_length": u_len,
        "path_depth": path_depth,
        "query_parameter_count": num_query_params,
        "special_character_count": specials,
        "digit_ratio": digit_ratio,
        "letter_ratio": letter_ratio,
    }


def extract_url_entropy_features(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Vectorized calculation of URL Shannon entropy and lexical structural features.
    
    Uses unique dictionary caching for optimal O(unique_urls) computational efficiency.
    """
    stats: Dict[str, Any] = {}

    if "normalized_resource" in df.columns:
        source_col = "normalized_resource"
    elif "resource_requested" in df.columns:
        source_col = "resource_requested"
    else:
        source_col = None

    if source_col is None:
        for f in [
            "url_entropy", "url_length", "path_depth",
            "query_parameter_count", "number_of_query_parameters",
            "special_character_count", "digit_ratio", "letter_ratio"
        ]:
            df[f] = 0.0
        return df, stats

    # Fast unique mapping
    unique_urls = df[source_col].dropna().unique()
    cache = {u: _compute_lexical_metrics(u) for u in unique_urls}
    cache[None] = _compute_lexical_metrics("")
    cache[""] = _compute_lexical_metrics("")

    for feat in [
        "url_entropy", "url_length", "path_depth",
        "query_parameter_count", "special_character_count",
        "digit_ratio", "letter_ratio"
    ]:
        feat_map = {u: cache[u][feat] for u in cache}
        df[feat] = df[source_col].map(feat_map).fillna(0.0)
        if feat in ["url_length", "path_depth", "query_parameter_count", "special_character_count"]:
            df[feat] = df[feat].astype(int)

    # Provide alias
    df["number_of_query_parameters"] = df["query_parameter_count"]

    stats["source_column"] = source_col
    stats["mean_url_entropy"] = float(df["url_entropy"].mean())
    stats["max_url_entropy"] = float(df["url_entropy"].max())
    stats["mean_url_length"] = float(df["url_length"].mean())

    return df, stats
