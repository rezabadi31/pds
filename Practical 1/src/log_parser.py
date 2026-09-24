"""src/log_parser.py
Practical 1: Unstructured Access Log Data Parser
==================================================
This module provides robust, reusable log loading, format detection,
regex-based parsing, DataFrame construction, and report generation utilities.
"""

import re
import csv
from pathlib import Path
from typing import Generator, Optional, Dict, Any, List, Union
from collections import Counter
from datetime import datetime

import pandas as pd
import numpy as np


# Regular expression for Honeypot / Intrusion Detection Access Log (8-field JSON array)
# Anchored on the mandatory ISO timestamp "YYYY-MM-DD HH:MM:SS"
HONEYPOT_JSON_PATTERN = re.compile(
    r'^\s*\[\s*'
    r'(?P<category_type>null|"(?:\\.|[^"\\])*"|\[.*?\]|\{.*?\})\s*,\s*'
    r'(?P<payload>.*?)\s*,\s*'
    r'"(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"\s*,\s*'
    r'(?P<client_ip>null|"(?:\\.|[^"\\])*")\s*,\s*'
    r'(?P<client_port>null|"(?:\\.|[^"\\])*"|\d+)\s*,\s*'
    r'(?P<user_agent>null|"(?:\\.|[^"\\])*")\s*,\s*'
    r'(?P<accept_language>null|"(?:\\.|[^"\\])*")\s*,\s*'
    r'(?P<proxy_ip>null|"(?:\\.|[^"\\])*")\s*'
    r'\]\s*$'
)

# Standard Apache Combined Log Format regex for comparison / fallback
APACHE_COMBINED_PATTERN = re.compile(
    r'^(?P<client_ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<request>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)\s+'
    r'"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
)

# Standard Apache Common Log Format regex for comparison / fallback
APACHE_COMMON_PATTERN = re.compile(
    r'^(?P<client_ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<request>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
)


def load_log_file(path: Union[str, Path]) -> Generator[str, None, None]:
    """Safely opens and yields raw lines from the log file.
    Gracefully handles decoding problems with UTF-8 replacement characters
    so that no malformed entries cause unhandled fatal exceptions.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Access log file not found at: {file_path}")

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            yield line


def detect_log_format(sample_lines: List[str]) -> Dict[str, Any]:
    """Inspects a collection of sample lines and programmatically identifies
    the underlying log format, supported schema, and regex pattern.
    """
    honeypot_matches = 0
    combined_matches = 0
    common_matches = 0
    tested = 0

    for line in sample_lines:
        s = line.strip()
        if not s:
            continue
        tested += 1
        if HONEYPOT_JSON_PATTERN.match(s) or (s.startswith('[') and '","' in s):
            honeypot_matches += 1
        elif APACHE_COMBINED_PATTERN.match(s):
            combined_matches += 1
        elif APACHE_COMMON_PATTERN.match(s):
            common_matches += 1

    if honeypot_matches >= combined_matches and honeypot_matches >= common_matches:
        return {
            "format_name": "Web Honeypot / Intrusion Detection Access Log (JSON Array)",
            "pattern": HONEYPOT_JSON_PATTERN,
            "fields": [
                "category_type",
                "payload",
                "timestamp",
                "client_ip",
                "client_port",
                "user_agent",
                "accept_language",
                "proxy_ip"
            ],
            "description": "8-element serialized JSON array capturing network, client, and attack indicators"
        }
    elif combined_matches >= common_matches:
        return {
            "format_name": "Apache / Nginx Combined Log Format",
            "pattern": APACHE_COMBINED_PATTERN,
            "fields": ["client_ip", "user", "timestamp", "method", "request", "protocol", "status", "size", "referrer", "user_agent"],
            "description": "Standard Nginx/Apache combined web server access log"
        }
    else:
        return {
            "format_name": "Apache / Nginx Common Log Format",
            "pattern": APACHE_COMMON_PATTERN,
            "fields": ["client_ip", "user", "timestamp", "method", "request", "protocol", "status", "size"],
            "description": "Standard Nginx/Apache common web server access log"
        }


def clean_field_value(val: Optional[str]) -> Optional[Union[str, int]]:
    """Cleans a captured regex token:
    - Normalizes 'null' string, empty string, or None to Python None
    - Strips surrounding quotes and unescapes slashes/quotes
    """
    if val is None:
        return None
    val = val.strip()
    if val == "null" or val == "":
        return None
    if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
        inner = val[1:-1]
        inner = inner.replace(r'\/', '/').replace(r'\"', '"').replace(r'\\', '\\')
        return inner if inner != "" else None
    return val


def split_concatenated_line(raw_line: str) -> List[str]:
    """Splits lines that contain concatenated JSON arrays (separated by '][')
    caused by buffer flushes in high-concurrency logging environments.
    """
    s = raw_line.strip()
    if not s:
        return []
    if "][" not in s:
        return [s]

    parts = s.split("][")
    normalized = []
    for part in parts:
        part_str = part.strip()
        if not part_str:
            continue
        if not part_str.startswith("["):
            part_str = "[" + part_str
        if not part_str.endswith("]"):
            part_str = part_str + "]"
        normalized.append(part_str)
    return normalized


def parse_log_line(line: str, pattern: Optional[re.Pattern] = None) -> Optional[Dict[str, Any]]:
    """Parses a single log entry line using regular expressions.

    Parameters:
        line (str): Raw log line string.
        pattern (Optional[re.Pattern]): Compiled regex pattern. Defaults to HONEYPOT_JSON_PATTERN.

    Returns:
        Optional[Dict[str, Any]]: Dictionary of structured fields if successful, None if malformed.
    """
    if not line:
        return None
    raw_str = line.strip()
    if not raw_str:
        return None

    pat = pattern if pattern is not None else HONEYPOT_JSON_PATTERN
    match = pat.match(raw_str)
    if not match:
        return None

    groups = match.groupdict()

    # Port handling
    raw_port = clean_field_value(groups.get("client_port"))
    port_val = None
    if raw_port is not None:
        try:
            port_val = int(raw_port)
        except (ValueError, TypeError):
            port_val = raw_port

    return {
        "category_type": clean_field_value(groups.get("category_type")),
        "payload": clean_field_value(groups.get("payload")),
        "timestamp": groups.get("timestamp"),
        "client_ip": clean_field_value(groups.get("client_ip")),
        "client_port": port_val,
        "user_agent": clean_field_value(groups.get("user_agent")),
        "accept_language": clean_field_value(groups.get("accept_language")),
        "proxy_ip": clean_field_value(groups.get("proxy_ip")),
    }


def parse_log_file(path: Union[str, Path], max_records: Optional[int] = None) -> Generator[Dict[str, Any], None, None]:
    """Streams parsed structured records from the access log file."""
    count = 0
    for raw_line in load_log_file(path):
        if not raw_line.strip():
            continue
        entries = split_concatenated_line(raw_line)
        for entry in entries:
            record = parse_log_line(entry)
            if record is not None:
                yield record
                count += 1
                if max_records is not None and count >= max_records:
                    return


def create_dataframe(data_source: Union[List[Dict[str, Any]], Union[str, Path]], nrows: Optional[int] = None) -> pd.DataFrame:
    """Constructs a structured pandas DataFrame from parsed records or a CSV file path.
    Converts timestamp to datetime and numeric fields appropriately.
    """
    if isinstance(data_source, (str, Path)):
        df = pd.read_csv(data_source, nrows=nrows)
    else:
        df = pd.DataFrame(data_source)

    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    if "client_port" in df.columns:
        df["client_port"] = pd.to_numeric(df["client_port"], errors="coerce")

    return df
