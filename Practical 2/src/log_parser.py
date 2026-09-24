r"""src/log_parser.py
Practical 2: Unstructured Log Structuring Engine
==================================================
This module provides streaming JSON ingestion, record extraction,
field mapping, type casting, DataFrame creation, and report generation.
"""

import json
import re
import csv
from pathlib import Path
from typing import Generator, Optional, Dict, Any, List, Union, Tuple
from collections import Counter
from datetime import datetime

import pandas as pd
import numpy as np


# The 8 source-available fields extracted from JSON arrays
SOURCE_FIELDS = [
    "category_type",
    "payload",
    "timestamp",
    "client_ip",
    "client_port",
    "user_agent",
    "accept_language",
    "proxy_ip"
]

# The 5 standard Apache/Nginx fields unavailable in raw honeypot schema
UNAVAILABLE_HTTP_FIELDS = [
    "request_type",
    "status_code",
    "resource_requested",
    "bytes_sent",
    "referrer"
]

# Complete 13 structured columns
ALL_STRUCTURED_COLUMNS = SOURCE_FIELDS + UNAVAILABLE_HTTP_FIELDS


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


def clean_str_value(val: Any) -> Optional[str]:
    """Cleans a string value: converts 'null', empty strings, or None to None."""
    if val is None:
        return None
    s = str(val).strip()
    if s == "" or s.lower() == "null":
        return None
    return s


def parse_raw_record(entry_str: str) -> Optional[Dict[str, Any]]:
    """Parses a single JSON-array string into a structured 13-column dictionary.

    Parameters:
        entry_str (str): JSON-serialized array e.g. '[null, null, "2023-01-08...", ...]'

    Returns:
        Optional[Dict[str, Any]]: Structured dictionary if valid, None if malformed.
    """
    if not entry_str:
        return None
    s = entry_str.strip()
    if not s:
        return None

    try:
        data = json.loads(s)
    except Exception:
        return None

    if not isinstance(data, list) or len(data) < 8:
        return None

    # Extract 8 source fields according to positions
    cat_val = clean_str_value(data[0])
    payload_val = clean_str_value(data[1])
    ts_val = clean_str_value(data[2])
    ip_val = clean_str_value(data[3])

    # Convert port to integer if valid numeric
    raw_port = data[4]
    port_val = None
    if raw_port is not None:
        try:
            port_val = int(raw_port)
        except (ValueError, TypeError):
            port_val = None

    ua_val = clean_str_value(data[5])
    lang_val = clean_str_value(data[6])
    proxy_val = clean_str_value(data[7])

    return {
        # 8 Source Fields
        "category_type": cat_val,
        "payload": payload_val,
        "timestamp": ts_val,
        "client_ip": ip_val,
        "client_port": port_val,
        "user_agent": ua_val,
        "accept_language": lang_val,
        "proxy_ip": proxy_val,
        # 5 Standard HTTP Fields (NaN / None)
        "request_type": None,
        "status_code": None,
        "resource_requested": None,
        "bytes_sent": None,
        "referrer": None
    }


def stream_parse_log_file(
    input_path: Union[str, Path],
    output_csv_path: Union[str, Path],
    sample_csv_path: Optional[Union[str, Path]] = None,
    sample_limit: int = 10000
) -> Dict[str, Any]:
    """Streams the raw log file line-by-line, parses records using JSON parser,
    and writes structured records incrementally to disk with minimal memory usage.

    Returns:
        Dict[str, Any]: Comprehensive parsing statistics and frequency distributions.
    """
    in_file = Path(input_path)
    if not in_file.exists():
        raise FileNotFoundError(f"Raw access log file not found at: {in_file}")

    out_file = Path(output_csv_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    sample_file = Path(sample_csv_path) if sample_csv_path else None
    if sample_file:
        sample_file.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = ALL_STRUCTURED_COLUMNS

    total_physical_lines = 0
    blank_lines = 0
    non_blank_lines = 0
    multi_entry_lines = 0
    extra_records_from_splits = 0

    total_extracted_records = 0
    successfully_parsed = 0
    malformed_records = 0

    null_counts = {f: 0 for f in fieldnames}
    ip_counter = Counter()
    ua_counter = Counter()
    category_counter = Counter()
    month_counter = Counter()

    first_timestamp = None
    last_timestamp = None
    invalid_timestamp_count = 0

    with open(out_file, "w", newline="", encoding="utf-8") as f_out, \
         (open(sample_file, "w", newline="", encoding="utf-8") if sample_file else open(Path("nul"), "w")) as f_sample:

        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()

        sample_writer = csv.DictWriter(f_sample, fieldnames=fieldnames) if sample_file else None
        if sample_writer:
            sample_writer.writeheader()

        with open(in_file, "r", encoding="utf-8", errors="replace") as f_in:
            for line in f_in:
                total_physical_lines += 1
                stripped = line.strip()
                if not stripped:
                    blank_lines += 1
                    continue

                non_blank_lines += 1
                entries = split_concatenated_line(stripped)
                if len(entries) > 1:
                    multi_entry_lines += 1
                    extra_records_from_splits += (len(entries) - 1)

                for entry_str in entries:
                    total_extracted_records += 1
                    record = parse_raw_record(entry_str)

                    if record is None:
                        malformed_records += 1
                    else:
                        successfully_parsed += 1
                        ts = record["timestamp"]
                        if ts:
                            if first_timestamp is None:
                                first_timestamp = ts
                            last_timestamp = ts
                            if len(ts) >= 7:
                                month_counter[ts[:7]] += 1
                        else:
                            invalid_timestamp_count += 1

                        for k in fieldnames:
                            if record[k] is None:
                                null_counts[k] += 1

                        cip = record["client_ip"]
                        if cip:
                            ip_counter[cip] += 1
                        ua = record["user_agent"]
                        if ua:
                            ua_counter[ua] += 1
                        cat = record["category_type"]
                        if cat:
                            category_counter[cat] += 1

                        writer.writerow(record)
                        if sample_writer and successfully_parsed <= sample_limit:
                            sample_writer.writerow(record)

    success_rate = (successfully_parsed / total_extracted_records * 100) if total_extracted_records else 0.0

    return {
        "input_path": str(in_file),
        "input_size_bytes": in_file.stat().st_size,
        "output_csv_path": str(out_file),
        "output_size_bytes": out_file.stat().st_size,
        "total_physical_lines": total_physical_lines,
        "blank_lines": blank_lines,
        "non_blank_lines": non_blank_lines,
        "multi_entry_lines": multi_entry_lines,
        "extra_records_from_splits": extra_records_from_splits,
        "total_extracted_records": total_extracted_records,
        "successfully_parsed": successfully_parsed,
        "malformed_records": malformed_records,
        "parsing_success_rate": success_rate,
        "null_counts": null_counts,
        "first_timestamp": first_timestamp,
        "last_timestamp": last_timestamp,
        "invalid_timestamp_count": invalid_timestamp_count,
        "ip_counter": ip_counter,
        "ua_counter": ua_counter,
        "category_counter": category_counter,
        "month_counter": month_counter,
        "fieldnames": fieldnames,
        "source_fields": SOURCE_FIELDS,
        "unavailable_fields": UNAVAILABLE_HTTP_FIELDS
    }


def load_structured_dataframe(
    csv_path: Union[str, Path],
    nrows: Optional[int] = None
) -> pd.DataFrame:
    """Loads the structured CSV into a pandas DataFrame with proper data types.
    Converts timestamp to datetime and numeric fields appropriately.
    """
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"Structured CSV not found at: {path}")

    df = pd.read_csv(path, nrows=nrows)

    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    if "client_port" in df.columns:
        df["client_port"] = pd.to_numeric(df["client_port"], errors="coerce")

    for col in UNAVAILABLE_HTTP_FIELDS:
        if col in df.columns:
            df[col] = np.nan

    return df
