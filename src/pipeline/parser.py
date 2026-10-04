"""src/pipeline/parser.py
Canonical Log Parsing & Schema Harmonization for Rox Platform
Translates heterogeneous raw log streams (JSON array honeypot, CLF/Combined, Generic, CSV, NDJSON)
into a canonical tabular DataFrame. Handles schema validation and missing column reporting gracefully.
"""

import re
import json
import io
from typing import List, Tuple, Dict, Any, Optional
import pandas as pd

# Canonical Column Schema
CANONICAL_COLUMNS = [
    "category_type",
    "payload",
    "timestamp",
    "client_ip",
    "client_port",
    "user_agent",
    "accept_language",
    "proxy_ip",
    "request_type",
    "status_code",
    "resource_requested",
    "bytes_sent",
    "referrer",
]

# Required attributes for full analysis
REQUIRED_COLUMNS = ["timestamp", "client_ip", "resource_requested"]
OPTIONAL_COLUMNS = ["user_agent", "status_code", "payload", "request_type", "bytes_sent", "referrer", "client_port"]

# Common Log Format / Combined Log Format Regex
CLF_COMBINED_REGEX = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\s"]+)(?:\s+(HTTP/[\d\.]+|-))?"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?',
    re.IGNORECASE,
)

# Generic web server log regex
GENERIC_WEB_REGEX = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+.*?(?:\[(?P<ts>[^\]]+)\])?.*?"(?P<method>[A-Z]{3,7})\s+(?P<uri>\S+).*?"\s*(?P<status>\d{3})?\s*(?P<bytes>\d+)?',
    re.IGNORECASE,
)


class LogParser:
    """Multi-format parser generating canonical security DataFrames."""

    @staticmethod
    def parse_lines_or_csv(
        raw_lines: List[str],
        filename: str,
        file_bytes: Optional[bytes] = None,
    ) -> Tuple[Optional[pd.DataFrame], Dict[str, Any], str]:
        """Parses raw lines or CSV bytes into canonical schema with schema diagnostics.
        
        Returns:
            Tuple of (df_canonical, schema_info, error_message)
        """
        ext = filename.lower().split(".")[-1] if "." in filename else ""
        schema_info: Dict[str, Any] = {
            "format_detected": "unknown",
            "available_optional_fields": [],
            "missing_optional_fields": [],
            "warnings": [],
        }

        # Branch 1: CSV format
        if ext == "csv" or (file_bytes and b"," in file_bytes[:1024]):
            df_csv, info, err = LogParser._parse_csv_file(file_bytes, raw_lines)
            if df_csv is not None and not df_csv.empty:
                return df_csv, info, ""
            # Fall back to text parsing if CSV fails

        if not raw_lines:
            return None, schema_info, "No data lines provided to parse."

        # Branch 2: Check for Honeypot JSON array format
        sample = "\n".join(raw_lines[:20])
        if "[" in sample and ("]" in sample or "][" in sample):
            df_honeypot = LogParser._parse_honeypot_json_arrays(raw_lines)
            if df_honeypot is not None and not df_honeypot.empty:
                schema_info["format_detected"] = "Honeypot JSON Arrays (Practical 01/02 Standard)"
                schema_info["available_optional_fields"] = [c for c in OPTIONAL_COLUMNS if c in df_honeypot.columns and (df_honeypot[c] != "-").any()]
                schema_info["missing_optional_fields"] = [c for c in OPTIONAL_COLUMNS if c not in schema_info["available_optional_fields"]]
                return df_honeypot, schema_info, ""

        # Branch 3: Standard CLF / Combined or Generic Web Access Log
        df_clf = LogParser._parse_clf_or_generic(raw_lines)
        if df_clf is not None and not df_clf.empty:
            schema_info["format_detected"] = "Apache / Nginx Combined Access Log"
            schema_info["available_optional_fields"] = [c for c in OPTIONAL_COLUMNS if c in df_clf.columns and (df_clf[c] != "-").any()]
            schema_info["missing_optional_fields"] = [c for c in OPTIONAL_COLUMNS if c not in schema_info["available_optional_fields"]]
            return df_clf, schema_info, ""

        # Branch 4: NDJSON (One JSON object per line)
        df_ndjson = LogParser._parse_ndjson(raw_lines)
        if df_ndjson is not None and not df_ndjson.empty:
            schema_info["format_detected"] = "Newline-Delimited JSON (NDJSON)"
            schema_info["available_optional_fields"] = [c for c in OPTIONAL_COLUMNS if c in df_ndjson.columns and (df_ndjson[c] != "-").any()]
            schema_info["missing_optional_fields"] = [c for c in OPTIONAL_COLUMNS if c not in schema_info["available_optional_fields"]]
            return df_ndjson, schema_info, ""

        return None, schema_info, "Rox could not parse this file. Reason: The uploaded file structure does not match a known log format (Honeypot JSON, CLF/Combined, NDJSON, or CSV)."

    @staticmethod
    def _parse_honeypot_json_arrays(raw_lines: List[str]) -> Optional[pd.DataFrame]:
        """Parses serialized JSON array logs matching Practical 1 & 2 schema."""
        parsed_rows = []
        for line in raw_lines:
            # Handle concatenated '][' multi-record lines
            chunks = line.split("][") if "][" in line else [line]
            for chunk in chunks:
                entry = chunk.strip()
                if not entry:
                    continue
                if not entry.startswith("["):
                    entry = "[" + entry
                if not entry.endswith("]"):
                    entry = entry + "]"
                try:
                    data = json.loads(entry)
                    if isinstance(data, list) and len(data) >= 4:
                        cat = str(data[0]) if (len(data) > 0 and data[0] is not None) else "web"
                        pay = str(data[1]) if (len(data) > 1 and data[1] is not None) else ""
                        ts = str(data[2]) if (len(data) > 2 and data[2] is not None) else ""
                        ip = str(data[3]) if (len(data) > 3 and data[3] is not None) else "127.0.0.1"
                        port = str(data[4]) if (len(data) > 4 and data[4] is not None) else "80"
                        ua = str(data[5]) if (len(data) > 5 and data[5] is not None) else "-"
                        lang = str(data[6]) if (len(data) > 6 and data[6] is not None) else "-"
                        proxy = str(data[7]) if (len(data) > 7 and data[7] is not None) else "-"
                        
                        # Resource path from payload or default
                        res = pay if pay.startswith("/") else ("/unknown" if not pay else f"/{pay[:50]}")

                        parsed_rows.append([
                            cat, pay, ts, ip, port, ua, lang, proxy,
                            "GET", "200", res, "0", "-"
                        ])
                except Exception:
                    pass

        if parsed_rows:
            return pd.DataFrame(parsed_rows, columns=CANONICAL_COLUMNS)
        return None

    @staticmethod
    def _parse_clf_or_generic(raw_lines: List[str]) -> Optional[pd.DataFrame]:
        """Parses standard Combined Log Format (CLF) or generic web access regex."""
        parsed_rows = []
        for line in raw_lines:
            m = CLF_COMBINED_REGEX.match(line)
            if m:
                ip, ts, method, uri, _, status, bytes_val, ref, ua = m.groups()
                parsed_rows.append([
                    "web",
                    uri or "",
                    ts or "",
                    ip or "127.0.0.1",
                    "80",
                    ua or "-",
                    "-",
                    "-",
                    method or "GET",
                    status or "200",
                    uri or "/",
                    bytes_val if (bytes_val and bytes_val != "-") else "0",
                    ref or "-",
                ])
                continue

            gm = GENERIC_WEB_REGEX.search(line)
            if gm:
                gd = gm.groupdict()
                parsed_rows.append([
                    "web",
                    gd.get("uri") or "",
                    gd.get("ts") or "",
                    gd.get("ip") or "127.0.0.1",
                    "80",
                    "-",
                    "-",
                    "-",
                    gd.get("method") or "GET",
                    gd.get("status") or "200",
                    gd.get("uri") or "/",
                    gd.get("bytes") or "0",
                    "-",
                ])

        if parsed_rows:
            return pd.DataFrame(parsed_rows, columns=CANONICAL_COLUMNS)
        return None

    @staticmethod
    def _parse_csv_file(file_bytes: Optional[bytes], raw_lines: List[str]) -> Tuple[Optional[pd.DataFrame], Dict[str, Any], str]:
        """Parses CSV with dynamic column alias matching."""
        schema_info: Dict[str, Any] = {
            "format_detected": "Structured CSV",
            "available_optional_fields": [],
            "missing_optional_fields": [],
            "warnings": [],
        }

        try:
            if file_bytes:
                df_raw = pd.read_csv(io.BytesIO(file_bytes))
            else:
                df_raw = pd.read_csv(io.StringIO("\n".join(raw_lines)))
        except Exception as e:
            return None, schema_info, f"CSV parsing failed: {str(e)}"

        if df_raw.empty:
            return None, schema_info, "CSV file is empty."

        cols_lower = {str(c).lower().strip(): c for c in df_raw.columns}

        def match_alias(aliases: List[str]) -> Optional[str]:
            for a in aliases:
                if a in cols_lower:
                    return cols_lower[a]
            return None

        c_ip = match_alias(["client_ip", "ip", "src_ip", "source_ip", "remote_addr", "remote_ip", "host"])
        c_ts = match_alias(["timestamp", "time", "datetime", "date", "@timestamp", "request_time"])
        c_res = match_alias(["resource_requested", "url", "uri", "path", "request_uri", "endpoint"])

        # Check required fields
        if not c_ip:
            return None, schema_info, "Rox cannot perform complete analysis because the uploaded CSV does not contain the required field: 'client_ip'."
        if not c_ts:
            return None, schema_info, "Rox cannot perform complete analysis because the uploaded CSV does not contain the required field: 'timestamp'."
        if not c_res:
            c_res = match_alias(["payload", "query", "body"])
            if not c_res:
                return None, schema_info, "Rox cannot perform complete analysis because the uploaded CSV does not contain the required field: 'resource_requested'."

        # Optional aliases
        c_meth = match_alias(["request_type", "method", "http_method", "verb"])
        c_stat = match_alias(["status_code", "status", "code", "http_status"])
        c_pay = match_alias(["payload", "body", "data", "params", "query"])
        c_ua = match_alias(["user_agent", "useragent", "agent", "browser"])
        c_bytes = match_alias(["bytes_sent", "bytes", "size", "length"])
        c_ref = match_alias(["referrer", "referer"])
        c_port = match_alias(["client_port", "port", "src_port"])
        c_cat = match_alias(["category_type", "category", "type"])

        df_out = pd.DataFrame()
        df_out["category_type"] = df_raw[c_cat].fillna("web").astype(str) if c_cat else "web"
        df_out["payload"] = df_raw[c_pay].fillna("").astype(str) if c_pay else ""
        df_out["timestamp"] = df_raw[c_ts].fillna("").astype(str)
        df_out["client_ip"] = df_raw[c_ip].fillna("127.0.0.1").astype(str)
        df_out["client_port"] = df_raw[c_port].fillna("80").astype(str) if c_port else "80"
        df_out["user_agent"] = df_raw[c_ua].fillna("-").astype(str) if c_ua else "-"
        df_out["accept_language"] = "-"
        df_out["proxy_ip"] = "-"
        df_out["request_type"] = df_raw[c_meth].fillna("GET").astype(str) if c_meth else "GET"
        df_out["status_code"] = df_raw[c_stat].fillna("200").astype(str) if c_stat else "200"
        df_out["resource_requested"] = df_raw[c_res].fillna("/").astype(str)
        df_out["bytes_sent"] = df_raw[c_bytes].fillna("0").astype(str) if c_bytes else "0"
        df_out["referrer"] = df_raw[c_ref].fillna("-").astype(str) if c_ref else "-"

        # Record available vs missing optional fields
        for opt, matched in [
            ("user_agent", c_ua), ("status_code", c_stat), ("payload", c_pay),
            ("request_type", c_meth), ("bytes_sent", c_bytes), ("referrer", c_ref), ("client_port", c_port)
        ]:
            if matched:
                schema_info["available_optional_fields"].append(opt)
            else:
                schema_info["missing_optional_fields"].append(opt)
                schema_info["warnings"].append(f"{opt.replace('_', ' ').capitalize()} features skipped because '{opt}' is not available.")

        return df_out, schema_info, ""

    @staticmethod
    def _parse_ndjson(raw_lines: List[str]) -> Optional[pd.DataFrame]:
        """Parses Newline-Delimited JSON records."""
        parsed = []
        for line in raw_lines:
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    parsed.append(obj)
            except Exception:
                pass

        if not parsed:
            return None

        df_raw = pd.DataFrame(parsed)
        cols_lower = {str(c).lower().strip(): c for c in df_raw.columns}

        def match_alias(aliases: List[str]) -> Optional[str]:
            for a in aliases:
                if a in cols_lower:
                    return cols_lower[a]
            return None

        c_ip = match_alias(["client_ip", "ip", "src_ip", "host"])
        c_ts = match_alias(["timestamp", "time", "datetime", "date"])
        c_res = match_alias(["resource_requested", "url", "uri", "path"])

        if not c_ip or not c_ts or not c_res:
            return None

        df_out = pd.DataFrame()
        df_out["category_type"] = "web"
        df_out["payload"] = df_raw[match_alias(["payload", "body"])].fillna("").astype(str) if match_alias(["payload", "body"]) else ""
        df_out["timestamp"] = df_raw[c_ts].fillna("").astype(str)
        df_out["client_ip"] = df_raw[c_ip].fillna("127.0.0.1").astype(str)
        df_out["client_port"] = "80"
        df_out["user_agent"] = df_raw[match_alias(["user_agent", "agent"])].fillna("-").astype(str) if match_alias(["user_agent", "agent"]) else "-"
        df_out["accept_language"] = "-"
        df_out["proxy_ip"] = "-"
        df_out["request_type"] = df_raw[match_alias(["request_type", "method"])].fillna("GET").astype(str) if match_alias(["request_type", "method"]) else "GET"
        df_out["status_code"] = df_raw[match_alias(["status_code", "status"])].fillna("200").astype(str) if match_alias(["status_code", "status"]) else "200"
        df_out["resource_requested"] = df_raw[c_res].fillna("/").astype(str)
        df_out["bytes_sent"] = "0"
        df_out["referrer"] = "-"

        return df_out
