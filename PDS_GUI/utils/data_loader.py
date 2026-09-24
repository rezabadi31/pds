"""data_loader.py
Safe, Cached, and Non-Blocking Data Loading Utilities
Prevents reading massive multi-hundred megabyte datasets into memory unnecessarily.
"""

from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple, Union
import datetime
import json
import pandas as pd
import streamlit as st

try:
    import pyarrow.parquet as pq
    HAS_PYARROW = True
except ImportError:
    HAS_PYARROW = False

from config import PRACTICAL_DIRS, EXPECTED_OUTPUTS


def check_file_status(practical_num: int) -> Dict[str, Any]:
    """Inspects expected outputs for a given practical and returns metadata."""
    spec = EXPECTED_OUTPUTS.get(practical_num, {})
    primary = spec.get("primary_file")
    report = spec.get("report_file")
    runner = spec.get("runner_script")

    primary_exists = primary is not None and primary.exists()
    report_exists = report is not None and report.exists()
    runner_exists = runner is not None and runner.exists()

    status = "AVAILABLE" if (primary_exists or report_exists) else "NOT AVAILABLE"

    file_info = {}
    if primary_exists:
        stat = primary.stat()
        file_info["primary_size_mb"] = round(stat.st_size / (1024 * 1024), 2)
        file_info["primary_mtime"] = datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        file_info["primary_name"] = primary.name
        file_info["primary_path"] = str(primary)
    else:
        # Check if sample file exists in processed or samples dir
        sample_found = None
        if primary:
            stem = primary.stem.replace("_access_logs", "").replace("_logs", "")
            candidates = [
                primary.parent / f"{stem}_sample.csv",
                primary.parent / f"{primary.stem}_sample.csv",
                primary.parent.parent / "outputs" / "samples" / f"{stem}_sample.csv",
                primary.parent.parent / "outputs" / "samples" / f"{primary.stem}_sample.csv",
                primary.parent.parent / "data" / "processed" / "parsed_sample.csv",
            ]
            for c in candidates:
                if c.exists():
                    sample_found = c
                    break

        if sample_found:
            stat = sample_found.stat()
            file_info["primary_size_mb"] = round(stat.st_size / (1024 * 1024), 2)
            file_info["primary_mtime"] = datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            file_info["primary_name"] = f"{primary.name} ({sample_found.name})"
            file_info["primary_path"] = str(sample_found)
            primary_exists = True
            status = "AVAILABLE"
        else:
            file_info["primary_name"] = primary.name if primary else "N/A"
            file_info["primary_path"] = str(primary) if primary else "N/A"
            file_info["primary_size_mb"] = 0.0
            file_info["primary_mtime"] = "N/A"

    return {
        "practical_num": practical_num,
        "title": spec.get("title", f"Practical {practical_num}"),
        "description": spec.get("description", ""),
        "status": status,
        "primary_exists": primary_exists,
        "report_exists": report_exists,
        "runner_exists": runner_exists,
        "runner_path": str(runner) if runner else "",
        "report_path": str(report) if report else "",
        "file_info": file_info,
    }


def get_all_system_status() -> List[Dict[str, Any]]:
    """Returns status dictionaries for all 10 practicals."""
    return [check_file_status(i) for i in range(1, 11)]


@st.cache_data(show_spinner=False)
def load_csv_sample(file_path: Union[str, Path], nrows: int = 1000) -> Optional[pd.DataFrame]:
    """Safely loads a preview slice from a CSV file without loading the entire dataset."""
    p = Path(file_path)
    if not p.exists():
        # Fallback to local sample file if large original is omitted from git
        stem = p.stem.replace("_access_logs", "").replace("_logs", "")
        candidates = [
            p.parent / f"{stem}_sample.csv",
            p.parent / f"{p.stem}_sample.csv",
            p.parent / f"sample_{p.name}",
            p.parent.parent / "outputs" / "samples" / f"{stem}_sample.csv",
            p.parent.parent / "outputs" / "samples" / f"{p.stem}_sample.csv",
        ]
        for c in candidates:
            if c.exists():
                p = c
                break

    if not p.exists():
        return None
    try:
        # Use low_memory=False and load sample
        df = pd.read_csv(p, nrows=nrows, low_memory=False)
        return df
    except Exception as e:
        st.warning(f"Unable to read CSV sample from {p.name}: {e}")
        return None


@st.cache_data(show_spinner=False)
def load_parquet_sample(file_path: Union[str, Path], nrows: int = 1000) -> Optional[pd.DataFrame]:
    """Safely reads a slice from an Apache Parquet file using pyarrow."""
    p = Path(file_path)
    if not p.exists():
        return None
    try:
        if HAS_PYARROW:
            table = pq.read_table(p)
            df = table.slice(0, nrows).to_pandas()
            return df
        else:
            return pd.read_parquet(p).head(nrows)
    except Exception as e:
        st.warning(f"Unable to read Parquet sample from {p.name}: {e}")
        return None


@st.cache_data(show_spinner=False)
def read_text_report(file_path: Union[str, Path]) -> Optional[str]:
    """Safely reads and returns text file content."""
    p = Path(file_path)
    if not p.exists():
        return None
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None


@st.cache_data(show_spinner=False)
def read_json_data(file_path: Union[str, Path]) -> Optional[Dict[str, Any]]:
    """Safely reads and parses a JSON file."""
    p = Path(file_path)
    if not p.exists():
        return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def find_plots_for_practical(practical_num: int) -> List[Path]:
    """Finds all PNG/JPG image files generated by a practical."""
    p_dir = PRACTICAL_DIRS.get(practical_num)
    if not p_dir or not p_dir.exists():
        return []

    plots = []
    # Search common plot directories
    for sub in ["outputs/plots", "plots", "outputs"]:
        target = p_dir / sub
        if target.exists():
            plots.extend(sorted(list(target.glob("*.png"))))
            plots.extend(sorted(list(target.glob("*.jpg"))))

    # Deduplicate while preserving order
    seen = set()
    unique_plots = []
    for p in plots:
        if p.name not in seen:
            seen.add(p.name)
            unique_plots.append(p)
    return unique_plots
