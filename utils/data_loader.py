"""utils/data_loader.py
Safe, Cached Data Loader and File Utilities
Optimized for high-performance Streamlit rendering without loading multi-hundred MB datasets into RAM.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional
import pandas as pd
import streamlit as st
from PIL import Image

from config import PROJECT_ROOT, PRACTICAL_DIRS


def resolve_file_path(path_str: str) -> Path:
    """Resolve relative or absolute file paths against PROJECT_ROOT."""
    p = Path(path_str)
    if p.is_absolute():
        return p
    return PROJECT_ROOT / p


def get_file_info(path_str: str) -> Dict[str, Any]:
    """Return existence, size in bytes, and human-readable size of a file."""
    p = resolve_file_path(path_str)
    exists = p.exists()
    size_bytes = p.stat().st_size if exists else 0
    
    if size_bytes >= 1024 * 1024:
        size_str = f"{size_bytes / (1024 * 1024):.2f} MB"
    elif size_bytes >= 1024:
        size_str = f"{size_bytes / 1024:.2f} KB"
    else:
        size_str = f"{size_bytes} bytes"
        
    return {
        "exists": exists,
        "path": p,
        "size_bytes": size_bytes,
        "size_str": size_str,
        "name": p.name,
    }


@st.cache_data(show_spinner=False)
def read_text_file(path_str: str, max_lines: int = 500) -> str:
    """Safely read text or report files with line capping."""
    p = resolve_file_path(path_str)
    if not p.exists():
        return f"[File not found on disk: {p}]"
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            lines = [f.readline() for _ in range(max_lines)]
            content = "".join(lines)
            if len(lines) == max_lines:
                content += f"\n\n... [Truncated at {max_lines} lines for fast display] ..."
            return content
    except Exception as e:
        return f"[Error reading file {p.name}: {str(e)}]"


@st.cache_data(show_spinner=False)
def read_json_file(path_str: str) -> Dict[str, Any]:
    """Safely read and parse JSON file."""
    p = resolve_file_path(path_str)
    if not p.exists():
        return {}
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        return {"error": str(e)}


@st.cache_data(show_spinner=False)
def load_csv_preview(path_str: str, nrows: int = 50) -> pd.DataFrame:
    """Safely load only the top N rows of a CSV file for high-speed UI preview."""
    p = resolve_file_path(path_str)
    if not p.exists():
        return pd.DataFrame()
    try:
        df = pd.read_csv(p, nrows=nrows)
        return df
    except Exception as e:
        return pd.DataFrame({"Error": [f"Could not load preview: {str(e)}"]})


@st.cache_data(show_spinner=False)
def load_parquet_preview(path_str: str, nrows: int = 50) -> pd.DataFrame:
    """Safely load top N rows of a Parquet file for preview."""
    p = resolve_file_path(path_str)
    if not p.exists():
        return pd.DataFrame()
    try:
        import pyarrow.parquet as pq
        parquet_file = pq.ParquetFile(p)
        batch = next(parquet_file.iter_batches(batch_size=nrows))
        df = batch.to_pandas()
        return df
    except Exception:
        try:
            df = pd.read_parquet(p)
            return df.head(nrows)
        except Exception as e:
            return pd.DataFrame({"Error": [f"Could not load parquet preview: {str(e)}"]})


@st.cache_data(show_spinner=False)
def load_full_small_csv(path_str: str) -> pd.DataFrame:
    """Load small CSV files (summaries, metrics, distributions) entirely."""
    p = resolve_file_path(path_str)
    if not p.exists():
        return pd.DataFrame()
    try:
        return pd.read_csv(p)
    except Exception:
        return pd.DataFrame()


def load_image(path_str: str) -> Optional[Image.Image]:
    """Load an image file safely."""
    p = resolve_file_path(path_str)
    if not p.exists():
        return None
    try:
        return Image.open(p)
    except Exception:
        return None


def get_all_practical_plots(practical_id: int) -> List[Dict[str, Any]]:
    """Scan and return all generated plot images for a practical."""
    p_dir = PRACTICAL_DIRS.get(practical_id)
    if not p_dir or not p_dir.exists():
        return []
    
    plots = []
    # Search in outputs/plots, plots, outputs/ml_verification
    candidate_dirs = [
        p_dir / "outputs" / "plots",
        p_dir / "plots",
        p_dir / "outputs" / "ml_verification",
    ]
    
    seen_paths = set()
    for c_dir in candidate_dirs:
        if c_dir.exists():
            for img_file in sorted(c_dir.glob("*.png")):
                if img_file not in seen_paths:
                    seen_paths.add(img_file)
                    plots.append({
                        "name": img_file.name,
                        "path": img_file,
                        "title": img_file.stem.replace("_", " ").title(),
                        "size_str": f"{img_file.stat().st_size / 1024:.1f} KB",
                    })
    return plots
