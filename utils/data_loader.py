"""utils/data_loader.py
Safe, Cached Data Loader and File Utilities for Rox Platform
Portable across local development and Streamlit Community Cloud without absolute paths.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional
import pandas as pd
import streamlit as st
from PIL import Image

from config import PROJECT_ROOT, ASSETS_DIR, PRACTICAL_DIRS


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
        return f"[File not found on disk: {p.name}]"
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
    """Safely load only top N rows of a CSV file for high-speed UI preview."""
    p = resolve_file_path(path_str)
    if not p.exists():
        return pd.DataFrame()
    try:
        return pd.read_csv(p, nrows=nrows)
    except Exception as e:
        return pd.DataFrame({"Error": [f"Could not load preview: {str(e)}"]})


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
    """Scan and return all generated plot images for a practical.
    
    Checks deployed assets/practicals/practical_XX first for Cloud portability,
    then checks Practical X/outputs/plots during local development.
    """
    plots = []
    seen_names = set()

    # Priority 1: Deployed assets directory (works on Cloud!)
    deployed_dir = ASSETS_DIR / "practicals" / f"practical_{practical_id:02d}"
    if deployed_dir.exists():
        for ext in ["*.png", "*.jpg", "*.webp"]:
            for img_file in sorted(deployed_dir.glob(ext)):
                if img_file.name not in seen_names:
                    seen_names.add(img_file.name)
                    plots.append({
                        "name": img_file.name,
                        "path": img_file,
                        "title": img_file.stem.replace("_", " ").title(),
                        "size_str": f"{img_file.stat().st_size / 1024:.1f} KB",
                    })

    # Priority 2: Practical folder outputs (local fallback)
    p_dir = PRACTICAL_DIRS.get(practical_id)
    if p_dir and p_dir.exists():
        candidate_dirs = [
            p_dir / "outputs" / "plots",
            p_dir / "plots",
            p_dir / "outputs" / "ml_verification",
        ]
        for c_dir in candidate_dirs:
            if c_dir.exists():
                for ext in ["*.png", "*.jpg", "*.webp"]:
                    for img_file in sorted(c_dir.glob(ext)):
                        if img_file.name not in seen_names:
                            seen_names.add(img_file.name)
                            plots.append({
                                "name": img_file.name,
                                "path": img_file,
                                "title": img_file.stem.replace("_", " ").title(),
                                "size_str": f"{img_file.stat().st_size / 1024:.1f} KB",
                            })
    return plots
