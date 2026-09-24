#!/usr/bin/env python3
r"""verify_visualization.py (Root Launcher)
Practical 8: Quality Validation Suite
====================================
Location: D:\Pds Practicals\Practical 8\verify_visualization.py
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.verify_visualization import run_verification

if __name__ == "__main__":
    success = run_verification()
    sys.exit(0 if success else 1)
