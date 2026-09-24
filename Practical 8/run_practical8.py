#!/usr/bin/env python3
r"""run_practical8.py (Root Launcher)
Practical 8: Data Visualization and Exploratory Data Analysis (EDA)
===================================================================
Location: D:\Pds Practicals\Practical 8\run_practical8.py
"""

import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.run_practical8 import main

if __name__ == "__main__":
    main()
