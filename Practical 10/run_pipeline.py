"""run_pipeline.py
Top-level runner for Practical 10: Reusable Data Pipeline for Log Files
Forwards arguments to pipeline.run_pipeline
"""

import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pipeline.run_pipeline import main

if __name__ == "__main__":
    main()
