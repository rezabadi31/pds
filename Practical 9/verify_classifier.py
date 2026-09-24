"""Top-level verification runner for Practical 9.
"""

import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.verify_classifier import run_verification

if __name__ == "__main__":
    success = run_verification()
    sys.exit(0 if success else 1)
