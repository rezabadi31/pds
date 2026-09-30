"""PDS_GUI/app.py
Legacy Entry Point Forwarder
Ensures backwards compatibility if launched from PDS_GUI directory or legacy Streamlit Cloud paths.
"""

import sys
from pathlib import Path

# Ensure root directory is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Forward directly to the redesigned master application
from app import main

if __name__ == "__main__":
    main()
