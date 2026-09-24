"""app.py
Root Streamlit Entry Point for Streamlit Community Cloud and Local Execution
PDS Log Analytics & Attack Detection System (Practicals 1 to 10)
"""

import sys
from pathlib import Path

# Resolve repository root and PDS_GUI directories
PROJECT_ROOT = Path(__file__).resolve().parent
GUI_DIR = PROJECT_ROOT / "PDS_GUI"

if str(GUI_DIR) not in sys.path:
    sys.path.insert(0, str(GUI_DIR))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Import master application runner from PDS_GUI
from PDS_GUI.app import main

if __name__ == "__main__":
    main()
