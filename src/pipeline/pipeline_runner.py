"""src/pipeline/pipeline_runner.py
Backward Compatibility Adapter for Rox Platform
Redirects legacy RoxLogAnalyzer calls directly to the modern, modular RoxPipeline.
"""

from typing import Dict, Any
from src.pipeline.pipeline import RoxPipeline, ask_rox


class RoxLogAnalyzer:
    """Compatibility wrapper that runs RoxPipeline."""

    def __init__(self, uploaded_file, filename: str):
        self.pipeline = RoxPipeline(uploaded_file, filename)

    def run_analysis(self) -> Dict[str, Any]:
        """Runs the pipeline and returns structured intelligence."""
        return self.pipeline.run()


__all__ = ["RoxLogAnalyzer", "ask_rox"]
