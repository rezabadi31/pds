"""pipeline package for Practical 10
Reusable Log Processing Pipeline
"""

from .config import DEFAULT_INPUT_PATH
from .log_pipeline import LogProcessingPipeline

__all__ = ["LogProcessingPipeline", "DEFAULT_INPUT_PATH"]
