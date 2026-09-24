"""run_pipeline.py
CLI Entry Point for Practical 10 Log Processing Pipeline
Supports --input, --output, --format, and --help
"""

import sys
import argparse
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pipeline.config import DEFAULT_INPUT_PATH, DATA_PROCESSED_DIR
from pipeline.log_pipeline import LogProcessingPipeline


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Practical 10: Reusable, Auditable, and Modular Log Processing Pipeline for Access Logs",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-i", "--input",
        dest="input_path",
        type=str,
        default=str(DEFAULT_INPUT_PATH),
        help="Path to the input raw log file (supports .log, .json, .txt).",
    )
    parser.add_argument(
        "-o", "--output",
        dest="output_dir",
        type=str,
        default=str(DATA_PROCESSED_DIR),
        help="Directory to save the processed output datasets and artifacts.",
    )
    parser.add_argument(
        "-f", "--format",
        dest="export_format",
        type=str,
        choices=["csv", "parquet", "all"],
        default="all",
        help="Desired serialization format for final feature-engineered dataset.",
    )
    return parser.parse_args()


def main():
    args = parse_arguments()

    formats = ["csv", "parquet"] if args.export_format == "all" else [args.export_format]

    pipeline = LogProcessingPipeline(
        input_path=args.input_path,
        output_dir=args.output_dir,
        export_formats=formats,
    )
    result = pipeline.run()

    # Return exit code based on validation
    sys.exit(0 if result.get("status") == "SUCCESS" else 1)


if __name__ == "__main__":
    main()
