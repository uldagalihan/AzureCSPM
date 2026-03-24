"""
Utility: convert CSV files in a directory to Excel (.xlsx) format.

Scans a target directory (default: the project output/ directory) for all
CSV files and converts each one to an Excel workbook. Existing .xlsx files
with the same base name are overwritten.

Usage:
    python csv_to_excel.py [--dir <directory>]
"""
import argparse
import logging
import os
import sys

import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DIR = os.path.join(_PROJECT_ROOT, "output")


def convert_directory(target_dir: str) -> None:
    """Convert all CSV files in *target_dir* to Excel format.

    Args:
        target_dir: Path to the directory containing CSV files.
    """
    csv_files = [f for f in os.listdir(target_dir) if f.endswith(".csv")]
    if not csv_files:
        logger.info("No CSV files found in '%s'.", target_dir)
        return

    for filename in csv_files:
        csv_path = os.path.join(target_dir, filename)
        xlsx_path = os.path.join(target_dir, filename.replace(".csv", ".xlsx"))
        try:
            df = pd.read_csv(csv_path)
            df.to_excel(xlsx_path, index=False)
            logger.info("Converted: %s -> %s", filename, os.path.basename(xlsx_path))
        except Exception as exc:
            logger.error("Failed to convert '%s': %s", filename, exc)


def main() -> None:
    """Entry point: parse arguments and run CSV-to-Excel conversion."""
    parser = argparse.ArgumentParser(description="Convert CSV exports to Excel format.")
    parser.add_argument(
        "--dir",
        default=DEFAULT_DIR,
        help=f"Directory containing CSV files (default: {DEFAULT_DIR})",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.dir):
        logger.error("Directory not found: %s", args.dir)
        sys.exit(1)

    logger.info("Converting CSVs in: %s", args.dir)
    convert_directory(args.dir)


if __name__ == "__main__":
    main()
