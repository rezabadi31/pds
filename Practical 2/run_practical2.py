#!/usr/bin/env python3
r"""
Practical 2: To Convert the Unstructured Log Data into a Structured Dataset
==========================================================================
Location: D:\Pds Practicals\Practical 2\run_practical2.py

Executable entry point for Practical 2.
"""

import sys
import time
from pathlib import Path

# Configure project root
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from practical_2 import (
    get_raw_log_path,
    step_1_check_input_dataset,
    step_2_inspect_raw_records,
    step_3_and_4_parse_and_extract,
    step_5_and_6_create_and_validate_dataframe,
    step_7_generate_plots,
    step_8_generate_reports,
    ALL_STRUCTURED_COLUMNS,
    SOURCE_FIELDS,
    UNAVAILABLE_HTTP_FIELDS,
    DATA_PROCESSED_DIR,
    OUTPUTS_DIR,
    PLOTS_DIR,
    REPORTS_DIR
)


def main():
    print("=" * 60)
    print("PRACTICAL 2")
    print("CONVERT UNSTRUCTURED LOG DATA INTO A STRUCTURED DATASET")
    print("=" * 60)

    # [1/8] Checking input dataset
    print("\n[1/8] Checking input dataset...")
    raw_path = get_raw_log_path()
    input_info = step_1_check_input_dataset(raw_path)
    print(f"-> Located raw access log: {input_info['name']}")
    print(f"-> Source Path: {input_info['path']}")
    print(f"-> File Size:   {input_info['size_bytes']:,} bytes ({input_info['size_mb']:.2f} MB)")

    # [2/8] Inspecting raw records
    print("\n[2/8] Inspecting raw records...")
    first_5 = step_2_inspect_raw_records(raw_path)
    print("First 3 raw JSON-array records:")
    for i, line in enumerate(first_5[:3], 1):
        print(f"  {i}. {line[:95]}...")

    # [3/8 & 4/8] Parsing records and extracting structured fields
    print("\n[3/8] Parsing records...")
    print("[4/8] Extracting structured fields...")
    start_t = time.time()
    stats = step_3_and_4_parse_and_extract(raw_path)
    parse_time = time.time() - start_t
    print(f"-> Streaming parsing completed in {parse_time:.2f} seconds.")
    print(f"   Physical Lines:       {stats['total_physical_lines']:,}")
    print(f"   Blank Lines:          {stats['blank_lines']:,}")
    print(f"   Multi-entry lines:    {stats['multi_entry_lines']:,} (+{stats['extra_records_from_splits']:,} extra records)")
    print(f"   Total Log Records:    {stats['total_extracted_records']:,}")
    print(f"   Successfully Parsed:  {stats['successfully_parsed']:,} ({stats['parsing_success_rate']:.4f}%)")
    print(f"   Malformed Records:    {stats['malformed_records']:,}")

    # [5/8] Creating Pandas DataFrame
    print("\n[5/8] Creating Pandas DataFrame...")
    df = step_5_and_6_create_and_validate_dataframe(stats)
    print(f"-> DataFrame instantiated successfully.")
    print(f"   Shape: {df.shape[0]:,} rows x {df.shape[1]} columns")

    # [6/8] Validating structured data
    print("\n[6/8] Validating structured data...")
    print(f"-> Columns ({len(df.columns)}): {', '.join(df.columns)}")
    print("\nDataFrame Head (first 5 rows):")
    print(df.head(5)[["timestamp", "client_ip", "client_port", "category_type", "user_agent"]])
    print("\nDataFrame Info:")
    df.info()
    print("\nMissing Values:")
    print(df.isnull().sum())

    # [7/8] Generating analysis and plots
    print("\n[7/8] Generating analysis and plots...")
    step_7_generate_plots(stats, df)
    print("-> Generated 5 plots in outputs/plots/:")
    print("   - top_10_ips.png")
    print("   - top_user_agents.png")
    print("   - records_over_time.png")
    print("   - missing_values.png")
    print("   - top_categories.png")

    # [8/8] Saving reports and outputs
    print("\n[8/8] Saving reports and outputs...")
    step_8_generate_reports(stats, df)
    print("-> Saved analytical reports in outputs/reports/:")
    print("   - parsing_report.txt")
    print("   - field_mapping_report.txt")
    print("   - data_quality_report.txt")
    print("   - structured_sample.txt")

    output_csv = Path(stats["output_csv_path"])
    print(f"-> Structured dataset saved at: {output_csv}")
    print(f"   Size: {output_csv.stat().st_size:,} bytes ({output_csv.stat().st_size/(1024*1024):.2f} MB)")

    # Final summary matching section 17
    print("\n" + "=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)
    print(f"Dataset:                          {input_info['name']}")
    print(f"Input Format:                     Web Honeypot / Intrusion Detection Access Log (JSON Array)")
    print(f"Total Records:                    {stats['total_extracted_records']:,}")
    print(f"Successfully Parsed:              {stats['successfully_parsed']:,}")
    print(f"Malformed:                        {stats['malformed_records']:,}")
    print(f"Parsing Success:                  {stats['parsing_success_rate']:.4f}%")
    print(f"DataFrame Rows:                   {stats['successfully_parsed']:,}")
    print(f"DataFrame Columns:                {len(ALL_STRUCTURED_COLUMNS)}")
    print(f"Structured Fields:                {', '.join(SOURCE_FIELDS)}")
    print(f"Unavailable Standard HTTP Fields: {', '.join(UNAVAILABLE_HTTP_FIELDS)}")
    print(f"Output:                           {output_csv}")
    print("STATUS: SUCCESS")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
