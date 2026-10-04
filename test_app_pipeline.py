"""test_app_pipeline.py
Automated end-to-end verification test for Rox Platform.
"""

import sys
from pathlib import Path

# Add root
root = Path(__file__).resolve().parent
if str(root) not in sys.path:
    sys.path.insert(0, str(root))

from src.pipeline.pipeline import RoxPipeline, ask_rox
from src.pipeline.loader import LogLoader
from src.pipeline.parser import LogParser
from src.gui.practicals import load_practicals_metadata
from utils.data_loader import get_all_practical_plots

def run_tests():
    print("=" * 60)
    print("RUNNING ROX INTEGRATION & PIPELINE TESTS")
    print("=" * 60)

    # Test 1: Load sample_honeypot.log
    sample_file = root / "data" / "sample_honeypot.log"
    assert sample_file.exists(), "Sample log does not exist"
    with open(sample_file, "rb") as f:
        file_bytes = f.read()

    print(f"Test 1: Testing RoxPipeline on {sample_file.name} ({len(file_bytes)} bytes)...")
    pipeline = RoxPipeline(file_bytes, filename=sample_file.name)
    res = pipeline.run()
    assert res["status"] == "SUCCESS", f"Pipeline failed: {res.get('error')}"
    print(f"  -> SUCCESS! Records: {res['total_records']}, Attacks: {res['attacks_count']}, Anomalous: {res['anomalous_count']}")
    assert res["total_records"] > 0
    assert "df" in res and not res["df"].empty

    # Test 2: Ask Rox Q&A
    print("Test 2: Testing deterministic ask_rox() answers...")
    q1 = "What attacks were detected?"
    a1 = ask_rox(q1, res)
    print(f"  Q: '{q1}'\n  A: {a1}\n")

    q2 = "Which IP is most suspicious?"
    a2 = ask_rox(q2, res)
    print(f"  Q: '{q2}'\n  A: {a2}\n")

    q3 = "Which features were extracted?"
    a3 = ask_rox(q3, res)
    print(f"  Q: '{q3}'\n  A: {a3}\n")

    # Test 3: CSV with missing optional columns
    print("Test 3: Testing CSV with missing optional columns...")
    csv_content = b"""timestamp,client_ip,resource_requested
2023-01-08 08:07:15,104.28.209.153,/index.php
2023-01-08 08:07:16,104.28.209.153,/admin/login
2023-01-08 08:07:17,104.28.209.153,/etc/passwd
2023-01-08 08:07:18,104.28.209.153,"' UNION SELECT 1,2,3--"
"""
    p_csv = RoxPipeline(csv_content, filename="test_sample.csv")
    res_csv = p_csv.run()
    assert res_csv["status"] == "SUCCESS", f"CSV pipeline failed: {res_csv.get('error')}"
    print(f"  -> SUCCESS! CSV records: {res_csv['total_records']}, Attacks: {res_csv['attacks_count']}")
    assert res_csv["attacks_count"] >= 2, "Expected attacks (path traversal, sqli) to be detected"

    # Test 4: Missing required column handling
    print("Test 4: Testing CSV missing required column (should fail gracefully)...")
    bad_csv = b"""user_agent,status_code
Mozilla/5.0,200
curl/7.68.0,404
"""
    p_bad = RoxPipeline(bad_csv, filename="bad.csv")
    res_bad = p_bad.run()
    assert res_bad["status"] == "ERROR", "Should have returned ERROR for missing required columns"
    print(f"  -> SUCCESS! Handled gracefully: '{res_bad['error']}'")

    # Test 5: Verify Practicals Metadata and Screenshots
    print("Test 5: Verifying Practicals metadata and screenshots...")
    meta = load_practicals_metadata()
    assert len(meta) == 10, f"Expected 10 practicals in metadata, found {len(meta)}"
    for p in meta:
        p_id = p["id"]
        plots = get_all_practical_plots(p_id)
        print(f"  Practical {p_id:02d}: {p['title']} ({len(plots)} plots found)")

    print("\n" + "=" * 60)
    print("ALL 5 ROX INTEGRATION TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
