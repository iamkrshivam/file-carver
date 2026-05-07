"""Integration test: carves test image and verifies recovered JPEGs."""
import hashlib
import json
import os
import subprocess
import sys
import pytest

TEST_IMAGE = "tests/test_image.raw"
OUTPUT_DIR = "tests/carved_output"
CARVER_CMD = ["python3", "carver.py", "--input", TEST_IMAGE, "--output", OUTPUT_DIR, "--investigator", "Tester"]

def setup_module():
    # Generate test image if not present
    if not os.path.exists(TEST_IMAGE):
        subprocess.run(["python3", "tests/generate_test_image.py"], check=True)

def teardown_module():
    # Cleanup carved output after tests
    import shutil
    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)

def test_carve_jpegs():
    """Carve test image and verify at least 4 JPEGs recovered with valid MD5."""
    # Remove previous output if exists
    if os.path.exists(OUTPUT_DIR):
        import shutil
        shutil.rmtree(OUTPUT_DIR)
    # Run carver
    result = subprocess.run(CARVER_CMD, capture_output=True, text=True)
    assert result.returncode == 0, f"Carver failed: {result.stderr}"
    # Load report
    report_path = os.path.join(OUTPUT_DIR, "report.json")
    assert os.path.exists(report_path), "Report not generated"
    with open(report_path, "r") as f:
        report = json.load(f)
    carved = report["carved_files"]
    jpeg_carved = [f for f in carved if f["type"] == "jpeg"]
    assert len(jpeg_carved) >= 4, f"Expected at least 4 JPEGs carved, got {len(jpeg_carved)}"
    # Verify each JPEG file exists and has non-zero size
    for f in jpeg_carved:
        fpath = f["output_path"]
        assert os.path.exists(fpath), f"Carved file missing: {fpath}"
        assert os.path.getsize(fpath) > 0, f"Zero-size file: {fpath}"
        # Check MD5 consistency with report
        with open(fpath, "rb") as fh:
            md5 = hashlib.md5(fh.read()).hexdigest()
        assert md5 == f["md5"], f"MD5 mismatch for {fpath}"
    # Check audit log exists
    audit_path = os.path.join(OUTPUT_DIR, "audit.jsonl")
    assert os.path.exists(audit_path), "Audit log missing"
