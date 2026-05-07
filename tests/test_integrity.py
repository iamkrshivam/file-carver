"""Unit tests for integrity module: SHA256 streaming and audit logging."""
import os
import tempfile
import hashlib
import json
import sys
sys.path.insert(0, ".")
from integrity import sha256_file_streaming, AuditLogger

def test_sha256_streaming():
    """Verify streaming hash matches reference."""
    data = b"A" * 1000000  # 1 MB
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        tmp = f.name
    try:
        h1 = sha256_file_streaming(tmp)
        h2 = hashlib.sha256(data).hexdigest()
        assert h1 == h2
    finally:
        os.unlink(tmp)

def test_audit_log():
    """Check audit logger creates valid JSONL entries."""
    with tempfile.TemporaryDirectory() as td:
        log_path = os.path.join(td, "audit.jsonl")
        logger = AuditLogger(log_path, "Test", "abcdef")
        logger.start()
        logger.log_carve_file("0001", "jpeg", 100, 200, "file.jpg")
        logger.finish()
        with open(log_path, "r") as f:
            lines = f.readlines()
        assert len(lines) >= 2  # start and file
        entry = json.loads(lines[1])
        assert entry["action"] == "carve_file"
        assert entry["file_id"] == "0001"
