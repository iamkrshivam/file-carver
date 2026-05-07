"""Forensic integrity: SHA256 hashing and audit logging."""
from __future__ import annotations
import hashlib
import json
import datetime
import socket
import os
from typing import Optional, TextIO

def sha256_file_streaming(path: str, chunk_size: int = 1_048_576) -> str:
    """Compute SHA256 hash of a file without loading it entirely into memory."""
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            sha.update(chunk)
    return sha.hexdigest()


class AuditLogger:
    """Immutable audit log (JSONL) for forensic chain of custody."""
    def __init__(self, output_path: str, investigator: str, source_hash: str):
        self.path = output_path
        self.investigator = investigator
        self.source_hash = source_hash
        self._file: Optional[TextIO] = None
        self._hostname = socket.gethostname()
        self._started = False

    def start(self) -> None:
        """Open audit log and write the start entry."""
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self._file = open(self.path, "w", encoding="utf-8")
        self._started = True
        self._log("carve_start", "Investigation started")

    def log_carve_file(self, file_id: str, file_type: str, offset_start: int, offset_end: int, output_name: str) -> None:
        self._log("carve_file", f"Carved {file_id} ({file_type})", {
            "file_id": file_id,
            "type": file_type,
            "offset_start": offset_start,
            "offset_end": offset_end,
            "output": output_name,
        })

    def log_warning(self, message: str, details: Optional[dict] = None) -> None:
        self._log("warning", message, details)

    def log_error(self, message: str, details: Optional[dict] = None) -> None:
        self._log("error", message, details)

    def finish(self) -> None:
        self._log("carve_end", "Investigation finished")
        if self._file:
            self._file.close()
            self._file = None
            self._started = False

    def _log(self, action: str, message: str, extra: Optional[dict] = None) -> None:
        if not self._file:
            raise RuntimeError("Audit log not started")
        entry = {
            "timestamp_utc": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "action": action,
            "investigator": self.investigator,
            "hostname": self._hostname,
            "source_sha256": self.source_hash,
            "message": message,
            **(extra or {}),
        }
        self._file.write(json.dumps(entry) + "\n")
        self._file.flush()
