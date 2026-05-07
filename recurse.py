"""Recursive container extraction: ZIP, DOCX, XLSX, PDF."""
from __future__ import annotations
import hashlib
import json
import logging
import os
import zipfile
import tempfile
from typing import Dict, List, Optional
from threat_protection import sanitize_filename

logger = logging.getLogger(__name__)
MAX_DEPTH = 5

_processed_hashes: set = set()

def compute_sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def is_supported_container(filename: str) -> bool:
    """Check extension for recognized container formats."""
    ext = os.path.splitext(filename)[1].lower()
    return ext in (".zip", ".docx", ".xlsx", ".pptx", ".odt", ".pdf")


def extract_and_recurse(container_path: str, output_parent_dir: str, depth: int = 0) -> List[str]:
    """
    Extract a container (ZIP, DOCX, etc.) into a subdirectory and return
    list of newly created file paths for further carving.
    """
    if depth > MAX_DEPTH:
        logger.warning("Recursion depth exceeded for %s", container_path)
        return []

    container_data: Optional[bytes] = None
    try:
        with open(container_path, "rb") as f:
            container_data = f.read()
    except Exception as e:
        logger.error("Cannot read container %s: %s", container_path, e)
        return []

    container_hash = compute_sha256_bytes(container_data)
    if container_hash in _processed_hashes:
        logger.info("Skipping already processed container: %s", container_path)
        return []
    _processed_hashes.add(container_hash)

    # Create output folder: ./carved/archives/<original_base>_unpacked/
    base = sanitize_filename(os.path.splitext(os.path.basename(container_path))[0])
    unpack_dir = os.path.join(output_parent_dir, "archives", f"{base}_unpacked")
    os.makedirs(unpack_dir, exist_ok=True)

    extracted_files: List[str] = []
    try:
        # Try ZIP (works for docx, xlsx, etc.)
        if zipfile.is_zipfile(container_path):
            with zipfile.ZipFile(container_path, "r") as zf:
                # Quick bomb check (already in threat_protection but we check again)
                for info in zf.infolist():
                    if info.file_size > 100_000_000:
                        logger.warning("Skipping large file inside container: %s", info.filename)
                        continue
                    target_name = sanitize_filename(info.filename)
                    target_path = os.path.join(unpack_dir, target_name)
                    os.makedirs(os.path.dirname(target_path) or unpack_dir, exist_ok=True)
                    with zf.open(info) as src, open(target_path, "wb") as dest:
                        dest.write(src.read())
                    extracted_files.append(target_path)
        else:
            # Future: PDF extraction, etc.
            logger.warning("Container extraction not supported for: %s", container_path)
            return []
    except Exception as e:
        logger.error("Extraction failed for %s: %s", container_path, e)
        return []

    # Recurse into nested containers among extracted files
    nested_results: List[str] = []
    for ef in extracted_files:
        if is_supported_container(ef):
            nested_results.extend(extract_and_recurse(ef, output_parent_dir, depth + 1))
    return extracted_files + nested_results
