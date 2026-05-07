"""Threat protection: zip bomb detection, path sanitization, malformed PDF handling."""
from __future__ import annotations
import os
import re
import logging
import zlib
from typing import Optional

logger = logging.getLogger(__name__)

MAX_COMPRESSION_RATIO = 1000
MAX_UNCOMPRESSED_SIZE = 100_000_000  # 100 MB


def sanitize_filename(name: str) -> str:
    """Replace dangerous characters to prevent path traversal."""
    sanitized = re.sub(r"[/\\:\x00]+", "_", name)
    sanitized = re.sub(r"\.\.", "_", sanitized)
    # Remove leading dots and spaces
    sanitized = sanitized.lstrip(". ")
    if not sanitized:
        sanitized = "unknown"
    return sanitized


def check_zip_bomb(compressed_size: int, uncompressed_size: int) -> bool:
    """Return True if the file appears to be a zip bomb."""
    if compressed_size <= 0:
        return False
    ratio = uncompressed_size / compressed_size
    if ratio > MAX_COMPRESSION_RATIO or uncompressed_size > MAX_UNCOMPRESSED_SIZE:
        return True
    return False


def safe_pdf_parse(raw_data: bytes) -> Optional[dict]:
    """Attempt to parse a PDF using pypdf (optional). Returns info dict or None on failure."""
    try:
        from pypdf import PdfReader
        import io
        reader = PdfReader(io.BytesIO(raw_data))
        num_pages = len(reader.pages)
        metadata = reader.metadata
        return {"pages": num_pages, "encrypted": reader.is_encrypted}
    except Exception as e:
        logger.warning("PDF parsing failed: %s", e)
        return {"pages": -1, "encrypted": False, "error": str(e)}


def safe_zip_extract(zip_path: str, output_dir: str) -> bool:
    """Extract a ZIP archive with basic size checks. Returns True if safe."""
    import zipfile
    with zipfile.ZipFile(zip_path, "r") as zf:
        total_uncompressed = sum(info.file_size for info in zf.infolist())
        total_compressed = sum(info.compress_size for info in zf.infolist())
        if check_zip_bomb(total_compressed, total_uncompressed):
            logger.error("ZIP bomb detected in %s", zip_path)
            return False
        # Check individual files
        for info in zf.infolist():
            if info.file_size > MAX_UNCOMPRESSED_SIZE:
                logger.error("File too large inside ZIP: %s", info.filename)
                continue
            # Sanitize path to prevent traversal
            target_name = sanitize_filename(info.filename)
            target_path = os.path.join(output_dir, target_name)
            os.makedirs(os.path.dirname(target_path) or output_dir, exist_ok=True)
            with zf.open(info) as source, open(target_path, "wb") as dest:
                dest.write(source.read())
    return True
