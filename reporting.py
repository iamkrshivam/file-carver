"""Reporting: produce JSON and CSV output, thumbnails, categorisation."""
from __future__ import annotations
import csv
import json
import os
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

THUMBNAIL_DIR = "thumbnails"

def generate_reports(
    carved_files: List[Dict[str, Any]],
    output_dir: str,
    source_info: Dict[str, Any],
    execution_info: Dict[str, Any],
    audit_log_path: str,
    warnings_count: int,
    errors_count: int,
) -> None:
    """Write the full JSON report and a flat CSV."""
    report = {
        "source_image": source_info,
        "execution": execution_info,
        "carved_files": carved_files,
        "audit_log_path": audit_log_path,
        "warnings_count": warnings_count,
        "errors_count": errors_count,
    }
    json_path = os.path.join(output_dir, "report.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("JSON report written to %s", json_path)

    csv_path = os.path.join(output_dir, "report.csv")
    fieldnames = ["file_id", "offset_start", "type", "size_bytes", "md5", "verified"]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for file_info in carved_files:
            writer.writerow(file_info)
    logger.info("CSV report written to %s", csv_path)


def create_thumbnail(file_path: str, output_dir: str, file_id: str) -> Optional[str]:
    """Attempt to create a thumbnail for JPEG/PNG using Pillow. Returns path or None."""
    try:
        from PIL import Image
    except ImportError:
        logger.warning("Pillow not available, skipping thumbnail for %s", file_id)
        return None
    thumb_dir = os.path.join(output_dir, THUMBNAIL_DIR)
    os.makedirs(thumb_dir, exist_ok=True)
    try:
        img = Image.open(file_path)
        img.thumbnail((128, 128))
        thumb_name = f"{file_id}_thumb.png"
        thumb_path = os.path.join(thumb_dir, thumb_name)
        img.save(thumb_path)
        return thumb_path
    except Exception as e:
        logger.warning("Thumbnail creation failed for %s: %s", file_id, e)
        return None


def categorize_risk(file_info: Dict[str, Any]) -> List[str]:
    """Return list of risk tags for a carved file."""
    tags = []
    if file_info.get("suspicious_zip_bomb"):
        tags.append("zip_bomb")
    if file_info.get("encrypted"):
        tags.append("encrypted")
    if file_info.get("entropy", 0) > 7.5:
        tags.append("high_entropy")
    return tags
