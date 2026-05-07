"""Filesystem-aware carving: NTFS and FAT unallocated cluster extraction."""
from __future__ import annotations
import struct
import logging
from typing import List, Tuple, Optional

logger = logging.getLogger(__name__)

# NTFS constants
NTFS_OEM_ID_OFFSET = 0x03
NTFS_SECTOR_SIZE_OFFSET = 0x0B
NTFS_CLUSTERS_PER_MFT_REC_OFFSET = 0x40  # actually MFT record size, but we use $MFT's info
NTFS_MFT_START_CLUSTER_OFFSET = 0x30
# Simplified – we'll parse $MFT file from known location

# FAT constants
FAT_SECTOR_SIZE_OFFSET = 0x0B
FAT_CLUSTER_SIZE_OFFSET = 0x0D
FAT_RESERVED_SECTORS_OFFSET = 0x0E
FAT_NUM_FATS_OFFSET = 0x10
FAT_ROOT_ENT_CNT_OFFSET = 0x11
FAT_FAT_SIZE_OFFSET = 0x16  # FAT16
FAT32_FAT_SIZE_OFFSET = 0x24


def parse_ntfs_unallocated(image_path: str) -> List[Tuple[int, int]]:
    """
    Return list of (start_byte_offset, size_bytes) for unallocated clusters
    on an NTFS volume. Simplified implementation: assumes entire volume is carved
    but identifies file record free space. For full accuracy, we would parse $Bitmap.
    This is a proof-of-concept. Falls back to empty list on failure.
    """
    try:
        with open(image_path, "rb") as f:
            # Read boot sector
            boot = f.read(512)
            oem = boot[3:11].decode("ascii").strip()
            if "NTFS" not in oem:
                logger.warning("NTFS signature not found")
                return []
            bytes_per_sector = struct.unpack("<H", boot[0x0B:0x0D])[0]
            sectors_per_cluster = boot[0x0D]
            cluster_size = bytes_per_sector * sectors_per_cluster
            # MFT start cluster (logical cluster number)
            mft_cluster = struct.unpack("<Q", boot[0x30:0x38])[0]
            mft_offset = mft_cluster * cluster_size
            f.seek(mft_offset)
            # MFT record size: from boot? Or assume 1024 bytes
            mft_record_size = 1024
            # Just a placeholder: we would need to parse $Bitmap to find free clusters.
            # For the exercise, return the whole image offset region (full scan fallback expected)
            logger.warning("NTFS unallocated parsing is simplified; returning empty list to force full scan")
            return []
    except Exception as e:
        logger.error("NTFS parsing failed: %s", e)
        return []


def parse_fat_unallocated(image_path: str) -> List[Tuple[int, int]]:
    """Return list of (start, size) for unallocated clusters on a FAT volume."""
    try:
        with open(image_path, "rb") as f:
            boot = f.read(512)
            fat_type = "FAT12"  # simplified
            bytes_per_sector = struct.unpack("<H", boot[0x0B:0x0D])[0]
            sectors_per_cluster = boot[0x0D]
            reserved_sectors = struct.unpack("<H", boot[0x0E:0x10])[0]
            num_fats = boot[0x10]
            # FAT size determination is complex; fallback
            logger.warning("FAT unallocated parsing is simplified; returning empty list")
            return []
    except Exception as e:
        logger.error("FAT parsing failed: %s", e)
        return []


def get_unallocated_regions(image_path: str, fs_type: str) -> List[Tuple[int, int]]:
    """
    Entry point: returns list of (start, size) for unallocated blocks.
    If parsing fails or returns empty, the caller should fall back to full-image carving.
    """
    if fs_type.lower() == "ntfs":
        return parse_ntfs_unallocated(image_path)
    elif fs_type.lower() in ("fat", "fat32", "fat16", "fat12"):
        return parse_fat_unallocated(image_path)
    else:
        logger.error("Unsupported filesystem: %s", fs_type)
        return []
