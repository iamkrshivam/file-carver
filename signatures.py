"""Advanced signature engine for file carving."""
from __future__ import annotations
import json
import re
from typing import Any, Dict, List, Optional, Tuple

# Default built-in signatures
BUILTIN_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "jpeg": {
        "header": {"type": "exact", "pattern": "FF D8 FF E0"},
        "footer": {"type": "exact", "pattern": "FF D9"},
        "max_size": 20_000_000,
        "footer_ambiguity": "last",
        "validation": "jpeg_structure",
    },
    "png": {
        "header": {"type": "exact", "pattern": "89 50 4E 47 0D 0A 1A 0A"},
        "footer": {"type": "exact", "pattern": "49 45 4E 44 AE 42 60 82"},
        "max_size": 50_000_000,
        "footer_ambiguity": "first",
        "validation": "png_crc",
    },
    "zip": {
        "header": {"type": "exact", "pattern": "50 4B 03 04"},
        "footer": {
            "type": "exact",
            "pattern": "50 4B 05 06",
            "footer_ambiguity": "last_valid_distance",
        },
        "max_size": 200_000_000,
        "min_size": 22,
        "footer_ambiguity": "last",
    },
    "pdf": {
        "header": {"type": "offset_variable", "pattern": "25 50 44 46", "max_offset": 1024},
        "footer": {"type": "wildcard", "pattern": "25 25 45 4F 46"},
        "max_size": 100_000_000,
        "footer_ambiguity": "first",
    },
    "gif": {
        "header": {"type": "exact", "pattern": "47 49 46 38"},
        "footer": {"type": "exact", "pattern": "00 3B"},
        "max_size": 10_000_000,
    },
    "bmp": {
        "header": {"type": "exact", "pattern": "42 4D"},
        "max_size": 20_000_000,
        # BMP has no universal footer; we carve to next header or max size.
    },
    "docx": {
        "header": {"type": "exact", "pattern": "50 4B 03 04"},
        "footer": {"type": "exact", "pattern": "50 4B 05 06"},
        "max_size": 100_000_000,
        "footer_ambiguity": "last",
    },
    "exe": {
        "header": {"type": "exact", "pattern": "4D 5A"},
        "max_size": 500_000_000,
    },
    "mp4": {
        "header": {"type": "exact", "pattern": "00 00 00 18 66 74 79 70"},
        "max_size": 2_000_000_000,
        "note": "fragmented MP4 recovery not supported",
    },
}


def load_signatures(path: str) -> Dict[str, Any]:
    """Load signature definitions from a JSON file, merging with builtins."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            user_sigs = json.load(f)
        merged = BUILTIN_SIGNATURES.copy()
        merged.update(user_sigs)
        return merged
    except FileNotFoundError:
        return BUILTIN_SIGNATURES


def pattern_to_bytes(pattern: str) -> bytes:
    """Convert a hex string with possible '??' wildcards to bytes and mask.
    Returns (pattern_bytes, mask) where mask bit=0 for wildcard.
    """
    parts = pattern.split()
    pat_bytes = bytearray()
    mask = bytearray()
    for p in parts:
        if p == "??":
            pat_bytes.append(0)
            mask.append(0)
        else:
            pat_bytes.append(int(p, 16))
            mask.append(0xFF)
    return bytes(pat_bytes), bytes(mask)


def find_pattern(data: bytes, pattern: str, offset: int = 0) -> int:
    """Locate pattern in data, supporting '??' wildcards. Return index or -1."""
    if "??" in pattern:
        pat_bytes, mask = pattern_to_bytes(pattern)
        for i in range(offset, len(data) - len(pat_bytes) + 1):
            if all((data[i + j] & mask[j]) == pat_bytes[j] for j in range(len(pat_bytes))):
                return i
        return -1
    else:
        pat_bytes = bytes.fromhex(pattern.replace(" ", ""))
        return data.find(pat_bytes, offset)


def resolve_footer_ambiguity(data: bytes, footer_spec: Dict[str, Any], min_file_size: int = 0) -> Optional[int]:
    """Given raw data and footer spec, return offset of the correct footer."""
    pattern = footer_spec.get("pattern", "")
    ambiguity = footer_spec.get("footer_ambiguity", "first")
    occurrences = []
    offset = 0
    pat_bytes_no_mask = bytes.fromhex(pattern.replace(" ", "")) if "??" not in pattern else None
    if pat_bytes_no_mask:
        # Simple exact search for all occurrences
        start = 0
        while True:
            pos = data.find(pat_bytes_no_mask, start)
            if pos == -1:
                break
            occurrences.append(pos)
            start = pos + 1
    else:
        # Wildcard search, not as efficient but ok for header/footer
        pat_bytes, mask = pattern_to_bytes(pattern)
        for i in range(len(data) - len(pat_bytes) + 1):
            if all((data[i + j] & mask[j]) == pat_bytes[j] for j in range(len(pat_bytes))):
                occurrences.append(i)
    if not occurrences:
        return None
    if ambiguity == "first":
        return occurrences[0]
    elif ambiguity == "last":
        return occurrences[-1]
    elif ambiguity == "last_valid_distance":
        # pick last footer that leaves at least min_file_size before it
        for pos in reversed(occurrences):
            if pos >= min_file_size:
                return pos
        return None
    return None
