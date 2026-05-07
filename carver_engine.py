"""Core file carving engine with fragmentation recovery and parallel processing (multi‑occurrence fix)."""
from __future__ import annotations
import hashlib
import logging
import math
import os
import struct
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Set

from signatures import (
    BUILTIN_SIGNATURES,
    find_pattern,
    resolve_footer_ambiguity,
)

logger = logging.getLogger(__name__)

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    if HAS_NUMPY:
        values = np.frombuffer(data, dtype=np.uint8)
        counts = np.bincount(values, minlength=256)
        probs = counts / len(values)
        probs = probs[probs > 0]
        return float(-np.sum(probs * np.log2(probs)) / 8.0)
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    total = len(data)
    entropy = 0.0
    for count in freq:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy / 8.0

@dataclass
class CarveCandidate:
    file_id: str = ""
    offset_start: int = 0
    offset_end: int = 0
    size_bytes: int = 0
    file_type: str = ""
    md5: str = ""
    sha1: str = ""
    entropy: float = 0.0
    verified: bool = False
    validation_details: str = ""
    fragmented: bool = False
    output_path: str = ""
    warning: Optional[str] = None
    suspicious_zip_bomb: bool = False
    encrypted: bool = False

def validate_jpeg(data: bytes) -> Tuple[bool, str]:
    if len(data) < 4:
        return False, "Too small"
    if data[0:2] != b"\xff\xd8":
        return False, "Missing SOI marker"
    if data[-2:] != b"\xff\xd9":
        return False, "Missing EOI marker"
    if b"\xff\xda" not in data:
        return False, "Missing SOS marker"
    return True, "Valid JPEG structure with EOI"

def validate_png(data: bytes) -> Tuple[bool, str]:
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return False, "Invalid PNG signature"
    if b"IEND" not in data:
        return False, "Missing IEND chunk"
    try:
        idx = data.find(b"IEND")
        if idx < 8:
            return False, "IEND not found"
        chunk_len = struct.unpack(">I", data[idx-4:idx])[0]
        chunk_type = data[idx:idx+4]
        chunk_data = data[idx+4:idx+4+chunk_len]
        crc_stored = data[idx+4+chunk_len:idx+8+chunk_len]
        crc_computed = struct.pack(">I", zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF)
        if crc_stored == crc_computed:
            return True, "Valid PNG (IEND CRC correct)"
        else:
            return False, "IEND CRC mismatch"
    except Exception as e:
        return False, f"PNG validation error: {e}"

def carve_file(
    data: bytes,
    file_type: str,
    signature: Dict[str, Any],
    global_offset: int,
    search_start: int = 0,
) -> Optional[CarveCandidate]:
    """Carve a single file starting from search_start within data."""
    header_spec = signature.get("header")
    footer_spec = signature.get("footer")
    max_file_size = signature.get("max_size", 50_000_000)
    max_file_size = min(max_file_size, len(data) - search_start) if max_file_size else (len(data) - search_start)
    if max_file_size <= 0:
        return None

    # Find header within search region
    header_pattern = header_spec.get("pattern", "")
    if header_spec.get("type") == "offset_variable":
        max_offset = header_spec.get("max_offset", 4096)
        search_region = data[search_start:search_start + max_offset + len(header_pattern)]
        header_offset_local = find_pattern(search_region, header_pattern)
        if header_offset_local == -1:
            return None
        header_offset = search_start + header_offset_local
    else:
        header_offset = find_pattern(data, header_pattern, search_start)
        if header_offset == -1:
            return None

    abs_start = global_offset + header_offset
    remaining = data[header_offset:]

    footer_offset = None
    if footer_spec:
        pattern = footer_spec.get("pattern", "")
        ambiguity = footer_spec.get("footer_ambiguity", "first")
        search_area = remaining[:max_file_size] if max_file_size else remaining
        if ambiguity == "last_valid_distance":
            min_dist = signature.get("min_size", 22)
            footer_relative = resolve_footer_ambiguity(search_area, footer_spec, min_file_size=min_dist)
        else:
            footer_relative = find_pattern(search_area, pattern)
            if footer_relative == -1 and ambiguity == "last":
                occurrences = []
                pos = 0
                while True:
                    pos = find_pattern(search_area, pattern, pos)
                    if pos == -1:
                        break
                    occurrences.append(pos)
                    pos += 1
                if occurrences:
                    footer_relative = occurrences[-1]
        if footer_relative is not None:
            footer_offset = footer_relative + len(bytes.fromhex(pattern.replace(" ", "")))

    if footer_offset is None:
        # Look for next header of same type to terminate
        next_header = find_pattern(remaining, header_pattern, 1)
        if next_header != -1 and next_header < (max_file_size or len(remaining)):
            carved_end = next_header
        else:
            # entropy drop heuristic
            window_size = 512
            end = len(remaining)
            if end > header_offset + 2 * window_size:
                entropies = []
                for i in range(window_size, end - window_size, window_size):
                    chunk = remaining[i:i+window_size]
                    entropies.append(shannon_entropy(chunk))
                drop_found = False
                for i in range(1, len(entropies)):
                    if entropies[i] < entropies[i-1] - 0.5:
                        carved_end = (i+1) * window_size
                        drop_found = True
                        break
                if not drop_found:
                    carved_end = min(max_file_size or end, end)
            else:
                carved_end = min(max_file_size or end, end)
    else:
        carved_end = footer_offset

    carved_data = remaining[:carved_end]
    if len(carved_data) < signature.get("min_size", 0):
        return None

    md5 = hashlib.md5(carved_data).hexdigest()
    sha1 = hashlib.sha1(carved_data).hexdigest()
    entropy = shannon_entropy(carved_data)

    verified = False
    validation_details = ""
    warning = None
    if file_type == "jpeg":
        verified, validation_details = validate_jpeg(carved_data)
        if not verified:
            if b"\xff\xda" in carved_data:
                validation_details = "Fragmented JPEG (no EOI, but SOS present)"
                warning = "Fragmented JPEG, may be incomplete"
    elif file_type == "png":
        verified, validation_details = validate_png(carved_data)
    elif file_type == "pdf":
        if carved_data.startswith(b"%PDF"):
            verified = True
            validation_details = "PDF header present"
    elif file_type == "zip":
        if carved_data.startswith(b"PK\x03\x04"):
            verified = True
            validation_details = "ZIP header valid"
    else:
        verified = True
        validation_details = "Header found"

    fragmented = (footer_offset is None) and (file_type == "jpeg" and b"\xff\xda" in carved_data)

    return CarveCandidate(
        offset_start=abs_start,
        offset_end=abs_start + len(carved_data),
        size_bytes=len(carved_data),
        file_type=file_type,
        md5=md5,
        sha1=sha1,
        entropy=entropy,
        verified=verified,
        validation_details=validation_details,
        fragmented=fragmented,
        warning=warning,
    )

def carve_chunk(
    chunk_data: bytes,
    global_offset: int,
    signatures: Dict[str, Any],
    file_counter_start: int,
) -> List[CarveCandidate]:
    """Carve all occurrences of all known file types from a chunk."""
    candidates = []
    fid = file_counter_start
    for file_type, sig in signatures.items():
        search_pos = 0
        while True:
            cand = carve_file(chunk_data, file_type, sig, global_offset, search_pos)
            if not cand:
                break
            cand.file_id = f"{fid:04d}"
            fid += 1
            candidates.append(cand)
            # Advance search position to after the carved file's end (relative to chunk)
            end_in_chunk = cand.offset_end - global_offset
            if end_in_chunk <= search_pos:
                end_in_chunk = search_pos + 1  # avoid infinite loop on zero-length
            search_pos = end_in_chunk
            # Safety break to prevent infinite loops
            if search_pos >= len(chunk_data):
                break
    return candidates

def carve_image_parallel(
    image_path: str,
    signatures: Dict[str, Any],
    num_workers: int = 1,
    overlap: int = 1_048_576,
) -> Tuple[List[CarveCandidate], int]:
    file_size = os.path.getsize(image_path)
    # Single-threaded or small file
    if num_workers <= 1 or file_size <= 100 * 1024 * 1024:
        with open(image_path, "rb") as f:
            data = f.read(file_size)
        candidates = carve_chunk(data, 0, signatures, 1)
        return candidates, 0

    # Parallel mode with overlapping chunks
    chunk_size = 100 * 1024 * 1024
    chunks = []
    start = 0
    while start < file_size:
        end = min(start + chunk_size, file_size)
        chunks.append((start, end))
        start = end - overlap
    logger.info("Splitting image into %d chunks", len(chunks))
    seen_offsets: Set[Tuple[int, str]] = set()
    all_candidates: List[CarveCandidate] = []
    warnings_count = 0
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = {}
        for idx, (ch_start, ch_end) in enumerate(chunks):
            future = executor.submit(
                _carve_chunk_from_path, image_path, ch_start, ch_end, signatures, idx * 1000 + 1
            )
            futures[future] = (ch_start, ch_end)
        for future in as_completed(futures):
            try:
                cands = future.result()
                for c in cands:
                    key = (c.offset_start, c.file_type)
                    if key not in seen_offsets:
                        seen_offsets.add(key)
                        all_candidates.append(c)
            except Exception as e:
                logger.error("Chunk failed: %s", e)
                warnings_count += 1
    # Reassign file IDs
    for i, c in enumerate(sorted(all_candidates, key=lambda x: x.offset_start), start=1):
        c.file_id = f"{i:04d}"
    return all_candidates, warnings_count

def _carve_chunk_from_path(
    image_path: str, start: int, end: int, signatures: Dict[str, Any], fid_start: int
) -> List[CarveCandidate]:
    with open(image_path, "rb") as f:
        f.seek(start)
        data = f.read(end - start)
    return carve_chunk(data, start, signatures, fid_start)
