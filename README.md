# File Carving Suite (DFIR Tool)

**Legal Disclaimer**: This tool is intended for lawful digital forensic investigations, incident response, and data recovery. Unauthorized use on systems you do not own or have legal authority to access may violate applicable laws. The authors assume no liability for misuse.

## Overview
A production‑ready file carving suite for recovering deleted files from raw disk images, memory dumps, or unallocated space. Designed for forensic soundness with full chain‑of‑custody logging, parallel carving, and optional filesystem‑aware parsing.

## Features
- Header‑footer carving, fragmented JPEG recovery, entropy‑based fragment detection
- Advanced signature engine (exact, wildcard, offset‑variable)
- Parallel carving with boundary‑safe chunk splitting and deduplication
- Immutable audit log (JSONL) and SHA‑256 source verification
- Threat protection against zip bombs, path traversal, malformed PDFs
- Optional NTFS/FAT unallocated space extraction (reduces false positives)
- Recursive container unpacking (ZIP, DOCX, XLSX, PDF)
- YARA rule scanning, E01 support, thumbnail generation (if libraries available)

## Installation

### Minimal (stdlib only)
```bash
pip install .
Full (recommended for investigations)
bash
pip install .[full]
Full extras include: pyewf, python-magic, yara-python, Pillow, pypdf, numpy.

Usage
bash
# Basic carving on raw image
python carver.py --input evidence.raw --output ./carved/

# Parallel carving with investigator name
python carver.py --input image.dd --output ./out --parallel 4 --investigator "J. Smith"

# Carve only unallocated NTFS clusters
python carver.py --input disk.img --output ./out --fs ntfs

# Recursively extract archives found in image and carve inside them
python carver.py --input disk.img --output ./out --recurse

# YARA scan carved files
python carver.py --input memory.dmp --output ./out --yara rules.yar

# E01 expert witness format
python carver.py --input evidence.E01 --output ./out
Advanced Features
Fragmented JPEG reconstruction: uses SOS markers to chain fragments

Entropy‑based fragment boundary detection (sliding window)

Footer ambiguity resolution: last valid footer for ZIP, etc.

Zip bomb detection: abrupt termination if compression ratio > 1000x

Automatic thumbnail generation for JPEG/PNG (requires Pillow)

Limitations
Fragmented MP4 recovery is not supported (heuristics too complex); a warning is raised if MP4 carving fails due to missing footer.

Full‑disk encryption containers are not automatically detected.
