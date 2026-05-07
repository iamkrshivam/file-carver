# Forensic File Carver (DFIR Tool)

**A production-ready, court-defensible file carving suite for digital forensic investigations.**

---

## ⚖️ Legal Disclaimer

This tool is intended **only** for lawful digital forensic investigations, incident response, and data recovery. Unauthorized use on systems you do not own or have no legal right to access may violate applicable laws. The authors assume **no liability** for misuse.

---

# 📌 Overview

Recover deleted files from:

* Raw disk images (`.dd`, `.raw`, `.img`)
* Memory dumps
* Unallocated space (even without a file system)

Designed for forensic soundness with:

* Full **chain-of-custody logging**
* **Parallel carving** for speed
* Optional **file-system-aware parsing** (NTFS / FAT)

---

# ✨ Features

* Header-footer carving + fragmented file recovery (`JPEG`, `PNG`, `PDF`, `ZIP`, etc.)
* Entropy-based fragment detection using sliding-window Shannon entropy
* Advanced signature engine:

  * Exact signatures
  * Wildcards (`??`)
  * Offset-variable patterns
* Parallel processing with:

  * Boundary-safe chunk splitting
  * Deduplication
* Immutable audit log (`JSONL`) with:

  * UTC timestamps
  * Investigator name
  * Source hash
* SHA-256 source verification performed **before carving**
* Evidence-safe workflow that **never modifies source media**
* Threat protection:

  * ZIP bomb detection
  * Path traversal sanitization
  * Malformed PDF handling
* Optional NTFS/FAT unallocated-space carving to reduce false positives
* Recursive container unpacking:

  * ZIP
  * DOCX
  * XLSX
  * PDF
* YARA rule scanning (requires `yara-python`)
* E01 Expert Witness format support (requires `pyewf`)
* Thumbnail generation for JPEG/PNG files (requires Pillow)

---

# 🛠️ Installation

## Minimal Installation (Standard Library Only)

```bash
pip install .
```

## Full Installation (Recommended)

```bash
pip install .[full]
```

### Full Extras Include

* `pyewf`
* `python-magic`
* `yara-python`
* `Pillow`
* `pypdf`
* `numpy`

The tool never crashes if an optional dependency is missing.
Instead, it prints a warning and continues with reduced functionality.

---

# 🚀 Usage

## Basic Carving

```bash
python carver.py --input evidence.raw --output ./carved/
```

## Add Investigator Name (Chain of Custody)

```bash
python carver.py \
    --input image.dd \
    --output ./out \
    --investigator "Jane Smith"
```

## Parallel Carving (4 Threads)

```bash
python carver.py \
    --input disk.img \
    --output ./out \
    --parallel 4
```

## Carve Only Unallocated NTFS Clusters

```bash
python carver.py \
    --input ntfs.dd \
    --output ./out \
    --fs ntfs
```

## Recursive Archive Carving

```bash
python carver.py \
    --input disk.img \
    --output ./out \
    --recurse
```

## Scan Carved Files with YARA Rules

```bash
python carver.py \
    --input memory.dmp \
    --output ./out \
    --yara rules.yar
```

## Carve an E01 Expert Witness File

```bash
python carver.py \
    --input evidence.E01 \
    --output ./out
```

## Full Real-World Investigation Example

```bash
python carver.py \
    --input /cases/001/disk.dd \
    --output /cases/001/recovered \
    --investigator "Det. Rajesh Kumar" \
    --parallel 8 \
    --fs ntfs \
    --recurse \
    --yara malware.yar
```

---

# 🔬 Advanced Features

## Fragmented JPEG Reconstruction

Uses SOS (Start of Scan) markers and heuristic chaining to reconstruct scattered JPEG fragments.

## Entropy-Based Fragment Boundary Detection

Sliding-window entropy analysis identifies likely compressed-data regions and fragmentation boundaries.

## Footer Ambiguity Resolution

For formats like ZIP, the tool selects the last valid End-of-Central-Directory record to reduce truncation errors.

## ZIP Bomb Detection

Extraction halts automatically if the compression ratio exceeds **1000×**.

## Automatic Thumbnail Generation

Recovered images can automatically generate preview thumbnails when Pillow is installed.

---

# ⚠️ Limitations

* Fragmented MP4 recovery is not currently supported.

  * MP4 fragmentation heuristics are significantly more complex.
  * Failures are logged with warnings.
* Full-disk encryption (`BitLocker`, `LUKS`, etc.) is not automatically detected.

  * Use decrypted disk images before carving.
* NTFS/FAT parsing is intentionally simplified.

  * In complex scenarios, the tool gracefully falls back to full-image carving.

---

# 🧪 Testing

## Generate a Synthetic Test Image

```bash
cd tests
python3 generate_test_image.py
```

## Run the Carver

```bash
cd ..
python3 carver.py \
    --input tests/test_image.raw \
    --output ./test_out
```

## Execute Tests

```bash
python3 -m pytest tests/
```

### Expected Results

* All tests should pass
* The carver should recover all embedded JPEGs
* Includes recovery of one deliberately fragmented JPEG

---

# 📂 Output Structure

```text
carved_out/
├── 0001.jpg
├── 0002.png
├── report.json
├── report.csv
├── audit.jsonl
└── thumbnails/
    ├── 0001_thumb.png
    └── ...
```

## Output Files

| File          | Description                          |
| ------------- | ------------------------------------ |
| `0001.jpg`    | Recovered carved files               |
| `report.json` | Full forensic report                 |
| `report.csv`  | Spreadsheet-friendly summary         |
| `audit.jsonl` | Immutable chain-of-custody log       |
| `thumbnails/` | Image previews (if Pillow installed) |

---

# 📄 License

MIT License — see the `LICENSE` file for details.

---

# 🤝 Contributing

Pull requests are welcome.

Before submitting:

* Ensure all tests pass
* Follow forensic-safe coding practices
* Add tests for new carving signatures or parsers

---

Built for the DFIR and incident response community.
