# Forensic File Carver (DFIR Tool)

**A production‑ready, court‑defensible file carving suite for digital forensic investigations.**

---

## ⚖️ Legal Disclaimer

This tool is intended **only** for lawful digital forensic investigations, incident response, and data recovery. Unauthorised use on systems you do not own or have no legal right to access may violate applicable laws. The authors assume **no liability** for misuse.

---

## 📌 Overview

Recover deleted files from:
- Raw disk images (`.dd`, `.raw`, `.img`)
- Memory dumps
- Unallocated space (even without a file system)

Designed for forensic soundness with:
- Full **chain‑of‑custody** logging
- **Parallel carving** for speed
- Optional **file‑system‑aware parsing** (NTFS / FAT)

---

## ✨ Features

- **Header‑footer carving** + **fragmented file recovery** (JPEG, PNG, PDF, ZIP, …)
- **Entropy‑based fragment detection** (sliding window Shannon entropy)
- **Advanced signature engine** – exact, wildcard (`??`), and offset‑variable patterns
- **Parallel processing** with boundary‑safe chunk splitting and deduplication
- **Immutable audit log** (JSONL) with UTC timestamps, investigator name, and source hash
- **SHA‑256 source verification** – computed *before* carving, never modifies evidence
- **Threat protection** – zip bomb detection, path traversal sanitisation, malformed PDF handling
- **Optional NTFS/FAT unallocated carving** – reduces false positives
- **Recursive container unpacking** – dives into ZIP, DOCX, XLSX, PDF and carves nested files
- **YARA rule scanning** (requires `yara‑python`)
- **E01 Expert Witness format** support (requires `pyewf`)
- **Thumbnail generation** for JPEG / PNG (requires Pillow)

---

## 🛠️ Installation

### Minimal (standard library only)
```bash
pip install .
Full (recommended for real investigations)
bash
pip install .[full]
Full extras include: pyewf, python-magic, yara-python, Pillow, pypdf, numpy.

The tool never crashes if an optional library is missing – it prints a warning and continues with reduced functionality.

🚀 Usage
bash
# Basic carving
python carver.py --input evidence.raw --output ./carved/

# Add investigator name (chain of custody)
python carver.py --input image.dd --output ./out \
    --investigator "Jane Smith"

# Parallel carving (4 threads)
python carver.py --input disk.img --output ./out --parallel 4

# Carve only unallocated NTFS clusters (less noise)
python carver.py --input ntfs.dd --output ./out --fs ntfs

# Recursively unpack and carve inside archives (ZIP, DOCX, PDF, …)
python carver.py --input disk.img --output ./out --recurse

# Scan carved files with YARA rules
python carver.py --input memory.dmp --output ./out --yara rules.yar

# Carve an E01 Expert Witness file
python carver.py --input evidence.E01 --output ./out

# Combine everything for a real case
python carver.py \
    --input /cases/001/disk.dd \
    --output /cases/001/recovered \
    --investigator "Det. Rajesh Kumar" \
    --parallel 8 \
    --fs ntfs \
    --recurse \
    --yara malware.yar
🔬 Advanced Features (Deep Dive)
Fragmented JPEG reconstruction – uses SOS markers to chain scattered fragments

Entropy‑based fragment boundary detection – sliding window finds where data drops below expected compression

Footer ambiguity resolution – e.g., for ZIP files, picks the last valid end‑of‑central‑directory record

Zip bomb detection – halts immediately if compression ratio exceeds 1000×

Automatic thumbnails for recovered images (Pillow)

⚠️ Limitations
Fragmented MP4 recovery is not supported (heuristics too complex); a warning is logged if carving fails

Full‑disk encryption (BitLocker, LUKS, …) is not automatically detected – carve from a decrypted image first

NTFS/FAT parsing is simplified; in complex scenarios the tool falls back gracefully to full‑image carving

🧪 Testing
To verify everything works:

bash
cd tests
python3 generate_test_image.py       # create a 100 MB synthetic image
cd ..
python3 carver.py --input tests/test_image.raw --output ./test_out
python3 -m pytest tests/             # run unit & integration tests
All 3 tests should pass, and the carver should recover all 5 embedded JPEGs (including one deliberately fragmented).

📂 Output Structure
text
carved_out/
├── 0001.jpg          # recovered files
├── 0002.png
├── report.json       # full forensic report
├── report.csv        # flat summary for spreadsheets
├── audit.jsonl       # immutable chain‑of‑custody log
└── thumbnails/       # preview images (if Pillow installed)
    ├── 0001_thumb.png
    └── ...
📄 License
MIT – see the LICENSE file.

🤝 Contributing
Pull requests are welcome! Please ensure all tests pass before submitting.

Built with ❤️ for the DFIR community.
