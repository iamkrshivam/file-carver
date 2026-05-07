#!/usr/bin/env bash
# Example commands for the File Carving Suite

# 1. Basic carve on raw image
python3 carver.py --input evidence.raw --output ./carved_out --investigator "J. Doe"

# 2. Parallel carve with 4 workers
python3 carver.py --input disk.img --output ./out --parallel 4

# 3. NTFS unallocated carve only
python3 carver.py --input ntfs_disk.dd --output ./out --fs ntfs

# 4. Carve all known file types and recursively unpack archives
python3 carver.py --input image.raw --output ./out --recurse --extract

# 5. YARA scanning of carved files
python3 carver.py --input memory.dmp --output ./out --yara rules.yar

# 6. Full pipeline with custom signatures
python3 carver.py --input case001.E01 --output ./case001_carved --signatures my_sigs.json --parallel 8 --investigator "Jane Smith"
