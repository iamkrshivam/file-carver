"""Generate a synthetic 100 MB raw image with 5 embedded JPEGs (one fragmented) and other files."""
import os
import random
import struct

def create_jpeg(width=100, height=100, quality=85):
    """Create a minimal valid JPEG in memory using PIL if available, otherwise hardcoded."""
    try:
        from PIL import Image
        import io
        img = Image.new('RGB', (width, height), color=(random.randint(0,255), random.randint(0,255), random.randint(0,255)))
        buf = io.BytesIO()
        img.save(buf, format='JPEG', quality=quality)
        return buf.getvalue()
    except ImportError:
        # Minimal valid JPEG (black 1x1)
        return bytes.fromhex(
            "FFD8FFE000104A46494600010101006000600000FFDB0043000201010201010202020202020202030503030303030604040305070607070706070708090B0908080A0807070A0D0A0A0B0C0C0C0C07090E0F0D0C0E0B0C0C0CFFDB004301020202030303060303060C0807080C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0CFFC00011080001000103011100021101031101FFC4001F0000010501010101010100000000000000000102030405060708090A0BFFC400B5100002010303020403050504040000017D01020300041105122131410613516107227114328191A1082342B1C11552D1F02433627282090A161718191A25262728292A3435363738393A434445464748494A535455565758595A636465666768696A737475767778797A838485868788898A92939495969798999AA2A3A4A5A6A7A8A9AAB2B3B4B5B6B7B8B9BAC2C3C4C5C6C7C8C9CAD2D3D4D5D6D7D8D9DAE1E2E3E4E5E6E7E8E9EAF1F2F3F4F5F6F7F8F9FAFFC4001F0100030101010101010101010000000000000102030405060708090A0BFFC400B51100020102040403040705040400010277000102031104052131061241510761711322328108144291A1B1C109233352F0156272D10A162434E125F11718191A262728292A35363738393A434445464748494A535455565758595A636465666768696A737475767778797A82838485868788898A92939495969798999AA2A3A4A5A6A7A8A9AAB2B3B4B5B6B7B8B9BAC2C3C4C5C6C7C8C9CAD2D3D4D5D6D7D8D9DAE2E3E4E5E6E7E8E9EAF2F3F4F5F6F7F8F9FAFFDA000C03010002110311003F00FD53A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002800A002809F7FFD9"
        )

def generate_test_image(output_path="test_image.raw", size_mb=100, seed=42):
    random.seed(seed)
    total_bytes = size_mb * 1024 * 1024
    # Create a base buffer filled with random data (simulate disk noise)
    data = bytearray(random.getrandbits(8) for _ in range(total_bytes))
    # We'll embed 5 JPEGs at known offsets
    jpeg_count = 5
    offsets = []
    for i in range(jpeg_count):
        jpeg_data = create_jpeg()
        # Ensure we don't overlap
        max_offset = total_bytes - len(jpeg_data)
        if i == 0:
            offset = 100000
        elif i == 1:
            offset = 500000
        elif i == 2:
            offset = 2000000
        elif i == 3:  # this will be fragmented (missing footer)
            offset = 4000000
        elif i == 4:
            offset = 8000000
        # For the fragmented one, we'll strip the footer bytes
        if i == 3:
            # remove EOI marker (FFD9) to simulate fragmentation
            jpeg_data = jpeg_data[:-2]  # remove last two bytes FFD9
            # also split it: we'll put part1 at offset, part2 at a far offset
            part1_len = len(jpeg_data) // 2
            part2 = jpeg_data[part1_len:]
            jpeg_data = jpeg_data[:part1_len]
            # embed part1
            data[offset:offset+len(jpeg_data)] = jpeg_data
            offsets.append((offset, len(jpeg_data), "jpeg_frag1"))
            # embed part2 at another location
            offset2 = offset + 200000
            data[offset2:offset2+len(part2)] = part2
            offsets.append((offset2, len(part2), "jpeg_frag2"))
            continue
        data[offset:offset+len(jpeg_data)] = jpeg_data
        offsets.append((offset, len(jpeg_data), "jpeg"))
    # Write to file
    with open(output_path, "wb") as f:
        f.write(data)
    print(f"Generated {output_path} ({size_mb} MB) with embedded JPEGs.")
    for off, size, desc in offsets:
        print(f"  Offset {off:10d}, size {size:7d}, type {desc}")

if __name__ == "__main__":
    generate_test_image()
