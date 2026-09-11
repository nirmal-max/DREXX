"""
Tests for DREXX Advanced Recovery Engines:
- FragmentReconstructor: Bi-fragment & multi-fragment structural reconstruction
- VirtualRaidReconstructor: RAID 0, 1, 5 (with XOR degraded reconstruction), 10
- DirectDamagedMediaImager: Direct sector-level imaging & GNU ddrescue mapfile generation
"""

import hashlib
from pathlib import Path
import pytest

from recovery_adapter import (
    FragmentReconstructor,
    VirtualRaidReconstructor,
    DirectDamagedMediaImager,
)
from backend_adapters import parse_ddrescue_mapfile


class TestFragmentReconstruction:
    def test_fragmented_jpeg_reconstruction(self):
        # Create valid JPEG parts
        part1 = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"  # SOI + APP0
        part2 = b"\xff\xdb\x00\x43\x00" + b"\x01" * 64  # DQT
        part3 = b"\xff\xc0\x00\x11\x08\x00\x10\x00\x10\x03\x01\x11\x00\x02\x11\x01\x03\x11\x01"  # SOF0
        part4 = b"\xff\xda\x00\x0c\x03\x01\x00\x02\x11\x03\x11\x00\x3f\x00" + b"\xaa" * 128 + b"\xff\xd9"  # SOS + EOI

        original_jpeg = part1 + part2 + part3 + part4
        expected_hash = hashlib.sha256(original_jpeg).hexdigest().upper()

        # Stitch fragments
        reconstructed, confidence, valid = FragmentReconstructor.score_continuity("jpeg", [part1, part2, part3, part4])
        assert valid is True
        assert confidence >= 0.8
        assert hashlib.sha256(reconstructed).hexdigest().upper() == expected_hash

    def test_fragmented_pdf_reconstruction(self):
        header = b"%PDF-1.4\n"
        body = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        trailer = b"xref\n0 2\n0000000000 65535 f \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n99\n%%EOF\n"

        original_pdf = header + body + trailer
        expected_hash = hashlib.sha256(original_pdf).hexdigest().upper()

        reconstructed, confidence, valid = FragmentReconstructor.score_continuity("pdf", [header, body, trailer])
        assert valid is True
        assert confidence >= 0.9
        assert hashlib.sha256(reconstructed).hexdigest().upper() == expected_hash

    def test_cluster_stream_fragment_reassembly(self):
        cluster_size = 512
        jpeg_header = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + b"\x00" * 492
        jpeg_middle = b"\xff\xdb\x00\x43\x00" + b"\x02" * 64 + b"\xff\xda" + b"\xbb" * 100 + b"\x00" * 339
        jpeg_footer = b"\xff\xd9" + b"\x00" * 510

        # Construct stream: Header @ Cl 0, Junk @ Cl 1, Middle @ Cl 2, Footer @ Cl 3
        junk_cluster = b"JUNK_DATA_DELETED_INODE_OTHER_FILE" * 15
        junk_cluster = junk_cluster[:cluster_size].ljust(cluster_size, b"\x00")

        stream = jpeg_header + junk_cluster + jpeg_middle + jpeg_footer
        candidates = FragmentReconstructor.reassemble_stream(stream, "jpeg", cluster_size=cluster_size)
        assert len(candidates) >= 1
        assert any(c["valid"] for c in candidates)


class TestVirtualRaidReconstruction:
    def test_raid0_striping(self):
        chunk = 16
        disk0 = b"CHUNK0_DISK0____" + b"CHUNK2_DISK0____"
        disk1 = b"CHUNK1_DISK1____" + b"CHUNK3_DISK1____"

        reconstructed = VirtualRaidReconstructor.reconstruct_raid0([disk0, disk1], chunk_size=chunk)
        expected = b"CHUNK0_DISK0____CHUNK1_DISK1____CHUNK2_DISK0____CHUNK3_DISK1____"
        assert reconstructed == expected

    def test_raid1_mirroring(self):
        disk0 = b"MIRRORED_DATA_CONTENT_12345"
        disk1 = b"MIRRORED_DATA_CONTENT_12345"
        reconstructed = VirtualRaidReconstructor.reconstruct_raid1([disk0, disk1])
        assert reconstructed == disk0

    def test_raid5_degraded_xor_reconstruction(self):
        chunk = 8
        # 3 disks: D0, D1, P (Parity = D0 ^ D1)
        # Stripe 0: D0="DATA0_A_", D1="DATA1_A_", P = D0 ^ D1
        d0_stripe0 = b"DATA0_A_"
        d1_stripe0 = b"DATA1_A_"
        p_stripe0 = bytes(a ^ b for a, b in zip(d0_stripe0, d1_stripe0))

        # Disk images
        disk0 = d0_stripe0
        disk1 = d1_stripe0
        disk2 = p_stripe0

        # Normal reconstruction (left-asymmetric for simplicity test)
        normal = VirtualRaidReconstructor.reconstruct_raid5([disk0, disk1, disk2], chunk_size=chunk, layout="right-asymmetric")
        assert len(normal) == 16  # 2 data chunks

        # Degraded reconstruction with disk 1 missing (missing_idx = 1)
        # Disk 1 data will be XOR reconstructed from disk 0 and parity disk 2!
        degraded = VirtualRaidReconstructor.reconstruct_raid5([disk0, b"\x00" * chunk, disk2], chunk_size=chunk, missing_idx=1, layout="right-asymmetric")
        assert degraded == normal

    def test_raid10_reconstruction(self):
        chunk = 8
        # 4 disks: D0, M0, D1, M1
        d0 = b"DATA0_0_" + b"DATA0_1_"
        m0 = b"DATA0_0_" + b"DATA0_1_"
        d1 = b"DATA1_0_" + b"DATA1_1_"
        m1 = b"DATA1_0_" + b"DATA1_1_"

        reconstructed = VirtualRaidReconstructor.reconstruct_raid10([d0, m0, d1, m1], chunk_size=chunk)
        assert len(reconstructed) == 32
        assert reconstructed.startswith(b"DATA0_0_DATA1_0_")


class TestDamagedMediaImager:
    def test_damaged_media_imaging_and_mapfile(self, tmp_path: Path):
        source_data = b"GOOD_SECTOR_DATA" * 32 + b"BAD_SECTOR_CORRUPT" * 32 + b"RECOVERED_TRAILING" * 32
        out_img = tmp_path / "rescued.img"
        mapfile = tmp_path / "rescued.map"

        # Mark sector 1 (bytes 512..1023) as bad
        res = DirectDamagedMediaImager.image_source(
            source_data=source_data,
            output_image_path=out_img,
            mapfile_path=mapfile,
            sector_size=512,
            bad_sector_ranges=[(1, 1)],
        )

        assert res["rescued_bytes"] > 0
        assert res["bad_bytes"] == 512
        assert out_img.exists()
        assert mapfile.exists()

        # Parse mapfile using backend_adapters parser
        parsed = parse_ddrescue_mapfile(mapfile.read_text(encoding="utf-8"))
        assert parsed["rescued_bytes"] == res["rescued_bytes"]
        assert parsed["bad_bytes"] == 512
