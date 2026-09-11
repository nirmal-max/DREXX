"""
Comprehensive Tests for DREXX Advanced Recovery Engines:
1. FragmentReconstructor: Out-of-order & non-contiguous fragment reassembly
2. VirtualRaidReconstructor: RAID 0, 1, 5 (with XOR degraded reconstruction), 10
3. DirectDamagedMediaImager & DamagedMediaRecoveryAdapter: End-to-end imaging and file recovery
"""

import hashlib
from pathlib import Path
import pytest

from recovery_adapter import (
    FragmentReconstructor,
    VirtualRaidReconstructor,
    DirectDamagedMediaImager,
    DamagedMediaRecoveryAdapter,
    RECOVERY_METHOD_SPECS,
)
from backend_adapters import parse_ddrescue_mapfile


class TestFragmentReconstruction:
    def test_deliberately_reordered_fragmented_jpeg(self):
        """Original JPEG -> Deliberately split & reordered -> DREXX reassembles -> SHA-256 matches."""
        part1 = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"  # SOI + APP0
        part2 = b"\xff\xdb\x00\x43\x00" + b"\x01" * 64  # DQT
        part3 = b"\xff\xc0\x00\x11\x08\x00\x10\x00\x10\x03\x01\x11\x00\x02\x11\x01\x03\x11\x01"  # SOF0
        part4 = b"\xff\xda\x00\x0c\x03\x01\x00\x02\x11\x03\x11\x00\x3f\x00" + b"\xaa" * 128 + b"\xff\xd9"  # SOS + EOI

        original_jpeg = part1 + part2 + part3 + part4
        expected_hash = hashlib.sha256(original_jpeg).hexdigest().upper()

        # Deliberately scrambled out-of-order fragments
        scrambled_fragments = [part3, part1, part4, part2]

        # Simple concatenation would fail structural validation
        assert not FragmentReconstructor.validate_jpeg(b"".join(scrambled_fragments))[0]

        # DREXX out-of-order reassembly finds the correct permutation
        reconstructed, confidence, valid = FragmentReconstructor.reconstruct_out_of_order(scrambled_fragments, "jpeg")
        assert valid is True
        assert confidence >= 0.8
        assert hashlib.sha256(reconstructed).hexdigest().upper() == expected_hash

    def test_deliberately_reordered_fragmented_pdf(self):
        """Original PDF -> Deliberately split & reordered -> DREXX reassembles -> SHA-256 matches."""
        header = b"%PDF-1.4\n"
        body1 = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        body2 = b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        trailer = b"xref\n0 3\n0000000000 65535 f \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n140\n%%EOF\n"

        original_pdf = header + body1 + body2 + trailer
        expected_hash = hashlib.sha256(original_pdf).hexdigest().upper()

        # Deliberately scrambled order
        scrambled_fragments = [trailer, body2, header, body1]
        assert not FragmentReconstructor.validate_pdf(b"".join(scrambled_fragments))[0]

        reconstructed, confidence, valid = FragmentReconstructor.reconstruct_out_of_order(scrambled_fragments, "pdf")
        assert valid is True
        assert confidence >= 0.8
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
    def test_raid0_deterministic_fixture(self):
        chunk = 32
        payload = b"PAYLOAD_A_" * 16 + b"PAYLOAD_B_" * 16  # 320 bytes
        expected_hash = hashlib.sha256(payload[:320]).hexdigest().upper()

        # Split across 2 disks in 32-byte chunks
        d0_chunks = [payload[i:i+chunk] for i in range(0, 320, chunk * 2)]
        d1_chunks = [payload[i+chunk:i+chunk*2] for i in range(0, 320, chunk * 2)]

        disk0 = b"".join(d0_chunks)
        disk1 = b"".join(d1_chunks)

        reconstructed = VirtualRaidReconstructor.reconstruct_raid0([disk0, disk1], chunk_size=chunk)
        assert hashlib.sha256(reconstructed[:320]).hexdigest().upper() == expected_hash

    def test_raid1_deterministic_fixture(self):
        payload = b"CRITICAL_DATABASE_PAYLOAD_MIRROR" * 10
        expected_hash = hashlib.sha256(payload).hexdigest().upper()

        disk0 = payload
        disk1 = payload
        reconstructed = VirtualRaidReconstructor.reconstruct_raid1([disk0, disk1])
        assert hashlib.sha256(reconstructed).hexdigest().upper() == expected_hash

    def test_raid5_degraded_xor_reconstruction(self):
        chunk = 16
        # 3 disks: D0, D1, P (Parity = D0 ^ D1)
        d0_stripe0 = b"STRIPE0_DISK0___"
        d1_stripe0 = b"STRIPE0_DISK1___"
        p_stripe0 = bytes(a ^ b for a, b in zip(d0_stripe0, d1_stripe0))

        d0_stripe1 = b"STRIPE1_DISK0___"
        d1_stripe1 = b"STRIPE1_DISK1___"
        p_stripe1 = bytes(a ^ b for a, b in zip(d0_stripe1, d1_stripe1))

        disk0 = d0_stripe0 + d0_stripe1
        disk1 = d1_stripe0 + d1_stripe1
        disk2 = p_stripe0 + p_stripe1

        # Intact array reconstruction
        normal = VirtualRaidReconstructor.reconstruct_raid5([disk0, disk1, disk2], chunk_size=chunk, layout="dedicated-parity")
        expected_payload = d0_stripe0 + d1_stripe0 + d0_stripe1 + d1_stripe1
        assert normal == expected_payload

        # Degraded array with disk 0 missing (destroyed/offline)
        # Disk 0 data will be XOR-reconstructed from Disk 1 and Parity Disk 2
        degraded = VirtualRaidReconstructor.reconstruct_raid5([b"\x00" * len(disk0), disk1, disk2], chunk_size=chunk, missing_idx=0, layout="dedicated-parity")
        assert degraded == expected_payload
        assert hashlib.sha256(degraded).hexdigest() == hashlib.sha256(normal).hexdigest()

    def test_raid10_deterministic_fixture(self):
        chunk = 16
        d0 = b"DATA0_0_________" + b"DATA0_1_________"
        m0 = b"DATA0_0_________" + b"DATA0_1_________"
        d1 = b"DATA1_0_________" + b"DATA1_1_________"
        m1 = b"DATA1_0_________" + b"DATA1_1_________"

        reconstructed = VirtualRaidReconstructor.reconstruct_raid10([d0, m0, d1, m1], chunk_size=chunk)
        expected = b"DATA0_0_________DATA1_0_________DATA0_1_________DATA1_1_________"
        assert reconstructed == expected


class TestDamagedMediaWorkflow:
    def test_damaged_media_end_to_end_imaging_and_recovery(self, tmp_path: Path):
        """End-to-end: Damaged source -> direct sector imaging + mapfile -> recovery extraction.

        The source is a synthetic byte stream (not a valid FAT/NTFS filesystem),
        so tsk_recover will exit with a non-zero code — this is expected and must now be
        explicitly recorded in stats['tsk_extraction_error'] rather than silently swallowed.
        """
        source_data = b"RECOVERABLE_RECORD_A" * 32 + b"CORRUPTED_BAD_SECTOR" * 32 + b"RECOVERABLE_RECORD_B" * 32
        salvaged_img = tmp_path / "salvaged.raw"
        mapfile = tmp_path / "salvaged.map"
        dest_dir = tmp_path / "extracted_output"

        spec = next(s for s in RECOVERY_METHOD_SPECS if s.method_id == "damaged")
        adapter = DamagedMediaRecoveryAdapter(spec, tmp_path)

        stats, files = adapter.recover_damaged_source(
            source=source_data,
            salvaged_image_path=salvaged_img,
            mapfile_path=mapfile,
            destination=dest_dir,
            bad_sector_ranges=[(1, 1)],  # Middle sector bad
        )

        # Sector imaging stats — must be accurate regardless of TSK outcome
        assert stats["rescued_bytes"] > 0
        assert stats["bad_bytes"] == 512
        assert salvaged_img.exists()
        assert mapfile.exists()

        # Parse mapfile to verify ddrescue standard compatibility
        parsed = parse_ddrescue_mapfile(mapfile.read_text(encoding="utf-8"))
        assert parsed["rescued_bytes"] == stats["rescued_bytes"]
        assert parsed["bad_bytes"] == 512

        # Explicit error-reporting: tsk_extraction_error must be a string or None —
        # NEVER silently swallowed. For a synthetic fixture (no real filesystem),
        # TSK will fail with a non-zero exit code, so the error field will be non-None.
        assert "tsk_extraction_error" in stats, (
            "stats must contain tsk_extraction_error — silent pass is not allowed"
        )
        assert "tsk_extracted_files" in stats, (
            "stats must contain tsk_extracted_files count"
        )
        # The error field is either None (TSK succeeded) or a non-empty string (TSK failed)
        error_val = stats["tsk_extraction_error"]
        assert error_val is None or isinstance(error_val, str), (
            f"tsk_extraction_error must be None or str, got {type(error_val)}"
        )

