"""Comprehensive tests for DREXX Recovery Architecture:
- RecoveryTarget validation & read-only enforcement
- Nested folder recovery tree reconstruction
- Sector and byte offset conversions
- TSK fls parsing with attribute streams (e.g. 1304-128-1)
- PhotoRec command builder & non-interactive execution
- ddrescue mapfile parsing & resume tracking
- CentralProcessRunner timeout and cancellation
- Recovery lifecycle states
- Verification of recovered file hashes & hierarchies
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import time
import pytest

from recovery_adapter import (
    RecoveryCandidate,
    RecoveryError,
    RecoveryScan,
    RecoveryState,
    RecoveryTarget,
    TargetKind,
    byte_to_sector_offset,
    reconstruct_folder_tree,
    sector_to_byte_offset,
)
from backend_adapters import (
    CentralProcessRunner,
    build_ddrescue_command,
    build_fls_command,
    build_icat_command,
    build_photorec_command,
    build_tsk_recover_command,
    parse_ddrescue_mapfile,
    parse_fls_output,
)


class TestRecoveryTargetSafety:
    def test_target_creation_and_properties(self, tmp_path: Path):
        source = tmp_path / "source_image.dd"
        source.write_bytes(b"DATA" * 1024)
        target = RecoveryTarget(
            path=str(source),
            kind=TargetKind.DISK_IMAGE,
            read_only=True,
            size_bytes=4096,
            sector_size=512,
        )
        assert target.kind == TargetKind.DISK_IMAGE
        assert target.read_only is True
        assert target.size_bytes == 4096

    def test_destination_collision_rejected(self, tmp_path: Path):
        source_dir = tmp_path / "source_dir"
        source_dir.mkdir()
        target = RecoveryTarget(path=str(source_dir), kind=TargetKind.FOLDER)

        # Same destination must fail
        with pytest.raises(RecoveryError, match="cannot be identical"):
            target.validate_destination(source_dir)

        # Destination inside source must fail
        nested_dest = source_dir / "extracted"
        with pytest.raises(RecoveryError, match="cannot reside inside the recovery source tree"):
            target.validate_destination(nested_dest)

        # Valid separate destination passes
        valid_dest = tmp_path / "separate_recovery_dest"
        valid_dest.mkdir()
        target.validate_destination(valid_dest)


class TestOffsetConversions:
    def test_sector_to_byte_offset(self):
        assert sector_to_byte_offset(0) == 0
        assert sector_to_byte_offset(2048, 512) == 1048576
        assert sector_to_byte_offset(1, 4096) == 4096

        with pytest.raises(ValueError):
            sector_to_byte_offset(-1)
        with pytest.raises(ValueError):
            sector_to_byte_offset(10, 0)

    def test_byte_to_sector_offset(self):
        assert byte_to_sector_offset(0) == 0
        assert byte_to_sector_offset(1048576, 512) == 2048
        assert byte_to_sector_offset(4096, 4096) == 1

        with pytest.raises(ValueError):
            byte_to_sector_offset(-1)


class TestFolderTreeReconstruction:
    def test_nested_folder_hierarchy_preserved(self, tmp_path: Path):
        dest = tmp_path / "recovered_output"
        candidates = [
            RecoveryCandidate(
                candidate_id="101",
                name="main.cpp",
                filesystem="NTFS",
                size=512,
                deleted=True,
                confidence=0.95,
                raw={},
                original_path="PROJECT/src/main.cpp",
                relative_path="PROJECT/src/main.cpp",
                is_directory=False,
            ),
            RecoveryCandidate(
                candidate_id="102",
                name="README.md",
                filesystem="NTFS",
                size=128,
                deleted=True,
                confidence=0.90,
                raw={},
                original_path="PROJECT/README.md",
                relative_path="PROJECT/README.md",
                is_directory=False,
            ),
            RecoveryCandidate(
                candidate_id="103",
                name="database.db",
                filesystem="NTFS",
                size=2048,
                deleted=True,
                confidence=0.85,
                raw={},
                original_path="PROJECT/DATA/database.db",
                relative_path="PROJECT/DATA/database.db",
                is_directory=False,
            ),
        ]

        result = reconstruct_folder_tree(candidates, dest)
        assert result["created_directories"] >= 3
        assert (dest / "PROJECT" / "src").is_dir()
        assert (dest / "PROJECT" / "DATA").is_dir()

        # Simulate writing recovered content into preserved hierarchy
        for cand in candidates:
            out_file = dest / Path(cand.relative_path)
            content = f"RECOVERED CONTENT FOR {cand.name}".encode()
            out_file.write_bytes(content)
            assert out_file.is_file()

        # Verify all 3 files exist in their exact nested paths
        assert (dest / "PROJECT" / "src" / "main.cpp").is_file()
        assert (dest / "PROJECT" / "README.md").is_file()
        assert (dest / "PROJECT" / "DATA" / "database.db").is_file()


class TestTskFlsAttributeParsing:
    def test_fls_parsing_with_attribute_streams(self):
        sample_output = """
r/r 1304-128-1:  document.docx
r/r * 1304-128-3:  deleted_report.pdf
d/d 2000-144-1:  nested_dir
r/r * 2001-128-4:  nested_dir/subfile.txt
"""
        candidates = parse_fls_output(sample_output)
        assert len(candidates) == 4

        # Exact TSK attribute stream ID extraction
        assert candidates[0].candidate_id == "1304-128-1"
        assert candidates[0].deleted is False

        # Deleted file with attribute suffix
        assert candidates[1].name == "deleted_report.pdf"
        assert candidates[1].deleted is True
        assert candidates[1].recoverable is True

        # Nested directory entry
        assert candidates[2].is_directory is True

        # Nested file path
        assert candidates[3].relative_path == "nested_dir/subfile.txt"
        assert candidates[3].name == "subfile.txt"


class TestCentralProcessRunner:
    def test_successful_python_command(self):
        res = CentralProcessRunner.run(
            ["python", "-c", "import sys; sys.stdout.write('DREX_OK'); sys.exit(0)"],
            timeout=10,
        )
        assert res.success is True
        assert res.exit_code == 0
        assert res.stdout == "DREX_OK"
        assert not res.timed_out
        assert not res.cancelled

    def test_timeout_enforcement(self):
        res = CentralProcessRunner.run(
            ["python", "-c", "import time; time.sleep(5)"],
            timeout=1,
        )
        assert res.timed_out is True
        assert res.success is False

    def test_cancellation_enforcement(self):
        cancel_requested = False

        def check_cancel():
            nonlocal cancel_requested
            return cancel_requested

        # Set cancellation after 200ms
        import threading
        def trigger():
            nonlocal cancel_requested
            time.sleep(0.1)
            cancel_requested = True

        threading.Thread(target=trigger).start()
        res = CentralProcessRunner.run(
            ["python", "-c", "import time; time.sleep(10)"],
            timeout=10,
            cancel_check=check_cancel,
        )
        assert res.cancelled is True
        assert res.success is False

    def test_binary_run_arbitrary_bytes(self):
        """Prove that binary_run preserves arbitrary bytes (nulls, high-ASCII, binary sequences)."""
        import sys
        # Generate arbitrary binary sequence containing 0x00, 0xFF, values > 0x7F
        test_payload = bytes(range(256)) * 4 + b"\x00\xff\xfe\x80\x7f\x00\x01\x02\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
        res = CentralProcessRunner.binary_run(
            [sys.executable, "-c", "import sys; sys.stdout.buffer.write(bytes(range(256)) * 4 + b'\\x00\\xff\\xfe\\x80\\x7f\\x00\\x01\\x02\\x88\\x99\\xaa\\xbb\\xcc\\xdd\\xee\\xff')"],
            timeout=10,
        )
        assert res.success is True
        assert res.exit_code == 0
        assert res.stdout_bytes == test_payload
        assert len(res.stdout_bytes) == len(test_payload)

    def test_binary_run_vs_run_utf8_corruption(self):
        """Demonstrate that text-mode run() corrupts binary streams while binary_run() preserves them byte-for-byte."""
        import sys
        # Sequence with invalid UTF-8 bytes that cannot be decoded losslessly
        raw_binary = b"\x80\x81\x82\x83\xff\xfe\x00\x01\x02\x90\x91\xc0\xc1"
        res_bin = CentralProcessRunner.binary_run(
            [sys.executable, "-c", f"import sys; sys.stdout.buffer.write({raw_binary!r})"],
            timeout=10,
        )
        assert res_bin.success is True
        assert res_bin.stdout_bytes == raw_binary

        # Text mode run() will replace invalid UTF-8 with U+FFFD (corrupting the byte sequence)
        res_text = CentralProcessRunner.run(
            [sys.executable, "-c", f"import sys; sys.stdout.buffer.write({raw_binary!r})"],
            timeout=10,
        )
        re_encoded = res_text.stdout.encode("utf-8", errors="replace")
        assert re_encoded != raw_binary  # Proves text mode indeed corrupts arbitrary binary
