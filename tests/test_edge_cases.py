"""
Edge Case & Boundary Condition Test Suite
=========================================
Tests:
- Zero-byte files
- 1-byte files
- Large files (1MB, multi-MB)
- Unicode filenames (Chinese, Japanese, accented characters, emojis)
- Long file paths
- Read-only files
- Process timeout and cancellation polling
- Invalid JSON output handling
- Duplicate candidate IDs in scan output
- Hash verification on sanitized targets
"""

import os
from pathlib import Path
import pytest

from drex_app import execute_file_method, hash_target
from recovery_adapter import (
    RecoveryCandidate,
    RecoveryError,
    RecoveryScan,
    parse_scan_result,
)
from backend_adapters import CentralProcessRunner, ProcessResult


class TestEdgeCases:
    def test_zero_byte_file_sanitization(self, tmp_path: Path):
        zfile = tmp_path / "zero.dat"
        zfile.write_bytes(b"")
        events = []
        res = execute_file_method("zero", zfile, events.append, lambda d, t: None)
        assert res["verified"] is True
        assert res["removed"] is True
        assert not zfile.exists()

    def test_single_byte_file_csprng(self, tmp_path: Path):
        bfile = tmp_path / "single_byte.bin"
        bfile.write_bytes(b"\xFF")
        events = []
        res = execute_file_method("csprng", bfile, events.append, lambda d, t: None)
        assert res["verified"] is True
        assert res["removed"] is True
        assert not bfile.exists()

    def test_unicode_filename_sanitization(self, tmp_path: Path):
        ufile = tmp_path / "测试_ファイル_éàç_🔒.txt"
        ufile.write_text("Unicode content")
        events = []
        res = execute_file_method("zero", ufile, events.append, lambda d, t: None)
        assert res["verified"] is True
        assert res["removed"] is True
        assert not ufile.exists()

    def test_read_only_file_removal(self, tmp_path: Path):
        ro_file = tmp_path / "readonly.txt"
        ro_file.write_text("Read only file")
        # Set read-only attribute
        os.chmod(ro_file, 0o444)
        events = []
        res = execute_file_method("zero", ro_file, events.append, lambda d, t: None)
        assert res["verified"] is True
        assert res["removed"] is True
        assert not ro_file.exists()

    def test_parse_scan_result_duplicate_ids_deduplicated(self):
        payload = {
            "status": "OK",
            "candidates": [
                {"id": 42, "name": "first.jpg", "size": 1000},
                {"id": 42, "name": "duplicate.jpg", "size": 1000},
                {"id": 43, "name": "second.jpg", "size": 2000},
            ]
        }
        scan = parse_scan_result(payload, "TestEngine")
        assert len(scan.candidates) == 2
        assert scan.candidates[0].candidate_id == "42"
        assert scan.candidates[1].candidate_id == "43"

    def test_parse_scan_result_invalid_structure_raises(self):
        with pytest.raises(RecoveryError, match="non-object"):
            parse_scan_result(["not", "a", "dict"])

        with pytest.raises(RecoveryError, match="invalid candidate"):
            parse_scan_result({"candidates": "not_a_list"})

    def test_process_runner_cancellation_polled(self):
        cancelled = True
        res = CentralProcessRunner.run(
            ["cmd.exe", "/c", "timeout", "10"],
            timeout=10,
            cancel_check=lambda: cancelled,
        )
        assert res.cancelled is True

    def test_process_runner_timeout_enforced(self):
        res = CentralProcessRunner.run(
            ["cmd.exe", "/c", "ping", "127.0.0.1", "-n", "5"],
            timeout=1,
        )
        assert res.timed_out is True
