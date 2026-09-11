"""Comprehensive test suite covering all 25 DREXX methods:
- 7 Drive Erasure methods
- 9 File/Folder Erasure methods
- 9 Recovery methods

Verifies capability detection, fail-closed security, real execution engines,
and certificate generation.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from drex_app import (
    DRIVE_METHODS,
    FILE_METHODS,
    RECOVERY_METHODS,
    CertificateManager,
    Store,
    dangerous_target,
    drive_method_status,
    execute_file_method,
    hash_target,
)
from recovery_adapter import (
    RECOVERY_METHOD_SPECS,
    FragmentRecoveryAdapter,
    QuickRecoveryAdapter,
    RecoveryDispatcher,
    RecoveryError,
    parse_scan_result,
)
from recovery_backends import (
    BACKENDS,
    METHOD_BACKENDS,
    backend_status,
    find_backend_executable,
)
from backend_adapters import (
    BACKEND_CAPABILITIES,
    build_ddrescue_command,
    build_fls_command,
    build_fsstat_command,
    build_icat_command,
    build_mmls_command,
    build_photorec_command,
    build_tsk_recover_command,
    parse_ddrescue_mapfile,
    parse_fls_output,
    parse_fsstat_output,
    parse_mmls_output,
)


# ─── 1. 25-Method Inventory & Integrity ──────────────────────────────

class TestMethodInventory:
    def test_exact_25_method_count(self):
        assert len(DRIVE_METHODS) == 7
        assert len(FILE_METHODS) == 9
        assert len(RECOVERY_METHODS) == 9
        assert len(DRIVE_METHODS) + len(FILE_METHODS) + len(RECOVERY_METHODS) == 25

    def test_drive_method_ids_unique(self):
        drive_ids = [m["id"] for m in DRIVE_METHODS]
        assert len(drive_ids) == 7
        assert len(set(drive_ids)) == 7
        expected = {"nist", "smart", "native", "ata", "nvme", "ieee", "overwrite"}
        assert set(drive_ids) == expected

    def test_file_method_ids_unique(self):
        file_ids = [m["id"] for m in FILE_METHODS]
        assert len(file_ids) == 9
        assert len(set(file_ids)) == 9
        expected = {
            "csprng", "crypto", "slack", "metadata", "policy",
            "free_space", "zero", "storage_aware", "temporary"
        }
        assert set(file_ids) == expected

    def test_recovery_method_ids_unique(self):
        rec_ids = [m[0] for m in RECOVERY_METHODS]
        assert len(rec_ids) == 9
        assert len(set(rec_ids)) == 9
        expected = {
            "quick", "smart", "targeted", "filesystem", "deep",
            "fragment", "raid", "damaged", "forensic"
        }
        assert set(rec_ids) == expected


# ─── 2. Recovery Methods & Backends ──────────────────────────────────

class TestRecoveryAdaptersAndBackends:
    def test_all_9_recovery_specs_mapped(self):
        assert len(RECOVERY_METHOD_SPECS) == 9
        spec_ids = {s.method_id for s in RECOVERY_METHOD_SPECS}
        method_ids = {m[0] for m in RECOVERY_METHODS}
        assert spec_ids == method_ids

    def test_fragment_recovery_file_types(self, tmp_path: Path):
        spec = next(s for s in RECOVERY_METHOD_SPECS if s.method_id == "fragment")
        adapter = FragmentRecoveryAdapter(spec, tmp_path, tmp_path, file_type="pdf")
        assert adapter.file_type == "pdf"

        # Valid file types
        for ftype in ("pdf", "jpeg", "png", "zip"):
            cmd = adapter.scan_command("image.raw", tmp_path / "out.json", file_type=ftype)
            assert "--type" in cmd
            assert cmd[cmd.index("--type") + 1] == ftype

        # Invalid file type raises RecoveryError
        with pytest.raises(RecoveryError, match="Unsupported fragment recovery file type"):
            adapter.scan_command("image.raw", tmp_path / "out.json", file_type="exe")

    def test_recovery_dispatcher_reports_truthful_status(self, tmp_path: Path):
        dispatcher = RecoveryDispatcher(tmp_path, tmp_path)
        for mid, _, _ in RECOVERY_METHODS:
            status, reason = dispatcher.status(mid)
            assert status == "Unavailable"
            assert len(reason) > 0


# ─── 3. File/Folder Erasure Real Execution ───────────────────────────

class TestFileErasureExecution:
    def test_csprng_random_overwrite(self, tmp_path: Path):
        target = tmp_path / "secret_data.bin"
        original_bytes = b"DREX_CSPRNG_TOP_SECRET_CONTENT" * 50
        target.write_bytes(original_bytes)
        before_hash = hash_target(target)

        events = []
        progress_events = []
        result = execute_file_method(
            "csprng",
            target,
            events.append,
            lambda d, t: progress_events.append((d, t)),
        )
        assert result["verified"] is True
        assert result["removed"] is True
        assert not target.exists()
        assert before_hash is not None

    def test_zero_overwrite_tree(self, tmp_path: Path):
        target_dir = tmp_path / "secret_folder"
        target_dir.mkdir()
        f1 = target_dir / "file1.txt"
        f2 = target_dir / "file2.bin"
        f1.write_text("file 1 content")
        f2.write_bytes(b"\xaa\xbb\xcc\xdd" * 20)

        events = []
        result = execute_file_method(
            "zero",
            target_dir,
            events.append,
            lambda d, t: None,
        )
        assert result["verified"] is True
        assert result["removed"] is True
        assert not target_dir.exists()

    def test_metadata_sanitizer(self, tmp_path: Path):
        target = tmp_path / "meta_test.txt"
        target.write_text("metadata target content")
        events = []
        result = execute_file_method(
            "metadata",
            target,
            events.append,
            lambda d, t: None,
        )
        assert target.exists()  # Metadata sanitizer preserves data content
        assert result["removed"] is False
        assert result["sha256_after"] is not None

    def test_temporary_cache_sanitizer(self, tmp_path: Path):
        target = tmp_path / "temp_cache.tmp"
        target.write_bytes(b"temporary cache residual data" * 10)
        events = []
        result = execute_file_method(
            "temporary",
            target,
            events.append,
            lambda d, t: None,
        )
        assert result["verified"] is True
        assert result["removed"] is True
        assert not target.exists()


# ─── 4. Target Safety Guards ─────────────────────────────────────────

class TestTargetSafety:
    def test_volume_roots_are_blocked(self):
        c_root = Path("C:\\")
        reason = dangerous_target(c_root)
        assert reason is not None
        assert "volume root" in reason.lower()

    def test_nonexistent_target_blocked(self, tmp_path: Path):
        bad_path = tmp_path / "does_not_exist.bin"
        reason = dangerous_target(bad_path)
        assert reason is not None
        assert "no longer exists" in reason.lower()

    def test_valid_temp_file_allowed(self, tmp_path: Path):
        good_file = tmp_path / "valid.txt"
        good_file.write_text("hello")
        reason = dangerous_target(good_file)
        assert reason is None


# ─── 5. Certificate & Audit Integrity ────────────────────────────────

class TestCertificateIntegrity:
    def test_tamper_evident_certificate_creation_and_verification(self, tmp_path: Path):
        store = Store(tmp_path / "drex_data")
        mgr = CertificateManager(store)

        op = {
            "type": "file",
            "method": "CSPRNG Random Overwrite",
            "target": str(tmp_path / "test.dat"),
            "target_size": "100 B",
            "passes": 1,
            "started": "2026-09-11T00:00:00Z",
            "completed": "2026-09-11T00:00:02Z",
            "duration": "2s",
            "status": "SUCCESS",
            "verification": "VERIFIED",
            "sha256_before": "f" * 64,
            "sha256_after": "Not applicable after verified removal",
        }
        cert = mgr.create(op)
        assert cert["certificate_id"].startswith("CERT-ERASE-")
        assert mgr.verify(cert) is True
        assert Path(cert["pdf_path"]).is_file()

        # Tampered certificate must fail verification
        tampered = dict(cert)
        tampered["method"] = "Unverified Wipe"
        assert mgr.verify(tampered) is False
