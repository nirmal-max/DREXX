"""Tests for recovery_backends.py — backend manifest and discovery integrity.

These tests ensure the backend specification data stays consistent and
discovery functions fail closed without installed binaries.
"""

from pathlib import Path

import pytest

from recovery_adapter import RECOVERY_METHOD_SPECS
from recovery_backends import (
    BACKENDS,
    METHOD_BACKENDS,
    BackendSpec,
    backend_status,
    find_backend_executable,
)


class TestBackendSpecs:
    def test_all_backend_ids_are_consistent(self):
        """Every backend referenced by METHOD_BACKENDS must exist in BACKENDS."""
        all_referenced = set()
        for backends in METHOD_BACKENDS.values():
            all_referenced.update(backends)
        assert all_referenced <= set(BACKENDS.keys()), \
            f"Unreferenced backends: {all_referenced - set(BACKENDS.keys())}"

    def test_all_recovery_methods_have_backend_mapping(self):
        """Every recovery method spec must have a backend mapping."""
        spec_ids = {s.method_id for s in RECOVERY_METHOD_SPECS}
        mapping_ids = set(METHOD_BACKENDS.keys())
        assert spec_ids == mapping_ids, \
            f"Mismatch: specs={spec_ids - mapping_ids}, backends={mapping_ids - spec_ids}"

    def test_backend_specs_are_frozen(self):
        """BackendSpec must be immutable."""
        spec = BACKENDS["testdisk"]
        with pytest.raises(AttributeError):
            spec.backend_id = "modified"

    def test_tsk_spec_contains_upstream_tools(self):
        """TSK spec must list the real upstream executables."""
        tsk = BACKENDS["tsk"]
        assert "fls.exe" in tsk.executable_names
        assert "icat.exe" in tsk.executable_names
        assert "fsstat.exe" in tsk.executable_names
        assert "tsk_recover.exe" in tsk.executable_names
        assert "mmls.exe" in tsk.executable_names

    def test_photorec_spec_has_correct_project_url(self):
        """PhotoRec comes from cgsecurity/testdisk, not a separate repo."""
        photorec = BACKENDS["photorec"]
        assert "cgsecurity/testdisk" in photorec.project_url

    def test_testdisk_and_photorec_share_project(self):
        """TestDisk and PhotoRec come from the same upstream project."""
        assert BACKENDS["testdisk"].project_url == BACKENDS["photorec"].project_url


class TestBackendDiscovery:
    def test_find_in_native_bin(self, tmp_path):
        """Discovery should find executables in native_bin/."""
        native_bin = tmp_path / "native_bin"
        native_bin.mkdir()
        (native_bin / "fls.exe").write_text("stub")
        found = find_backend_executable("tsk", tmp_path)
        assert found is not None
        assert found.name == "fls.exe"

    def test_find_in_third_party(self, tmp_path):
        """Discovery should check third_party/<backend_id>/ too."""
        tp = tmp_path / "third_party" / "tsk"
        tp.mkdir(parents=True)
        (tp / "icat.exe").write_text("stub")
        found = find_backend_executable("tsk", tmp_path)
        assert found is not None
        assert found.name == "icat.exe"

    def test_meipass_has_priority(self, tmp_path):
        """When _MEIPASS is provided, it should be searched first."""
        meipass = tmp_path / "meipass"
        meipass_bin = meipass / "native_bin"
        meipass_bin.mkdir(parents=True)
        (meipass_bin / "fls.exe").write_text("meipass stub")

        native_bin = tmp_path / "native_bin"
        native_bin.mkdir()
        (native_bin / "fls.exe").write_text("root stub")

        found = find_backend_executable("tsk", tmp_path, meipass)
        assert found is not None
        assert str(meipass) in str(found)

    def test_not_found_returns_none(self, tmp_path):
        """When no executable exists, return None — don't crash."""
        found = find_backend_executable("tsk", tmp_path)
        assert found is None

    def test_source_checkout_is_not_an_executable(self, tmp_path):
        """A .c or .h file in native_bin should NOT match as an executable."""
        native_bin = tmp_path / "native_bin"
        native_bin.mkdir()
        (native_bin / "fls.c").write_text("source code, not exe")
        found = find_backend_executable("tsk", tmp_path)
        assert found is None


class TestBackendStatus:
    def test_fails_closed_with_no_binaries(self, tmp_path):
        """backend_status must report MISSING when no binaries are found."""
        for method_id in METHOD_BACKENDS:
            status, reason = backend_status(method_id, tmp_path)
            assert status == "BACKEND MISSING", f"{method_id} did not fail closed"
            assert "official backend executable" in reason

    def test_detected_when_binary_present(self, tmp_path):
        """When at least one required backend executable exists, report DETECTED."""
        native_bin = tmp_path / "native_bin"
        native_bin.mkdir()
        (native_bin / "testdisk.exe").write_text("stub")
        (native_bin / "photorec.exe").write_text("stub")
        status, reason = backend_status("quick", tmp_path)
        assert status == "BACKEND DETECTED"

    def test_unknown_method_returns_unsupported(self, tmp_path):
        """An unknown method ID should return UNSUPPORTED."""
        status, reason = backend_status("nonexistent_method", tmp_path)
        assert status == "UNSUPPORTED"
