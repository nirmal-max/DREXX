import tempfile
from pathlib import Path

import pytest

from recovery_adapter import RECOVERY_METHOD_SPECS, QuickRecoveryAdapter, RecoveryDispatcher, RecoveryError, parse_scan_result
from recovery_backends import METHOD_BACKENDS, backend_status


def test_quick_scan_result_is_parsed_defensively():
    result = parse_scan_result({
        "status": "OK",
        "source": {"identity": "fixture"},
        "candidates": [{"id": 12, "name": "photo.jpg", "filesystem": "NTFS", "size": 4200, "deleted": True, "confidence": 0.94}, {"name": "missing-id"}],
        "warnings": ["limited evidence"],
    })
    assert result.status == "OK"
    assert len(result.candidates) == 1
    assert result.candidates[0].candidate_id == "12"
    assert result.candidates[0].confidence == 0.94


def test_missing_quickscan_fails_closed():
    with tempfile.TemporaryDirectory() as directory:
        adapter = QuickRecoveryAdapter(Path(directory))
        assert not adapter.available
        with pytest.raises(RecoveryError, match="requires The Sleuth Kit"):
            adapter.require_executable()


def test_all_recovery_methods_are_registered_to_distinct_local_modules(tmp_path: Path):
    dispatcher = RecoveryDispatcher(tmp_path, tmp_path)
    assert len(RECOVERY_METHOD_SPECS) == 9
    assert set(dispatcher.adapters) == {spec.method_id for spec in RECOVERY_METHOD_SPECS}
    assert len({spec.method_id for spec in RECOVERY_METHOD_SPECS}) == 9
    for spec in RECOVERY_METHOD_SPECS:
        status, reason = dispatcher.status(spec.method_id)
        assert status == "Unavailable"
        assert len(reason) > 0


def test_method_specific_json_shapes_are_normalized():
    targeted = parse_scan_result({"status": "success", "candidates": [{"id": 7, "type": "PDF", "size": 12, "confidence": 88}]}, "Targeted Recovery")
    assert targeted.candidates[0].candidate_id == "7"
    assert targeted.candidates[0].filesystem == "PDF"
    deep = parse_scan_result({"status": "complete", "candidates": [{"filesystem": "NTFS", "declared_size": 42, "score": 80}]}, "Deep Recovery")
    assert len(deep.candidates) == 0


def test_official_backend_status_fails_closed_without_installed_binaries(tmp_path: Path):
    assert set(METHOD_BACKENDS) == {spec.method_id for spec in RECOVERY_METHOD_SPECS}
    status, reason = backend_status("quick", tmp_path, tmp_path)
    assert status == "BACKEND MISSING"
    assert "official backend executable" in reason
