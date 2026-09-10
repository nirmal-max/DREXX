import tempfile
from pathlib import Path

import pytest

from recovery_adapter import RECOVERY_METHOD_SPECS, QuickRecoveryAdapter, RecoveryDispatcher, RecoveryError, parse_scan_result


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
        with pytest.raises(RecoveryError, match="not built/installed"):
            adapter.require_executable()


def test_all_recovery_methods_are_registered_to_distinct_local_modules(tmp_path: Path):
    dispatcher = RecoveryDispatcher(tmp_path, tmp_path)
    assert len(RECOVERY_METHOD_SPECS) == 9
    assert set(dispatcher.adapters) == {spec.method_id for spec in RECOVERY_METHOD_SPECS}
    assert len({spec.module_dir for spec in RECOVERY_METHOD_SPECS}) == 9
    for spec in RECOVERY_METHOD_SPECS:
        status, reason = dispatcher.status(spec.method_id)
        assert status == "Unavailable"
        assert spec.display_name in reason or spec.method_id == "quick"
