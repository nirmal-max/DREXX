import tempfile
from pathlib import Path

import pytest

from recovery_adapter import QuickRecoveryAdapter, RecoveryError, parse_scan_result


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
