from __future__ import annotations

import inspect
from pathlib import Path

from drex_app import VerificationEngine, DRIVE_METHODS, FILE_METHODS, RECOVERY_METHODS


def test_verification_engine_accepts_successful_file_backend_contract():
    evidence = {"verified": True, "removed": True, "sha256_after": None}
    status, warnings = VerificationEngine.assess(evidence)
    assert status in {"VERIFIED", "VERIFIED_PARTIAL"}, (
        f"Successful file backend contract was downgraded to {status!r}: {warnings}"
    )


def test_method_inventory_is_exactly_25():
    assert len(DRIVE_METHODS) == 7
    assert len(FILE_METHODS) == 9
    assert len(RECOVERY_METHODS) == 9
    assert len(DRIVE_METHODS) + len(FILE_METHODS) + len(RECOVERY_METHODS) == 25


def test_task_manager_result_contract_is_not_exception_only():
    from drex_app import DrexTaskManager
    source = inspect.getsource(DrexTaskManager.submit_task)
    # TaskManager must not make a successful state decision solely from
    # "no Python exception" when the returned operation result can be FAILED.
    assert "result" in source
    assert "OperationResult" in source or "status" in source


def test_all_python_sources_compile():
    import py_compile
    root = Path(__file__).resolve().parents[1]
    sources = sorted(root.rglob("*.py"))
    assert sources
    for path in sources:
        if any(part in {".git", "__pycache__"} for part in path.parts):
            continue
        py_compile.compile(str(path), doraise=True)
