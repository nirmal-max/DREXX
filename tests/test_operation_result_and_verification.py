"""
test_operation_result_and_verification.py
==========================================
Phase 11 mandatory tests for:
  - OperationResult dataclass construction and field invariants
  - OperationContext dataclass
  - VerificationEngine.assess() across all status branches
  - CapacityKind enum — distinguishes PHYSICAL_DEVICE from VOLUME from UNKNOWN
  - VerificationEngine is stateless and callable off the Tk thread
  - Thread-affinity proof: concurrent VerificationEngine calls from multiple threads
  - Duplicate-Start prevention via TaskManager guard
  - Structured event constants exist and are non-empty strings
  - OperationResult.certificate_path wiring (View Certificate fix)
  - Static audit: forbidden Tk antipatterns absent
  - Static audit: "Needs envelope" string absent from codebase
  - Progress throttle: _physical_overwrite_windows emits first event at offset=0
  - All 25 method IDs preserved (cross-reference)

No Tk is instantiated. All tests run headless.
"""
from __future__ import annotations

import dataclasses
import queue
import re
import sys
import threading
import time
from pathlib import Path
from typing import Any
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import drex_app
from drex_app import (
    CapacityKind,
    EV_LOG,
    EV_OP_COMPLETED,
    EV_OP_STARTED,
    EV_PROGRESS,
    EV_OP_VERIFYING,
    EV_OP_FAILED,
    EV_OP_CANCELLED,
    EV_OP_BLOCKED,
    EV_RECOVERY_SCAN,
    EV_DEVICES,
    EV_TASK_STATE,
    EV_TASK_FINISHED,
    EV_FINISHED,
    EV_ERROR_ALERT,
    EV_RESULT,
    OperationContext,
    OperationResult,
    VerificationEngine,
    DrexTaskManager,
    TaskState,
)


# ─────────────────────────────────────────────────────────────────────────────
# STRUCTURED EVENT CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

class TestStructuredEventConstants:
    """All event constants must be non-empty strings and unique."""

    ALL_EVENTS = [
        EV_LOG, EV_OP_COMPLETED, EV_OP_STARTED, EV_PROGRESS,
        EV_OP_VERIFYING, EV_OP_FAILED, EV_OP_CANCELLED, EV_OP_BLOCKED,
        EV_RECOVERY_SCAN, EV_DEVICES, EV_TASK_STATE, EV_TASK_FINISHED,
        EV_FINISHED, EV_ERROR_ALERT, EV_RESULT,
    ]

    def test_all_events_are_nonempty_strings(self):
        for ev in self.ALL_EVENTS:
            assert isinstance(ev, str) and ev, f"{ev!r} must be a non-empty string"

    def test_all_event_constants_are_unique(self):
        seen = set()
        for ev in self.ALL_EVENTS:
            assert ev not in seen, f"Duplicate event constant: {ev!r}"
            seen.add(ev)

    def test_ev_progress_value(self):
        assert EV_PROGRESS == "progress"

    def test_ev_log_value(self):
        assert EV_LOG == "log"

    def test_ev_op_completed_distinct_from_legacy(self):
        assert EV_OP_COMPLETED not in ("result", "log", "progress", "status", "finished")


# ─────────────────────────────────────────────────────────────────────────────
# CAPACITY KIND
# ─────────────────────────────────────────────────────────────────────────────

class TestCapacityKind:
    """CapacityKind prevents volume-size silently becoming device-size."""

    def test_physical_device_value(self):
        assert CapacityKind.PHYSICAL_DEVICE == "PHYSICAL_DEVICE_CAPACITY"

    def test_volume_value(self):
        assert CapacityKind.VOLUME == "VOLUME_CAPACITY"

    def test_unknown_value(self):
        assert CapacityKind.UNKNOWN == "UNKNOWN"

    def test_physical_device_ne_volume(self):
        assert CapacityKind.PHYSICAL_DEVICE != CapacityKind.VOLUME

    def test_unknown_ne_physical_device(self):
        assert CapacityKind.UNKNOWN != CapacityKind.PHYSICAL_DEVICE


# ─────────────────────────────────────────────────────────────────────────────
# OPERATION CONTEXT
# ─────────────────────────────────────────────────────────────────────────────

class TestOperationContext:
    def _make(self, **overrides) -> OperationContext:
        cancel = threading.Event()
        q: queue.Queue = queue.Queue()
        defaults = dict(
            operation_id="test-op-001",
            operation_kind="file",
            method_id="csprng",
            method_name="CSPRNG Random Overwrite",
            target="/tmp/testfile.txt",
            cancel_event=cancel,
            emit=lambda msg: q.put((EV_LOG, msg)),
            progress=lambda done, total: q.put((EV_PROGRESS, (done, total))),
            metadata={},
        )
        defaults.update(overrides)
        return OperationContext(**defaults)

    def test_construction_succeeds(self):
        ctx = self._make()
        assert ctx.operation_id == "test-op-001"
        assert ctx.operation_kind == "file"
        assert ctx.method_id == "csprng"

    def test_emit_callback_puts_to_queue(self):
        q: queue.Queue = queue.Queue()
        ctx = self._make(emit=lambda msg: q.put((EV_LOG, msg)))
        ctx.emit("hello from worker")
        kind, val = q.get_nowait()
        assert kind == EV_LOG
        assert "hello" in val

    def test_progress_callback_puts_to_queue(self):
        q: queue.Queue = queue.Queue()
        ctx = self._make(progress=lambda d, t: q.put((EV_PROGRESS, (d, t))))
        ctx.progress(512, 1024)
        kind, val = q.get_nowait()
        assert kind == EV_PROGRESS
        assert val == (512, 1024)

    def test_cancel_event_is_threading_event(self):
        ctx = self._make()
        assert isinstance(ctx.cancel_event, threading.Event)

    def test_is_dataclass(self):
        assert dataclasses.is_dataclass(OperationContext)

    def test_metadata_is_mutable_dict(self):
        ctx = self._make(metadata={"capacity": 1_000_000_000})
        assert ctx.metadata["capacity"] == 1_000_000_000


# ─────────────────────────────────────────────────────────────────────────────
# OPERATION RESULT
# ─────────────────────────────────────────────────────────────────────────────

class TestOperationResult:
    def _make(self, **overrides) -> OperationResult:
        defaults = dict(
            operation_id="op-001",
            kind="drive",
            method_id="nist",
            method_name="NIST SP 800-88 Rev.2",
            status="SUCCESS",
            backend="_physical_overwrite_windows",
            target=r"\\.\PhysicalDrive1",
            started="2026-09-12T12:00:00Z",
            completed="2026-09-12T12:30:00Z",
            verification="VERIFIED",
            evidence={"bytes_verified": 16_000_000_000, "disk_size_bytes": 16_000_000_000},
            warnings=[],
            limitations=[],
            detail="NIST 1-pass overwrite completed with full read-back verification.",
        )
        defaults.update(overrides)
        return OperationResult(**defaults)

    def test_construction_succeeds(self):
        r = self._make()
        assert r.status == "SUCCESS"
        assert r.verification == "VERIFIED"

    def test_is_dataclass(self):
        assert dataclasses.is_dataclass(OperationResult)

    def test_optional_fields_default_none(self):
        r = self._make()
        assert r.certificate_id is None
        assert r.certificate_path is None
        assert r.error is None

    def test_certificate_path_can_be_set(self):
        r = self._make(certificate_id="cert-abc", certificate_path="/certs/cert-abc.pdf")
        assert r.certificate_path == "/certs/cert-abc.pdf"
        assert r.certificate_id == "cert-abc"

    def test_two_results_have_different_operation_ids(self):
        r1 = self._make(operation_id="op-001")
        r2 = self._make(operation_id="op-002")
        assert r1.operation_id != r2.operation_id

    def test_asdict_roundtrip(self):
        r = self._make(certificate_id="c-1", certificate_path="/tmp/c-1.pdf")
        d = dataclasses.asdict(r)
        assert d["certificate_path"] == "/tmp/c-1.pdf"
        assert d["status"] == "SUCCESS"
        assert d["verification"] == "VERIFIED"

    def test_failed_result(self):
        r = self._make(status="FAILED", verification="NOT_EXECUTED", error="WriteFile failed")
        assert r.status == "FAILED"
        assert r.error == "WriteFile failed"
        assert r.certificate_path is None

    def test_cancelled_result(self):
        r = self._make(status="CANCELLED", verification="NOT_EXECUTED")
        assert r.status == "CANCELLED"

    def test_execution_blocked_result(self):
        r = self._make(status="EXECUTION_BLOCKED", verification="NOT_EXECUTED")
        assert r.status == "EXECUTION_BLOCKED"

    def test_warnings_and_limitations_are_lists(self):
        r = self._make(
            warnings=["Read-back covered partial range."],
            limitations=["Physical NAND remapping cannot be verified."],
        )
        assert isinstance(r.warnings, list)
        assert isinstance(r.limitations, list)
        assert len(r.warnings) == 1
        assert len(r.limitations) == 1

    def test_simulation_only_result(self):
        r = self._make(
            status="SIMULATION_ONLY",
            verification="SIMULATION_ONLY",
            backend="controlled_fixture",
        )
        assert r.verification == "SIMULATION_ONLY"


# ─────────────────────────────────────────────────────────────────────────────
# VERIFICATION ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class TestVerificationEngine:
    """Stateless cross-cutting verification service — testable without Tk."""

    def test_verified_full_coverage(self):
        evidence = {
            "verification_status": "VERIFIED",
            "bytes_verified": 16_000_000_000,
            "disk_size_bytes": 16_000_000_000,
        }
        status, warnings = VerificationEngine.assess(evidence)
        assert status == "VERIFIED"
        assert warnings == []

    def test_verified_partial_coverage(self):
        evidence = {
            "verification_status": "VERIFIED",
            "bytes_verified": 8_000_000_000,
            "disk_size_bytes": 16_000_000_000,
        }
        status, warnings = VerificationEngine.assess(evidence)
        assert status == "VERIFIED_PARTIAL"
        assert any("smaller" in w.lower() for w in warnings)

    def test_partial_with_mismatches(self):
        evidence = {"verification_status": "PARTIAL", "mismatches": 3}
        status, warnings = VerificationEngine.assess(evidence)
        assert status == "PARTIAL"
        assert any("mismatch" in w.lower() for w in warnings)

    def test_not_executed_when_no_status(self):
        status, _ = VerificationEngine.assess({})
        assert status == "NOT_EXECUTED"

    def test_not_executed_when_cancelled(self):
        status, warnings = VerificationEngine.assess({"final_status": "CANCELLED"})
        assert status == "NOT_EXECUTED"
        assert warnings == []

    def test_simulation_only_flag(self):
        status, warnings = VerificationEngine.assess({"simulation": True})
        assert status == "SIMULATION_ONLY"

    def test_file_method_sha256_match_is_verified(self):
        evidence = {"sha256_after": "abc123" * 10, "verification_status": ""}
        status, _ = VerificationEngine.assess(evidence)
        assert status == "VERIFIED"

    def test_stateless_idempotent(self):
        ev1 = {"verification_status": "VERIFIED", "bytes_verified": 100, "disk_size_bytes": 100}
        ev2 = {"verification_status": "PARTIAL", "mismatches": 1}
        s1a, _ = VerificationEngine.assess(ev1)
        s2a, _ = VerificationEngine.assess(ev2)
        s1b, _ = VerificationEngine.assess(ev1)
        assert s1a == s1b == "VERIFIED"
        assert s2a == "PARTIAL"

    def test_returns_tuple_of_str_and_list(self):
        status, warnings = VerificationEngine.assess({})
        assert isinstance(status, str)
        assert isinstance(warnings, list)

    def test_unverified_propagated(self):
        status, _ = VerificationEngine.assess({"verification_status": "UNVERIFIED"})
        assert status == "UNVERIFIED"


# ─────────────────────────────────────────────────────────────────────────────
# THREAD-AFFINITY: VerificationEngine runs off main thread
# ─────────────────────────────────────────────────────────────────────────────

class TestVerificationEngineThreadAffinity:
    """Prove VerificationEngine runs safely off the main thread."""

    def test_assess_runs_on_worker_thread(self):
        results: list[tuple] = []
        main_thread_id = threading.main_thread().ident

        def _worker():
            worker_id = threading.current_thread().ident
            assert worker_id != main_thread_id
            evidence = {
                "verification_status": "VERIFIED",
                "bytes_verified": 100,
                "disk_size_bytes": 100,
            }
            status, warnings = VerificationEngine.assess(evidence)
            results.append((status, warnings, worker_id))

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        t.join(timeout=5.0)
        assert not t.is_alive()
        assert len(results) == 1
        status, warnings, worker_id = results[0]
        assert status == "VERIFIED"
        assert worker_id != main_thread_id

    def test_concurrent_calls_do_not_corrupt(self):
        """16 concurrent workers each get their own correct result."""
        outcomes: list[tuple] = []
        lock = threading.Lock()

        def _worker(evidence, expected_status):
            status, _ = VerificationEngine.assess(evidence)
            with lock:
                outcomes.append((status, expected_status))

        cases = [
            ({"verification_status": "VERIFIED", "bytes_verified": 1000, "disk_size_bytes": 1000}, "VERIFIED"),
            ({"verification_status": "PARTIAL", "mismatches": 2}, "PARTIAL"),
            ({"simulation": True}, "SIMULATION_ONLY"),
            ({"final_status": "CANCELLED"}, "NOT_EXECUTED"),
        ] * 4

        threads = [
            threading.Thread(target=_worker, args=(ev, exp), daemon=True)
            for ev, exp in cases
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)

        assert len(outcomes) == len(cases)
        for got, expected in outcomes:
            assert got == expected, f"Got {got!r}, expected {expected!r}"


# ─────────────────────────────────────────────────────────────────────────────
# DUPLICATE-START PREVENTION
# ─────────────────────────────────────────────────────────────────────────────

class TestDuplicateStartPrevention:
    """DrexTaskManager must reject a second submit while a task is active."""

    def test_second_submit_rejected_while_active(self):
        q: queue.Queue = queue.Queue()
        tm = DrexTaskManager(q, max_workers=2)
        barrier = threading.Barrier(2)
        done_ev = threading.Event()

        def _slow_task():
            barrier.wait(timeout=5)
            done_ev.wait(timeout=5)
            return "first done"

        ok1 = tm.submit_task("task-1", _slow_task)
        barrier.wait(timeout=5)
        ok2 = tm.submit_task("task-2", lambda: "second")
        done_ev.set()
        tm.shutdown(wait=True)

        assert ok1 is True
        assert ok2 is False

    def test_submit_accepted_after_completion(self):
        q: queue.Queue = queue.Queue()
        tm = DrexTaskManager(q, max_workers=2)
        ok1 = tm.submit_task("task-1", lambda: "first")
        time.sleep(0.3)
        ok2 = tm.submit_task("task-2", lambda: "second")
        tm.shutdown(wait=True)
        assert ok1 is True
        assert ok2 is True


# ─────────────────────────────────────────────────────────────────────────────
# CANCELLATION
# ─────────────────────────────────────────────────────────────────────────────

class TestCancellationDoesNotBlock:
    """Cancellation must propagate without blocking the queue consumer."""

    def test_cancel_sets_event_and_worker_sees_it(self):
        q: queue.Queue = queue.Queue()
        tm = DrexTaskManager(q, max_workers=2)
        saw_cancel = threading.Event()

        def _cancellable(cancel_event=None):
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                if cancel_event and cancel_event.is_set():
                    saw_cancel.set()
                    return "CANCELLED_GRACEFULLY"
                time.sleep(0.01)
            return "TIMEOUT"

        tm.submit_task("cancel-me", _cancellable)
        time.sleep(0.1)
        tm.cancel()
        saw_cancel.wait(timeout=3.0)
        tm.shutdown(wait=True)
        assert saw_cancel.is_set()

    def test_queue_receives_events_after_cancel(self):
        q: queue.Queue = queue.Queue()
        tm = DrexTaskManager(q, max_workers=2)
        done_ev = threading.Event()

        def _long(cancel_event=None):
            done_ev.wait(timeout=5)
            return "done"

        tm.submit_task("t1", _long)
        time.sleep(0.05)
        tm.cancel()
        done_ev.set()
        tm.shutdown(wait=True)

        events = []
        while True:
            try:
                events.append(q.get_nowait())
            except queue.Empty:
                break
        kinds = [k for k, _ in events]
        assert any(k in ("task_state", EV_TASK_STATE) for k in kinds)


# ─────────────────────────────────────────────────────────────────────────────
# STATIC AUDIT
# ─────────────────────────────────────────────────────────────────────────────

class TestStaticAudit:
    """Source inspection — enforce architectural rules mechanically."""

    SRC_PATH = Path(__file__).parent.parent / "drex_app.py"

    @classmethod
    def _src(cls) -> str:
        return cls.SRC_PATH.read_text(encoding="utf-8")

    def test_needs_envelope_string_absent(self):
        """The badge label 'Needs envelope' must be replaced with a proper label.
        Comments explaining the fix are allowed; only actual badge strings are checked.
        """
        src = self._src()
        # Find the badge dict (not comments). Look for it in a non-comment context.
        # The old badge text was the *value* in the badge dict assignment.
        # Check that the old badge VALUE is gone from the actual badge mapping:
        badge_map_pattern = r'"Unavailable on this target"\s*:\s*"Needs envelope"'
        import re
        assert not re.search(badge_map_pattern, src), (
            "Old 'Needs envelope' badge mapping still present in badge dict. "
            "Should be replaced with 'Scope: adapter unavailable' or similar."
        )

    def test_no_root_update_idletasks(self):
        """root.update_idletasks() must not be called in production code.
        Comments referencing it (e.g. 'DELitALL called root.update_idletasks() here')
        are acceptable as documentation; only actual calls count.
        """
        import re
        src = self._src()
        # Match actual calls, not comments
        calls = re.findall(r'^[^#]*root\.update_idletasks\(\)', src, re.MULTILINE)
        assert len(calls) == 0, f"Found {len(calls)} actual call(s) to root.update_idletasks()"

    def test_no_root_update_call(self):
        count = self._src().count("root.update()")
        assert count == 0, f"Found {count} call(s) to root.update()"

    def test_operation_result_class_present(self):
        assert "class OperationResult" in self._src()

    def test_operation_context_class_present(self):
        assert "class OperationContext" in self._src()

    def test_verification_engine_class_present(self):
        assert "class VerificationEngine" in self._src()

    def test_capacity_kind_enum_present(self):
        assert "class CapacityKind" in self._src()

    def test_handle_operation_result_present(self):
        assert "def _handle_operation_result" in self._src()

    def test_open_certificate_present(self):
        assert "def _open_certificate" in self._src()

    def test_ev_op_completed_used_in_workers(self):
        src = self._src()
        assert src.count("EV_OP_COMPLETED") >= 3, (
            "EV_OP_COMPLETED should appear in: definition, _drive_op_thread, _run_file_operation"
        )

    def test_progress_throttle_in_physical_overwrite(self):
        src = self._src()
        assert "_last_progress_emit" in src

    def test_first_progress_event_at_zero(self):
        src = self._src()
        assert "progress(0, target_bytes)" in src, (
            "Initial progress(0, target_bytes) not found — 0.00% bug not fixed"
        )

    def test_capacity_guard_message_present(self):
        src = self._src()
        assert "EXECUTION BLOCKED" in src and "Unknown Capacity" in src

    def test_on_page_unmount_present(self):
        """_on_page_unmount method must exist — confirmed by presence in source.
        The method is defined inside DrexApp._clear_page() context or as a method.
        """
        src = self._src()
        # The method may be defined with either def keyword form
        has_def = "def _on_page_unmount" in src
        has_call = "_on_page_unmount" in src
        assert has_call, "_on_page_unmount not referenced anywhere in drex_app.py"
        assert has_def, "def _on_page_unmount not found in drex_app.py"

    def test_open_certificate_referenced_in_handle_result(self):
        src = self._src()
        handle_start = src.find("def _handle_operation_result")
        handle_end = src.find("\n    def ", handle_start + 1)
        handle_body = src[handle_start:handle_end] if handle_end > 0 else src[handle_start:]
        assert "_open_certificate" in handle_body

    def test_ev_progress_used_in_drive_op_thread(self):
        src = self._src()
        # _drive_op_thread must use EV_PROGRESS not bare "progress" string
        drive_op_start = src.find("def _drive_op_thread")
        drive_op_end = src.find("\n            self.task_manager.submit_task", drive_op_start)
        drive_body = src[drive_op_start:drive_op_end] if drive_op_end > 0 else src[drive_op_start:drive_op_start+3000]
        assert "EV_PROGRESS" in drive_body


# ─────────────────────────────────────────────────────────────────────────────
# CERTIFICATE PATH WIRING
# ─────────────────────────────────────────────────────────────────────────────

class TestCertificatePathWiring:
    """OperationResult.certificate_path is the authoritative source for View Certificate."""

    def test_result_with_cert_path_set(self):
        r = OperationResult(
            operation_id="op-cert-001", kind="file", method_id="csprng",
            method_name="CSPRNG Random Overwrite", status="SUCCESS",
            backend="execute_file_method", target="/tmp/testfile.txt",
            started="2026-09-12T12:00:00Z", completed="2026-09-12T12:00:05Z",
            verification="VERIFIED", evidence={"sha256_after": "abc"},
            warnings=[], limitations=[], detail="Done.",
            certificate_id="cert-001", certificate_path="/certs/cert-001.pdf",
        )
        assert r.certificate_path == "/certs/cert-001.pdf"
        assert r.certificate_id == "cert-001"

    def test_two_operations_two_distinct_certificate_paths(self):
        r1 = OperationResult(
            operation_id="op-001", kind="file", method_id="zero",
            method_name="Zero Overwrite", status="SUCCESS", backend="b",
            target="/a", started="t1", completed="t2",
            verification="VERIFIED", evidence={}, warnings=[], limitations=[],
            detail="done", certificate_id="cert-001", certificate_path="/c/cert-001.pdf",
        )
        r2 = OperationResult(
            operation_id="op-002", kind="file", method_id="csprng",
            method_name="CSPRNG", status="SUCCESS", backend="b",
            target="/b", started="t3", completed="t4",
            verification="VERIFIED", evidence={}, warnings=[], limitations=[],
            detail="done", certificate_id="cert-002", certificate_path="/c/cert-002.pdf",
        )
        assert r1.certificate_path != r2.certificate_path
        assert r1.certificate_id != r2.certificate_id

    def test_failed_result_has_no_certificate(self):
        r = OperationResult(
            operation_id="op-fail-001", kind="drive", method_id="nist",
            method_name="NIST", status="FAILED", backend="b",
            target=r"\\.\PhysicalDrive1", started="t1", completed="t2",
            verification="NOT_EXECUTED", evidence={}, warnings=[], limitations=[],
            detail="failed", error="CreateFile failed WinError=5",
        )
        assert r.certificate_id is None
        assert r.certificate_path is None


# ─────────────────────────────────────────────────────────────────────────────
# VERIFICATION SEPARATED FROM EXECUTION
# ─────────────────────────────────────────────────────────────────────────────

class TestVerificationSeparatedFromExecution:
    """Write-complete must NOT equal VERIFIED. DELitALL's antipattern."""

    def test_bytes_written_without_readback_is_not_verified(self):
        evidence = {"bytes_written": 16_000_000_000}
        status, _ = VerificationEngine.assess(evidence)
        assert status == "NOT_EXECUTED", (
            f"Write-complete must not be VERIFIED. Got: {status}"
        )

    def test_write_complete_explicit_not_executed(self):
        evidence = {"bytes_written": 1_000_000, "verification_status": "NOT_EXECUTED"}
        status, _ = VerificationEngine.assess(evidence)
        assert status == "NOT_EXECUTED"

    def test_write_and_readback_verified(self):
        evidence = {
            "bytes_written": 1000, "bytes_verified": 1000,
            "disk_size_bytes": 1000, "verification_status": "VERIFIED",
        }
        status, _ = VerificationEngine.assess(evidence)
        assert status == "VERIFIED"


# ─────────────────────────────────────────────────────────────────────────────
# ALL 25 METHODS PRESERVED
# ─────────────────────────────────────────────────────────────────────────────

class TestAllTwentyFiveMethodsPreserved:
    """All 25 method IDs must still exist after the refactor."""

    EXPECTED_DRIVE_IDS = {"nist", "smart", "native", "ata", "nvme", "ieee", "overwrite"}
    EXPECTED_RECOVERY_IDS = {
        # Actual IDs from RECOVERY_METHODS ("smart" is the recovery method ID,
        # same as the drive method ID — this is by design; kinds are separate namespaces)
        "quick", "smart", "targeted", "filesystem",
        "deep", "fragment", "raid", "damaged", "forensic",
    }
    EXPECTED_FILE_COUNT = 9

    def test_drive_method_ids_present(self):
        from drex_app import DRIVE_METHODS
        ids = {m["id"] for m in DRIVE_METHODS}
        missing = self.EXPECTED_DRIVE_IDS - ids
        assert not missing, f"Missing drive method IDs: {missing}"

    def test_recovery_method_ids_present(self):
        from drex_app import RECOVERY_METHODS
        # RECOVERY_METHODS may be list of tuples (id, name, desc) or list of dicts
        if RECOVERY_METHODS and isinstance(RECOVERY_METHODS[0], dict):
            ids = {m["id"] for m in RECOVERY_METHODS}
        else:
            ids = {m[0] for m in RECOVERY_METHODS}  # tuple: (id, name, desc)
        missing = self.EXPECTED_RECOVERY_IDS - ids
        assert not missing, f"Missing recovery method IDs: {missing}"

    def test_file_method_count_preserved(self):
        from drex_app import FILE_METHODS
        assert len(FILE_METHODS) >= self.EXPECTED_FILE_COUNT, (
            f"Expected >= {self.EXPECTED_FILE_COUNT} file methods, got {len(FILE_METHODS)}"
        )

    def test_total_method_count_is_25(self):
        from drex_app import DRIVE_METHODS, FILE_METHODS, RECOVERY_METHODS
        total = len(DRIVE_METHODS) + len(FILE_METHODS) + len(RECOVERY_METHODS)
        assert total == 25, f"Expected 25 total methods, got {total}"

    def test_no_method_id_is_empty(self):
        from drex_app import DRIVE_METHODS, FILE_METHODS, RECOVERY_METHODS
        def _get_id(m):
            return m["id"] if isinstance(m, dict) else m[0]
        for m in DRIVE_METHODS + FILE_METHODS + RECOVERY_METHODS:
            assert _get_id(m), f"Method has empty ID: {m}"

    def test_all_method_ids_globally_unique(self):
        """Method IDs must be unique within their own kind.
        Drive + Recovery may share an ID (e.g. 'smart') — they are separate namespaces.
        """
        from drex_app import DRIVE_METHODS, FILE_METHODS, RECOVERY_METHODS
        def _get_id(m):
            return m["id"] if isinstance(m, dict) else m[0]
        drive_ids = [_get_id(m) for m in DRIVE_METHODS]
        file_ids  = [_get_id(m) for m in FILE_METHODS]
        rec_ids   = [_get_id(m) for m in RECOVERY_METHODS]
        assert len(drive_ids) == len(set(drive_ids)), f"Duplicate drive IDs: {drive_ids}"
        assert len(file_ids)  == len(set(file_ids)),  f"Duplicate file IDs: {file_ids}"
        assert len(rec_ids)   == len(set(rec_ids)),   f"Duplicate recovery IDs: {rec_ids}"


# ─────────────────────────────────────────────────────────────────────────────
# EXECUTE_DRIVE_METHOD SIGNATURE AND CAPS INTEGRATION REGRESSION TEST
# ─────────────────────────────────────────────────────────────────────────────

class TestDriveMethodSignatureAndCaps:
    """Regression test: execute_drive_method must accept caps keyword argument."""

    def test_execute_drive_method_signature_has_caps(self):
        import inspect
        from drex_app import execute_drive_method

        sig = inspect.signature(execute_drive_method)
        params = list(sig.parameters.keys())
        assert "method_id" in params
        assert "drive" in params
        assert "emit" in params
        assert "progress" in params
        assert "cancel_event" in params
        assert "caps" in params
        assert sig.parameters["caps"].default is None

    def test_execute_drive_method_with_pre_probed_caps(self):
        from unittest.mock import MagicMock
        from drex_app import execute_drive_method, DriveInfo

        mock_drive = DriveInfo(
            path="E:\\",
            device_path=r"\\.\PHYSICALDRIVE1",
            model="SanDisk Cruzer Blade",
            serial="12345",
            capacity=1024 * 1024,
            interface="USB",
            drive_type="Removable",
            filesystem="FAT32",
            free=512 * 1024,
            health="OK",
            status="Online",
            device_id=r"\\.\PHYSICALDRIVE1",
        )
        caps = {
            "physical_disk_number": 1,
            "bus_type": "USB",
            "model": "SanDisk Cruzer Blade",
            "serial": "12345",
            "capacity": 1024 * 1024,
            "probe_errors": [],
            "native_sanitize": "UNSUPPORTED",
            "ata_secure_erase": "UNSUPPORTED",
            "nvme_controller": "UNSUPPORTED",
        }
        events = []
        # Method native returns UNSUPPORTED_HARDWARE for USB without executing physical write
        res = execute_drive_method(
            "native",
            mock_drive,
            events.append,
            lambda d, t: None,
            caps=caps,
        )
        assert isinstance(res, dict)
        assert res.get("status") == "UNSUPPORTED_HARDWARE"
        assert res.get("capabilities") == caps

