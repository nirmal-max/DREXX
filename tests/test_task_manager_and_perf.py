import time
import queue
import re
from pathlib import Path
import tempfile
import pytest

from drex_app import (
    DrexTimer,
    DrexProgressTracker,
    DrexTaskManager,
    TaskState,
    DrexCapabilityManager,
    DrexDeviceManager,
    DriveInfo,
    target_properties_fast,
    count_folder_size_async,
)


def test_drex_timer_precision():
    timer = DrexTimer()
    assert timer.formatted() == "00:00:00.000"
    assert not timer.is_running
    
    timer.start()
    assert timer.is_running
    time.sleep(0.05)
    formatted = timer.formatted()
    assert re.match(r"^\d{2}:\d{2}:\d{2}\.\d{3}$", formatted)
    assert timer.elapsed >= 0.04

    timer.stop()
    assert not timer.is_running
    elapsed_frozen = timer.elapsed
    time.sleep(0.02)
    assert timer.elapsed == elapsed_frozen

    timer.reset()
    assert timer.elapsed == 0.0
    assert timer.formatted() == "00:00:00.000"


def test_drex_progress_tracker():
    tracker = DrexProgressTracker()
    assert tracker.percentage_str == "0.00%"
    assert tracker.speed_str == "—"
    assert tracker.eta_str == "ETA: —"

    # Known total
    tracker.start(total_bytes=10_000_000, stage="NIST 800-88")
    assert tracker.stage_text == "NIST 800-88"
    assert not tracker.is_streaming

    time.sleep(0.03)
    tracker.update(5_000_000)
    assert tracker.percentage == 50.0
    assert tracker.percentage_str == "50.00%"
    assert "MB/s" in tracker.speed_str or "KB/s" in tracker.speed_str or "B/s" in tracker.speed_str

    # Streaming mode (unknown total)
    tracker.reset()
    tracker.start(total_bytes=0, stage="Scanning")
    assert tracker.is_streaming
    time.sleep(0.02)
    tracker.update(1_048_576)
    assert "1.00 MB" in tracker.percentage_str
    assert "calculating" in tracker.eta_str.lower()


def test_drex_task_manager_success():
    q = queue.Queue()
    tm = DrexTaskManager(q, max_workers=2)
    try:
        def sample_worker():
            return 42

        submitted = tm.submit_task("sample_task", sample_worker)
        assert submitted is True

        # Wait for task completion via queue
        finished = False
        start_time = time.time()
        while time.time() - start_time < 3.0:
            try:
                kind, val = q.get(timeout=0.2)
                if kind == "task_finished":
                    task_id, result, exc = val
                    assert task_id == "sample_task"
                    assert result == 42
                    assert exc is None
                    finished = True
                    break
            except queue.Empty:
                pass

        assert finished is True
        assert tm.state == TaskState.SUCCESS
    finally:
        tm.shutdown(wait=True)


def test_drex_task_manager_failure():
    q = queue.Queue()
    tm = DrexTaskManager(q, max_workers=2)
    try:
        def failing_worker():
            raise RuntimeError("Hardware IO failure")

        tm.submit_task("fail_task", failing_worker)

        finished = False
        start_time = time.time()
        while time.time() - start_time < 3.0:
            try:
                kind, val = q.get(timeout=0.2)
                if kind == "task_finished":
                    task_id, result, exc = val
                    assert task_id == "fail_task"
                    assert isinstance(exc, RuntimeError)
                    finished = True
                    break
            except queue.Empty:
                pass

        assert finished is True
        assert tm.state == TaskState.FAILED
    finally:
        tm.shutdown(wait=True)


def test_drex_task_manager_cancellation():
    q = queue.Queue()
    tm = DrexTaskManager(q, max_workers=2)
    try:
        def cancellable_worker(cancel_event=None):
            for _ in range(50):
                if cancel_event and cancel_event.is_set():
                    return "cancelled"
                time.sleep(0.02)
            return "done"

        tm.submit_task("cancel_task", cancellable_worker)
        time.sleep(0.05)
        assert tm.is_active()
        assert tm.cancel() is True

        finished = False
        start_time = time.time()
        while time.time() - start_time < 3.0:
            try:
                kind, val = q.get(timeout=0.2)
                if kind == "task_finished":
                    finished = True
                    break
            except queue.Empty:
                pass

        assert finished is True
        assert tm.state == TaskState.CANCELLED
    finally:
        tm.shutdown(wait=True)


def test_drex_capability_manager_caching():
    cm = DrexCapabilityManager(ttl_seconds=5.0)
    mock_drive = DriveInfo(path="X:", device_path=r"\\.\PhysicalDrive9", model="TestDrive", serial="12345", capacity=1000)

    # First call will probe and cache (or fail gracefully with probe_errors)
    caps1 = cm.get_capabilities(mock_drive)
    assert isinstance(caps1, dict)

    # Invalidate cache
    cm.invalidate("X:")
    assert "X:" not in cm._cache


def test_drex_device_manager_caching():
    dm = DrexDeviceManager(ttl_seconds=10.0)
    # Background discovery
    res = []
    dm.start_async_discovery(lambda drives: res.append(drives))
    start_time = time.time()
    while not res and time.time() - start_time < 15.0:
        time.sleep(0.1)
    assert len(res) == 1
    assert isinstance(res[0], list)


def test_fast_target_properties_and_async_folder_size():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"A" * 1024)

        # File properties
        props_file = target_properties_fast(test_file)
        assert props_file["Filename"] == "test.bin"
        assert "BIN" in props_file["File Type"]
        assert "1,024 bytes" in props_file["Size"]

        # Subdirectory with files
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "f1.txt").write_bytes(b"12345")
        (sub / "f2.txt").write_bytes(b"67890")

        props_dir = target_properties_fast(tmp_path)
        assert props_dir["File Type"] == "Folder"

        # Async folder size
        results = []
        count_folder_size_async(tmp_path, lambda size, disk: results.append((size, disk)))
        start_time = time.time()
        while not results and time.time() - start_time < 3.0:
            time.sleep(0.05)
        assert len(results) == 1
        total_size, total_disk = results[0]
        assert total_size == 1024 + 5 + 5
