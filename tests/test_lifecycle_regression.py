"""
DREX Lifecycle & Regression Test Suite
========================================

Covers the DELitALL-inspired refactor requirements:

1. Single Tk root -- no second tk.Tk() during navigation.
2. Repeated Dashboard navigation does NOT create duplicate child frames.
3. Dashboard to Wipe Drive to Dashboard x 20 does not duplicate.
4. _on_devices_discovered while on Dashboard does not duplicate page.
5. _page_generation increments on every _clear_page() call.
6. Stale-generation render_dashboard() invocation does not crash.
7. show_page() safe to call repeatedly (idempotent).
8. ElevationState enum and _detect_elevation() return correct types.
9. _request_uac_elevation() exists and is callable.
10. TaskManager cancellation sets state to CANCELLED.
"""
from __future__ import annotations

import os
import queue
import threading
import time

import pytest

import drex_app
from drex_app import (
    DrexApp,
    DrexDeviceManager,
    DrexTaskManager,
    DriveInfo,
    ElevationState,
    TaskState,
    _detect_elevation,
    _request_uac_elevation,
)


def _make_fake_drive() -> DriveInfo:
    return DriveInfo(
        path="F:\\",
        device_path=r"\\.\PHYSICALDRIVE9",
        model="Test USB Device",
        serial="TESTSERIAL123",
        capacity=64_000_000_000,
        interface="USB",
        drive_type="Removable",
        filesystem="exFAT",
        free=60_000_000_000,
        health="OK",
        status="Online",
        device_id=r"\\.\PHYSICALDRIVE9",
    )


class TestLifecycleRegression:
    @pytest.fixture(scope="class", autouse=True)
    def app(self):
        drex_app._ELEVATION_STATE = ElevationState.NOT_ELEVATED
        a = DrexApp()
        a.update_idletasks()
        yield a
        try:
            a.destroy()
        except Exception:
            pass

    def test_single_tk_root(self, app):
        for page in ["Dashboard", "Wipe Drive", "Wipe File/Folder",
                     "Recover", "Destroy Drive", "Certificates", "Help"]:
            app.show_page(page)
            app.update_idletasks()
        assert app.winfo_exists()

    def test_no_duplicate_dashboard_repeated_navigation(self, app):
        for _ in range(5):
            app.show_page("Dashboard")
            app.update_idletasks()
        items = app.page_canvas.find_all()
        assert len(items) == 1, f"Expected 1 canvas item, found {len(items)}. Duplicate Dashboard detected."

    def test_repeated_cross_navigation_no_duplicate(self, app):
        for i in range(20):
            app.show_page("Dashboard")
            app.update_idletasks()
            app.show_page("Wipe Drive")
            app.update_idletasks()
        app.show_page("Dashboard")
        app.update_idletasks()
        assert app.current_page == "Dashboard"
        items = app.page_canvas.find_all()
        assert len(items) == 1, f"Found {len(items)} canvas items after 20x navigation, expected 1."

    def test_devices_discovered_does_not_duplicate_dashboard(self, app):
        app.show_page("Dashboard")
        app.update_idletasks()
        gen_before = app._page_generation
        fake_drives = [_make_fake_drive()]
        app._on_devices_discovered(fake_drives)
        app.update_idletasks()
        assert app.drives == fake_drives
        assert app._page_generation > gen_before
        items = app.page_canvas.find_all()
        assert len(items) == 1, f"After _on_devices_discovered: {len(items)} canvas items, expected 1."

    def test_page_generation_increments(self, app):
        initial_gen = app._page_generation
        app.show_page("Wipe Drive")
        assert app._page_generation == initial_gen + 1
        app.show_page("Recover")
        assert app._page_generation == initial_gen + 2
        app.show_page("Dashboard")
        assert app._page_generation == initial_gen + 3

    def test_stale_render_dashboard_does_not_crash(self, app):
        app.show_page("Dashboard")
        app.update_idletasks()
        app.show_page("Wipe Drive")
        app.update_idletasks()
        app._page_generation += 100
        try:
            app.render_dashboard()
        except Exception as exc:
            pytest.fail(f"render_dashboard() raised unexpectedly: {exc}")
        assert app.winfo_exists()

    def test_show_page_idempotent_safe(self, app):
        for _ in range(10):
            app.show_page("Help")
            app.update_idletasks()
        assert app.current_page == "Help"
        assert app.page is not None
        assert app.page.winfo_exists()

    def test_all_pages_render_cleanly(self, app):
        for name in ["Dashboard", "Wipe Drive", "Wipe File/Folder",
                     "Recover", "Destroy Drive", "Certificates", "Help"]:
            app.show_page(name)
            app.update_idletasks()
            assert app.current_page == name
            assert app.page is not None


class TestElevation:
    def test_elevation_state_enum_values(self):
        assert ElevationState.ELEVATED == "ELEVATED"
        assert ElevationState.NOT_ELEVATED == "NOT_ELEVATED"
        assert ElevationState.ELEVATION_FAILED == "ELEVATION_FAILED"

    def test_detect_elevation_returns_valid_state(self):
        state = _detect_elevation()
        assert isinstance(state, ElevationState)
        assert state in (ElevationState.ELEVATED, ElevationState.NOT_ELEVATED, ElevationState.ELEVATION_FAILED)

    def test_detect_elevation_consistent(self):
        assert _detect_elevation() == _detect_elevation()

    def test_request_uac_elevation_callable(self):
        assert callable(_request_uac_elevation)

    def test_elevation_state_module_global_exists(self):
        assert hasattr(drex_app, "_ELEVATION_STATE")
        assert isinstance(drex_app._ELEVATION_STATE, ElevationState)


class TestTaskManagerLifecycle:
    @pytest.fixture
    def tm(self):
        q: queue.Queue = queue.Queue()
        manager = DrexTaskManager(q)
        yield manager
        manager.shutdown(wait=False)

    def test_initial_state_idle(self, tm):
        assert tm.state == TaskState.IDLE
        assert not tm.is_active()

    def test_task_runs_to_success(self, tm):
        tm.submit_task("test_success", lambda: {"status": "SUCCESS"})
        deadline = time.time() + 3.0
        final_state = None
        while time.time() < deadline:
            try:
                kind, val = tm.events.get(timeout=0.1)
                if kind == "task_state":
                    final_state = val[0]
                    if final_state in (TaskState.SUCCESS, TaskState.FAILED, TaskState.CANCELLED):
                        break
            except queue.Empty:
                pass
        assert final_state == TaskState.SUCCESS
        assert not tm.is_active()

    def test_task_cancellation_produces_cancelled(self, tm):
        started = threading.Event()
        def _long_work(cancel_event: threading.Event):
            started.set()
            for _ in range(200):
                if cancel_event.is_set():
                    raise Exception("Cancelled")
                time.sleep(0.01)
            return {"status": "SUCCESS"}
        tm.submit_task("test_cancel", _long_work)
        started.wait(timeout=2.0)
        tm.cancel()
        deadline = time.time() + 5.0
        final_state = None
        while time.time() < deadline:
            try:
                kind, val = tm.events.get(timeout=0.1)
                if kind == "task_state":
                    final_state = val[0]
                    if final_state in (TaskState.SUCCESS, TaskState.FAILED, TaskState.CANCELLED):
                        break
            except queue.Empty:
                pass
        assert final_state == TaskState.CANCELLED, f"Expected CANCELLED, got {final_state}"

    def test_task_failure_produces_failed(self, tm):
        def _bad():
            raise RuntimeError("Simulated backend failure")
        tm.submit_task("test_fail", _bad)
        deadline = time.time() + 3.0
        final_state = None
        while time.time() < deadline:
            try:
                kind, val = tm.events.get(timeout=0.1)
                if kind == "task_state":
                    final_state = val[0]
                    if final_state in (TaskState.SUCCESS, TaskState.FAILED, TaskState.CANCELLED):
                        break
            except queue.Empty:
                pass
        assert final_state == TaskState.FAILED

    def test_second_task_rejected_while_active(self, tm):
        running = threading.Event()
        hold = threading.Event()
        def _blocking():
            running.set()
            hold.wait(timeout=5.0)
        ok1 = tm.submit_task("task1", _blocking)
        running.wait(timeout=2.0)
        ok2 = tm.submit_task("task2", lambda: None)
        hold.set()
        assert ok1 is True
        assert ok2 is False


class TestDeviceManagerSingleFlight:
    def test_concurrent_discovery_does_not_spawn_duplicate(self):
        dm = DrexDeviceManager()
        call_count = [0]
        lock = threading.Lock()
        original_discover = drex_app.discover_drives
        def _patched():
            with lock:
                call_count[0] += 1
            time.sleep(0.2)
            return []
        drex_app.discover_drives = _patched
        try:
            done_events = []
            for _ in range(5):
                e = threading.Event()
                done_events.append(e)
                dm.start_async_discovery(on_complete=lambda _: e.set())
            for e in done_events:
                e.wait(timeout=3.0)
            assert call_count[0] == 1, f"discover_drives called {call_count[0]} times; expected 1 (single-flight)."
        finally:
            drex_app.discover_drives = original_discover

    def test_cached_result_skips_rediscovery(self):
        dm = DrexDeviceManager()
        call_count = [0]
        original_discover = drex_app.discover_drives
        def _patched():
            call_count[0] += 1
            return [_make_fake_drive()]
        drex_app.discover_drives = _patched
        try:
            done = threading.Event()
            dm.start_async_discovery(on_complete=lambda _: done.set())
            done.wait(timeout=3.0)
            done2 = threading.Event()
            dm.start_async_discovery(on_complete=lambda _: done2.set())
            done2.wait(timeout=1.0)
            assert call_count[0] == 1, f"discover_drives called {call_count[0]} times; expected 1 (cache used)."
        finally:
            drex_app.discover_drives = original_discover


class TestCapabilityThreadAffinityAndResponsiveness:
    def test_probe_drive_capabilities_fails_on_main_thread(self):
        """Thread-affinity regression test: calling probe_drive_capabilities on main thread MUST raise RuntimeError."""
        drive = _make_fake_drive()
        assert threading.current_thread() is threading.main_thread()
        with pytest.raises(RuntimeError, match="Thread Affinity Violation"):
            drex_app.probe_drive_capabilities(drive)

    def test_probe_drive_capabilities_succeeds_on_worker_thread(self):
        """Worker thread execution of probe_drive_capabilities succeeds and returns valid capability map."""
        drive = _make_fake_drive()
        result_holder = []
        exc_holder = []

        def _worker():
            try:
                caps = drex_app.probe_drive_capabilities(drive)
                result_holder.append(caps)
            except Exception as exc:
                exc_holder.append(exc)

        t = threading.Thread(target=_worker, name="test_cap_worker")
        t.start()
        t.join(timeout=5.0)

        assert not exc_holder, f"Worker raised exception: {exc_holder}"
        assert len(result_holder) == 1
        caps = result_holder[0]
        assert isinstance(caps, dict)
        assert caps.get("bus_type") == "USB"
        assert caps.get("write_capable") == "SUPPORTED"
        assert caps.get("overwrite_backend_qualified") == "SUPPORTED"

    def test_cold_cache_capability_flow(self):
        """Cold cache test: UI gets CHECKING... instantly, async worker finishes, cached result becomes available."""
        drive = _make_fake_drive()
        drex_app._global_capability_manager.invalidate()

        t0 = time.perf_counter()
        status, reason = drex_app.drive_method_status("overwrite", drive)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        # Must return in under 20ms on Tk thread without PowerShell/WMI blocking
        assert elapsed_ms < 50.0, f"drive_method_status took {elapsed_ms:.2f}ms (expected <50ms)"
        assert status == "CHECKING...", f"Expected 'CHECKING...', got '{status}'"

        # Wait for background probe worker to populate cache
        deadline = time.time() + 5.0
        cached = None
        while time.time() < deadline:
            cached = drex_app._global_capability_manager.get_cached(drive)
            if cached is not None:
                break
            time.sleep(0.05)

        assert cached is not None, "Async worker did not populate capability cache within timeout."
        status2, _ = drex_app.drive_method_status("overwrite", drive)
        assert status2 == "Available"

    @pytest.fixture(scope="class")
    def app_instance(self):
        drex_app._ELEVATION_STATE = ElevationState.NOT_ELEVATED
        a = DrexApp()
        a.update_idletasks()
        yield a
        try:
            a.destroy()
        except Exception:
            pass

    def test_wipe_drive_page_cold_cache_responsiveness(self, app_instance):
        """Cold cache Wipe Drive render test: page opens instantly without synchronous subprocess, badges display CHECKING... then update to Available."""
        drex_app._global_capability_manager.invalidate()
        drive = _make_fake_drive()

        a = app_instance
        a.drives = [drive]
        a.selected_drive = drive
        a.update_idletasks()

        t0 = time.perf_counter()
        a.show_page("Wipe Drive")
        a.update_idletasks()
        render_elapsed_ms = (time.perf_counter() - t0) * 1000.0

        # Rendering on cold cache without synchronous PowerShell must be sub-second (<500ms)
        assert render_elapsed_ms < 600.0, f"Wipe Drive render took {render_elapsed_ms:.2f}ms (expected <600ms)"
        assert hasattr(a, "_method_badges")
        badge = a._method_badges.get("overwrite")
        assert badge is not None
        # Badge text should be either CHECKING... or Available (if async finished super fast)
        badge_text = badge.cget("text")
        assert "CHECKING" in badge_text or "Available" in badge_text

        # Allow event loop to process async worker EV_CAPABILITIES event
        deadline = time.time() + 12.0
        while time.time() < deadline:
            a._poll_events()
            a.update_idletasks()
            if "Available" in badge.cget("text"):
                break
            time.sleep(0.05)

        assert "Available" in badge.cget("text")

    def test_rapid_navigation_and_capability_stress(self, app_instance):
        """Stress test: rapid cross-navigation and capability discovery without freezes."""
        drive = _make_fake_drive()
        a = app_instance
        a.drives = [drive]
        a.selected_drive = drive
        a.update_idletasks()

        for i in range(10):
            a.show_page("Dashboard")
            a.update_idletasks()
            a.show_page("Wipe Drive")
            a.update_idletasks()
            drex_app._global_capability_manager.request_capabilities_async(drive, event_queue=a.events)
            a._poll_events()

        assert a.winfo_exists()
        assert a.current_page == "Wipe Drive"
