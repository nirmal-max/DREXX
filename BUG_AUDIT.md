# DREXX Static & Runtime Bug Audit Dossier

**Audit Date**: 2026-09-11  
**Repository**: `D:\DREXX`  
**Scope**: Full Codebase Static Analysis, Keyword Sweep, Recovery Adapters, Backend Process Execution, Encoding, and Safety Guards.

---

## Audit Methodology

Every occurrence of critical keywords (`pass`, `TODO`, `FIXME`, `NotImplemented`, `placeholder`, `mock`, `synthetic`, `stub`, `raise RuntimeError`, `raise RecoveryError`, `except Exception`, `subprocess`, `shell=True`, `Popen`, `os.system`) was audited across all python modules and test suites.

---

## Bug Inventory & Analysis

### BUG-01: Windows OEM CodePage UnicodeDecodeError in Subprocess Runner
* **ID**: `BUG-01`
* **File**: `backend_adapters.py` (Line 499)
* **Function**: `CentralProcessRunner.run()`
* **Severity**: `CRITICAL`
* **Problem**: Calling `subprocess.Popen(..., text=True)` without specifying `encoding="utf-8"` and `errors="replace"` caused Python on Windows to default to the OEM/ANSI codepage (`cp1252`). When native tools (`photorec_win.exe`, `tsk_recover.exe`, `fls.exe`) emitted non-ASCII characters or raw binary streams, Python threw `UnicodeDecodeError: 'charmap' codec can't decode byte 0x9d`.
* **Runtime Impact**: The process runner thread crashed, causing background tasks to terminate abruptly without capturing output.
* **Affected Methods**: All recovery methods (17–25) and native process execution.
* **Fix**: Configured `encoding="utf-8"` and `errors="replace"` in `subprocess.Popen()`.
* **Test Required**: `tests/test_edge_cases.py::TestEdgeCases::test_unicode_filename_sanitization` and physical scan execution.

---

### BUG-02: Recovery Adapter Architecture Inconsistency & Fake Binary Fallacy
* **ID**: `BUG-02`
* **File**: `recovery_adapter.py` (Lines 176–487)
* **Classes**: `QuickRecoveryAdapter`, `FilesystemRecoveryAdapter`, `DeepRecoveryAdapter`, `ForensicRecoveryAdapter`
* **Severity**: `HIGH`
* **Problem**: `recovery_adapter.py` inherited hypothetical specifications (`quickscan.exe`, `fsrecover.exe`, `deepscan.exe`) rather than binding to the real upstream binaries installed in `native_bin/` (`fls.exe`, `fsstat.exe`, `icat.exe`, `tsk_recover.exe`, `photorec_win.exe`, `testdisk_win.exe`). `RecoveryDispatcher.status()` reported `"Unavailable"` even when the official tools were present.
* **Runtime Impact**: The application was unable to execute real recovery methods through the dispatcher despite having working native binaries.
* **Affected Methods**: Methods 17–25.
* **Fix**: Unified `recovery_adapter.py` with `backend_adapters.py` and `recovery_backends.py` to target official upstream binaries.
* **Test Required**: `tests/test_all_25_methods.py` and `tests/test_recovery_backends.py`.

---

### BUG-03: TSK fls Recursive Parameter `-r` Hanging on Flat exFAT Filesystems
* **ID**: `BUG-03`
* **File**: `backend_adapters.py` (Line 41) / `tests/physical_usb_test.py`
* **Function**: `build_fls_command()`
* **Severity**: `MEDIUM`
* **Problem**: Passing `-r` (recursive) to `fls.exe` against exFAT volumes causes TSK 4.15.0 to hang because the TSK exFAT driver does not support recursive directory descent on flat root tables.
* **Runtime Impact**: Physical USB disk scans timed out after 60 seconds with no output.
* **Affected Methods**: Methods 17, 18, 19, 20, 25 when executed on exFAT storage.
* **Fix**: Omitted `-r` when executing against flat exFAT root directories or parameterized directory inode traversal.
* **Test Required**: `tests/run_forensic_icat.py` and physical recovery test suite.

---

### BUG-04: Windows Console CP1252 Unicode Glyph Printing Failure
* **ID**: `BUG-04`
* **File**: `tests/physical_usb_test.py` (Lines 123, 222, 297, 336)
* **Severity**: `MEDIUM`
* **Problem**: Log statements containing Unicode arrow glyphs (`→` / `\u2192`) raised `UnicodeEncodeError: 'charmap' codec can't encode character '\u2192'` under Windows standard terminal output.
* **Runtime Impact**: Execution scripts crashed during progress logging.
* **Affected Methods**: Test scripts and verification harnesses.
* **Fix**: Replaced Unicode arrows with ASCII `->`.
* **Test Required**: `tests/test_all_25_methods.py`.

---

### BUG-05: GNU ddrescue Mapfile Status Header Token Count Misclassification
* **ID**: `BUG-05`
* **File**: `backend_adapters.py` (Line 355)
* **Function**: `parse_ddrescue_mapfile()`
* **Severity**: `MEDIUM`
* **Problem**: `parse_ddrescue_mapfile` unconditionally skipped the first non-comment line, failing when the mapfile omitted a 2-token status line and began immediately with 3-token block regions.
* **Runtime Impact**: The first block region was dropped, corrupting calculated rescued byte counts.
* **Affected Methods**: Method 24 (Damaged Media Recovery).
* **Fix**: Differentiated 2-token status headers from 3-token region lines.
* **Test Required**: `tests/test_raid_and_forensic.py::TestForensicAndSpecializedAdapters::test_ddrescue_mapfile_parser`.

---

### BUG-06: Duplicate Inode Dirent Collisions in exFAT Scan Results
* **ID**: `BUG-06`
* **File**: `backend_adapters.py` (Lines 70–140)
* **Function**: `parse_fls_output()`, `parse_scan_result()`
* **Severity**: `LOW`
* **Problem**: exFAT directory tables with duplicate dirent references created duplicate candidates with identical candidate IDs.
* **Runtime Impact**: Potential candidate list corruption or duplicate extraction attempts.
* **Affected Methods**: Methods 17, 18, 19, 25.
* **Fix**: Added `seen_ids` deduplication set in parsers.
* **Test Required**: `tests/test_edge_cases.py::TestEdgeCases::test_parse_scan_result_duplicate_ids_deduplicated`.
