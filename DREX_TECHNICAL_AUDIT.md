# DREXX Technical Audit & Bug Inventory

This document records the comprehensive technical audit of the DREXX repository across all 25 methods, architecture layers, security boundaries, and external tool integrations.

---

## I. Bug & Architectural Gap Inventory

### BUG-001: Missing Explicit RecoveryTarget Abstraction
- **File**: `recovery_adapter.py` / `drex_app.py`
- **Component**: Recovery Architecture
- **Problem**: Recovery targets were passed as raw strings without distinguishing target kinds (file, folder, nested folder, disk image, partition, physical device) or enforcing read-only constraints.
- **Root Cause**: Early prototypes assumed all sources were either raw paths or `\\.\PhysicalDriveN`.
- **Impact**: Inability to properly handle disk image files vs directory trees vs physical drives with specific read-only guards.
- **Required Fix**: Implement a comprehensive `RecoveryTarget` dataclass with `TargetKind` enum (`FILE`, `FOLDER`, `DISK_IMAGE`, `PARTITION`, `PHYSICAL_DEVICE`), read-only validation, and source/destination collision prevention.
- **Status**: FIXED

---

### BUG-002: Incomplete Directory Tree Reconstruction in Folder Recovery
- **File**: `backend_adapters.py` / `recovery_adapter.py`
- **Component**: Recovery Engine
- **Problem**: Folder recovery was flatly extracting candidates or passing single inodes without preserving relative subfolder directory hierarchies.
- **Root Cause**: Parsers did not retain parent directory mappings from recursive `fls -r` output or construct nested directory paths on extraction.
- **Impact**: Files in subfolders were flattened into destination root or lacked parent directory structure.
- **Required Fix**: Parse full relative directory paths from `fls -r -p` output and reconstruct complete folder hierarchies on disk during recovery.
- **Status**: FIXED

---

### BUG-003: Fragment Recovery File Type Decoupling
- **File**: `recovery_adapter.py`
- **Component**: Fragment Recovery Module
- **Problem**: `FragmentRecoveryAdapter` threw an exception in `scan_command` without receiving the user's selected file type (`pdf`, `jpeg`, `png`, `zip`).
- **Root Cause**: File type parameter was not piped through the adapter interface.
- **Impact**: Fragment recovery scan failed immediately.
- **Required Fix**: Accept `file_type` in `FragmentRecoveryAdapter` and validate against supported formats (`pdf`, `jpeg`, `png`, `zip`).
- **Status**: FIXED

---

### BUG-004: Lack of Centralized Safe Process Runner with Process Group Cancellation
- **File**: `recovery_adapter.py` / `backend_adapters.py`
- **Component**: Execution Engine
- **Problem**: Subprocesses were started individually without centralized timeout handling, cancellation polling, or stdout/stderr buffering.
- **Root Cause**: Ad-hoc `subprocess.Popen` in multiple functions.
- **Impact**: Risk of orphaned processes on timeout/cancellation or deadlocks on large stdout streams.
- **Required Fix**: Implement `CentralProcessRunner` providing argument arrays, timeout enforcement, non-blocking polling, process tree termination, and structured execution logs.
- **Status**: FIXED

---

### BUG-005: Sector vs Byte Offset Unit Ambiguity
- **File**: `backend_adapters.py`
- **Component**: Forensic / Partition Offsets
- **Problem**: TSK `mmls` outputs sector offsets (512-byte units) while filesystem callers often supply byte offsets.
- **Root Cause**: Missing explicit conversion functions between sectors and bytes.
- **Impact**: Incorrect `-o` arguments passed to `fls`, `icat`, or `fsstat`.
- **Required Fix**: Create `sector_to_bytes()` and `bytes_to_sectors()` conversion utilities with configurable sector size (512, 4096).
- **Status**: FIXED

---

### BUG-006: Missing Recovery Lifecycle State Machine
- **File**: `recovery_adapter.py` / `drex_app.py`
- **Component**: UI & Engine State Synchronization
- **Problem**: Recovery operations transitioned informally between string labels rather than a well-defined state machine.
- **Root Cause**: Direct status string assignments in UI handlers.
- **Impact**: Inconsistent UI button states and progress indicators during complex workflows.
- **Required Fix**: Implement `RecoveryState` enum (`IDLE`, `DISCOVERING`, `SCANNING`, `CANDIDATES_FOUND`, `READY_TO_RECOVER`, `RECOVERING`, `VERIFYING`, `RECOVERED`, `PARTIAL`, `FAILED`, `CANCELLED`, `TIMEOUT`).
- **Status**: FIXED

---

### BUG-007: Misplaced GitHub Actions CI Workflows
- **File**: `methods/.github/workflows/`
- **Component**: CI / CD Infrastructure
- **Problem**: Workflows were nested under `methods/.github/workflows/` instead of `.github/workflows/` at the repository root.
- **Root Cause**: Repository restructuring misplaced the `.github` directory.
- **Impact**: GitHub Actions would not trigger automatically on repository push.
- **Required Fix**: Move all workflows to `.github/workflows/` at repository root.
- **Status**: FIXED

---

### BUG-008: Pytest Collection and PYTHONPATH Resolution
- **File**: `pytest.ini`
- **Component**: Test Infrastructure
- **Problem**: Pytest failed to resolve top-level modules when run from different directories without `pythonpath = .`.
- **Root Cause**: Missing `pythonpath` directive in `pytest.ini`.
- **Impact**: Module import errors during automated test discovery.
- **Required Fix**: Add `pythonpath = .` and `testpaths = tests` to `pytest.ini`.
- **Status**: FIXED

---

## II. 25-Method Architecture Verification Matrix

Every method has been audited against its implementation file, entry point, backend dependency, real execution path, and fail-closed safety:

| # | Method | Domain | Entry Point / Path | Backend | Status |
|---|--------|--------|-------------------|---------|--------|
| 1 | NIST SP 800-88 Rev.2 | Drive | `methods/Drive Erasure/nist_sp_800_88r2_v2.1.0` | Policy / Native Dispatch | PASS (Policy Engine) / HW Qualified |
| 2 | Smart Sanitization | Drive | `methods/Drive Erasure/smart_sanitization_v2.1.0` | Decision Engine | PASS (Decision Engine) / HW Qualified |
| 3 | Device-Native Sanitize | Drive | `methods/Drive Erasure/device_native_sanitize_v2.1.0` | Native Controller | HW Qualified / Fail-Closed |
| 4 | ATA Secure Erase | Drive | `methods/Drive Erasure/ata_secure_erase_v2.1.0` | ATA Controller | HW Qualified / Fail-Closed |
| 5 | NVMe Secure Erase | Drive | `methods/Drive Erasure/nvme_secure_erase_v2.1.0` | NVMe Controller | HW Qualified / Fail-Closed |
| 6 | IEEE 2883 Purge | Drive | `methods/Drive Erasure/ieee_2883_purge_v2.1.0` | IEEE Policy Engine | PASS (Policy Engine) / HW Qualified |
| 7 | Verified Overwrite | Drive | `methods/Drive Erasure/verified_overwrite_v2.1.0` | Direct Overwrite Engine | PASS — REAL EXECUTION VERIFIED |
| 8 | CSPRNG Random Overwrite | File | `methods/File-Folder Erasure/CSPRNG_Random_Overwrite_Production_Component_v0.1.0` | OS CSPRNG (`secrets`) | PASS — REAL EXECUTION VERIFIED |
| 9 | Cryptographic Erasure | File | `methods/File-Folder Erasure/Cryptographic_Erasure_Sanitization_Production_Component_v0.1.0` | AES-256 Key Store | PASS — REAL EXECUTION VERIFIED |
| 10 | File Slack / Cluster-Tip | File | `methods/File-Folder Erasure/File_Slack_Cluster_Tip_Sanitization_Production_Component_v0.1.0` | Cluster Sanitizer | PASS (Synthetic Backend) / Host Qualified |
| 11 | Filesystem Metadata | File | `methods/File-Folder Erasure/Filesystem Metadata Sanitization Standalone` | Metadata Sanitizer | PASS — REAL EXECUTION VERIFIED |
| 12 | NIST SP 800-88 Policy Engine | File | `methods/File-Folder Erasure/NIST_SP_800_88_Sanitization_Policy_Engine_v0.1.0` | NIST Policy Engine | PASS — REAL EXECUTION VERIFIED |
| 13 | Secure Free Space Wiping | File | `methods/File-Folder Erasure/Secure_Free_Space_Wiping_Production_Component_v0.1.0` | Free Space Wiper | PASS — REAL EXECUTION VERIFIED |
| 14 | Single-Pass Zero Overwrite | File | `methods/File-Folder Erasure/Single-Pass_Zero_Overwrite_Production_Component_v0.1.0` | Zero Overwrite Engine | PASS — REAL EXECUTION VERIFIED |
| 15 | Storage-Aware Sanitization | File | `methods/File-Folder Erasure/Storage_Aware_Sanitization_Fallback_Production_Component_v0.1.0` | Storage Aware Engine | PASS — REAL EXECUTION VERIFIED |
| 16 | Temporary / Cache Sanitization | File | `methods/File-Folder Erasure/Temporary_Cache_Residual_Trace_Sanitization_Production_Component_v0.1.0` | Trace Sanitizer | PASS — REAL EXECUTION VERIFIED |
| 17 | Quick Recovery | Recovery | `methods/Recovery/Module1_Quick_Recovery_Production_Baseline_v0.1.0` | TSK / PhotoRec / Native | BACKEND UNAVAILABLE (Host missing binaries) |
| 18 | Smart Recovery | Recovery | `methods/Recovery/Module2_Smart_Recovery_Production_Baseline_v0.1.0` | TSK / PhotoRec / Native | BACKEND UNAVAILABLE (Host missing binaries) |
| 19 | Targeted Recovery | Recovery | `methods/Recovery/Module3_Targeted_Recovery_Production_Baseline_v0.1.0` | PhotoRec / TSK / Native | BACKEND UNAVAILABLE (Host missing binaries) |
| 20 | Filesystem Recovery | Recovery | `methods/Recovery/Module4_Filesystem_Recovery_Production_Baseline_v0.1.0` | TSK (`fls`/`fsstat`/`tsk_recover`) | BACKEND UNAVAILABLE (Host missing binaries) |
| 21 | Deep Recovery | Recovery | `methods/Recovery/Module5_Deep_Recovery_Production_Baseline_v0.1.0` | PhotoRec / Native | BACKEND UNAVAILABLE (Host missing binaries) |
| 22 | Fragment Recovery | Recovery | `methods/Recovery/Module6_Fragment_Recovery_Production_Baseline_v0.1.0` | PhotoRec / Native | BACKEND UNAVAILABLE (Host missing binaries) |
| 23 | Storage / RAID Recovery | Recovery | `methods/Recovery/Module7_Storage_RAID_Recovery_Production_Baseline_v0.1.0` | TSK / TestDisk / Native | BACKEND UNAVAILABLE (Host missing binaries) |
| 24 | Damaged Media Recovery | Recovery | `methods/Recovery/Module8_Damaged_Media_Recovery_Production_Baseline_v0.1.0` | GNU ddrescue / Native | BACKEND UNAVAILABLE (Host missing binaries) |
| 25 | Forensic Recovery | Recovery | `methods/Recovery/Module9_Forensic_Recovery_Production_Baseline_v0.1.0` | TSK / Autopsy / Native | BACKEND UNAVAILABLE (Host missing binaries) |
