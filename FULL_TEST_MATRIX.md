# DREXX Full Test Matrix

**Date**: 2026-09-11  
**Repository**: `D:\DREXX`  
**Test Suite**: `pytest -q` (98 automated tests across 9 test modules)

---

## Automated Test Modules Breakdown

| Module | Test Area | Tests | Status | Description |
| :--- | :--- | :--- | :--- | :--- |
| `tests/test_all_25_methods.py` | 25-Method Inventory & Execution | 12 | ✅ PASS | Method uniqueness, specs, file erasure execution, tamper-evident certificates |
| `tests/test_backend_adapters.py` | Command Construction & Upstream Flags | 22 | ✅ PASS | TSK, PhotoRec, TestDisk, ddrescue command builders and parsers |
| `tests/test_recovery_adapter.py` | Recovery Adapter Base & Dispatcher | 5 | ✅ PASS | Scan normalization, candidate parsing, fail-closed discovery |
| `tests/test_recovery_backends.py` | Backend Manifest & Discovery | 12 | ✅ PASS | Backend specifications, paths, licenses, prioritization |
| `tests/test_recovery_comprehensive.py` | End-to-End Recovery Scenarios | 14 | ✅ PASS | Image mounting, unallocated carving, cancellation, timeout |
| `tests/test_folder_recovery.py` | Folder Recovery Architecture | 5 | ✅ PASS | `RecoveryTarget(FOLDER)`, `reconstruct_folder_tree()`, nested hierarchy |
| `tests/test_edge_cases.py` | Boundary Conditions & Robustness | 8 | ✅ PASS | Zero-byte, 1-byte, Unicode filenames, read-only files, duplicate IDs |
| `tests/test_raid_and_forensic.py` | RAID, Forensic & Damaged Media | 4 | ✅ PASS | ddrescue mapfiles, mmls partitions, forensic icat command builders |
| `tests/test_app.py` | GUI & Core Application Flow | 16 | ✅ PASS | App startup, doctor, safety guards, device enumeration |

**Total Automated Tests**: 98 passed in 9.65s (100% pass rate)

---

## 25 Methods Detailed Test Coverage

| # | Method | Unit Test | Integration Test | Real / Physical Test | Verification Mechanism | Status |
|---|---|---|---|---|---|---|
| **1** | NIST SP 800-88 Rev.2 | `test_all_25_methods.py` | `run_sanitization_validation.py` | Decision Engine Run | Clear vs Purge rule evaluation | `PASS — DECISION ENGINE VERIFIED` |
| **2** | Smart Sanitization | `test_all_25_methods.py` | `run_sanitization_validation.py` | Decision Engine Run | Storage-aware evaluator | `PASS — DECISION ENGINE VERIFIED` |
| **3** | Device-Native Sanitize | `test_all_25_methods.py` | `drex_app.py` probe | Hardware Probe | Fail-closed check on USB bridge | `UNSUPPORTED` |
| **4** | ATA Secure Erase | `test_all_25_methods.py` | `drex_app.py` probe | Hardware Probe | Fail-closed check for ATA port | `UNSUPPORTED` |
| **5** | NVMe Secure Erase | `test_all_25_methods.py` | `drex_app.py` probe | Hardware Probe | Fail-closed check for NVMe IOCTL | `UNSUPPORTED` |
| **6** | IEEE 2883 Purge | `test_all_25_methods.py` | `run_sanitization_validation.py` | Policy Engine Run | IEEE 2883-2022 Section 5.3 check | `PASS — DECISION ENGINE VERIFIED` |
| **7** | Verified Overwrite | `test_all_25_methods.py` | `run_sanitization_validation.py` | 1MB 3-pass test target | Multi-pass write + readback | `PASS — REAL EXECUTION VERIFIED` |
| **8** | CSPRNG Random Overwrite | `test_all_25_methods.py` | `test_edge_cases.py` | Controlled file target | `os.urandom` stream + deletion | `PASS — REAL EXECUTION VERIFIED` |
| **9** | Cryptographic Erasure | `test_all_25_methods.py` | `run_sanitization_validation.py` | Key Lifecycle Run | Envelope key purge from memory | `PASS — SYNTHETIC BACKEND VERIFIED` |
| **10** | File Slack / Cluster-Tip | `test_all_25_methods.py` | `run_sanitization_validation.py` | Cluster-Tip Fill Run | Slack region zeroing verified | `PASS — SYNTHETIC BACKEND VERIFIED` |
| **11** | Metadata Sanitization | `test_all_25_methods.py` | `test_all_25_methods.py` | Controlled target | Timestamps neutralized & SHA-256 | `PASS — REAL EXECUTION VERIFIED` |
| **12** | NIST Policy Engine | `test_all_25_methods.py` | `run_sanitization_validation.py` | Rule matrix run | Media rule matching verified | `PASS — DECISION ENGINE VERIFIED` |
| **13** | Secure Free-Space Wiping | `test_all_25_methods.py` | `run_sanitization_validation.py` | 2MB unallocated fill | Zero filler write & reclaim | `PASS — REAL EXECUTION VERIFIED` |
| **14** | Single-Pass Zero Overwrite | `test_all_25_methods.py` | `test_edge_cases.py` | Directory tree target | Single-pass zero + deletion | `PASS — REAL EXECUTION VERIFIED` |
| **15** | Storage-Aware Fallback | `test_all_25_methods.py` | `run_sanitization_validation.py` | Fallback matrix run | Dynamic fallback evaluation | `PASS — DECISION ENGINE VERIFIED` |
| **16** | Temporary / Cache Sanitization | `test_all_25_methods.py` | `test_all_25_methods.py` | Temp cache target | Cache residue purged & verified | `PASS — REAL EXECUTION VERIFIED` |
| **17** | Quick Recovery | `test_recovery_comprehensive.py` | `test_backend_adapters.py` | Physical USB `F:` | `fls` discovery + `icat` recovery | `PASS — REAL EXECUTION VERIFIED` |
| **18** | Smart Recovery | `test_recovery_comprehensive.py` | `test_backend_adapters.py` | Physical USB `F:` | `fsstat` + `fls` + `tsk_recover` | `PASS — REAL EXECUTION VERIFIED` |
| **19** | Targeted Recovery | `test_backend_adapters.py` | `test_raid_and_forensic.py` | Physical USB `F:` | Inode 8470 extracted & PIL verified | `PASS — REAL EXECUTION VERIFIED` |
| **20** | Filesystem Recovery | `test_backend_adapters.py` | `test_folder_recovery.py` | Physical USB `F:` | `tsk_recover` assembly + dirs | `PASS — REAL EXECUTION VERIFIED` |
| **21** | Deep Recovery | `test_backend_adapters.py` | `test_recovery_comprehensive.py` | Physical USB `F:` | PhotoRec batch command check | `PARTIAL` |
| **22** | Fragment Recovery | `test_all_25_methods.py` | `test_backend_adapters.py` | Physical USB `F:` | PhotoRec carving command check | `PARTIAL` |
| **23** | RAID / Storage Recovery | `test_raid_and_forensic.py` | `test_backend_adapters.py` | Physical USB `F:` | Non-RAID single LUN check | `UNSUPPORTED` |
| **24** | Damaged Media Recovery | `test_raid_and_forensic.py` | `test_backend_adapters.py` | Missing binary check | ddrescue missing on Windows | `BACKEND UNAVAILABLE` |
| **25** | Forensic Recovery | `test_backend_adapters.py` | `test_raid_and_forensic.py` | Physical USB `F:` | `fls` + `icat` + SHA-256 ledger | `PASS — REAL EXECUTION VERIFIED` |
