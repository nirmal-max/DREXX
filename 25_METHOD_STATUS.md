# DREXX 25-Method Technical & Capability Status Matrix

**Last updated**: 2026-09-11 — Final Validation Phase complete.

This document provides the authoritative technical reference for all 25 sanitization, erasure, and recovery methods in DREXX.

---

## Backends Detected (`python drex_app.py --doctor`)

| Backend | Status | Executable | Source |
|---------|--------|-----------|--------|
| TestDisk 7.2 | ✅ INSTALLED | `native_bin/testdisk_win.exe` | cgsecurity.org official Win64 release |
| PhotoRec 7.2 | ✅ INSTALLED | `native_bin/photorec_win.exe` | cgsecurity.org (bundled with TestDisk) |
| The Sleuth Kit 4.15.0 | ✅ INSTALLED | `native_bin/fls.exe` | github.com/sleuthkit/sleuthkit official Win32 release |
| GNU ddrescue | ❌ NOT AVAILABLE | — | No official Windows build; Linux-native tool |
| Autopsy | ❌ NOT INSTALLED | — | Requires separate full installer |

---

## End-to-End Recovery Test Results

**Test image**: `native_bin/drex_test.img` — 64MiB FAT32 volume  
**Test executed**: `python tests/create_test_image.py`  
**Result**: **6/6 PASS — All file hashes match baseline**

| File | Baseline SHA-256 | Recovery Status | Hash Match |
|------|-----------------|-----------------|------------|
| `DREX_TEST/file1.txt` | `330F9A2F4BCC70EE…` | ✅ Recovered | ✅ MATCH |
| `DREX_TEST/report.pdf` | `C7C83AECAF35449A…` | ✅ Recovered | ✅ MATCH |
| `DREX_TEST/image.jpg` | `7ED662A66FA99214…` | ✅ Recovered | ✅ MATCH |
| `DREX_TEST/PROJECT/main.cpp` | `05850BCA022DD2D9…` | ✅ Recovered | ✅ MATCH |
| `DREX_TEST/PROJECT/README.txt` | `ACA93A165FFC339A…` | ✅ Recovered | ✅ MATCH |
| `DREX_TEST/DATA/database.db` | `A897873792E1AE19…` | ✅ Recovered | ✅ MATCH |

**fls deleted-file entries found**: 6/6  
**tsk_recover files extracted**: 6/6  
**Directory hierarchy preserved**: Yes (`PROJECT/` folder structure intact)  
**Source image modified**: No (read-only during recovery)

---

## I. Drive Erasure (7 Methods)

| # | Method ID | Display Name | Standard / Assurance | Component / Path | Status |
|---|-----------|--------------|----------------------|------------------|--------|
| 1 | `nist` | NIST SP 800-88 Rev.2 | NIST Clear / Purge | `methods/Drive Erasure/nist_sp_800_88r2_v2.1.0` | ✅ IMPLEMENTED — HARDWARE VALIDATION PENDING |
| 2 | `smart` | Smart Sanitization | Multi-tier Safety Evaluation | `methods/Drive Erasure/smart_sanitization_v2.1.0` | ✅ IMPLEMENTED — HARDWARE VALIDATION PENDING |
| 3 | `native` | Device-Native Sanitize | Controller-Level Purge | `methods/Drive Erasure/device_native_sanitize_v2.1.0` | ✅ IMPLEMENTED — HARDWARE VALIDATION PENDING |
| 4 | `ata` | ATA Secure Erase | ATA Standard Command Set | `methods/Drive Erasure/ata_secure_erase_v2.1.0` | ✅ IMPLEMENTED — HARDWARE VALIDATION PENDING |
| 5 | `nvme` | NVMe Secure Erase | NVMe Format / Sanitize | `methods/Drive Erasure/nvme_secure_erase_v2.1.0` | ✅ IMPLEMENTED — HARDWARE VALIDATION PENDING |
| 6 | `ieee` | IEEE 2883 Purge | Technology-Aware Purge | `methods/Drive Erasure/ieee_2883_purge_v2.1.0` | ✅ IMPLEMENTED — HARDWARE VALIDATION PENDING |
| 7 | `overwrite` | Verified Overwrite | Multi-pass Overwrite | `methods/Drive Erasure/verified_overwrite_v2.1.0` | ✅ IMPLEMENTED — HARDWARE VALIDATION PENDING |

> **Note on Hardware Validation Pending**: Drive erasure methods require admin privileges + a disposable physical drive or VHD (diskpart requires admin). The code path is implemented and unit-tested. Real execution is blocked without a disposable drive and admin elevation.

---

## II. File & Folder Erasure (9 Methods)

| # | Method ID | Display Name | Technical Description | Status |
|---|-----------|--------------|-----------------------|--------|
| 8 | `csprng` | CSPRNG Random Overwrite | Cryptographically secure random pattern overwrite | ✅ IMPLEMENTED |
| 9 | `crypto` | Cryptographic Erasure | Envelope key destruction | ✅ IMPLEMENTED |
| 10 | `slack` | File Slack / Cluster-Tip | Cluster tail sanitization | ✅ IMPLEMENTED |
| 11 | `metadata` | Filesystem Metadata Sanitization | OS metadata scrub | ✅ IMPLEMENTED |
| 12 | `policy` | NIST SP 800-88 Policy Engine | Policy-guided sanitization | ✅ IMPLEMENTED |
| 13 | `free_space` | Secure Free-Space Wiping | Unallocated space filler | ✅ IMPLEMENTED |
| 14 | `zero` | Single-Pass Zero Overwrite | Direct zero overwrite & verify | ✅ IMPLEMENTED |
| 15 | `storage_aware` | Storage-Aware Sanitization | Device-aware execution & fallback | ✅ IMPLEMENTED |
| 16 | `temporary` | Temporary / Cache Sanitization | Secure temp & artifact removal | ✅ IMPLEMENTED |

---

## III. Recovery Methods (9 Methods)

| # | Method ID | Display Name | Backend | Executables | Real Execution | Status |
|---|-----------|--------------|---------|-------------|---------------|--------|
| 17 | `quick` | Quick Recovery | TestDisk 7.2 / PhotoRec 7.2 | `testdisk_win.exe`, `photorec_win.exe` | ✅ Detected | ✅ BACKEND INSTALLED |
| 18 | `smart` | Smart Recovery | TSK 4.15.0 + PhotoRec 7.2 | `fls.exe`, `photorec_win.exe` | ✅ Detected | ✅ BACKEND INSTALLED |
| 19 | `targeted` | Targeted Recovery | PhotoRec 7.2 + TSK | `photorec_win.exe`, `fls.exe` | ✅ Detected | ✅ BACKEND INSTALLED |
| 20 | `filesystem` | Filesystem Recovery | TSK 4.15.0 | `fls.exe`, `fsstat.exe` | ✅ **REAL EXECUTION VERIFIED** | ✅ **PASS** |
| 21 | `deep` | Deep Recovery | PhotoRec 7.2 | `photorec_win.exe` | ✅ Detected | ✅ BACKEND INSTALLED |
| 22 | `fragment` | Fragment Recovery | PhotoRec 7.2 | `photorec_win.exe` | ✅ Detected | ✅ BACKEND INSTALLED |
| 23 | `raid` | Storage / RAID Recovery | TSK + TestDisk | `fls.exe`, `testdisk_win.exe` | ✅ Detected | ✅ BACKEND INSTALLED |
| 24 | `damaged` | Damaged Media Recovery | GNU ddrescue | — | ❌ Not available on Windows | `BACKEND UNAVAILABLE` |
| 25 | `forensic` | Forensic Recovery | TSK 4.15.0 | `fls.exe`, `icat.exe`, `tsk_recover.exe` | ✅ **REAL EXECUTION VERIFIED** | ✅ **PASS** |

### Method 20 & 25 — Real Execution Evidence

**`fls -r -d -f fat32 drex_test.img`** output:
```
r/r * 22:    DREX_TEST/file1.txt
r/r * 24:    DREX_TEST/report.pdf
r/r * 26:    DREX_TEST/image.jpg
r/r * 86:    DREX_TEST/PROJECT/main.cpp
r/r * 88:    DREX_TEST/PROJECT/README.txt
r/r * 134:   DREX_TEST/DATA/database.db
```

**`tsk_recover -f fat32 -e drex_test.img <outdir>`** result: **Files Recovered: 6**

**`fsstat -f fat32 drex_test.img`**: File System Type: FAT32 — confirmed operational.

---

## IV. Capability Reporting & Security Contracts

1. **Strict Fail-Closed Architecture**: A method or backend is never reported as available simply because code or directories exist. Executables are detected dynamically in `native_bin`, `third_party/`, or system PATH.
2. **Tamper-Evident Certificates**: Every completed erasure and recovery operation generates an offline-verifiable certificate signed with **ECDSA P-256 / SHA-256** and verifiable via QR code and JSON/PDF verification tools.
3. **Safety Protection**: Volume roots (`C:\`), Windows system directories (`System32`, `WinSxS`, `Program Files`), and the DREXX application directory are protected from destructive operations.
4. **Source Read-Only Guarantee**: Recovery operations open source images in read-only mode. The test image was confirmed unmodified by recovery operations.
5. **ddrescue unavailability**: GNU ddrescue has no official Windows build. Method 24 (Damaged Media Recovery) reports `BACKEND UNAVAILABLE` on Windows. This is factual, not a limitation of the DREX implementation.

---

## V. Test Suite Results

```
81 passed in 5.31s
```

All 81 automated tests passing as of 2026-09-11. Tests cover:
- All 25 method definitions
- Backend detection (fail-closed)
- TSK fls output parsing (attribute IDs, folder flags)
- Recovery state machine transitions
- Folder tree reconstruction
- SHA-256 certificate generation
