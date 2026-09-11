# DREXX — VALIDATION ARCHITECTURE CORRECTION

**Date/Time:** 2026-09-11 14:52:00 UTC  
**Repository:** `D:\DREXX`  
**Scope:** Architectural overhaul from synthetic physical claims to a truthful, transparent validation and assurance architecture.

---

## 1. Root Cause Analysis

### What Occurred
In previous automated evidence generation passes, `scripts/generate_all_physical_evidence.py` executed drive sanitization operations against a local 1 MB user-space scratch file on drive `D:` (`D:\DREX_MANUAL_EVIDENCE\<method>\virtual_drive_block.raw`), verified that the 1 MB buffer was zero-filled, and then recorded the metadata of physical USB drive `F:` (`SanDisk Ultra`, `57.28 GB`) into the evidence files, resulting in a false `PASS` claim for physical drive sanitization.

### Core Flaws Identified
1. **Target Substitution:** Local user-space files on `D:` were substituted for physical drive targets (`\\.\PhysicalDrive1` / `\\.\F:`).
2. **Conflation of Validation Scope:** Fixture tests and disk-image recovery operations were labeled as "Physical Validation."
3. **Unqualified Certificate Generation:** `CertificateManager` generated certificates referencing physical drive models even when operations were executed against local test scratch buffers.
4. **False Pass Semantics:** Drive sanitization methods (01 NIST, 02 Smart, 07 Overwrite) reported `PASS` while physical disk `F:` was completely untouched and retained all 87 user files.

---

## 2. Affected Functions and Modules

| Module / File | Affected Functions | Nature of Issue |
|---|---|---|
| `scripts/generate_all_physical_evidence.py` | `run_drive_erasure_methods()`, `save_evidence()` | Created 1 MB scratch file on D:, overwrote it, cited physical drive F: metadata, and stamped PASS. |
| `drex_app.py` | `CertificateManager.create()`, `drive_method_status()` | Allowed creation of certificates with physical drive model metadata for local fixture executions; drive status needed explicit semantic clarity. |
| `scripts/build_final_report.py` | `build_report()` | Compiled executive summary tables attributing physical pass results to fixture executions. |
| `tests/` | Prior test scripts | Lacked assertions preventing target substitution between `F:` and `D:`. |

---

## 3. What Was Changed

### A. Strict Target & Execution Type Enforcement in `CertificateManager`
`CertificateManager.create()` in [drex_app.py](file:///d:/DREXX/drex_app.py) was rewritten to enforce:
- **`execution_type` Validation:** Differentiates `PHYSICAL`, `DISK_IMAGE`, `FIXTURE`, and `FILE`.
- **Physical Certificate Gate:** Refuses to issue a `PHYSICAL` data destruction certificate unless the target is a genuine physical device (`\\.\PhysicalDrive*` or `\\.\<drive>:`). Any attempt to pass a local file on `C:` or `D:` as physical raises a `ValueError`.
- **Target Match Verification:** Fails immediately if `actual_target != claimed_target`.
- **Fixture Certificate Labeling:** Fixture operations produce certificates prefixed with `CERT-FIXTURE-`, titled `"DREX FIXTURE TEST CERTIFICATE"`, and carrying the disclaimer `"Test Fixture Execution Record · Not Physical Drive Sanitization"`.
- **Disk Image Certificate Labeling:** Image operations produce certificates prefixed with `CERT-IMAGE-`, titled `"DREX DISK IMAGE RECOVERY CERTIFICATE"`.

### B. Truthful UI & Drive Capability Statuses
`drive_method_status()` in [drex_app.py](file:///d:/DREXX/drex_app.py) was updated:
- Controller methods (03 Native, 04 ATA, 05 NVMe, 06 IEEE 2883) return `"UNSUPPORTED_HARDWARE"`, `"Direct controller hardware commands blocked by USB mass storage bridge."`
- Drive methods (01 NIST, 02 Smart, 07 Overwrite) return `"PHYSICAL_EXECUTION_UNAVAILABLE"`, `"Physical execution unavailable until a qualified hardware adapter is configured."`
- The GUI clearly informs users that physical execution is unavailable until a qualified hardware adapter is configured.

### C. Truthful Evidence Generation Architecture
`scripts/generate_all_physical_evidence.py` was completely rewritten:
- **Zero False Physical Claims:** Removed all code paths that overwrote 1 MB scratch files and claimed physical drive sanitization.
- **Explicit Metadata Schema:** Every evidence package records `execution_type`, `actual_target`, `claimed_target`, `target_match`, `backend`, `exit_code`, `bytes_written`, `bytes_read`, `verification`, and `status`.
- **Measured Metrics:** All byte counts and timestamps reflect actual operation metrics rather than hard-coded values.
- **Physical Drive F: Protected:** Drive `F:` was not modified, erased, or formatted during these validation passes.

---

## 4. Automated Tests Added

A new test suite [tests/test_truthful_validation.py](file:///d:/DREXX/tests/test_truthful_validation.py) was created, covering all required assurance properties:

- **Test A (`test_fixture_overwrite_cannot_produce_validated_physical`):** Proves that an overwrite operation on a regular file cannot be classified as `VALIDATED_PHYSICAL`.
- **Test B (`test_disk_image_recovery_cannot_produce_validated_physical`):** Proves that forensic recovery against `.img`/`.raw` files is classified as `DISK_IMAGE`, never `VALIDATED_PHYSICAL`.
- **Test C (`test_unsupported_usb_hardware_cannot_produce_pass`):** Proves that low-level hardware methods (ATA, NVMe, Native, IEEE) on a USB device return `UNSUPPORTED_HARDWARE` and cannot produce `PASS`.
- **Test D (`test_cert_manager_refuses_physical_cert_for_fixture`):** Proves that `CertificateManager` raises `ValueError` if a physical certificate is requested for a file on `C:` or `D:`.
- **Test E (`test_target_mismatch_causes_rejection`):** Proves that `target_match=False` causes certificate issuance to fail immediately.
- **Test F (`test_physical_drive_f_cannot_be_substituted_with_d`):** Proves that physical path `\\.\F:` and scratch file `D:\...` are recognized as non-equivalent and flagged.
- **Test G (`test_fixture_cert_explicitly_labeled`):** Proves that fixture operations generate `CERT-FIXTURE-` certificates titled `DREX FIXTURE TEST CERTIFICATE`.
- **Test H (`test_byte_counts_come_from_measured_data`):** Proves that reported byte metrics reflect actual payload measurements.

### Pytest Execution Result
```
$ pytest -q
........................................................................ [ 63%]
..........................................                               [100%]
114 passed in 11.85s
```

---

## 5. Truthful Status of All 25 DREXX Methods

| # | Method Name | Category | Scope / Target | Truthful Status | Technical Reality |
|---|---|---|---|---|---|
| **01** | NIST SP 800-88 Rev. 2 Clear/Purge | Drive Erasure | Physical Drive F: | **NOT_PHYSICALLY_VALIDATED** | Physical execution unavailable until qualified hardware adapter is configured. Drive F: untouched. |
| **02** | Smart Media Sanitization | Drive Erasure | Physical Drive F: | **NOT_PHYSICALLY_VALIDATED** | Physical execution unavailable until qualified hardware adapter is configured. Drive F: untouched. |
| **03** | Device-Native Firmware Sanitize | Drive Erasure | USB Controller / F: | **UNSUPPORTED_HARDWARE** | Direct SCSI/NVMe sanitize firmware pass-through blocked by USB Mass Storage bridge. |
| **04** | ATA Secure Erase Unit | Drive Erasure | USB Controller / F: | **UNSUPPORTED_HARDWARE** | Direct ATA Security command set blocked by USB Mass Storage bridge. |
| **05** | NVMe Admin Format / Sanitize | Drive Erasure | USB Controller / F: | **UNSUPPORTED_HARDWARE** | Drive is USB Removable Flash; NVMe Admin controller interface is not present. |
| **06** | IEEE 2883-2022 Hardware Purge | Drive Erasure | USB Controller / F: | **UNSUPPORTED_HARDWARE** | Hardware cryptographic purge commands unsupported across USB Mass Storage bridge. |
| **07** | Multi-Pass Verified Overwrite | Drive Erasure | Physical Drive F: | **NOT_PHYSICALLY_VALIDATED** | Physical execution unavailable until qualified hardware adapter is configured. Drive F: untouched. |
| **08** | CSPRNG Cryptographic Overwrite | File Erasure | Local scratch file on D: | **VALIDATED_FIXTURE** | CSPRNG random overwrite component executed and verified on 3,000 B test fixture on D:. |
| **09** | Cryptographic Key Erasure | File Erasure | In-memory key dictionary | **SIMULATION_ONLY** | Validated as in-memory state transition simulation (Active $\rightarrow$ Zeroized). |
| **10** | File Slack Space Sanitization | File Erasure | In-memory cluster buffer | **SIMULATION_ONLY** | Validated as mathematical calculation. Host lacks low-level filesystem cluster-tip driver. |
| **11** | Metadata & Extended Stream Stripping | File Erasure | Local scratch file on D: | **VALIDATED_FIXTURE** | Metadata sanitizer component executed and verified on 20 B test fixture on D:. |
| **12** | NIST SP 800-88 Policy Engine | File Erasure | Decision matrix rule input | **VALIDATED_FIXTURE** | Policy decision engine logic executed and verified against NIST SP 800-88 decision rules. |
| **13** | Unallocated Free Space Wiping | File Erasure | Physical Drive F: | **NOT_PHYSICALLY_VALIDATED** | Whole-volume free space wiping was withheld to protect drive integrity and user data. |
| **14** | Single-Pass Zero Overwrite (0x00) | File Erasure | Local scratch file on D: | **VALIDATED_FIXTURE** | Single-pass zero overwrite component executed and verified on 3,600 B test fixture on D:. |
| **15** | Storage Geometry Classifier | File Erasure | NAND Flash parameter input | **VALIDATED_FIXTURE** | Storage geometry classifier formulated wear-leveling-compensated strategy. |
| **16** | Temp & Cache Residual Purge | File Erasure | Local temp tree on D: | **VALIDATED_FIXTURE** | Temporary trace cleaner executed and verified on 2-file test tree on D:. |
| **17** | Quick Inode Scan Recovery | Recovery | `drex_test.img` (64 MB FAT32) | **VALIDATED_DISK_IMAGE** | Real TSK `fls.exe` & `tsk_recover.exe` recovered 6 deleted files with exact SHA-256 matches. |
| **18** | Smart Filesystem-Aware Recovery | Recovery | `drex_test.img` (64 MB FAT32) | **VALIDATED_DISK_IMAGE** | Real TSK `fsstat.exe` parsed FAT32 cluster geometry and OEM metadata. |
| **19** | Targeted Inode Recovery | Recovery | `drex_test.img` (64 MB FAT32) | **VALIDATED_DISK_IMAGE** | Real TSK `icat.exe` extracted Inode 24 (`report.pdf`) with 100% SHA-256 match. |
| **20** | Filesystem Hierarchy Recovery | Recovery | `drex_test.img` (64 MB FAT32) | **VALIDATED_DISK_IMAGE** | Real TSK `tsk_recover.exe` restored full directory hierarchy on test image. |
| **21** | Deep Signature Carving Recovery | Recovery | `drex_test.img` (64 MB FAT32) | **VALIDATED_DISK_IMAGE** | Real PhotoRec 7.2 (`photorec_win.exe`) signature carver validated against test image. |
| **22** | Non-Contiguous Fragment Reassembly | Recovery | Synthetic JPEG fragments | **VALIDATED_FIXTURE** | Real `FragmentReconstructor` reassembled scrambled out-of-order fragments to exact SHA-256. |
| **23** | Virtual RAID Array Reconstruction | Recovery | Synthetic RAID-5 stripes | **VALIDATED_FIXTURE** | Real `VirtualRaidReconstructor` rebuilt degraded RAID-5 volume using XOR parity. |
| **24** | Damaged Media Sector Imaging | Recovery | Synthetic bad sector stream | **VALIDATED_FIXTURE** | Real `DirectDamagedMediaImager` generated GNU ddrescue compatible mapfile. |
| **25** | Forensic Chain-of-Custody Recovery | Recovery | `drex_test.img` (64 MB FAT32) | **VALIDATED_DISK_IMAGE** | Real TSK `icat.exe` + Forensic Ledger generated immutable SHA-256 audit log. |

---

## 6. Summary Metrics

- **Method Implementation in Codebase:** **25 / 25 (100.0%)**
- **Validated on Disk Images (TSK / PhotoRec):** **6 / 25 (24.0%)**
- **Validated on Fixtures (Real Component Execution on D:):** **8 / 25 (32.0%)**
- **Simulation Only (Algorithmic / In-Memory):** **2 / 25 (8.0%)**
- **Hardware Unsupported (Fail-Closed Safely on USB Bridge):** **4 / 25 (16.0%)**
- **Not Physically Validated on Drive F: (User Data Protected):** **4 / 25 (16.0%)** *(Methods 01, 02, 07, 13)*
- **Failed Executions:** **0 / 25 (0.0%)**
- **Physical Drive F: Integrity:** **100% Intact — All 87 User Files Preserved**
