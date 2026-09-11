# DREXX Authoritative 25-Method Validation Matrix

This document provides the definitive verification matrix for all 25 sanitization and recovery capabilities in DREXX.
All 25 requested methods are implemented, with validation status explicitly classified according to actual execution evidence.

---

## 25-Method Empirical Validation Matrix

| # | Method Name | Category | Backend | Test Target | Actual Execution & Evidence | Verification | Final Status | Limitations / Platform Reality |
| :---: | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | NIST SP 800-88 Rev.2 Clear/Purge | Drive Sanitization | Storage IOCTL / Bus Sanitize | Physical Drives | Gated by hardware controller interface | Fail-closed | `PHYSICAL_EXECUTION_UNAVAILABLE` | Consumer USB bridges do not pass through vendor ATA/NVMe sanitize IOCTLs. |
| **2** | Smart Sanitization | Drive Sanitization | Media Classifier + Engine Selector | Physical Drives | Fail-closed selection against test targets | Fail-closed | `NOT_PHYSICALLY_VALIDATED` | Whole-drive destructive testing omitted to prevent hardware corruption. |
| **3** | Device-Native Firmware Sanitize | Drive Sanitization | Native ATA/NVMe Sanitize Commands | Physical Drives | Gated by hardware capability detection | Fail-closed | `UNSUPPORTED_HARDWARE` | USB bridge intercepts native opcode dispatch. |
| **4** | ATA Secure Erase | Drive Sanitization | ATA Command Set (Security Erase) | Physical Drives | Gated by hardware controller | Fail-closed | `UNSUPPORTED_HARDWARE` | Requires direct SATA/AHCI controller attachment. |
| **5** | NVMe Secure Erase / Format | Drive Sanitization | NVMe Command Set (Format / Sanitize) | Physical Drives | Gated by NVMe controller | Fail-closed | `UNSUPPORTED_HARDWARE` | Requires PCIe / direct NVMe controller attachment. |
| **6** | IEEE 2883 Purge | Drive Sanitization | IEEE 2883 Compliant Primitives | Physical Drives | Gated by controller specification | Fail-closed | `UNSUPPORTED_HARDWARE` | Firmware compliance required. |
| **7** | Multi-Pass Verified Overwrite | Drive Sanitization | Multi-Pass Pattern Generator | Physical Drives | Gated to dedicated safe drives | Fail-closed | `NOT_PHYSICALLY_VALIDATED` | Full whole-drive overwrite omitted during safety audit. |
| **8** | CSPRNG Random Overwrite | File Sanitization | `secrets.token_bytes` / In-Process CSPRNG | Physical File on SanDisk F: (`test_csprng.dat`) | File content overwritten with CSPRNG entropy; verified bitwise; truncated to 0B; unlinked | `VERIFIED` | **PASS — REAL PHYSICAL FILE** | File-level overwrite; verified on physical SanDisk F: volume. |
| **9** | Cryptographic Erasure (File) | File Sanitization | AES Key Wrapping / Key Destruction | In-Memory Fixture Buffer | Simulation fixture encrypts buffer with ephemeral key and discards key | `VERIFIED` | **SIMULATION_ONLY** | In-memory key destruction model; full volume crypto-shred requires BitLocker/LUKS integration. |
| **10** | File Slack / Cluster Tip Purge | File Sanitization | Low-Level Cluster Boundary Zeroing | Synthetic Cluster Fixture Buffer | Algorithmic cluster slack truncation and zero padding | `VERIFIED` | **SIMULATION_ONLY** | In-memory cluster simulation; raw filesystem cluster access requires kernel driver on Windows. |
| **11** | Filesystem Metadata Sanitization | File Sanitization | Python `os.utime` / File Attribute Reset | Physical File on SanDisk F: (`test_meta.txt`) | Timestamps reset; attributes cleared; content preserved bit-for-bit | `VERIFIED` | **PASS — REAL PHYSICAL FILE** | Standard Win32 timestamp & attribute clearing. Low-level MFT record clearing requires raw disk write. |
| **12** | NIST SP 800-88 Policy Engine | Sanitization Policy | Policy Decision Matrix | Decision Fixture | Policy engine classifies media type (SSD/HDD/Removable) and selects valid policy | `VERIFIED` | **PASS — POLICY ENGINE** | Policy matrix evaluation engine. |
| **13** | Secure Free-Space Wiping | Sanitization | Temporary File Balloon Overwrite | Volume Free Space | Gated by whole-volume scope checks in GUI | Fail-closed | `NOT_PHYSICALLY_VALIDATED` | Operates on volume free space; folder-scoped execution disabled for safety. |
| **14** | Single-Pass Zero Overwrite | File Sanitization | Buffer Zero Fill (`\x00`) | Physical File on SanDisk F: (`test_zero.dat`) | File filled with `\x00`; verified bitwise; truncated to 0B; unlinked | `VERIFIED` | **PASS — REAL PHYSICAL FILE** | File-level overwrite; verified on physical SanDisk F: volume. |
| **15** | Storage-Aware Sanitization & Fallback | Sanitization Engine | Fallback Decision Tree | Media Classifier Fixtures | Storage-aware decision tree handles fallback across rotational/flash storage | `VERIFIED` | **PASS — REAL FIXTURE** | Classifier and fallback execution verified against simulated media fixtures. |
| **16** | Temporary & Cache Purge | File Sanitization | Recursive Safe Cleaner | Physical Directory on SanDisk F: (`test_temp_cache/`) | Recursively purges and unlinks 3 temporary cache files across 2 directories | `VERIFIED` | **PASS — REAL PHYSICAL FILE** | Physical directory tree cleaned and unlinked on SanDisk F:. |
| **17** | Quick Recovery | Data Recovery | The Sleuth Kit (`fls.exe` + `icat.exe`) | `native_bin/drex_test.img` (64MB FAT32) | Discovered 6 deleted candidates; extracted Inode 22 (`file1.txt`, 49B) with 100% SHA-256 match | `HASH_MATCH` | **PASS — REAL DISK IMAGE** | Requires supported filesystem structures. |
| **18** | Smart Recovery | Data Recovery | TSK (`fsstat.exe` + `fls.exe` + `icat.exe`) | `native_bin/drex_test.img` (64MB FAT32) | Geometry analysis parsed FAT32, 512B sectors, DREXTEST label; prioritized & extracted Inodes with 100% SHA-256 match | `HASH_MATCH` | **PASS — REAL DISK IMAGE** | Filesystem geometry analysis informs candidate ranking. |
| **19** | Targeted Inode Recovery | Data Recovery | TSK (`fls.exe` + `icat.exe`) | `native_bin/drex_test.img` (64MB FAT32) | Targeted exact Inode extraction of Inode 22 (`file1.txt`) via `CentralProcessRunner.binary_run()` | `HASH_MATCH` | **PASS — REAL DISK IMAGE** | Exact inode mapping recovery. |
| **20** | Filesystem Recovery | Data Recovery | TSK (`tsk_recover.exe`) | `native_bin/drex_test.img` (64MB FAT32) | Extracted complete directory tree (`file1.txt`, `image.jpg`, `report.pdf`) with exact SHA-256 hashes | `HASH_MATCH` | **PASS — REAL DISK IMAGE** | Preserves directory hierarchy. |
| **21** | Deep Recovery | Data Recovery | PhotoRec 7.2 (`photorec_win.exe`) | `native_bin/drex_test.img` (64MB FAT32) | PhotoRec 7.2.0.0 confirmed via PE FileVersionInfo; all subprocess invocation attempts in standard shell returned `[WinError 740]`; carved files = 0; source SHA-256 unchanged (`CED107EC…`). DREXX command builder and routing confirmed correct. Execution gated at OS loader. | `UAC_BLOCKED` | **EXECUTION_BLOCKED — UAC_ELEVATION_REQUIRED** | `photorec_win.exe` embeds Windows manifest `requestedExecutionLevel=highestAvailable`; all invocations from non-elevated shell return WinError 740. Run DREXX elevated (Run as Administrator) for actual carving. |
| **22** | Fragment Recovery | Data Recovery | DREXX `FragmentReconstructor` | Scrambled Out-of-Order JPEG/PDF Streams | Correctly reassembled `[p3, p1, p4, p2]` permutation with 100% SHA-256 match; naive concat differs | `HASH_MATCH` | **PASS — REAL FIXTURE** | Permutation reassembly algorithm for JPEG, PDF, PNG, ZIP. |
| **23** | Storage / RAID Recovery | Data Recovery | DREXX `VirtualRaidReconstructor` | Synthetic RAID 0, 1, 5, 10 Buffers | Recovered degraded RAID 5 array with missing disk via XOR parity reconstruction; 100% byte match | `HASH_MATCH` | **SIMULATION_ONLY** | In-memory synthetic RAID array reconstruction (Linux mdadm unavailable on Windows). |
| **24** | Damaged Media Recovery | Data Recovery | `DirectDamagedMediaImager` | Synthetic Bad Sector Buffer | Rescued 1,536 intact bytes, skipped bad block at sector 1, generated GNU ddrescue-compatible `.map` file | `VERIFIED` | **PASS — REAL FIXTURE** | Native fallback imager (GNU ddrescue physical executable unavailable on Windows). |
| **25** | Forensic Recovery | Data Recovery | TSK (`fls`+`icat`) + Forensic Ledger | `native_bin/drex_test.img` (64MB FAT32) | Extracted 3 files; generated `FORENSIC_EVIDENCE_LEDGER.json` with SHA-256 chain; verified intact PASS; tamper test detected corrupted entry FAIL | `HASH_MATCH` | **PASS — REAL DISK IMAGE** | Cryptographically chained, tamper-evident forensic evidence ledger. |

---

## Method Classification Summary

- **PASS — REAL PHYSICAL FILE (4 methods):** #8, #11, #14, #16
- **PASS — REAL DISK IMAGE (5 methods):** #17, #18, #19, #20, #25
- **PASS — REAL FIXTURE / ENGINE (3 methods):** #15, #22, #24
- **PASS — POLICY ENGINE (1 method):** #12
- **SIMULATION_ONLY (3 methods):** #9, #10, #23
- **UNSUPPORTED_HARDWARE (4 methods):** #3, #4, #5, #6
- **NOT_PHYSICALLY_VALIDATED / PHYSICAL_EXECUTION_UNAVAILABLE (4 methods):** #1, #2, #7, #13
- **EXECUTION_BLOCKED — UAC_ELEVATION_REQUIRED (1 method):** #21