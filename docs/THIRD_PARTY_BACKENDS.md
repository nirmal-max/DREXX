# DREXX Third-Party Backend Manifest & Integration Architecture

This document specifies the authoritative upstream open-source backends, native toolchains, platform availability, and execution mechanics integrated into DREXX.

---

## 1. Upstream Backends Specification

| Backend Name | Upstream Project | License | Platform Support | Bundled Executables (`native_bin/`) | Invocation Mechanism |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **The Sleuth Kit (TSK)** | [sleuthkit/sleuthkit](https://github.com/sleuthkit/sleuthkit) v4.15.0 | Mixed (CPL / IBM / GPL) | Windows (Cygwin/MinGW), Linux, macOS | `fls.exe`, `fsstat.exe`, `icat.exe`, `tsk_recover.exe`, `mmls.exe` | Subprocess via `CentralProcessRunner.run()` / `binary_run()` |
| **PhotoRec** | [cgsecurity/testdisk](https://github.com/cgsecurity/testdisk) v7.2 | GNU GPL v2 | Windows (x86_64), Linux, macOS | `photorec_win.exe` | Subprocess batch execution (`/cmd <image> search`) |
| **TestDisk** | [cgsecurity/testdisk](https://github.com/cgsecurity/testdisk) v7.2 | GNU GPL v2 | Windows (x86_64), Linux, macOS | `testdisk_win.exe` | Interactive TUI (detection & manual invocation) |
| **GNU ddrescue** | [GNU ddrescue](https://savannah.gnu.org/git/?group=ddrescue) | GNU GPL v2+ | Linux only (Physical execution unavailable on Windows) | None (Windows fallback: `DirectDamagedMediaImager`) | DREXX native direct sector recovery engine with `.map` mapfile compatibility |
| **mdadm** | [Linux RAID](https://git.kernel.org/pub/scm/utils/mdadm/mdadm.git) | GNU GPL v2 | Linux only (Physical execution unavailable on Windows) | None (Windows fallback: `VirtualRaidReconstructor`) | DREXX algorithmic XOR parity reconstruction engine |
| **Cryptographic Primitives** | [Python Cryptography](https://github.com/pyca/cryptography) / `secrets` / `hashlib` | Apache 2.0 / BSD | Cross-platform | In-process Python standard library & cryptography wheel | In-memory CSPRNG, SECP256R1 ECDSA, SHA-256 |

---

## 2. Platform Realities on Windows

1. **Storage Device Erasure via Low-Level Bus / IOCTLs (Methods 1–7):**
   - Direct ATA Secure Erase (`hdparm`), NVMe Format/Sanitize (`nvme-cli`), and SCSI/SAS Sanitize (`sg3_utils`) require direct kernel controller access.
   - Under consumer USB mass-storage bridge chips (UASP/BOT), pass-through of ATA/NVMe sanitize commands is blocked by bridge firmware.
   - Therefore, Methods 1–7 are honestly marked as `PHYSICAL_EXECUTION_UNAVAILABLE` or `UNSUPPORTED_HARDWARE` in non-pass-through environments. DREXX never fabricates success or substitutes destructive `diskpart clean` as a fake NIST compliance pass.

2. **Binary Recovery Stream Integrity:**
   - Inode file carving via `icat.exe` produces raw byte streams containing arbitrary null bytes (`0x00`) and high-order bytes (`> 0x7F`).
   - All binary recovery routes through `CentralProcessRunner.binary_run()`, bypassing text-mode UTF-8 re-encoding to guarantee bit-for-bit byte preservation (`input bytes == recovered bytes`).

3. **UAC Elevation for Carvers:**
   - `photorec_win.exe` embeds a Windows UAC manifest (`requireAdministrator`). When executed from standard user shells, Windows raises `[WinError 740] The requested operation requires elevation`. Elevated administrative context is required for full direct-drive raw carving.

---

## 3. Truth in Certification Architecture

- **Target Validation:** `CertificateManager` enforces target match checks. If `actual_target != claimed_target`, issuance fails immediately.
- **Physical vs Fixture Isolation:** Certificates for test buffers or synthetic images are strictly issued as `CERT-FIXTURE-` or `CERT-IMAGE-`. `PHYSICAL` certificates are only generated for validated `\\.\PhysicalDrive*` or `\\.\<drive>:` targets.
- **Cryptographic Signature:** All issued certificates are digitally signed using ECDSA SECP256R1 and recorded in tamper-evident ledger logs.
