# DREXX Technical Architecture & Engineering Documentation

**Application**: DREX Platform  
**Version**: 1.0.0  
**Language**: Python 3.14 / Win32 Native Subsystems  
**Upstream Backends**: The Sleuth Kit (TSK) 4.15.0, TestDisk / PhotoRec 7.2  

---

## 1. System Architecture Overview

DREXX utilizes a decoupled, modular architecture where the user interface, business logic, sanitization pipelines, and external forensic backends communicate through strictly typed adapters.

```
                          ┌───────────────────────┐
                          │   DrexApp (Tkinter)   │
                          └───────────┬───────────┘
                                      │
            ┌─────────────────────────┴─────────────────────────┐
            │                                                   │
            ▼                                                   ▼
┌───────────────────────────┐                       ┌───────────────────────┐
│   Sanitization Pipeline   │                       │   RecoveryDispatcher  │
│ - Overwrite Engines       │                       │ - BaseRecoveryAdapter │
│ - Decision Engines        │                       │ - Specific Adapters   │
│ - CertificateManager      │                       └───────────┬───────────┘
└───────────┬───────────────┘                                   │
            │                                                   ▼
            │                                       ┌───────────────────────┐
            │                                       │  backend_adapters.py  │
            │                                       │ - CentralProcessRunner│
            │                                       │ - Command Builders    │
            │                                       │ - Output Parsers      │
            │                                       └───────────┬───────────┘
            │                                                   │
            ▼                                                   ▼
┌───────────────────────────┐                       ┌───────────────────────┐
│     Audit & Data Store    │                       │ Upstream Native Bin   │
│ - JSON Ledger Records     │                       │ - fls.exe, icat.exe   │
│ - PDF Reports             │                       │ - photorec_win.exe    │
└───────────────────────────┘                       └───────────────────────┘
```

---

## 2. Recovery Dispatcher & Method Adapters

`RecoveryDispatcher` provides a single authoritative entry point mapping all 9 recovery method IDs to their respective adapter instances:

* **`QuickRecoveryAdapter` (Method 17)**:
  - Invokes `fls.exe -r -d -f <fstype> <source>` to discover unallocated inodes.
  - Invokes `icat.exe -r -f <fstype> <source> <inode>` for precise inode stream recovery.
* **`SmartRecoveryAdapter` (Method 18)**:
  - Executes `fsstat.exe` to inspect volume geometry, sector sizes, and filesystem type.
  - Dynamically orchestrates between `fls`, `icat`, and `tsk_recover`.
* **`TargetedRecoveryAdapter` (Method 19)**:
  - Binds user-selected candidate IDs to exact inode identifiers, ensuring candidates are not falsely associated by filename or file size alone.
* **`FilesystemRecoveryAdapter` (Method 20)**:
  - Uses `tsk_recover.exe -f <fstype> -e <source> <destination>` to restore complete nested directory hierarchies with preserved directory structure.
* **`DeepRecoveryAdapter` (Method 21)**:
  - Uses `photorec_win.exe /cmd <source> search` to perform unallocated cluster signature carving.
* **`FragmentRecoveryAdapter` (Method 22)**:
  - Employs `FragmentReconstructor` to parse structural markers across fragmented cluster chains (JPEG DQT/SOF/SOS, PDF xref/trailer/EOF, PNG IHDR/IDAT/IEND, ZIP central directory).
* **`RaidRecoveryAdapter` (Method 23)**:
  - Employs `VirtualRaidReconstructor` to virtually reconstruct RAID 0, 1, 5 (with degraded single-disk XOR parity recovery), and RAID 10 array streams.
* **`DamagedMediaRecoveryAdapter` (Method 24)**:
  - Employs `DirectDamagedMediaImager` to image failing media into disk images while writing standard GNU ddrescue-compatible `.map` mapfiles.
* **`ForensicRecoveryAdapter` (Method 25)**:
  - Acquires targeted files and produces `FORENSIC_EVIDENCE_LEDGER.json` containing immutable timestamps, inode IDs, file sizes, and SHA-256 hashes.

---

## 3. Process Execution & Error Isolation

All native subprocess invocations route through `CentralProcessRunner.run()` in `backend_adapters.py`:
* **Encoding Safety**: Passes `encoding="utf-8"`, `errors="replace"` to handle arbitrary non-ASCII bytes and Windows OEM/CP1252 codepages without crashing.
* **Timeout & Cancellation**: Monitors execution with background polling against user cancel events and hard timeout limits.
* **Argument Array Construction**: Uses raw argument lists (never `shell=True`) to prevent shell injection and path traversal vulnerabilities.

---

## 4. Safety Architecture & Target Validation

Before executing any destructive or recovery operation:
1. **Target Identification**: Logical drive letters are mapped to their physical disk numbers via Windows WMI / SetupAPI to ensure operations target the intended physical drive.
2. **Protected Path Blocking**: System drives (`PhysicalDrive0`, `C:\`, `\Windows`, `\System32`) are hard-blocked from destructive drive wiping.
3. **Destination Collision Prevention**: `RecoveryTarget.validate_destination()` ensures the destination directory is not on the same source tree or physical volume.

---

## 5. Tamper-Evident Evidence & Cryptographic Verification

* **Audit Certificates**: Managed by `CertificateManager`, every certificate is hashed using SHA-256 and signed with metadata including operation ID, method, start/end timestamps, and target hashes.
* **Forensic Ledger**: Forensic recovery writes JSON ledgers where each item contains pre-calculated SHA-256 hashes, ensuring evidentiary integrity for court or compliance audits.
