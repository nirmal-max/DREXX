# DREXX User Manual & Operations Guide

**Application**: DREX — Unified Secure Data Sanitization + Advanced Forensic Recovery Platform  
**Version**: 1.0.0  
**Platform**: Windows 10 / 11 (64-bit)  

---

## 1. Introduction

DREXX is a unified desktop and CLI solution for verified secure data erasure and forensically sound digital asset recovery. It provides 25 specialized methods spanning Drive Erasure, File/Folder Erasure, and Advanced File Carving & Recovery.

---

## 2. Architecture & Core Concepts

```
                  ┌──────────────────────────────┐
                  │          DREXX GUI           │
                  │   (Dashboard, Wipe, Recover) │
                  └──────────────┬───────────────┘
                                 │
                 ┌───────────────┴───────────────┐
                 │                               │
                 ▼                               ▼
    ┌────────────────────────┐      ┌────────────────────────┐
    │  Sanitization Pipeline │      │   RecoveryDispatcher   │
    │  (Kernel direct I/O,   │      │  (Method Adapters 17-25│
    │   CSPRNG, Overwrite)   │      │   TSK, PhotoRec, DREXX)│
    └────────────┬───────────┘      └────────────┬───────────┘
                 │                               │
                 ▼                               ▼
    ┌────────────────────────┐      ┌────────────────────────┐
    │ Tamper-Evident SHA-256 │      │ Forensic Ledger & Hash │
    │   Audit Certificate    │      │  Verification System   │
    └────────────────────────┘      └────────────────────────┘
```

---

## 3. Graphical User Interface (GUI) Navigation

1. **Dashboard**: Live device discovery, system doctor diagnostics, quick health metrics, and method summary.
2. **Wipe Drive**: Select a physical drive target (`PhysicalDriveX`), choose from 7 drive erasure methods, review safety warnings, and initiate verified sanitization.
3. **Wipe File/Folder**: Select individual files, folders, or volume slack spaces, apply one of 9 granular file erasure methods, and generate audit certificates.
4. **Recover Data**: Select source drive/image, choose from 9 recovery methods, scan for deleted candidates, inspect file metadata, and extract to an isolated destination.
5. **Certificates**: Browse, inspect, and export cryptographically verified PDF/JSON sanitization certificates.
6. **Help & Diagnostics**: Run doctor self-tests, check external backend status, and inspect system log streams.

---

## 4. Drive Erasure Operations (Methods 1–7)

### Safety Rules
* Destination and target are validated prior to execution.
* Direct physical drive wipes require Administrator privileges.
* Protected system volumes (e.g. `C:\`, `Windows`, `System32`) are blocked from accidental destruction.

### Methods
1. **NIST SP 800-88 Rev. 2**: Industry-standard Clear and Purge overwrite cycles.
2. **Smart Sanitization**: Dynamic multi-factor evaluation based on drive geometry and interface bus.
3. **Device Native Sanitize**: Controller firmware block erasure (fails closed on USB bridges).
4. **ATA Secure Erase**: Direct SATA bus security protocol purge (fails closed on USB bridges).
5. **NVMe Secure Erase**: PCIe NVMe Admin command sanitize (fails closed on non-PCIe buses).
6. **IEEE 2883-2022 Purge**: Storage security standard purge command set.
7. **Verified Overwrite**: 3-pass overwrite pattern with bit-by-bit verification pass.

---

## 5. File & Folder Erasure Operations (Methods 8–16)

1. **CSPRNG Random Overwrite**: Cryptographically strong pseudo-random stream destruction.
2. **Cryptographic Erasure**: Destruction and zeroization of encryption key headers.
3. **File Slack Space Sanitization**: Zeroes residual data in the final cluster beyond the EOF marker.
4. **Metadata Sanitization**: Strips EXIF metadata, document properties, and NTFS Alternate Data Streams (ADS).
5. **NIST Policy Compliance**: Rule-based enforcement of sanitization policies.
6. **Free Space Sanitization**: Overwrites unallocated disk clusters.
7. **Single-Pass Zero Overwrite**: Direct 0x00 kernel overwrite.
8. **Storage-Aware Sanitization**: Flash memory and magnetic platter optimized sanitization.
9. **Temporary & Cache Sanitization**: Recursive deep purge of application caches and browser temp files.

---

## 6. Recovery & Advanced Carving (Methods 17–25)

### Safety Rails
* **Read-Only Source**: The source disk or image is opened strictly read-only.
* **Destination Isolation**: Output must reside on a separate physical volume to prevent overwriting deleted data.

### Methods
1. **Quick Recovery (Method 17)**: High-speed TSK `fls` metadata scan + `icat` targeted extraction.
2. **Smart Recovery (Method 18)**: Automated inspection of filesystem headers via `fsstat` to select the optimal extraction path.
3. **Targeted Recovery (Method 19)**: User-selected candidate extraction via exact inode and attribute bindings.
4. **Filesystem Recovery (Method 20)**: Full hierarchical directory and file tree extraction via `tsk_recover`.
5. **Deep Recovery (Method 21)**: Raw signature-based carving of unallocated clusters via PhotoRec 7.2.
6. **Fragment Recovery (Method 22)**: Bi-fragment and multi-fragment structural reconstruction of fragmented JPEG, PDF, PNG, and ZIP files.
7. **RAID Recovery (Method 23)**: Virtual reconstruction of RAID 0, 1, 5 (with degraded XOR parity recovery), and RAID 10 volumes.
8. **Damaged Media Recovery (Method 24)**: Resilient sector-level imaging with bad sector skipping and GNU ddrescue-compatible `.map` mapfile generation.
9. **Forensic Recovery (Method 25)**: Acquisition with an immutable `FORENSIC_EVIDENCE_LEDGER.json` logging SHA-256 hashes of all extracted evidence.

---

## 7. Command Line Interface (CLI)

```powershell
# Run system doctor diagnostic
python drex_app.py --doctor

# Run internal self-test suite
python drex_app.py --self-test

# Display version information
python drex_app.py --version
```

---

## 8. Verification & Certificates

Every successful sanitization or recovery generates an audit record containing:
* Unique Certificate ID
* Target device / file identity
* Start and completion timestamps (UTC)
* Pre-wipe and post-wipe SHA-256 hashes
* Method-specific verification result (`VERIFIED`, `HASH_MATCH`)
* Digital signature / tamper-evident SHA-256 chain

Certificates can be viewed in the GUI or exported directly to JSON / PDF.
