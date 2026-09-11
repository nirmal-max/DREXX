# DREX — Unified Data Recovery & Sanitization Platform

**DREX (Data Recovery & Erasure eXcellence)** is an offline, security-grade platform providing 25 distinct methods for drive sanitization, file/folder secure wiping, and digital forensic recovery.

---

## Key Features & Architecture

- **25 Defensible Methods**:
  - **7 Drive Erasure Methods**: NIST SP 800-88 Rev.2, Smart Sanitization, Device-Native Sanitize, ATA Secure Erase, NVMe Secure Erase, IEEE 2883 Purge, Verified Overwrite.
  - **9 File & Folder Erasure Methods**: CSPRNG Random Overwrite, Cryptographic Erasure, File Slack / Cluster-Tip Sanitization, Filesystem Metadata Sanitization, NIST SP 800-88 Policy Engine, Secure Free Space Wiping, Single-Pass Zero Overwrite, Storage-Aware Sanitization Fallback, Temporary / Cache Residual Trace Sanitization.
  - **9 Recovery Methods**: Quick Recovery, Smart Recovery, Targeted Recovery, Filesystem Recovery, Deep Recovery, Fragment Recovery, Storage / RAID Recovery, Damaged Media Recovery, Forensic Recovery.
- **Fail-Closed Capability Engine**: Real-time capability detection. Uninstalled tools or unsupported platforms are strictly reported as `BACKEND UNAVAILABLE` or `UNSUPPORTED`.
- **Read-Only Source Enforcement**: Recovery operations never write to or modify the source disk, disk image, or partition.
- **Directory Hierarchy Preservation**: Folder recovery preserves complete nested directory structures (`PROJECT/DATA/subfile.txt`).
- **Tamper-Evident Cryptographic Certificates**: Every verified operation generates an offline-verifiable certificate signed with **ECDSA P-256 / SHA-256** and accompanied by an encoded QR code and PDF report.
- **System Protection**: Built-in safeguards protect system volumes (`C:\`), Windows directories (`System32`, `WinSxS`), and application binaries.

---

## Installation & Setup

### Prerequisites
- Python 3.10+ (Tested up to Python 3.14)
- Supported OS: Windows 10/11, Windows Server, Linux (CLI / adapters)
- Dependencies: `cryptography`, `reportlab`, `qrcode`, `pillow`, `pytest`

### Quick Start
```powershell
# Clone the repository
git clone https://github.com/nirmal-max/DREXX.git
cd DREXX

# Install Python requirements
pip install -r requirements.txt  # or: pip install cryptography reportlab qrcode pillow pytest

# Run system diagnostic doctor
python drex_app.py --doctor

# Launch DREX Graphical Interface
python drex_app.py
```

---

## System Diagnostics (`drex doctor`)

Run `python drex_app.py --doctor` to inspect local backend tools, detected storage devices, administrative privileges, and method counts in structured JSON.

---

## Testing & Quality Assurance

Run the comprehensive test suite with `pytest`:

```powershell
pytest -q
```

All 81 unit, integration, and security tests execute against verified adapters, safety guards, and decision engines.

---

## Official Upstream Recovery Backends

DREXX is designed to interface with authoritative upstream digital forensic tools:
- **The Sleuth Kit (TSK)**: `fls`, `icat`, `fsstat`, `tsk_recover`, `mmls` ([sleuthkit.org](https://www.sleuthkit.org/))
- **TestDisk & PhotoRec**: Non-interactive file carving and partition analysis ([cgsecurity.org](https://www.cgsecurity.org/))
- **GNU ddrescue**: Damaged media imaging with mapfile resume ([gnu.org/software/ddrescue](https://www.gnu.org/software/ddrescue/))
- **Autopsy**: GUI forensic integration ([sleuthkit.org/autopsy](https://www.sleuthkit.org/autopsy/))

When external binaries are placed in `native_bin/` or added to system PATH, DREXX automatically detects their presence and enables their corresponding execution workflows.

---

## License & Notice

Licensed under the project repository terms. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for third-party component licenses.
