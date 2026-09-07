# CODEX HANDOFF — DREX

Read this file first, then inspect the entire `Architecture/` vault and the DREX GitHub repository.

## Build objective
Create the complete DREX Windows desktop application from:
1. Existing DREX repository methods.
2. UI images in `UI DESIGN/`.
3. The page rules in `Window/Page Window/`.

Do not ask the developer to design the technical architecture. Choose the appropriate implementation architecture yourself.

## Application
DREX is fully offline. Normal operation must not require cloud APIs, online authentication, online help or an internet connection.

Main navigation:
- Dashboard
- Wipe Drive
- Wipe File/Folder
- Recover
- Destroy Drive
- Certificates
- Help

## Operation rules
### Wipe Drive
Show device properties and 7 method cards:
- NIST SP 800-88 Rev.2
- Smart Sanitization
- Device-Native Sanitize
- ATA Secure Erase
- NVMe Secure Erase
- IEEE 2883 Purge
- Verified Overwrite

One method selected at a time. Execute selected method, show live log and progress, verify where applicable, then create an accurate certificate only after successful completion/verification.

### Wipe File/Folder
Show file/folder properties and 9 method cards:
- CSPRNG Random Overwrite
- Cryptographic Erasure
- File Slack / Cluster-Tip Sanitization
- Filesystem Metadata Sanitization
- NIST SP 800-88 Policy Engine
- Secure Free-Space Wiping
- Single-Pass Zero Overwrite
- Storage-Aware Sanitization & Fallback
- Temporary / Cache Sanitization

One method selected at a time. Integrate the existing repository implementation. Filesystem Metadata Sanitization is one user-facing capability even if the repository contains duplicate layers/versions.

### Recovery
Show target/device properties and 9 method cards:
- Quick Recovery
- Smart Recovery
- Targeted Recovery
- Filesystem Recovery
- Deep Recovery
- Fragment Recovery
- Storage / RAID Recovery
- Damaged Media Recovery
- Forensic Recovery

One method selected at a time. Show recovery log and progress. Produce an accurate recovery certificate after successful completion.

### Destroy Drive
**Informational assessment only.**
- Detect/inspect the device.
- Show device type, capacity, serial number, supported software sanitization methods and recommendation.
- If software sanitization is unavailable, explain the limitation and recommend appropriate alternative sanitization or authorized/certified disposal.
- Do not physically destroy hardware.
- Do not expose an unsafe physical-destruction workflow.
- Do not generate a certificate claiming DREX physically destroyed the device.

### Certificates
Provide:
- All Certificates
- Erasure Certificates
- Recovery Certificates
- Search
- Certificate/session details
- PDF view/export
- Pagination/list management

A failed or unverified operation must not appear as a successful certificate.

### Help
Use the supplied built-in Help Center design. It must work offline. Include Getting Started, Wiping, Recovery, Drive Destruction, Certificates, Troubleshooting and Safety guidance.

## Shared UI behavior
- Main window contains sidebar and page window.
- Operation pages use target/device properties where relevant.
- Wipe Drive, Wipe File/Folder and Recovery show live operation logs and progress.
- Success and error states must be visually distinct.
- Preserve the supplied DREX branding and visual hierarchy.

## Dashboard
Show:
- Drives Wiped
- Files/Folders Wiped
- Files Recovered
- Certificates

Do not show a "Destroyed Drives" statistic because Destroy Drive is informational only.

Also show operation shortcuts, detected devices, system health, recent activity and security highlights as shown in the UI reference.

## Installer
Create a conventional Windows installer with **Inno Setup**:
`DREX-Setup.exe`

Installer must:
- install the complete application and required runtime/native files;
- create appropriate shortcuts;
- provide an uninstaller;
- support offline installation;
- offer launch-after-install;
- be tested on a clean supported Windows environment.

## Quality rule
Do not treat a passing simulated/unit test as proof of real hardware qualification. Clearly separate software testing from physical-device validation.

## Completion condition
The task is complete only when the application builds, tests pass, the installed application launches correctly from a clean installation, and the final `DREX-Setup.exe` is produced.

## Certificate reference
The `Certificate/` folder is authoritative for the certificate visual reference
and certificate-generation behavior. Use `Certificate/DREX Certificate Reference.png`
as the visual template and `Certificate/CERTIFICATE_SPECIFICATION.md` as the
implementation rules. Generate certificates from actual operation data only.
Do not fabricate hashes, signatures, QR validation data or successful results.
