# Module 1 — Quick Recovery

Production-oriented C++20 source baseline for a filesystem-metadata-first deleted-file
recovery engine. It is intentionally conservative about support claims.

## Scope

Quick is deliberately narrow:

- read-only RAW/image input
- Windows physical-device source support (`\\.\PhysicalDriveN`) on Windows
- MBR and GPT partition discovery
- filesystem detection
- NTFS MFT enumeration and deleted-file candidate extraction
- NTFS resident and non-resident `$DATA` reconstruction when the data runlist is intact
- FAT12/16/32 directory analysis and contiguous deleted-file recovery where enough metadata survives
- exFAT directory-set analysis and contiguous deleted-file recovery where enough metadata survives
- candidate confidence/evidence
- JSON result output
- source fingerprinting
- cancellation
- no write path to the source
- deterministic unit tests for parsers and core structures

## Important support boundary

This release is an engineering foundation, not a claim of universal filesystem
coverage. It does NOT silently perform raw carving, deep scanning, fragment
inference, RAID reconstruction, bad-sector imaging, or forensic acquisition.

Unsupported or insufficiently evidenced cases are reported explicitly so the
future Smart/Targeted/Deep/Fragment modes can take over.

## Build

Linux/macOS:
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build -j
    ctest --test-dir build --output-on-failure

Windows (Visual Studio):
    cmake -S . -B build -A x64
    cmake --build build --config Release
    ctest --test-dir build -C Release --output-on-failure

## CLI

Image:
    quickscan --source evidence.raw --output results.json

Partition:
    quickscan --source evidence.raw --partition 1 --output results.json

Recover one candidate:
    quickscan --source evidence.raw --recover-candidate 123 --destination recovered

The CLI is intentionally conservative. Recovery is always to a destination
separate from the source.

## Design

Source -> Partition -> Filesystem -> Metadata -> Deleted Candidate ->
Extent/Data Run Resolution -> Validation -> Candidate -> Safe Extraction.

The core candidate schema is shared by later modules.
