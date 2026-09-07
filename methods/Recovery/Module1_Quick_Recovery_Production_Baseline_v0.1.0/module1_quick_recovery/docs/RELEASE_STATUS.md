# Release status

## Delivered

This ZIP is **Module 1 — Quick Recovery v0.1.0 production engineering baseline**. It is source-complete for the implemented scope and includes tests, architecture, security notes, research notes, and a CMake build.

## Implemented scope

- read-only image/file source
- Windows PhysicalDrive read-only source
- MBR/GPT discovery
- NTFS deleted MFT-record candidates with resident/non-resident data mappings
- FAT12/16/32 deleted directory-entry candidates with contiguous reconstruction
- exFAT deleted file-entry-set candidates with contiguous reconstruction
- evidence/confidence metadata
- JSON result output
- destination-only recovery
- cancellation hooks
- deterministic parser tests

## Not yet release-certified

The following are mandatory before calling the binary a commercial release:

1. Real NTFS/FAT/exFAT image corpus with byte-for-byte golden files.
2. NIST/CFTT deleted-file test corpus where licensing/access permits.
3. EXT2/3/4 provider.
4. Broader NTFS edge cases: record reuse, ADS, sparse/compressed files, attribute lists, hard links, complex fragmentation.
5. exFAT/FAT fragmentation and directory-tree reconstruction.
6. Fuzzing and malformed-image regression corpus.
7. ASan/UBSan and Windows security testing.
8. Physical HDD/SSD/USB/SD integration testing.
9. Performance and I/O amplification benchmarks on multi-terabyte images.
10. Windows code signing, installer and privilege/device-access validation.
11. Third-party dependency/license audit.
12. Independent recovery accuracy comparison against UFS Explorer, R-Studio and TSK on the same images.

The package deliberately reports unsupported or insufficient-evidence cases rather than silently escalating into raw carving or deep scanning.
