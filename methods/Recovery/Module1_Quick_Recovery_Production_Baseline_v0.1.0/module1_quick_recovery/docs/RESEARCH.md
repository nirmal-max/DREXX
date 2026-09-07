# Module 1 Research Record

## Commercial/reference products

### UFS Explorer
Primary benchmark for filesystem-aware recovery workflow. Its documentation
separates indexing an existing filesystem from broader scans and describes
deleted-file recovery and saved scan information.

### R-Studio
Primary benchmark for structural reasoning. IntelligentScan analyzes filesystem
structures, validates fields and relationships, and can identify structures such
as MBR/GPT, NTFS MFT records, FAT/exFAT structures, Ext superblocks and others.

### The Sleuth Kit
Low-level forensic benchmark. Its filesystem tools separate filesystem objects,
metadata and data extraction; `icat` is a reference for extracting an object
from filesystem metadata.

### PhotoRec
Carving benchmark for later Targeted/Deep work. It is intentionally not used by
Quick.

### DMDE / Stellar
Commercial recovery benchmarks for workflow, result presentation and recovery
behavior. Their broad recovery features are intentionally not pulled into Quick.

## Authoritative format references

- Microsoft NTFS MFT documentation.
- Microsoft exFAT filesystem specification.
- Linux/ext4 documentation for future EXT provider work.
- NIST CFTT Deleted File Recovery specifications/test images.

## Open-source implementation candidates

libfsntfs, libfsfat and libfsapfs were evaluated as research/reference candidates.
Their current project metadata describes LGPL-3.0-or-later licensing and, in the
case of libfsntfs/libfsfat/libfsapfs, experimental status or feature limits.
They are NOT bundled here.

## Engineering conclusion

Quick should exploit surviving filesystem metadata first. It should not become a
hidden raw-carving or deep-scan engine. If metadata evidence is insufficient,
the job reports an explicit escalation state.

## Production gates still required before commercial release

- extensive real-image regression corpus
- Windows physical-device integration tests
- NTFS edge cases: compression, sparse files, ADS, record reuse, corruption
- FAT/exFAT edge cases and Unicode cases
- EXT2/3/4 provider
- APFS/HFS+/ReFS providers if marketed
- fuzzing and malformed-image corpus
- ASan/UBSan/Windows Application Verifier runs
- large-disk performance benchmarks
- source-integrity verification
- dependency/license/security audit
- code signing and installer validation
- byte-for-byte comparison against known originals

## Verification performed for this package

- CMake Release build completed successfully with GCC 14.2 in the build environment.
- CTest: 1/1 deterministic parser/core test passed.
- CLI smoke test against a generated MBR fixture passed and correctly reported an unsupported filesystem rather than inventing recovery results.

This environment did not contain real NTFS/FAT/exFAT recovery images, so this package does not claim byte-for-byte recovery validation against real deleted-file corpora. That validation is a release gate, not something inferred from compilation.
