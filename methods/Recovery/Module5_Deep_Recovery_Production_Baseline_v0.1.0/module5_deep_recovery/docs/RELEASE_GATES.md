# Commercial release gates

This v0.1.0 baseline is buildable and testable, but a commercial release must
still pass:

- real NTFS/FAT/exFAT/EXT image corpus
- formatted/repartitioned images
- multiple filesystem generations at one physical location
- false-positive filesystem corpus
- corrupted boot sectors and backup boot sectors
- sparse/partial images
- 4 KiB-sector devices
- >2 TiB images
- cancellation/resume equivalence tests
- fuzzing of every parser
- ASan/UBSan and Windows verifier
- differential comparison against mature recovery products
- performance benchmarks on HDD, SSD and image files
- crash-safe state commits
- cryptographic integrity of state/results
- license/security audit
