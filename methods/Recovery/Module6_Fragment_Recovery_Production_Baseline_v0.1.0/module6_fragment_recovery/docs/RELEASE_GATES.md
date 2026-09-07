# Release gates

Before commercial release:
- create a ground-truth corpus with controlled fragmentation
- test NTFS/FAT/exFAT/EXT sourced extent maps
- add format-specific continuation plugins for major file families
- validate JPEG/PNG/PDF/ZIP/Office/MP4/SQLite and media containers
- test multi-fragment files with interleaving
- test overwritten fragments
- measure false-chain rate
- compare results with mature recovery tools
- add property-based/fuzz testing
- benchmark graph search on multi-terabyte images
- cryptographically record reconstruction plans
