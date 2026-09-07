# Module 4 — Filesystem Recovery

Production-oriented C++20 filesystem-structure recovery engine.

## Purpose

Filesystem mode reconstructs and enumerates surviving filesystem structures:
partitions, superblocks/boot records, metadata objects, directory entries and
file extents. It is the structural layer between Quick/Smart and Deep/Fragment.

This implementation is deliberately read-only. It does not repair the source
filesystem and does not mount the source.

## Supported providers in this baseline

- NTFS: boot geometry, MFT record enumeration, resident/non-resident $DATA,
  FILE_NAME metadata, parent reference and data runs.
- FAT12/16/32: BPB geometry, FAT chain traversal, root/subdirectory directory
  entries, deleted/live entries, long-file-name reconstruction, file extents.
- exFAT: boot region geometry, FAT chain traversal, root directory, file entry
  sets, stream extension, name entries, allocation bitmap awareness and extent
  reconstruction.
- EXT2/EXT3/EXT4: superblock, block-group descriptors, inode table, inode
  metadata, extent-tree traversal and directory entry enumeration.

## CLI

Inspect a source:
  fsrecover --source image.raw --output filesystem.json

Select a partition:
  fsrecover --source image.raw --partition 1 --output filesystem.json

The JSON result includes filesystem geometry, health checks, directory objects,
file metadata and extent maps.

## Design boundary

Filesystem mode is metadata/structure recovery. It does not perform:
- broad raw signature carving (Module 3)
- probabilistic strategy selection (Module 2)
- arbitrary fragmented-content inference (Module 6)
- RAID reconstruction (Module 7)
- failing-media read scheduling (Module 8)
- forensic evidence packaging (Module 9)

## Commercial release gates

This baseline needs a large real-image corpus and differential testing against
mature tools before a commercial release claim. See docs/RESEARCH.md.
