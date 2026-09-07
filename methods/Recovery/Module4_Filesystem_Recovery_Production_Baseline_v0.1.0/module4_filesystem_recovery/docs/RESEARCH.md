# Module 4 research

## UFS Explorer

UFS Explorer documents lost-file recovery as a filesystem-aware scanning
process and supports searching for lost filesystem structures/partitions by
metadata. Its workflow can scan selected storage ranges, search filesystem
types, retain scan results, and open detected volumes for browsing.

Architecture adopted:
- scan a defined storage region
- detect filesystem structures
- preserve a reusable reconstructed-volume description
- enumerate directories/files through filesystem metadata
- maintain explicit scan/reconstruction state

Sources:
https://www.ufsexplorer.com/manual/std/
https://www.ufsexplorer.com/manual/pro/

## R-Studio

R-Studio's IntelligentScan is the benchmark for structural recognition and
relationship validation. Module 4 therefore treats filesystem structures as a
graph of dependent metadata rather than a list of magic bytes.

Architecture adopted:
- validate geometry before parsing
- validate metadata relationships
- build directory and file-object relationships
- expose multiple health/consistency signals
- never equate a signature hit with a valid filesystem

## The Sleuth Kit

TSK explicitly separates filesystem, data units, metadata and file-name
categories. Its metadata objects can contain data-run information and file
timestamps. This maps directly to the internal model here:
filesystem -> metadata object -> name -> extents/data units.

Source:
https://www.sleuthkit.org/sleuthkit/docs/api-docs/4.15.0-develop/fspage.html

## Microsoft exFAT specification

The implementation follows the documented exFAT concepts of:
- boot regions
- FAT region
- cluster heap
- directory-entry sets
- allocation bitmap
- file/stream/name entries
- NoFatChain

Source:
https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification

## NTFS

The provider implements the common NTFS 3.x metadata model:
MFT records, attributes, $FILE_NAME, $DATA and runlists. It is deliberately
read-only and does not implement proprietary recovery behavior.

## EXT2/3/4

The EXT provider is implemented against the public on-disk model used by
e2fsprogs. e2fsprogs exposes ext2/ext3/ext4 filesystem-specific libraries, but
its GPL/LGPL licensing must be separately reviewed before linking any code.
No e2fsprogs source is bundled here.

## Third-party/IP boundary

No UFS Explorer, R-Studio or TSK source is copied. The implementation is
original and uses public filesystem specifications and concepts.

Open-source libraries were considered as integration candidates but are not
bundled in this baseline to keep the commercial licensing boundary explicit.
