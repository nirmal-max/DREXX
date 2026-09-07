# Deep research — Filesystem Metadata Sanitization

## NIST SP 800-88 Rev. 2
NIST SP 800-88 Rev. 2 is the current final revision, published September 2025.
It defines sanitization as rendering access to target data infeasible for a given
level of effort and emphasizes a programmatic approach, validation, and use of
current applicable standards. It does not prescribe a universal "metadata wipe"
command.

## Microsoft SDelete
Microsoft SDelete v2.06 documents a critical NTFS limitation: its free-space
operation securely fills free MFT records but does not securely delete file names
located in free directory space because that space is not available for allocation.
This is direct evidence that filesystem-internal metadata cannot safely be treated
as ordinary free file data.

SDelete also uses repeated renaming to overwrite the current file name when securely
deleting a file. That operation changes the active directory entry; it does not prove
historical journal/snapshot removal.

## GNU shred
GNU Coreutils documentation explains that ordinary deletion removes a directory entry
while data and metadata can remain in storage. It also documents that journaling,
snapshots, copy-on-write, compression, RAID and similar filesystem designs can defeat
simple in-place overwrite assumptions. Its `shred` implementation can wipe a current
file name before unlinking and can round writes to filesystem block size to cover slack.

## Eraser
Heidi Eraser is open source under GPL and provides secure erasure tasks, file/folder
targets, free-space operations, and custom erasure methods. Its architecture and
documentation were reviewed as a Windows reference. No Eraser source is copied here.

## nwipe
nwipe was reviewed for device-level erasure, verification, logging and the separation
between filesystem-level operations and whole-device sanitization. It is not used as
a source dependency.

## Permanent Eraser
The open-source Permanent Eraser project was reviewed as a macOS reference. It contains
filesystem/file-erasure related source and bundled utilities, demonstrating the need
for OS-specific implementations.

## Engineering conclusion
A commercial metadata module should have two distinct layers:

1. Exposed metadata sanitizer:
   xattrs, timestamps, current permissions/ACLs, and current directory names.
2. Filesystem-internal metadata handlers:
   NTFS MFT/free directory space, ext4 journal/dirent behavior, APFS/Btrfs
   copy-on-write/snapshots, etc.

Layer 2 must use filesystem-specific, reviewed mechanisms and should return UNSUPPORTED
rather than guessing.

This package implements Layer 1 conservatively and provides the integration contract
for Layer 2.
