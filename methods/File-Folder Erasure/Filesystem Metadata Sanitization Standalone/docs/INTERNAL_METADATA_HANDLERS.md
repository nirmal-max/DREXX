# Filesystem-internal metadata handler boundary

## Decision

DREX must not claim generic filesystem-internal metadata sanitization from portable file APIs.
The handler layer therefore detects the filesystem and fails closed unless a reviewed,
filesystem-specific backend is explicitly qualified.

## Reference tree

NIST SP 800-88 Rev.2
-> sanitization assurance / validation
-> applicable current standards and qualified techniques
-> filesystem-specific implementation where required

NTFS / ReFS
-> MFT records
-> directory slack / deleted names
-> transaction history
-> requires Windows/filesystem-specific qualified mechanism

ext2/3/4
-> inode and directory metadata
-> JBD2 journal
-> requires filesystem-specific qualified mechanism

Btrfs
-> copy-on-write extents
-> metadata trees
-> snapshots/subvolumes
-> requires filesystem-specific snapshot + media policy

APFS/HFS+
-> filesystem-internal records
-> snapshots / copy-on-write behavior where applicable
-> requires Apple/filesystem-specific qualified mechanism

## Why the handler fails closed

Microsoft SDelete documents that NTFS free directory space containing deleted names is
not available for normal allocation, so ordinary free-space filling cannot guarantee
name removal. Linux kernel documentation shows that ext4 records metadata transactions
in JBD2. Btrfs documentation describes copy-on-write and snapshots that can preserve
shared historical blocks.

Therefore a portable `open/write/unlink` implementation cannot honestly claim complete
filesystem-internal sanitization.

## Contract

`assess_internal_metadata(target)` returns:

- `REQUIRES_FILESYSTEM_SPECIFIC_BACKEND` for known filesystems whose internals need a
  qualified handler;
- `UNSUPPORTED` when the filesystem cannot be safely identified;
- a recommended route that prefers a qualified filesystem-specific workflow or an
  appropriate media-level purge.

This module intentionally performs **assessment, not raw filesystem-structure writes**.
A future backend must be separately reviewed, tested on disposable media, and explicitly
qualified before it can be registered as a destructive sanitization implementation.
