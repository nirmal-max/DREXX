# Research summary

## NIST SP 800-88 Rev. 2

NIST SP 800-88 Rev. 2 is the current final revision (September 2025). It describes
media sanitization as rendering access to target data infeasible for a given level
of effort. Rev. 2 focuses on establishing an enterprise sanitization program and
validation, and replaces detailed technique recipes (other than cryptographic erase
guidance) with recommendations to follow current relevant standards such as IEEE 2883,
NSA specifications, or an approved organizational standard.

**Engineering conclusion:** free-space wiping is a logical filesystem-level mechanism,
not a universal device purge.

## Microsoft SDelete

SDelete v2.06 (Microsoft Learn, March 2026) explicitly supports cleaning free space
on logical disks. Its documented approach is important: it allocates the largest
possible files and overwrites those allocated files so previously free clusters are
reused and sanitized. It also describes additional NTFS MFT free-space handling and
admits that some free directory space containing deleted names cannot be allocated
for overwriting.

**Engineering conclusion:** allocation-based wiping is safer than direct raw writes
to arbitrary free blocks, but it cannot claim coverage of filesystem areas that the
filesystem will not expose for allocation.

## GNU shred

GNU shred documents that deleted file data remains recoverable until storage is
rewritten and warns about filesystem behavior, snapshots, mirrors and other situations
where overwriting a logical file may not reach every physical copy. Its default block
rounding can also cover the last filesystem block's slack.

**Engineering conclusion:** free-space sanitization must be explicitly scoped and
must not be described as universal physical sanitization.

## nwipe

nwipe is a mature disk-level erasure project. It uses large I/O buffers, verification,
logging, direct I/O options and has extensive SSD/NVMe considerations. Its current
documentation is a useful reference for distinguishing block-device erasure from
filesystem free-space operations.

**Engineering conclusion:** keep this component at the filesystem allocation layer
and use native device sanitization elsewhere.

## Eraser

The open-source Eraser project provides a mature Windows erasure architecture and
historical filesystem-aware methods. It is useful as an implementation reference,
but no third-party source is bundled here.

## Security model

This implementation:
- requires explicit execution confirmation;
- defaults to a 64 MiB reserve;
- writes only through normal filesystem allocation;
- uses fsync;
- verifies filler content before removal;
- performs best-effort cleanup on errors;
- records an auditable result;
- does not claim coverage of snapshots, backups, flash translation layers, inaccessible
  metadata or other copies.

## Production integration

The higher-level NIST policy engine should decide whether free-space wiping is suitable.
The execution result should feed the audit/certificate subsystem and must not be turned
into a "purge successful" statement without technology-specific evidence.
