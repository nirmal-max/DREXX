# Module 7 research record

## UFS Explorer RAID Recovery

UFS Explorer's RAID Recovery supports standard, nested and custom RAID
patterns, missing-drive placeholders, virtual reconstruction, automatic RAID
recognition, and safe read-only operation. It explicitly supports RAID 0,
RAID 1E, RAID 3, RAID 5, RAID 6, RAID 7, RAID 10/50/60 and other layouts.

Sources:
https://www.ufsexplorer.com/manual/raid/
https://www.ufsexplorer.com/manual/standard/raid-builder/

Architecture adopted:
- member devices/images are components
- layout is virtual and read-only
- missing members are represented explicitly
- layout parameters are separate from data extraction
- multiple reconstruction attempts do not modify sources

## R-Studio

R-Studio documents virtual RAID construction, reverse RAID and recovery of
missing/corrupt members using redundancy. Its manual also emphasizes that
controller metadata may need reconstruction.

Source:
https://www.r-studio.com/downloads/Recovery_Manual.pdf

Architecture adopted:
- virtual RAID layer
- member mapping independent of physical devices
- parity/redundancy reconstruction
- reverse/reconstructed output remains separate from sources

## DMDE

DMDE's RAID constructor supports individual disks/partitions/images and an
automatic calculation mode for unknown parameters and disk order. It warns
that incorrect RAID type, rotation or disk order can still produce misleading
directory structures.

Source:
https://dmde.com/manual/raids.html

Architecture adopted:
- candidate layouts
- evidence scoring
- explicit uncertainty
- bounded parameter search rather than one blind guess

## mdadm

Linux md RAID stores metadata in superblocks. mdadm documents metadata
formats including 0.90 and 1.x variants and their placement/constraints.

Source:
https://man7.org/linux/man-pages/man8/mdadm.8.html

This baseline reads md metadata as evidence but does not invoke mdadm or write
superblocks.

## The Sleuth Kit

TSK treats disk images as a layer beneath volume/filesystem analysis and
supports raw and multiple image containers through an image API.

Sources:
https://www.sleuthkit.org/sleuthkit/docs/api-docs/4.15.0-develop/imgpage.html
https://www.sleuthkit.org/sleuthkit/docs/api-docs/4.15.0-develop/tsk__img_8h.html

Architecture adopted:
storage reconstruction -> virtual disk -> Module 4/5 filesystem layer.

## Commercial/IP boundary

No proprietary recovery source is copied. The implementation is original and
uses public RAID mathematics, public metadata documentation and an explicit
read-only virtual-device model.
