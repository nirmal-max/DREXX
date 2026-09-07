# Module 7 — Storage / RAID Recovery

Read-only storage reconstruction engine for RAID and array recovery.

## Supported baseline

- RAID 0 striping
- RAID 1 mirror selection
- RAID 5 single-parity reconstruction
- RAID 6 dual-parity reconstruction
- RAID 10 mirrored-stripe mapping
- linear/spanned layout
- Linux md RAID superblock 1.x discovery (metadata evidence)
- configurable component order
- missing-drive placeholders
- virtual logical address mapping
- parity reconstruction
- candidate-layout scoring
- JSON layout reports
- optional virtual-image export for a bounded range

The engine never writes to member disks.

## Important

RAID recovery is a layout-reconstruction problem. A filesystem can appear
"valid" under an incorrect disk order or stripe geometry, so this module
produces explicit candidate layouts and confidence/evidence rather than
silently selecting a configuration.

## CLI

raidscan --level 5 --stripe 65536 --members disk0.img,disk1.img,disk2.img,disk3.img --output raid.json

For a missing member use an empty placeholder:
raidscan --level 5 --stripe 65536 --members a.img,b.img,,d.img --output raid.json

Export a virtual range:
raidscan --level 5 --stripe 65536 --members a.img,b.img,c.img,d.img \
  --export virtual.img --offset 0 --size 10485760
