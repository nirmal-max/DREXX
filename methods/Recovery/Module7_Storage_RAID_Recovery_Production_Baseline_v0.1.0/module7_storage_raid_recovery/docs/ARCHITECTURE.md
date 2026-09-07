# Architecture

Physical members/images
       |
       v
member inventory + metadata evidence
       |
       v
layout hypotheses
       |
       +---- RAID0
       +---- RAID1
       +---- RAID5
       +---- RAID6
       +---- RAID10
       +---- linear
       |
       v
virtual address mapper
       |
       +---- direct member read
       +---- mirror selection
       +---- XOR parity
       +---- P/Q Reed-Solomon
       |
       v
virtual storage
       |
       v
filesystem / deep recovery modules

The mapper exposes a logical byte address space. It never modifies member
images.

RAID5:
  stripe_unit -> rotating data/parity disk -> member offset

RAID6:
  two parity equations P and Q -> reconstruct one or two missing members

RAID10:
  logical stripe -> mirror pair -> selected healthy member

Production implementations must account for vendor-specific layouts, sector
offsets, parity rotation, delayed parity, metadata placement, nested arrays
and filesystem/container signatures.
