# Module 8 — Damaged Media Recovery

Read-only, failure-aware disk imaging/recovery layer.

## Core design

Never start filesystem recovery against an unstable source when a safe image
can be acquired first.

Pipeline:

source
 -> bounded read
 -> adaptive block sizing
 -> fast-pass good regions
 -> failed/slow region map
 -> retry / split
 -> reverse-edge pass
 -> final sector pass
 -> image + map
 -> Modules 4/5/6/7

The baseline supports regular files and any source exposed through the source
interface. Platform-specific physical-device adapters are intentionally
separated from the safe imaging core.

## CLI

mediaimager --source disk.img --output recovery.img --map recovery.map \
  --block-sectors 256 --retries 2

The source is opened read-only. Destination and map are separate files.

A failed sector is represented in the map and filled with a deterministic
pattern in the destination image. The source is never written.
