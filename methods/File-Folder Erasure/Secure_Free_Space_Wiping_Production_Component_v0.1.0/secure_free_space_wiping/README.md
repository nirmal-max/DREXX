# Secure Free-Space Wiping — Production-Oriented Component

A safety-first free-space sanitization component for an explicitly selected mounted
filesystem directory. It uses an allocation strategy: create controlled filler files
inside the target filesystem, fill them with the selected sanitization pattern, flush
and fsync them, then remove the filler files.

## Why allocation instead of raw free-block writes?

Writing directly to arbitrary "free blocks" is unsafe and filesystem-specific. Microsoft
SDelete documents the same high-level strategy for Windows: allocate as much free space
as possible, write/overwrite the allocated files, and clean residual NTFS MFT free
records through further allocations. This component adopts the allocation strategy but
does not claim to cover filesystem metadata structures that cannot be allocated normally.

## Modes

- `zero`: write 0x00 into allocated filler files.
- `random`: use OS CSPRNG bytes.
- `verify`: read back the filler files before removal.
- `--reserve-bytes`: leave a safety reserve instead of consuming every reported byte.
- `--execute --confirm <exact-target>`: required for destructive execution.
- default CLI behavior is dry-run.

## Scope and limitations

This component targets **unallocated user-addressable filesystem capacity** by allocating
ordinary files. It is not a raw-device purge operation.

It cannot guarantee removal of data held in:

- SSD/NVMe flash translation layers or over-provisioning;
- remapped sectors;
- snapshots / copy-on-write histories;
- backups, replicas, cloud copies;
- inaccessible filesystem metadata/journal regions;
- another filesystem or partition;
- hardware caches.

Do not call a successful free-space wipe a device-level purge unless the surrounding
policy and technology-specific method establish that assurance.

## Important operational warning

Free-space wiping deliberately consumes most available capacity. Running it on a production
filesystem can cause applications to fail due to temporary disk exhaustion. Use the reserve
option, quiesce applications, and follow an approved maintenance procedure.

## Example

Dry run:

```bash
python -m free_space_wiper /mnt/target
```

Execute with a 64 MiB reserve:

```bash
python -m free_space_wiper /mnt/target \
  --execute --confirm /mnt/target \
  --reserve-bytes 67108864 \
  --pattern zero --verify
```

## Testing

```bash
python -m pytest -q tests
```

Tests include a fake filesystem allocator and bounded local allocation tests. No raw block
device is touched.

## Commercial integration

The code is original and does not bundle proprietary source from SDelete, Blancco,
BitRaser, Ontrack or other commercial products. Review license, platform behavior,
assurance requirements and legal/compliance requirements before commercial deployment.
