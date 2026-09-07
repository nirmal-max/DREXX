# Single-Pass Zero Overwrite — Production-Oriented File Sanitization Component

A cross-platform Python reference implementation for **single-pass zero overwrite of
ordinary files/directories**, with safety controls, atomic audit records, verification,
and explicit limitations.

## What this component does

For a selected regular file, it:

1. validates the target and refuses symlinks;
2. opens the file for in-place binary writing;
3. overwrites the current logical file contents with `0x00`;
4. flushes and calls `fsync()` where supported;
5. reads the file back and verifies every byte is zero;
6. optionally truncates to zero bytes and unlinks it;
7. records an audit event with hashes of the original test content and the operation metadata.

For directories it processes regular files recursively, without following symlinks.

## Important scope

This is a **logical overwrite / Clear-oriented mechanism for applicable storage**.
It does NOT claim that a host-level overwrite purges data from:

- SSD/NVMe flash translation layers;
- remapped sectors;
- over-provisioned storage;
- snapshots / copy-on-write versions;
- backups or replicas;
- filesystem journals not covered by the target operation;
- application caches or other copies.

NIST SP 800-88 Rev. 2 defines "clear" as logical sanitization using user-addressable
storage commands such as rewriting, while current Rev. 2 directs organizations toward
IEEE 2883, NSA specifications, or an approved organizational standard for technique
details. Use the policy engine to decide whether this method is appropriate.

## Safety

The executable CLI defaults to **dry-run**. Destructive execution requires:

```text
--execute --confirm <exact-target>
```

The implementation refuses:

- symlinks;
- non-regular files;
- root directory `/`;
- filesystem root on Windows;
- empty or ambiguous targets.

## Install / run

```bash
python -m pip install -e .
python -m zero_overwrite --help

# dry run
python -m zero_overwrite file.txt

# execute a single file
python -m zero_overwrite file.txt --execute --confirm file.txt --verify

# execute a directory
python -m zero_overwrite ./sensitive --execute --confirm ./sensitive --verify
```

## Test

```bash
python -m pytest -q tests
```

The test suite uses temporary files and never targets a real disk device.

## Commercialization

This package contains only original implementation code plus documentation/research
references. It does not bundle proprietary source from Microsoft, Blancco, BitRaser,
Ontrack, or other commercial products.

Review dependencies, licenses, threat model, platform-specific behavior, and legal/
compliance requirements before commercial deployment.
