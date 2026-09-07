# CSPRNG Random Overwrite — Production-Oriented File Sanitization Component

A safety-first implementation of **single-pass CSPRNG random overwrite** for applicable
regular files and directories.

## What it does

- Generates overwrite bytes from the operating system's cryptographically secure random source.
- Writes the random stream across the complete logical file length in one pass.
- Flushes and calls `fsync()` where supported.
- Optionally reads the file back and verifies that its bytes are no longer equal to the
  original content (a probabilistic postcondition, not proof of physical media sanitization).
- Optionally removes the filesystem entry after successful verification.
- Produces structured audit records.
- Refuses symbolic links and non-regular files.
- Defaults to dry-run at the CLI.

## Why CSPRNG?

The random data is generated from the OS CSPRNG (`secrets.token_bytes`), rather than a
non-cryptographic PRNG such as Mersenne Twister. This follows the security requirement
for unpredictable overwrite data.

## NIST position

NIST SP 800-88 Rev. 2 is the current final revision. Its "clear" definition covers
logical sanitization of user-addressable storage using normal storage interfaces.
Rev. 2 does not prescribe a universal fixed number of overwrite passes; technique
selection should follow IEEE 2883, NSA specifications, or an approved organizational
standard.

This component therefore calls itself a **CSPRNG Random Overwrite mechanism**, not a
universal "NIST-certified wipe".

## Critical media limitation

A host-level random overwrite is not a universal purge mechanism for SSD/NVMe/flash.
Wear-leveling, remapping, over-provisioning, snapshots, backups, mirrors, and other
copies can prevent host writes from covering every physical representation.

The policy engine should select native/device sanitization or cryptographic erase when
the requested assurance requires it.

## Safety

Execution requires:

```text
--execute --confirm <exact-target>
```

Default mode is dry-run.

## Run

```bash
python -m pip install -e .
python -m csprng_overwrite --help

# dry-run
python -m csprng_overwrite secret.bin

# execute + verify
python -m csprng_overwrite secret.bin --execute --confirm secret.bin --verify
```

## Test

```bash
python -m pytest -q tests
```

Tests use only temporary files; no raw block devices are touched.

## Commercial integration

The implementation is original and does not bundle proprietary source from commercial
eraser products. Review your organization's legal, licensing, assurance and compliance
requirements before claiming a particular certification.
