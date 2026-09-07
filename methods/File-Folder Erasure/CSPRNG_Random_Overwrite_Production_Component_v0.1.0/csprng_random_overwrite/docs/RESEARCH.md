# Deep research summary — CSPRNG Random Overwrite

## NIST SP 800-88 Rev. 2

NIST's current final revision was published in September 2025. Its glossary defines
"clear" as logical sanitization of user-addressable storage using the same interface
available to the user, typically standard read/write commands. Rev. 2 does not
prescribe a universal fixed overwrite-pass recipe; technique details are tied to
IEEE 2883, NSA specifications, or an approved organizational standard.

**Design consequence:** this package is a mechanism for an approved logical-clear
workflow, not a claim that one random pass is universally sufficient for every medium.

## nwipe

nwipe implements a PRNG Stream method and supports CSPRNGs including ChaCha20 and
AES-256-CTR. It also uses large aligned I/O buffers and configurable direct/cached
I/O. Its current documentation explicitly discusses SSD/NVMe wear leveling,
over-provisioning and the need for native device sanitization.

**Design consequence:** use a CSPRNG for the random stream, but route SSD/NVMe
targets through the policy engine rather than assuming host random overwrite is purge.

## The Devourer

This Windows project uses Node.js `crypto.randomBytes` for a CSPRNG overwrite pass
and combines it with other passes. It also documents risks from SSD/NVMe, TRIM,
snapshots, BitLocker and reparse points.

**Design consequence:** use an OS-backed CSPRNG and explicitly reject the claim
that host random overwrite defeats flash translation or external copies.

## Secure File Shredder

This .NET 8 Windows application uses cryptographic random data for configurable
overwrite passes and provides a queue/GUI workflow.

**Design consequence:** separate the erasure engine from the GUI so it can later
be embedded into the unified platform.

## GNU shred

GNU shred is a mature POSIX reference for random-source overwrite. Its documentation
also warns that filesystems with snapshots, backups, mirrors, or special allocation
behavior can preserve data outside the overwritten logical file.

**Design consequence:** verification is evidence that the target logical content changed;
it is not proof that all copies disappeared.

## SecureWipe

SecureWipe provides a modern open-source workflow distinguishing ordinary HDD wiping
from native SSD/NVMe secure erase and includes test-disk facilities.

**Design consequence:** this module should be selected only when the policy engine
has established that host-level logical overwrite is appropriate.

## Randomness design

The implementation uses Python's `secrets.token_bytes`, which delegates to the
operating system's secure randomness source. It does not use Mersenne Twister,
SplitMix64, XORoshiro, or another non-cryptographic generator for the overwrite
stream.

## Verification design

The implementation records SHA-256 before and after the overwrite. Verification
checks that the resulting logical file content is not identical to the original
cryptographic digest. This is intentionally not described as a forensic proof of
physical-media sanitization.
