# Deep research summary

## NIST SP 800-88 Rev. 2

NIST defines "clear" as a sanitization method using logical techniques to sanitize
data in user-addressable storage locations, typically through standard read/write
commands. Rev. 2 is the current final revision (September 2025). It shifted away
from prescribing a fixed catalog of overwrite techniques and instead recommends
IEEE 2883, NSA specifications, or an organization-approved standard for technique
details.

**Engineering conclusion:** single-pass zero overwrite is implemented here as a
logical overwrite primitive for applicable media, not as a universal purge method.

## Nwipe

The open-source nwipe project implements "Fill With Zeros" and separate verification
methods, uses large aligned I/O buffers and discusses direct/cached I/O. Its current
documentation also warns that SSD/NVMe require native secure-erase mechanisms because
wear-leveling and over-provisioning can prevent host writes from reaching all physical
media.

We use these ideas as behavioral references; no nwipe source is bundled.

## SDelete

Microsoft Sysinternals SDelete is a mature Windows secure-deletion utility that
supports one or more overwrite passes and free-space operations. We use its documented
behavior as a Windows reference. SDelete is not bundled and its proprietary/source
licensing is not assumed.

## Eraser

The open-source Eraser project contains a mature plugin abstraction for overwrite
methods and multiple historical algorithms. We use it as an architectural reference,
not as copied code.

## SecureWipe

SecureWipe is a GPLv3 project that distinguishes HDD logical wiping from SSD/NVMe
native/firmware sanitization and provides a test-disk mode. Its architecture supports
the key safety conclusion of this component: do not claim a one-pass host overwrite
is a purge of modern flash storage.

## Secure Delete

The Rust `secure_delete` project demonstrates a compact cross-platform file/folder
overwrite workflow, configurable patterns and explicit confirmation. It is useful
for CLI/UX comparisons.

## The Devourer

This Windows-oriented project uses chunked writes, CSPRNG support, fsync and metadata
handling. It explicitly warns that multiple host passes do not defeat SSD wear-leveling,
controller remapping, snapshots, or external copies.

## GNU shred

GNU coreutils `shred` is a standard POSIX reference for repeated overwriting. Its
documentation also contains important caveats about filesystems, snapshots and
modern storage.

## Security conclusion

A commercial implementation should report:

"Logical overwrite verified"

rather than:

"All physical copies of this data are irrecoverable."

That distinction is central to a trustworthy sanitization product.
