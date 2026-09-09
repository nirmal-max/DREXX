# Security policy

Akhanda produces records intended to be relied on as evidence. A defect that lets a record
be altered, reordered or removed without detection is not a bug in a utility, it is a
failure of the one thing the tool exists to do. Please report anything of that kind
privately.

## Reporting a vulnerability

Open a **private** security advisory through GitHub:

<https://github.com/pulkit6732/AKHANDA/security/advisories/new>

Please do not open a public issue for a vulnerability, and please do not disclose it
publicly until a fix is available.

Include, as far as you are able:

- what you did, in enough detail to reproduce it
- what you expected the tool to do, and what it did instead
- the chain, certificate or command output that shows the problem
- the version, the commit hash, and the `entry_version` of the chain involved

A chain file is safe to attach. It contains hashes, public key identifiers and signatures,
never evidence content and never a private key. **Never attach a private key**, an
`operator_key.pem`, a `concur_key.pem`, or a `witness_token`.

## What we consider a vulnerability

In descending order of seriousness:

| Class | Example |
|---|---|
| Undetected mutation | any way to change, reorder or remove an entry that verification still reports as valid |
| Signature forgery | producing a preimage collision, or a valid signature without the private key |
| Co-signer bypass | reaching `WITNESS_COSIGNED` without a genuine second key on a separate machine |
| Silent downgrade | an operation recording a higher custody tier than it actually reached |
| Amendment abuse | repointing an `AMEND` at a different record, or amending without the change being visible |
| Unrecorded refusal | a blocked operation that leaves no `REFUSED` entry |
| Destructive misfire | erasure touching a device other than the confirmed target |

## What is a known limit, not a vulnerability

These are documented in the README and are properties of the design. Reports of them are
welcome as discussion, but they are not treated as vulnerabilities.

- **The chain cannot prove nothing was withheld.** It proves nothing was altered after
  being written. An operation never recorded at all leaves no trace to detect. This is
  integrity, not completeness, and no single operator ledger can close it.
- **A private key readable on the operator's own machine.** Without a passphrase the
  operator key sits on disk unencrypted, and the tool says so on `init`. Anyone who can
  read that file can sign as the operator. That is the stated tier, `SOFTWARE_KEY`.
- **The presence device is not a secure key store.** CVE-2019-17391 extracts ESP32 eFuse
  keys by voltage glitching and is unpatchable on shipped silicon. The device confirms
  presence and nothing more.
- **WSL2 is not a co-signer boundary.** This is measured, not assumed, and the tests that
  measure it are in `akhanda/tests/test_cosigner_boundary.py`. Host the witness on a
  physically separate machine.
- **Tail truncation is not detectable from a chain file alone.** Only the witness's
  independent head record separates a truncated chain from a genuinely short one.

## Cryptography

Ed25519 (RFC 8032) for signatures, SHA-256 for hashing, RFC 6962 domain separation for the
Merkle layer. Every field is length prefixed before it enters a hash, so two different
records cannot produce identical signing bytes. There is a regression test for that and it
must not be removed.

Ed25519 is an elliptic curve scheme and therefore in the class NIST deprecates by 2030 and
removes by 2035. The entry format version sits inside the signed preimage, so an old
verifier refuses a newer chain rather than mis-verifying it. Migration to ML-DSA
(FIPS 204) is designed for and not yet shipped.

## Scope

This policy covers the code in this repository. It does not cover the security of a
deployment you configure, the physical security of your machines, or the correctness of
the legal conclusions anyone draws from a certificate this tool produces.
