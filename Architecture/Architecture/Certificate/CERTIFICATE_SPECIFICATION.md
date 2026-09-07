# DREX Certificate — Codex Specification

## Purpose
Generate a local PDF certificate for completed DREX operations. The supplied
`DREX Certificate Reference.png` is the visual reference/template.

## Certificate sections
- DREX Certificate of Data Destruction
- Tamper-Proof Digital Certificate
- Certificate ID
- Issue timestamp (UTC)
- Device Information:
  - Device Path
  - Device Type
  - Device Model
  - Serial Number
  - Drive Size
- Wipe Operation Details:
  - Method
  - Passes
  - Start time
  - Completion time
  - Duration
  - Status
- Verification Data:
  - SHA-256 Before
  - SHA-256 After
  - Verification result
- Scan to Verify:
  - QR code containing certificate validation information / Certificate ID
- Digital Signature:
  - Signature Hash
  - Public Key Fingerprint
- Legal/assurance notice
- DREX footer

## Dynamic data
Replace all bracketed placeholders in the reference with real values from the
actual operation. Do not invent values.

## Result wording
The certificate must truthfully describe the operation:
- Drive sanitization: use sanitization/erase wording.
- File/folder sanitization: use sanitization/erase wording.
- Recovery: generate a recovery certificate with recovery wording.
- Destroy Drive: no destruction certificate; this page is assessment only.

Do not use "DATA SUCCESSFULLY DESTROYED" for an operation that only performed
software sanitization. The final wording must match the actual operation.

## Certificate creation rule
Generate a successful certificate only after the operation completes and all
required verification checks succeed.

A failed, cancelled, or unverified operation must never produce a certificate
that claims successful completion.

If an audit record is retained for a failed operation, clearly mark it as
failed/partial and never present it as successful sanitization.

## Certificate storage
Store generated certificates and their metadata locally so they appear in:
- All Certificates
- Erasure Certificates
- Recovery Certificates

Support search, viewing and PDF export/opening from the Certificate Centre.

## Cryptographic implementation
The reference establishes the required certificate fields, QR validation,
digital signature information and SHA-256 fields. Codex must implement these
using a sound local cryptographic design and must not fabricate hashes,
signatures, fingerprints or validation results.
