# Cryptographic Erasure Sanitization

Production-oriented cryptographic-erasure component.

## Core principle

Cryptographic Erasure (CE) is not "overwrite the encrypted file with random bytes".
It is sanitization by destroying the encryption key(s) that protect the target data.

The implementation therefore separates:

1. **Data encryption** — encrypted payload remains untouched.
2. **Key custody** — a dedicated key store owns the data-encryption key.
3. **Key destruction** — the key store performs an irreversible destroy operation.
4. **Post-destruction validation** — the target key is no longer retrievable and an
   encrypted object can no longer be decrypted through the managed key.
5. **Audit** — records the key identifier, target identifier, operation, result and
   timestamps, but NEVER records plaintext keys.

## Included implementation

The ZIP contains a reference-grade local envelope-encryption backend using the
`cryptography` package and AES-256-GCM, plus a strict key-store interface that can be
implemented by an enterprise KMS/HSM.

The local backend is intentionally a development/reference backend. Production
deployment should connect the same interface to a managed KMS/HSM with a documented
key-destruction API and independent audit trail.

## Important distinction

Destroying a key is only CE if all copies of the relevant confidentiality-protecting
keys are destroyed or rendered inaccessible. If the same plaintext key exists in:
- another KMS/HSM;
- a backup;
- a recovery export;
- a snapshot;
- a cached application process;
- an externally managed key store;

then destroying one copy does not establish complete cryptographic erasure.

Likewise, deleting a wrapping key does not necessarily destroy the underlying data key
if another copy of the data key survives.

## Safety

- Dry-run by default.
- Explicit `--execute` and exact `--confirm`.
- Key material is never printed.
- Audit records contain hashes/IDs, not secret key bytes.
- Destroy operations are irreversible in the local backend.
- No raw disk-sector writes.
- No automatic deletion of unrelated files.
- Verification attempts decryption after destruction and expects failure.

## Example

Create an encrypted object:

    python -m crypto_eraser create-secret encrypted.bin       --key-id customer-records

Destroy the key:

    python -m crypto_eraser destroy-key customer-records       --execute --confirm customer-records --audit audit.json

Verify:

    python -m crypto_eraser verify encrypted.bin customer-records

The exact CLI is deliberately local/reference oriented. Enterprise adapters should use
the same interface with a real KMS/HSM.

## Testing

    python -m pytest -q tests
