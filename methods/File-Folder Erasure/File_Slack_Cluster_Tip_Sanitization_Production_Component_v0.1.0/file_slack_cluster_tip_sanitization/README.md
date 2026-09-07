# File Slack / Cluster-Tip Sanitization

Production-oriented, conservative filesystem component for sanitizing the unused tail
of an allocated filesystem cluster for an explicitly selected regular file.

The implementation deliberately refuses unsupported physical layouts instead of
guessing a disk-sector offset from logical file size.

It provides:
- allocation-unit tail calculation;
- a deterministic synthetic backend for testing;
- explicit execution confirmation;
- zero or OS-CSPRNG random patterns;
- verification;
- JSON audit records;
- an unsupported-backend safety path.

IMPORTANT: logical EOF arithmetic alone does NOT prove the physical cluster containing
the tail. A production filesystem backend must obtain a trusted allocation map.

Compressed, sparse, encrypted, copy-on-write, deduplicated, network and virtual
filesystems can invalidate naive assumptions. SSD/NVMe flash translation can also
prevent logical writes from proving physical-media sanitization.

CLI defaults to dry-run.

Test:
    python -m pytest -q tests
