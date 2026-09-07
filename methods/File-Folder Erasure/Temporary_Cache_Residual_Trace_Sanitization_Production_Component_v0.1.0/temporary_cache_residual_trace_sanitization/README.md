# Temporary / Cache / Residual-Trace Sanitization

Production-oriented, conservative trace-cleaning component for explicitly selected
user/application/system trace locations.

It uses a policy-driven catalog instead of broad wildcard deletion.

Supported trace classes:
- temporary files/directories;
- browser/application caches through explicit catalog entries;
- recycle/trash directories when explicitly configured;
- application logs through explicit catalog entries;
- application history databases through explicit catalog entries;
- thumbnail/cache directories;
- known crash-dump directories;
- residual lock/journal-like application files when explicitly cataloged.

The engine is intentionally **catalog-driven**. It never guesses that a directory named
"cache" is safe to delete.

Safety:
- dry-run by default;
- exact --confirm required for execution;
- path canonicalization;
- symlink/reparse-point avoidance;
- root/home/current-working-directory protection;
- allowlist/catalog matching;
- no raw filesystem writes;
- open-file policy is explicit;
- audit JSON;
- optional secure-overwrite before deletion for eligible regular files.

Important limitation:
Deleting a cache/log/temp path removes the currently addressable copy. It does not
prove that the same data is absent from filesystem journals, snapshots, backups, replicas,
browser databases, application logs elsewhere, swap/pagefile, memory, or SSD/NVMe
physical remapped storage. The policy engine must select appropriate additional methods.

The package includes a small cross-platform baseline catalog and a synthetic catalog for
tests. It does not silently delete arbitrary OS directories.

Example:

    python -m trace_sanitizer /tmp/my-trace --dry-run

Execution:

    python -m trace_sanitizer /tmp/my-trace --execute --confirm /tmp/my-trace       --secure-overwrite --audit audit.json

Tests:

    python -m pytest -q tests
