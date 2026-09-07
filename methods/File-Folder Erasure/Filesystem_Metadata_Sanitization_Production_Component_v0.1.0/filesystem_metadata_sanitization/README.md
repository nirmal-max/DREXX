# Filesystem Metadata Sanitization

A production-oriented, conservative component for sanitizing filesystem metadata that
the host operating system exposes through documented APIs.

## Scope

The component can inspect and, when explicitly requested, sanitize:

- extended attributes (xattrs) on platforms that expose them;
- access/modification timestamps;
- selected POSIX permission bits;
- file/directory names through a separate controlled rename operation;
- directory-entry names only for entries explicitly selected by the caller.

It deliberately does NOT claim to sanitize metadata that is not exposed through a safe
portable API, including arbitrary deleted directory-entry slack, historical journal
records, snapshots, filesystem-internal MFT free records, backups, replicas, or
controller-level copies.

## Safety model

- Dry-run is the default.
- `--execute` is required for changes.
- `--confirm` must exactly equal the selected target.
- Recursive operation is opt-in.
- Symlinks are never followed.
- Metadata changes are recorded in an audit JSON file.
- Unsupported metadata operations are reported rather than guessed.
- The component never writes raw filesystem structures.

## Important forensic distinction

Deleting a file normally removes its directory entry but does not guarantee destruction
of historical filesystem metadata. Microsoft SDelete documents that NTFS free MFT space
requires special handling and that free directory space containing deleted names cannot
simply be allocated and overwritten. Therefore this module treats filesystem-internal
historical metadata as a separate, filesystem-specific capability.

## Example

Inventory:

    python -m metadata_sanitizer path/to/file

Sanitize exposed metadata:

    python -m metadata_sanitizer path/to/file --execute --confirm path/to/file         --clear-xattrs --normalize-times --audit audit.json

Rename metadata before deletion:

    python -m metadata_sanitizer path/to/file --execute --confirm path/to/file         --rename --name-token sanitized

The rename operation changes the current directory entry. It does not prove removal of
historical copies from journals, snapshots, backups or forensic images.

## Testing

    python -m pytest -q tests

Tests use temporary files and synthetic metadata where the host supports xattrs.
