# Architecture

## Layering

1. Source provider
2. Partition analyzer
3. Filesystem detector/provider
4. Metadata indexer
5. Deleted-object detector
6. Extent/data-run resolver
7. Validation
8. Candidate manager
9. Provenance/result persistence
10. Destination writer

The source abstraction intentionally exposes reads only.

## Escalation contract

QUICK_SUCCESS
QUICK_PARTIAL
NO_RECOVERABLE_METADATA
UNSUPPORTED_FILESYSTEM
CORRUPT_FILESYSTEM
SOURCE_READ_ERROR
CANCELLED

A "no recoverable metadata" result does not mean the media contains no
recoverable data. It means this strategy did not find sufficient evidence.
