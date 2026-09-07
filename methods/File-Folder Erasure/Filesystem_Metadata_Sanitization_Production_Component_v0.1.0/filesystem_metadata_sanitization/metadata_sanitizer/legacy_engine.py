"""Removed legacy duplicate implementation.

The canonical implementation is metadata_sanitizer.engine. This module exists
only as a compatibility marker so the repository cannot accidentally carry a
second sanitizer implementation.
"""

from .engine import MetadataError, MetadataResult, inspect_metadata, sanitize_metadata, write_audit

__all__ = [
    "MetadataError",
    "MetadataResult",
    "inspect_metadata",
    "sanitize_metadata",
    "write_audit",
]
