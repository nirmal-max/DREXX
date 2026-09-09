"""
One canonical serialisation, used everywhere a result record is digested.

There is exactly one function here on purpose. AetherProof shipped a defect where the
documentation said commitments were sorted one way and the code sorted them another;
two implementations, each correctly following one reading, produced different signatures
for the same object. The fix was not better documentation, it was a single normative
implementation that every caller delegates to.

The same rule applies here. The erasure engine, the recovery engine, and the verifier
that checks a stored result against the hash in the ledger must all compute the digest
the same way. They do that by calling this, not by each doing "sorted keys, no spaces".
"""

from __future__ import annotations
import hashlib
import json
from typing import Any

# Domain tag: a result record digest must never collide with an entry preimage digest,
# even if the bytes were somehow identical.
RESULT_DOMAIN = b"akhanda.result.v1"


def canonical_bytes(obj: Any) -> bytes:
    """Deterministic UTF-8 encoding: sorted keys, no insignificant whitespace.

    `ensure_ascii=False` so a Devanagari operator name is stored as itself rather than
    as escapes, the digest is over the same text a human reads in the file.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def result_digest(obj: Any) -> str:
    """SHA-256 over the canonical encoding of a result record. Hex."""
    return hashlib.sha256(RESULT_DOMAIN + canonical_bytes(obj)).hexdigest()
