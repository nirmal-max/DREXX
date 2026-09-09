"""Self-attestation: what produced this entry, committed inside the entry.

THE GAP THIS CLOSES. Every entry says what was done. None of them said what DID it. Given
a chain, you could prove the operations were not altered, and still not answer the first
question a defence expert asks about any automated result: *which build produced this, and
is it the build you validated?* The answer was "the tool", as if there were only ever one.

There is never only one. Code changes between the validation run and the case, between the
first drive and the fortieth, between the lab that made the image and the lab that verifies
it. A forensic tool that cannot name itself makes every downstream claim about its own
behaviour unfalsifiable.

WHAT THIS IS NOT. It is not a self-modifying or self-improving tool. That would be
inadmissible for exactly the reason this module exists: a process that changes itself is a
process the certificate cannot describe, and BSA 2023 s.63(4) requires the certificate to
describe the process. What this makes possible is the *honest* version of the same idea , 
the tool can change between versions, and every entry states which side of every change it
falls on. Evolution becomes a signed, dated fact in the same ledger as the evidence,
instead of an unrecorded event nobody can bound.

    tool_ref() -> "akhanda/0.1.0+<code_digest[:16]>"

The code digest covers the source of every module that can affect what an entry says: the
attestation core, the encoders, the two engines, the policy gate. It deliberately does NOT
cover the console, the docs, or the tests -- changing a test must not invalidate a chain,
and a digest that moves for reasons unrelated to behaviour trains people to ignore it.

REPRODUCIBILITY IS THE WHOLE POINT, so the digest is computed from source text with line
endings normalised. A chain written on Linux and verified on Windows must produce the same
tool_ref for the same code, or a git checkout on the wrong platform would read as a
different tool.
"""
from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path

TOOL_NAME = "akhanda"
TOOL_VERSION = "0.1.0"

# Domain tag: a code digest must never be confusable with an entry hash or a Merkle node.
TOOLREF_TAG = b"akhanda.toolref.v1"

# The modules whose source can change what an entry says. Ordered, because the digest is
# order-dependent and the order must not come from a directory listing.
#
# WHY THIS LIST AND NOT "EVERYTHING". A digest over the whole tree moves when a docstring
# in a script changes, and a signal that fires on irrelevant changes is a signal people
# learn to ignore. Every path here is one whose behaviour a court could reasonably ask
# about. Adding a module that affects entry content and forgetting to list it here is the
# real risk, and test_self_attestation.py pins the list against the package on disk.
ATTESTED_MODULES = (
    "attestation/core.py",
    "attestation/canonical.py",
    "attestation/tiers.py",
    "attestation/policy.py",
    "attestation/keys.py",
    "attestation/store.py",
    "attestation/case.py",
    "attestation/toolref.py",
    "erasure/engine.py",
    "erasure/file_eraser.py",
    "recovery/engine.py",
    "presence/client.py",
    "witness/client.py",
    "anchor/ots.py",
)

_SRC = Path(__file__).resolve().parents[1]


def _normalise(raw: bytes) -> bytes:
    """CRLF -> LF, and strip a UTF-8 BOM.

    A chain written on Linux and verified on Windows must agree. Git's autocrlf rewrites
    line endings on checkout, so a byte-for-byte digest of the file on disk would report a
    different tool for identical code -- a false alarm that would make the field useless
    precisely where cross-platform verification matters most.
    """
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    return raw.replace(b"\r\n", b"\n")


@lru_cache(maxsize=1)
def code_digest() -> str:
    """SHA-256 over the attested source, length-prefixed by path then content.

    Length-prefixed for the same reason every other encoding in this codebase is: joining
    path and content with a delimiter would let a file whose text contains that delimiter
    impersonate a different file boundary. Rule 1 applies to source as much as to fields.

    A missing module is hashed as absent rather than skipped. Deleting a file must change
    the digest -- if it did not, removing a module would be the one code change the tool
    could not detect in itself.
    """
    h = hashlib.sha256()
    h.update(TOOLREF_TAG)
    for rel in ATTESTED_MODULES:
        path = _SRC / rel
        blob = _normalise(path.read_bytes()) if path.is_file() else b"\x00ABSENT"
        h.update(len(rel).to_bytes(4, "big"))
        h.update(rel.encode("utf-8"))
        h.update(len(blob).to_bytes(4, "big"))
        h.update(blob)
    return h.hexdigest()


def tool_ref() -> str:
    """The value that goes inside the signed preimage.

    Short by design. It sits in every entry, is read aloud in demos, and is compared by
    eye far more often than by machine; 16 hex characters of a SHA-256 is 64 bits, which
    is not a collision-resistance claim and is not being asked to be one. The full digest
    is available from `code_digest()` and is what `describe()` reports for the record.
    """
    return f"{TOOL_NAME}/{TOOL_VERSION}+{code_digest()[:16]}"


def describe() -> dict:
    """The full self-description, for certificates and evidence files."""
    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "tool_ref": tool_ref(),
        "code_digest": code_digest(),
        "attested_modules": list(ATTESTED_MODULES),
        "meaning": (
            "tool_ref is inside the signed preimage of every entry, so each entry states "
            "which build produced it. This does NOT mean the tool is validated -- it "
            "means the tool is IDENTIFIED, which is the prerequisite for validation "
            "meaning anything. A build that was never validated is still named honestly."
        ),
    }


def compare(entry_tool_ref: str) -> dict:
    """Was this entry produced by the build that is running now? Reports, never raises.

    A mismatch is NOT an error and must never be presented as one. Chains outlive builds;
    an entry written by last month's version is normal, expected, and exactly the case
    this field was added to make visible rather than invisible. The verifier's job is to
    say WHICH build, not to insist on one.
    """
    current = tool_ref()
    if not entry_tool_ref:
        return {"known": False, "same_build": False, "current": current,
                "reason": ("this entry names no tool; it predates self-attestation "
                           "(ENTRY_VERSION < 3) or was written by something else")}
    if entry_tool_ref == current:
        return {"known": True, "same_build": True, "current": current,
                "reason": "produced by the build verifying it now"}

    same_version = entry_tool_ref.rsplit("+", 1)[0] == f"{TOOL_NAME}/{TOOL_VERSION}"
    return {
        "known": True, "same_build": False, "current": current,
        "entry_tool_ref": entry_tool_ref,
        "reason": (
            "same declared version, DIFFERENT code digest: the source changed without "
            "the version being bumped. Not tampering, and worth knowing before quoting "
            "a validation result that was measured against one of the two."
            if same_version else
            "produced by a different build than the one verifying it now. Expected for "
            "any chain older than the running version; the point is that it is stated."
        ),
    }
