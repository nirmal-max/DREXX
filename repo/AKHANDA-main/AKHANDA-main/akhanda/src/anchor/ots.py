"""
External anchor, OWNER: lead. Wraps OpenTimestamps.

Contract:
    merkle_root(entry_hashes: list[bytes]) -> bytes
    submit(root: bytes) -> {"ok", "proof_path", "reason"}
    verify(ots_proof_path: str) -> {"confirmed", "block_height", "reason"}

Every N entries, compute a Merkle root over all entry_hashes and submit it. Bitcoin
confirmation takes 1-2 hours, so for the demo anchor one checkpoint early in the day and
verify against THAT confirmed one live. Show the live submission as "in progress".

NEVER claim legal recognition in India. It is a cryptographic guarantee of the same
class courts increasingly accept, not a legal one. docs/ENGINEERING_RULES.md section 6.

DEFECT FIXED HERE, read this before touching merkle_root. The previous version padded
an odd level by appending the last node to itself. That is the Bitcoin CVE-2012-2459
pattern: [A,B,C] and [A,B,C,C] produce an IDENTICAL root, so the root did not identify a
unique set of entries and a chain could be extended by a duplicate without changing its
anchor. It also had no leaf/node domain separation, so an internal node could be
replayed as a leaf (second-preimage). Both are fixed below, following RFC 6962 §2.1.
This is the same defect AetherProof found and fixed in its own Merkle code.
"""

from __future__ import annotations
import hashlib
import shutil
import subprocess
from pathlib import Path

# RFC 6962 §2.1 domain-separation tags. Leaves and internal nodes MUST hash under
# different prefixes, or every node is a bare 32-byte digest and an internal node can be
# presented as a leaf.
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

OTS_BINARY = "ots"


def merkle_leaf(leaf: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + leaf).digest()


def merkle_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def merkle_root(entry_hashes: list[bytes]) -> bytes:
    """Merkle root over entry hashes, RFC 6962 style.

    An unpaired node is PROMOTED unchanged to the next level, never duplicated. A single
    leaf returns its tagged hash, not the raw input, returning it unchanged would break
    domain separation for one-entry trees.
    """
    if not entry_hashes:
        return b"\x00" * 32

    level = [merkle_leaf(h) for h in entry_hashes]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(merkle_node(level[i], level[i + 1]))
            else:
                nxt.append(level[i])  # odd node out: promote, never duplicate
        level = nxt
    return level[0]


def inclusion_proof(entry_hashes: list[bytes], index: int) -> list[tuple]:
    """Audit path proving entry_hashes[index] is under merkle_root(entry_hashes).

    Returns [(sibling_bytes, is_left), ...] from the leaf upward. Rebuilds the tree per
    call, so this is O(n), acceptable at forensic chain lengths (hundreds of entries),
    and the honest note is that it would need level caching at scale.
    """
    if not entry_hashes or not (0 <= index < len(entry_hashes)):
        raise IndexError("index out of range for this tree")

    path: list[tuple] = []
    level = [merkle_leaf(h) for h in entry_hashes]
    idx = index
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                if i == idx:
                    path.append((level[i + 1], False))   # sibling on the right
                elif i + 1 == idx:
                    path.append((level[i], True))        # sibling on the left
                nxt.append(merkle_node(level[i], level[i + 1]))
            else:
                nxt.append(level[i])
        idx //= 2
        level = nxt
    return path


def verify_inclusion(leaf: bytes, path: list[tuple], root: bytes) -> bool:
    """Recompute the root from a leaf and its audit path. O(log n)."""
    node = merkle_leaf(leaf)
    for sibling, sibling_is_left in path:
        node = (merkle_node(sibling, node) if sibling_is_left
                else merkle_node(node, sibling))
    return node == root


def _ots_available() -> bool:
    return shutil.which(OTS_BINARY) is not None


def submit(root: bytes, out_dir: str = ".") -> dict:
    """Submit the root to OpenTimestamps calendar servers.

    Degrades cleanly (docs/ENGINEERING_RULES.md rule 3): if the client is not installed or the network
    is unreachable, this returns ok=False with a reason. It does NOT raise, and the
    caller records the chain as unanchored rather than failing the operation.
    """
    out = Path(out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    stamp_file = out / f"checkpoint_{root.hex()[:16]}.root"
    stamp_file.write_bytes(root)

    if not _ots_available():
        return {"ok": False, "proof_path": str(stamp_file),
                "reason": "opentimestamps-client not installed; root written, unanchored"}

    try:
        proc = subprocess.run(
            [OTS_BINARY, "stamp", str(stamp_file)],
            capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "proof_path": str(stamp_file),
                "reason": f"ots stamp failed: {exc}"}

    proof = Path(str(stamp_file) + ".ots")
    if proc.returncode != 0 or not proof.exists():
        return {"ok": False, "proof_path": str(stamp_file),
                "reason": f"ots stamp returned {proc.returncode}: {proc.stderr.strip()}"}

    return {"ok": True, "proof_path": str(proof),
            "reason": "submitted; Bitcoin confirmation typically takes 1-2 hours"}


def verify(ots_proof_path: str) -> dict:
    """Verify a .ots proof.

    Returns confirmed=False with a reason for every failure path, missing client,
    missing file, pending confirmation. Pending is NOT an error and is never reported as
    a failure; it is reported as pending, because saying "not anchored" about a
    submission still waiting for a block would be a false claim in the other direction.
    """
    path = Path(ots_proof_path)
    if not path.exists():
        return {"confirmed": False, "block_height": None,
                "reason": f"proof file not found: {path}"}
    if not _ots_available():
        return {"confirmed": False, "block_height": None,
                "reason": "opentimestamps-client not installed; cannot verify"}

    try:
        proc = subprocess.run(
            [OTS_BINARY, "verify", str(path)],
            capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"confirmed": False, "block_height": None,
                "reason": f"ots verify failed: {exc}"}

    text = (proc.stdout or "") + (proc.stderr or "")
    height = None
    for token in text.replace(",", " ").split():
        if token.isdigit() and len(token) >= 6:
            height = int(token)
            break

    if "Success" in text or "attests existence" in text:
        return {"confirmed": True, "block_height": height,
                "reason": "anchored in the Bitcoin blockchain"}
    if "Pending" in text or "pending" in text:
        return {"confirmed": False, "block_height": None,
                "reason": "submitted, awaiting Bitcoin confirmation"}
    return {"confirmed": False, "block_height": None,
            "reason": f"ots verify inconclusive: {text.strip()[:200]}"}
