"""
Chain persistence.

The chain lives in one JSON file. That is a deliberate choice over SQLite: the
evidential value of this record depends on a third party being able to read and verify
it years later with nothing but a text editor and a public key. A database file is a
worse artefact to hand to a court than a signed flat file.

Two failure modes are guarded, both learned from AetherProof's log:

  1. **CWD-relative paths fork the record.** Signing from two directories produced two
     separate logs and neither was complete. Every path here resolves to absolute.
  2. **A half-written file is worse than no file.** Writes go to a temp file in the
     same directory and are then atomically replaced, so a crash mid-save leaves the
     previous good chain intact rather than a truncated one.

What this does NOT do: prevent an operator with write access from replacing the whole
file. Nothing local can. That is what the witness node's independent head record is for.
"""

from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Optional

from .canonical import result_digest
from .core import Chain
from .keys import home


def chain_path(path: Optional[Path] = None) -> Path:
    """Absolute path of the chain file. Never CWD-relative."""
    if path:
        return Path(path).resolve()
    return home() / "chain.json"


def save_chain(chain: Chain, path: Optional[Path] = None) -> Path:
    """Atomically write the chain. Returns the path written."""
    target = chain_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(chain.to_json(), encoding="utf-8")
    os.replace(tmp, target)  # atomic on POSIX and on Windows for same-volume replace
    return target


def load_chain(path: Optional[Path] = None) -> Chain:
    """Load the chain, or return a fresh empty one if the file does not exist yet."""
    target = chain_path(path)
    if not target.exists():
        return Chain()
    return Chain.from_json(target.read_text(encoding="utf-8"))


# ------------------------------------------------------------ result records
#
# Each ledger entry commits to `result_hash`, the digest of the operation's own result
# record: which offsets were sampled, what was read back, whether verification passed,
# what the carver found. Until now that record was written only if the caller asked for
# it, so the chain routinely committed to a document that had been discarded. A hash of
# a file nobody kept proves nothing; the question "what does this hash commit to?" has
# to have an answer you can hand over. These functions make keeping it the default.

def results_dir(base: Optional[Path] = None) -> Path:
    return (Path(base).resolve() if base else home()) / "results"


def result_path(entry_hash: str, base: Optional[Path] = None) -> Path:
    """One file per entry, named by the entry hash it belongs to.

    Named by ENTRY hash, not result hash: an investigator holding a chain entry can find
    its evidence without computing anything.
    """
    return results_dir(base) / f"{entry_hash}.json"


def save_result(entry_hash: str, result, base: Optional[Path] = None) -> Path:
    """Atomically persist the record an entry commits to. Returns the path written."""
    target = result_path(entry_hash, base)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, target)
    return target


def load_result(entry_hash: str, base: Optional[Path] = None):
    """The stored record, or None if it was never written or has been removed."""
    target = result_path(entry_hash, base)
    if not target.exists():
        return None
    try:
        return json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def verify_result(entry, base: Optional[Path] = None) -> dict:
    """Re-check one entry's stored record against the hash the entry committed to.

    Three distinct outcomes, deliberately not collapsed into a bool:
      present=False            the record is missing, the commitment stands but the
                               evidence it points at is gone
      present=True, ok=False   the record was ALTERED after signing
      present=True, ok=True    the record on disk is the record that was signed
    """
    stored = load_result(entry.entry_hash, base)
    if stored is None:
        return {"seq": entry.seq, "present": False, "ok": False,
                "reason": "no result record stored for this entry"}
    actual = result_digest(stored)
    if actual != entry.result_hash:
        return {"seq": entry.seq, "present": True, "ok": False,
                "reason": ("stored result record does not match the hash this entry "
                           "committed to, the record was altered after signing")}
    return {"seq": entry.seq, "present": True, "ok": True,
            "reason": "result record matches the committed hash"}


def verify_all_results(chain: Chain, base: Optional[Path] = None) -> dict:
    """Roll the per-entry check up over a whole chain."""
    checks = [verify_result(e, base) for e in chain.entries]
    missing = [c["seq"] for c in checks if not c["present"]]
    altered = [c["seq"] for c in checks if c["present"] and not c["ok"]]
    return {
        "total": len(checks),
        "matched": sum(1 for c in checks if c["ok"]),
        "missing": missing,
        "altered": altered,
        "checks": checks,
    }


def export_console_state(chain: Chain, path: Optional[Path] = None) -> Path:
    """Write the file the console reads.

    The console is required to render correct state from this file WITHOUT the backend
    running (docs/TEAM_ROLES.md, role 4 acceptance test), so this is the whole contract
    between the lead and role 4.
    """
    target = Path(path).resolve() if path else (home() / "chain.json")
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(chain.to_json(), encoding="utf-8")
    os.replace(tmp, target)
    return target
