"""
Witness node, runs on the Raspberry Pi Zero 2W. Holds the concurring party key and keeps
its OWN record of chain heads, so a workstation that later rewrites its whole chain no
longer matches the witness. That divergence is the property no single-machine ledger can
offer.

WHETHER THE WORKSTATION CAN SEE THIS KEY DEPENDS ENTIRELY ON WHERE YOU RUN THIS FILE, and
that is measured per host in **docs/COSIGNER_HOSTING.md**. Read it before claiming a
custody boundary.

The short version: on a separate physical machine the key is genuinely out of reach. Under
WSL2 it is not, an unprivileged Windows user reads and writes root-owned 0600 files
through `\\wsl.localhost`, and can forge this node's own head log with a single write,
which does not degrade the divergence detection so much as switch it off. WSL2 is a fine
place to develop and rehearse. It is not a co-signer.

Run on the Pi:  python3 node.py
The workstation reaches it over the LAN at http://<pi-ip>:8000

Dependencies: fastapi, uvicorn, cryptography

DESIGN NOTES, because two of these were bugs before they were notes:

  * The key is generated ONCE and persisted, not regenerated per process. A key that
    changes on restart invalidates every co-signature the witness ever issued, the
    signatures stay in the operator's chain and stop verifying, which looks exactly like
    tampering. Persist it, restrict it, and never copy it to the workstation.

  * The witness's head chain is a DIFFERENT construction from the entry chain, and its
    exact bytes are a contract shared with witness/client.py::witness_head_chain. If one
    side changes, divergence detection silently reports a rewrite that never happened.

  * The witness log is append-only in memory AND on disk. An in-memory-only log makes a
    Pi reboot look like a rewritten chain.

HONEST LIMIT (docs/ENGINEERING_RULES.md section 6): the witness only knows about entries it was asked to
co-sign. It proves nothing about operations that were never submitted to it.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

from fastapi import FastAPI
from pydantic import BaseModel
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

app = FastAPI(title="Akhanda Witness Node")

WITNESS_HOME = Path(os.environ.get("AKHANDA_WITNESS_HOME", Path.home() / ".akhanda-witness"))
KEY_PATH = WITNESS_HOME / "concur_key.pem"
LOG_PATH = WITNESS_HOME / "witness_log.jsonl"

GENESIS = "00" * 32


def _load_or_create_key() -> Ed25519PrivateKey:
    """Generate on first boot, persist with restrictive permissions, reuse thereafter."""
    WITNESS_HOME.mkdir(parents=True, exist_ok=True)
    if KEY_PATH.exists():
        key = serialization.load_pem_private_key(KEY_PATH.read_bytes(), password=None)
        # NOT an assert. Python run with -O strips asserts, and this one is the only thing
        # standing between a wrong key file and a witness that signs with it. A check that
        # disappears under an optimisation flag is not a check (bandit B101).
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError(
                f"{KEY_PATH} does not hold an Ed25519 private key (got "
                f"{type(key).__name__}). Refusing to start rather than co-sign with a key "
                "of the wrong type.")
        return key
    key = Ed25519PrivateKey.generate()
    KEY_PATH.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    try:
        os.chmod(KEY_PATH, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return key


def _key_id(pub) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def _load_log() -> list[dict]:
    if not LOG_PATH.exists():
        return []
    out = []
    for line in LOG_PATH.read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def _append_log(record: dict) -> None:
    WITNESS_HOME.mkdir(parents=True, exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, separators=(",", ":")) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


_concur_key = _load_or_create_key()
_witness_log: list[dict] = _load_log()


def witness_head_chain(entry_hashes: list[str]) -> str:
    """The witness's own head construction.

    MUST stay byte-identical to witness/client.py::witness_head_chain.
    """
    head = GENESIS
    for h in entry_hashes:
        head = hashlib.sha256((head + h).encode()).hexdigest()
    return head


class CoSignRequest(BaseModel):
    seq: int
    entry_hash: str  # hex


@app.post("/witness/cosign")
def cosign(req: CoSignRequest):
    try:
        digest = bytes.fromhex(req.entry_hash)
    except ValueError:
        return {"error": "entry_hash must be hex"}
    if len(digest) != 32:
        return {"error": "entry_hash must be a 32-byte SHA-256 digest"}

    sig = _concur_key.sign(digest).hex()

    prev = _witness_log[-1]["witness_head_hash"] if _witness_log else GENESIS
    witness_head = hashlib.sha256((prev + req.entry_hash).encode()).hexdigest()

    record = {
        "seq": req.seq,
        "entry_hash": req.entry_hash,
        "witness_head_hash": witness_head,
        "concur_sig": sig,
    }
    _witness_log.append(record)
    _append_log(record)

    return {
        "concur_sig": sig,
        "witness_head_hash": witness_head,
        "witness_seq": len(_witness_log) - 1,
        "concur_key_id": _key_id(_concur_key.public_key()),
    }


@app.get("/witness/head")
def head():
    if not _witness_log:
        return {"head_hash": GENESIS, "seq": -1, "count": 0}
    last = _witness_log[-1]
    return {
        "head_hash": last["witness_head_hash"],
        "seq": last["seq"],
        "count": len(_witness_log),
    }


@app.get("/witness/pubkey")
def pubkey():
    raw = _concur_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {"pubkey_hex": raw.hex(), "key_id": _key_id(_concur_key.public_key())}


@app.get("/witness/log")
def full_log():
    """The witness's whole independent record. Published on purpose: a witness that
    keeps its record secret cannot be checked by the party it is witnessing for."""
    return {"count": len(_witness_log), "records": _witness_log}


if __name__ == "__main__":
    import uvicorn

    # Binding to all interfaces is DELIBERATE and is the point of the node: the witness
    # must be reachable from the operator's machine, which is a different machine. It is
    # configurable so a deployment can narrow it to one interface, and it defaults to
    # reachable because a witness nobody can reach silently degrades every operation to
    # SOFTWARE_KEY (bandit B104, reviewed and kept).
    host = os.environ.get("AKHANDA_WITNESS_HOST", "0.0.0.0")  # noqa: S104 - see above
    port = int(os.environ.get("AKHANDA_WITNESS_PORT", "8000"))
    print(f"witness node on {host}:{port}  (AKHANDA_WITNESS_HOST to narrow)")
    uvicorn.run(app, host=host, port=port)
