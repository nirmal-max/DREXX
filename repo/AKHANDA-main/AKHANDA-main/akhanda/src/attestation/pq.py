"""Post-quantum signatures, so a chain signed in 2026 is still provable in 2040.

THE PROBLEM, WITH DATES RATHER THAN ADJECTIVES. Ed25519 is an elliptic-curve signature.

    NIST FIPS 203/204/205 finalised          13 August 2024
    Federal deadline for digital signatures  2031
    RSA-2048 and ECC P-256 deprecated        2030
    Quantum-vulnerable algorithms removed
        from NIST standards                  2035

Indian criminal proceedings routinely run 10-20 years through trial and appeal. A chain of
custody signed today may be examined in 2040, five years after the algorithm that signed
it left the standards. The literature names this exactly: ACPO, NIST SP 800-101 and
ISO/IEC 27037 "make no provision for algorithm agility or quantum resilience", and evidence
authenticated under a broken scheme becomes "legally contestable".

WHAT IS AND IS NOT CLAIMED. Papers already recommend PQC for chain-of-custody logs. This is
not our idea and is not presented as one, the claim is FIRST IMPLEMENTER, not first
thinker. Nor is the claim that quantum computers will break Ed25519 by any particular date;
that is unknowable and unnecessary. The claim is about **standards deprecation and legal
contestability**, both of which are dated and citable.

WHY THIS IS ADDITIVE AND NOT A FORMAT BREAK. `operator_sig` and `concur_sig` are attached
AFTER signing, they are signatures OVER the entry hash, not fields inside the preimage. A
post-quantum signature is the same shape, so it needs no 17th hashed field, no
ENTRY_VERSION 4, and no synchronised change across three verifier implementations. An
existing verifier reads a PQ-signed chain unchanged; it simply does not know about the
extra signature.

    dual_sign(entry, ed_key, pq_key)     both signatures over the same entry hash
    verify_entry(entry, ed_pub, pq_pub)  reports WHICH layers ran, never just a boolean
    assess_chain(entries)                how much of this chain is quantum-protected

STRIPPING IS THE ATTACK THIS GUARDS. An adversary who cannot forge either signature can
still DELETE the post-quantum one, silently downgrading the chain to the algorithm they
expect to break. `pq_algorithm` is recorded separately from the signature itself, so an
entry that names an algorithm and carries no signature for it is a STRIPPED entry, a
finding, not a chain that merely lacks protection.
"""
from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa

# ML-DSA-65 is NIST security category 3, the level FIPS 204 positions as the general
# default. -44 is faster and lighter, -87 is stronger; 65 is chosen because a chain is
# kilobytes beside the multi-gigabyte images it describes, so the signature size that
# matters least is the one worth spending.
ALGORITHM = "ML-DSA-65"
_PRIVATE = mldsa.MLDSA65PrivateKey
_PUBLIC = mldsa.MLDSA65PublicKey

# Recognised so a chain written under one algorithm is READ rather than mis-verified, the
# same discipline ENTRY_VERSION applies to the entry format.
KNOWN_ALGORITHMS = {
    "ML-DSA-44": (mldsa.MLDSA44PrivateKey, mldsa.MLDSA44PublicKey),
    "ML-DSA-65": (mldsa.MLDSA65PrivateKey, mldsa.MLDSA65PublicKey),
    "ML-DSA-87": (mldsa.MLDSA87PrivateKey, mldsa.MLDSA87PublicKey),
}

PQ_KEY_ENV = "AKHANDA_PQ_KEY"

# Verification states. "Not protected" and "stripped" are different facts and are never
# collapsed: the first is a chain that predates the migration, the second is an attack.
PROTECTED = "PROTECTED"
UNPROTECTED = "NOT_PROTECTED"
STRIPPED = "STRIPPED"
FORGED = "SIGNATURE_INVALID"
UNKNOWN_ALG = "UNKNOWN_ALGORITHM"


@dataclass
class PQVerification:
    """What the post-quantum layer actually established about one entry."""
    state: str
    algorithm: str = ""
    reason: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ChainAssessment:
    """How much of a chain would survive its own signing algorithm being deprecated."""
    entries: int = 0
    protected: int = 0
    unprotected: int = 0
    stripped: list = field(default_factory=list)
    invalid: list = field(default_factory=list)
    algorithms: list = field(default_factory=list)
    fully_protected: bool = False
    reason: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ─────────────────────────────────────────────────────────────── keys

def generate():
    """A fresh ML-DSA-65 private key."""
    return _PRIVATE.generate()


def public_bytes(pub) -> bytes:
    return pub.public_bytes_raw()


def load_public(raw: bytes, algorithm: str = ALGORITHM):
    """Load a public key for a NAMED algorithm.

    The algorithm is a parameter rather than an assumption: a 1,952-byte blob is an
    ML-DSA-65 key and a 1,312-byte blob is ML-DSA-44, and guessing from length would make
    the verifier's behaviour depend on a coincidence of sizes.
    """
    pair = KNOWN_ALGORITHMS.get(algorithm)
    if pair is None:
        raise ValueError(f"unknown post-quantum algorithm {algorithm!r}; "
                         f"known: {sorted(KNOWN_ALGORITHMS)}")
    return pair[1].from_public_bytes(raw)


def key_path() -> Path:
    env = os.environ.get(PQ_KEY_ENV)
    if env:
        return Path(env)
    home = Path(os.environ.get("AKHANDA_HOME", Path.home() / ".akhanda"))
    return home / "operator_pq_key.pem"


def load_or_create(path: Optional[Path] = None):
    """The operator's post-quantum key, created on first use.

    Stored as PKCS#8 PEM, which for ML-DSA holds the 32-byte seed rather than the expanded
    key, so the file is small and the key is regenerated deterministically from it.
    Permissions are tightened on POSIX for the same reason the Ed25519 key's are.
    """
    p = path or key_path()
    if p.is_file():
        key = serialization.load_pem_private_key(p.read_bytes(), password=None)
        if not isinstance(key, _PRIVATE):
            raise TypeError(
                f"{p} does not hold an {ALGORITHM} private key (got {type(key).__name__}). "
                "Refusing to sign with a key of the wrong type.")
        return key

    key = generate()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
    if os.name != "nt":
        os.chmod(p, 0o600)
    return key


# ─────────────────────────────────────────────────────────────── signing

def sign(key, entry_hash_hex: str) -> str:
    """Sign the SAME bytes the Ed25519 signature covers: the entry hash itself.

    Signing the same message under both algorithms is what makes this a genuine dual
    signature rather than two unrelated attestations, a verifier holding either public key
    is checking the same claim about the same entry.
    """
    return key.sign(bytes.fromhex(entry_hash_hex)).hex()


def dual_sign(entry, pq_key) -> None:
    """Attach a post-quantum signature to an already Ed25519-signed entry.

    Called after `Chain.append`, so the entry hash exists and neither signature can change
    it. The algorithm is recorded on the entry, which is what makes a later stripping
    detectable.
    """
    if not entry.entry_hash:
        raise ValueError("entry has no hash yet; dual_sign runs after the entry is signed")
    entry.pq_algorithm = ALGORITHM
    entry.operator_pq_sig = sign(pq_key, entry.entry_hash)


# ─────────────────────────────────────────────────────────────── verification

def verify_entry(entry, pq_pub=None) -> PQVerification:
    """What did the post-quantum layer establish here? Reports; never raises.

    Four outcomes that must stay distinct:

        NOT_PROTECTED  no PQ algorithm named and no PQ signature. Normal for a chain
                       written before the migration. NOT a failure.
        STRIPPED       an algorithm is named and the signature is gone. Someone removed
                       it, and that is an attack rather than an absence.
        PROTECTED      the signature verified against the supplied public key.
        SIGNATURE_INVALID  it did not.
    """
    alg = getattr(entry, "pq_algorithm", "") or ""
    sig = getattr(entry, "operator_pq_sig", "") or ""

    if not alg and not sig:
        return PQVerification(UNPROTECTED, reason=(
            "no post-quantum signature. This entry is protected by Ed25519 alone, which "
            "NIST removes from its standards by 2035. Not a defect, a chain written "
            "before the migration."))
    if alg and not sig:
        return PQVerification(STRIPPED, algorithm=alg, reason=(
            f"the entry names {alg} but carries no signature for it. An adversary who "
            "cannot forge either signature can still DELETE the post-quantum one to "
            "downgrade the chain to the algorithm they expect to break. This is that."))
    if sig and not alg:
        return PQVerification(STRIPPED, reason=(
            "a post-quantum signature is present but names no algorithm, so it cannot be "
            "verified against any key. The algorithm field was removed or never written."))
    if alg not in KNOWN_ALGORITHMS:
        return PQVerification(UNKNOWN_ALG, algorithm=alg, reason=(
            f"{alg!r} is not an algorithm this build knows. Refused rather than "
            "mis-verified, a chain from a newer build is unreadable here, not broken."))
    if pq_pub is None:
        return PQVerification(UNPROTECTED, algorithm=alg, reason=(
            f"the entry carries an {alg} signature, but no public key was supplied to "
            "check it against. Unverified is reported as unverified, never as valid."))

    try:
        pq_pub.verify(bytes.fromhex(sig), bytes.fromhex(entry.entry_hash))
    except (InvalidSignature, ValueError) as exc:
        return PQVerification(FORGED, algorithm=alg,
                              reason=f"{alg} signature did not verify: {type(exc).__name__}")
    return PQVerification(PROTECTED, algorithm=alg, reason=(
        f"{alg} signature verified over the same entry hash the Ed25519 signature covers"))


def assess_chain(entries: list, pq_pub=None) -> ChainAssessment:
    """How much of this chain outlives Ed25519? Reports a mixture honestly.

    A migration is gradual by nature: old entries have one signature, new ones have two.
    A chain that is 40% protected must report 40%, not round to "protected" because the
    head is.
    """
    a = ChainAssessment(entries=len(entries))
    algs = set()
    for e in entries:
        v = verify_entry(e, pq_pub)
        if v.algorithm:
            algs.add(v.algorithm)
        if v.state == PROTECTED:
            a.protected += 1
        elif v.state == UNPROTECTED:
            a.unprotected += 1
        elif v.state == STRIPPED:
            a.stripped.append(e.seq)
        else:
            a.invalid.append(e.seq)

    a.algorithms = sorted(algs)
    a.fully_protected = bool(entries) and a.protected == len(entries)

    if not entries:
        a.reason = "empty chain"
    elif a.stripped or a.invalid:
        a.reason = (
            f"{len(a.stripped)} stripped and {len(a.invalid)} invalid post-quantum "
            f"signature(s). Stripped entries name an algorithm and carry no signature for "
            f"it, seq {a.stripped or '-'}.")
    elif a.fully_protected:
        a.reason = (f"all {len(entries)} entries carry a verified {', '.join(a.algorithms)} "
                    "signature alongside Ed25519, so the chain survives the deprecation of "
                    "either algorithm alone")
    elif a.protected:
        a.reason = (f"{a.protected} of {len(entries)} entries are post-quantum protected; "
                    f"{a.unprotected} rely on Ed25519 alone. A migration in progress, "
                    "reported as a mixture rather than rounded to either end.")
    else:
        a.reason = (f"none of {len(entries)} entries carry a post-quantum signature. The "
                    "chain is protected by Ed25519 alone, which NIST removes from its "
                    "standards by 2035.")
    return a


def describe() -> dict:
    """What this module claims, for the certificate, and what it does not."""
    return {
        "algorithm": ALGORITHM,
        "standard": "NIST FIPS 204 (ML-DSA), finalised 13 August 2024",
        "why": (
            "Ed25519 is an elliptic-curve signature. NIST deprecates ECC P-256 by 2030 and "
            "removes quantum-vulnerable algorithms from its standards by 2035, while "
            "Indian criminal proceedings routinely run 10-20 years through appeal. A chain "
            "signed in 2026 may be examined after the algorithm that signed it has left "
            "the standards."),
        "claimed": (
            "That this chain carries a signature made with an algorithm NIST expects to "
            "still accept in 2040, alongside the classical one."),
        "not_claimed": (
            "That quantum computers will break Ed25519 by any particular date, that is "
            "unknowable and unnecessary to the argument. And not that post-quantum "
            "chain-of-custody is our idea: the literature already recommends it. The claim "
            "is first implementer, not first thinker."),
    }
