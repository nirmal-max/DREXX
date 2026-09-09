"""
Key generation and persistence for the operator key.

PROVENANCE: the failure modes guarded here were found in AetherProof's keystore , 
(a) a home directory captured at import time silently ignored the env var for half the
tool, so two halves of one program disagreed about where the key lived; (b) a
CWD-relative default path forked the record per working directory. Both are fixed by
reading the environment on every call and resolving to an absolute path.

HONEST LIMIT (docs/ENGINEERING_RULES.md rule 4): this is a software key on the operator's own machine.
File permissions are not a secret. Set AKHANDA_KEY_PASSPHRASE and the PEM is encrypted
at rest; leave it unset and anyone who can read the file can sign as the operator. The
ESP32 does not fix this, it confirms presence, it does not hold the key.
"""

from __future__ import annotations
import os
import stat
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

HOME_ENV = "AKHANDA_HOME"
PASSPHRASE_ENV = "AKHANDA_KEY_PASSPHRASE"


def home() -> Path:
    """Where keys, the chain, and certificates live.

    Read from the environment on EVERY call, never captured at import.
    """
    d = os.environ.get(HOME_ENV)
    return Path(d).resolve() if d else (Path.home() / ".akhanda").resolve()


def operator_key_path() -> Path:
    return home() / "operator_key.pem"


def operator_pub_path() -> Path:
    return home() / "operator_pub.pem"


def witness_pub_path() -> Path:
    """Cached copy of the witness's concurring public key.

    Cached on purpose. Verification must work when the Pi is switched off, seized, or
    on a different network, a verifier who must reach the witness to check a signature
    has a chain of custody that expires with an IP address. The key is public, so
    caching it costs nothing and removes a live dependency from the verify path.
    """
    return home() / "witness_pub.pem"


def _passphrase() -> Optional[bytes]:
    p = os.environ.get(PASSPHRASE_ENV)
    return p.encode("utf-8") if p else None


def _restrict(path: Path) -> None:
    """Best effort 0600. On Windows the POSIX bits are advisory, so this is not a
    security control there, it is stated rather than relied on."""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def save_private_key(key: Ed25519PrivateKey, path: Optional[Path] = None) -> Path:
    path = Path(path) if path else operator_key_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    pw = _passphrase()
    enc = (serialization.BestAvailableEncryption(pw) if pw
           else serialization.NoEncryption())
    path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    ))
    _restrict(path)
    return path


def save_public_key(pub: Ed25519PublicKey, path: Optional[Path] = None) -> Path:
    path = Path(path) if path else operator_pub_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    return path


def load_private_key(path: Optional[Path] = None) -> Ed25519PrivateKey:
    path = Path(path) if path else operator_key_path()
    key = serialization.load_pem_private_key(path.read_bytes(), password=_passphrase())
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"{path} is not an Ed25519 private key")
    return key


def load_public_key(path: Optional[Path] = None) -> Ed25519PublicKey:
    path = Path(path) if path else operator_pub_path()
    pub = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(pub, Ed25519PublicKey):
        raise TypeError(f"{path} is not an Ed25519 public key")
    return pub


def load_or_create_operator_key() -> Ed25519PrivateKey:
    """Load the operator key, generating one on first use. Idempotent."""
    path = operator_key_path()
    if path.exists():
        return load_private_key(path)
    key = Ed25519PrivateKey.generate()
    save_private_key(key, path)
    save_public_key(key.public_key(), operator_pub_path())
    return key


def cache_witness_key(pub: Ed25519PublicKey) -> Path:
    """Store the witness public key locally so verification never needs the network."""
    return save_public_key(pub, witness_pub_path())


def load_witness_key() -> Optional[Ed25519PublicKey]:
    """The cached witness key, or None if we have never spoken to a witness.

    None means "not checked", never "no witness signature exists". The caller must not
    treat an absent key as agreement.
    """
    path = witness_pub_path()
    if not path.exists():
        return None
    try:
        return load_public_key(path)
    except (OSError, ValueError, TypeError):
        return None


def public_key_hex(pub: Ed25519PublicKey) -> str:
    """Raw 32-byte public key as hex, the form the witness node returns."""
    return pub.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def public_key_from_hex(hex_str: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_str))
