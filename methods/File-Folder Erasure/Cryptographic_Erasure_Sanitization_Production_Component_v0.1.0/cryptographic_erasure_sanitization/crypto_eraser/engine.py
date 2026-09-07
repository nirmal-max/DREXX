from __future__ import annotations
from dataclasses import dataclass, asdict
from pathlib import Path
import base64, binascii, hashlib, json, os, secrets, stat, time
from typing import Protocol
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class CryptoErasureError(RuntimeError): pass

def _utc_now(): return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
def _id_hash(value: str): return hashlib.sha256(value.encode()).hexdigest()

def _write_all(fd: int, data: bytes) -> None:
    view=memoryview(data); offset=0
    while offset<len(view):
        n=os.write(fd,view[offset:])
        if n<=0: raise CryptoErasureError("short/failed key-store write")
        offset+=n

class KeyStore(Protocol):
    def create_key(self,key_id:str)->None: ...
    def get_key(self,key_id:str)->bytes: ...
    def destroy_key(self,key_id:str)->None: ...
    def exists(self,key_id:str)->bool: ...

class LocalKeyStore:
    """Reference/testing key store; production should use an authoritative KMS/HSM."""
    def __init__(self,directory):
        self.directory=Path(directory); self.directory.mkdir(parents=True,exist_ok=True)
        try: os.chmod(self.directory,0o700)
        except OSError: pass
    def _path(self,key_id):
        if not key_id or "/" in key_id or "\\" in key_id or key_id in {".",".."}: raise CryptoErasureError("invalid key identifier")
        return self.directory/(key_id+".key")
    def create_key(self,key_id):
        p=self._path(key_id)
        if p.exists(): raise CryptoErasureError("key already exists")
        key=secrets.token_bytes(32); fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_BINARY,0o600)
        try: _write_all(fd,key); os.fsync(fd)
        finally: os.close(fd)
        return True
    def get_key(self,key_id):
        p=self._path(key_id)
        if not p.exists(): raise CryptoErasureError("key not found")
        data=p.read_bytes()
        if len(data)!=32: raise CryptoErasureError("invalid key length")
        return data
    def destroy_key(self,key_id):
        p=self._path(key_id)
        if not p.exists(): raise CryptoErasureError("key not found")
        replacement=secrets.token_bytes(32); fd=os.open(p,os.O_WRONLY|os.O_TRUNC|os.O_BINARY)
        try: _write_all(fd,replacement); os.fsync(fd)
        finally: os.close(fd)
        p.unlink()
        try:
            dfd=os.open(self.directory,os.O_RDONLY)
            try: os.fsync(dfd)
            finally: os.close(dfd)
        except OSError: pass
        return True
    def exists(self,key_id): return self._path(key_id).exists()

@dataclass(frozen=True)
class Envelope:
    version:int; key_id:str; nonce_b64:str; ciphertext_b64:str; aad_b64:str; target_id:str
    def to_dict(self): return asdict(self)

def create_envelope(key_store:KeyStore,key_id:str,plaintext:bytes,target_id:str):
    key=key_store.get_key(key_id); nonce=secrets.token_bytes(12); aad=target_id.encode(); ciphertext=AESGCM(key).encrypt(nonce,plaintext,aad)
    return Envelope(1,key_id,base64.b64encode(nonce).decode(),base64.b64encode(ciphertext).decode(),base64.b64encode(aad).decode(),target_id)

def save_envelope(path,envelope:Envelope):
    p=Path(path); p.parent.mkdir(parents=True,exist_ok=True); tmp=p.with_suffix(p.suffix+".tmp")
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_BINARY,0o600)
    try: _write_all(fd,json.dumps(envelope.to_dict(),sort_keys=True).encode("utf-8")); os.fsync(fd)
    finally: os.close(fd)
    os.replace(tmp,p)

def load_envelope(path):
    try: raw=json.loads(Path(path).read_text(encoding="utf-8")); env=Envelope(**raw)
    except (OSError,ValueError,TypeError,KeyError) as exc: raise CryptoErasureError("invalid envelope") from exc
    if env.version!=1 or not env.key_id or not env.target_id: raise CryptoErasureError("invalid envelope metadata")
    try:
        nonce=base64.b64decode(env.nonce_b64,validate=True); ciphertext=base64.b64decode(env.ciphertext_b64,validate=True); aad=base64.b64decode(env.aad_b64,validate=True)
    except (binascii.Error,ValueError,TypeError) as exc: raise CryptoErasureError("invalid envelope encoding") from exc
    if len(nonce)!=12 or len(ciphertext)<16 or aad!=env.target_id.encode(): raise CryptoErasureError("invalid envelope cryptographic fields")
    return env

def decrypt_envelope(key_store:KeyStore,envelope:Envelope):
    key=key_store.get_key(envelope.key_id); nonce=base64.b64decode(envelope.nonce_b64,validate=True); ciphertext=base64.b64decode(envelope.ciphertext_b64,validate=True); aad=base64.b64decode(envelope.aad_b64,validate=True)
    if envelope.target_id.encode()!=aad: raise CryptoErasureError("envelope AAD/target mismatch")
    return AESGCM(key).decrypt(nonce,ciphertext,aad)

def destroy_key(key_store:KeyStore,key_id:str):
    if not key_store.exists(key_id): raise CryptoErasureError("key does not exist")
    key_store.destroy_key(key_id)
    if key_store.exists(key_id): raise CryptoErasureError("key still exists after destroy")
    return True

def verify_erasure(key_store:KeyStore,envelope:Envelope):
    try: envelope=load_envelope_from_object(envelope)
    except CryptoErasureError: return False,"verification-error"
    if key_store.exists(envelope.key_id): return False,"key-still-present"
    try: decrypt_envelope(key_store,envelope)
    except CryptoErasureError as exc:
        if str(exc)=="key not found": return True,"key-unavailable"
        return False,"verification-error"
    except Exception: return False,"verification-error"
    return False,"decryption-still-succeeded"

def load_envelope_from_object(envelope:Envelope):
    if envelope.version!=1 or not envelope.key_id or not envelope.target_id: raise CryptoErasureError("invalid envelope metadata")
    try:
        nonce=base64.b64decode(envelope.nonce_b64,validate=True); ciphertext=base64.b64decode(envelope.ciphertext_b64,validate=True); aad=base64.b64decode(envelope.aad_b64,validate=True)
    except (binascii.Error,ValueError,TypeError) as exc: raise CryptoErasureError("invalid envelope encoding") from exc
    if len(nonce)!=12 or len(ciphertext)<16 or aad!=envelope.target_id.encode(): raise CryptoErasureError("invalid envelope cryptographic fields")
    return envelope

def write_audit(path,*,action,key_id,target_id,status,details=None):
    record={"schema":"secure-erasure.audit.v1","method":"cryptographic-erasure","action":action,"created_utc":_utc_now(),"key_id_hash":_id_hash(key_id),"target_id_hash":_id_hash(target_id),"status":status,"details":details or {},"secrets_recorded":False}
    out=Path(path); out.parent.mkdir(parents=True,exist_ok=True); tmp=out.with_suffix(out.suffix+".tmp")
    tmp.write_text(json.dumps(record,indent=2,sort_keys=True),encoding="utf-8"); os.replace(tmp,out); return out
