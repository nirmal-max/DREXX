import json
import pytest
from crypto_eraser.engine import LocalKeyStore, create_envelope, save_envelope, load_envelope, decrypt_envelope, destroy_key, verify_erasure, write_audit, CryptoErasureError


def test_key_lifecycle(tmp_path):
    ks=LocalKeyStore(tmp_path/"keys")
    ks.create_key("customer-data")
    assert ks.exists("customer-data")
    assert len(ks.get_key("customer-data"))==32
    destroy_key(ks,"customer-data")
    assert not ks.exists("customer-data")


def test_encryption_roundtrip(tmp_path):
    ks=LocalKeyStore(tmp_path/"keys"); ks.create_key("k")
    env=create_envelope(ks,"k",b"secret", "object-1")
    assert decrypt_envelope(ks,env)==b"secret"


def test_cryptographic_erasure_makes_data_undecryptable(tmp_path):
    ks=LocalKeyStore(tmp_path/"keys"); ks.create_key("k")
    env=create_envelope(ks,"k",b"secret-data", "object-1")
    p=tmp_path/"encrypted.json"; save_envelope(p,env)
    destroy_key(ks,"k")
    ok,reason=verify_erasure(ks,load_envelope(p))
    assert ok and reason=="key-unavailable"
    with pytest.raises(CryptoErasureError):
        decrypt_envelope(ks,env)


def test_ciphertext_survives_key_destruction(tmp_path):
    ks=LocalKeyStore(tmp_path/"keys"); ks.create_key("k")
    env=create_envelope(ks,"k",b"secret-data","object-1")
    before=env.ciphertext_b64
    destroy_key(ks,"k")
    assert env.ciphertext_b64==before


def test_audit_has_no_secret(tmp_path):
    out=write_audit(tmp_path/"audit.json",action="destroy-key",key_id="k",target_id="object",status="SANITIZED")
    data=json.loads(out.read_text())
    assert data["secrets_recorded"] is False
    assert "key_id" not in data
    assert len(data["key_id_hash"])==64


def test_bad_aad_is_not_accepted(tmp_path):
    ks=LocalKeyStore(tmp_path/"keys"); ks.create_key("k")
    env=create_envelope(ks,"k",b"secret","object-1")
    tampered=env.__class__(env.version,env.key_id,env.nonce_b64,env.ciphertext_b64,env.aad_b64,"object-2")
    with pytest.raises(CryptoErasureError, match="AAD/target mismatch"):
        decrypt_envelope(ks,tampered)


def test_verification_does_not_treat_unexpected_backend_error_as_success(tmp_path):
    class BrokenStore:
        def exists(self, key_id): return False
        def get_key(self, key_id): raise OSError("backend unavailable")
    ks=BrokenStore()
    env=create_envelope(LocalKeyStore(tmp_path/"keys"), "k", b"x", "obj") if False else None
    from crypto_eraser.engine import Envelope
    env=Envelope(1,"k","AA==","AA==","b2Jq","obj")
    ok,reason=verify_erasure(ks,env)
    assert ok is False
    assert reason=="verification-error"
