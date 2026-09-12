import json
from pathlib import Path

from drex_app import (
    CertificateManager,
    FILE_METHODS,
    DRIVE_METHODS,
    RECOVERY_METHODS,
    Store,
    execute_file_method,
    hash_target,
)


def test_user_facing_method_counts_and_unique_ids():
    assert len(DRIVE_METHODS) == 7
    assert len(FILE_METHODS) == 9
    assert len(RECOVERY_METHODS) == 9
    assert len({m["id"] for m in DRIVE_METHODS}) == 7
    assert len({m["id"] for m in FILE_METHODS}) == 9
    assert len({m[0] for m in RECOVERY_METHODS}) == 9


def test_certificate_is_signed_and_verifiable(tmp_path):
    store = Store(tmp_path / "data")
    manager = CertificateManager(store)
    record = manager.create({
        "type": "file",
        "method": "Single-Pass Zero Overwrite",
        "target": str(tmp_path / "fixture.bin"),
        "target_size": "4 B",
        "started": "2026-09-03T00:00:00Z",
        "completed": "2026-09-03T00:00:01Z",
        "duration": "1s",
        "status": "SUCCESS",
        "verification": "VERIFIED",
        "sha256_before": "a" * 64,
        "sha256_after": "Not applicable after verified removal",
    })
    assert manager.verify(record)
    assert Path(record["pdf_path"]).exists()
    loaded = json.loads((store.certs_dir / f"{record['certificate_id']}.json").read_text())
    assert loaded["qr_payload"]
    loaded["method"] = "tampered"
    assert not manager.verify(loaded)


def test_zero_adapter_removes_and_verifies_file(tmp_path):
    target = tmp_path / "secret.bin"
    target.write_bytes(b"sensitive test payload" * 100)
    before = hash_target(target)
    events = []
    progress = []
    result = execute_file_method("zero", target, events.append, lambda done, total: progress.append((done, total)))
    assert result["verified"] is True
    assert result["removed"] is True
    assert before
    assert not target.exists()
    assert progress
    assert any("zero" in event.lower() for event in events)


def test_unsupported_file_method_fails_closed(tmp_path):
    target = tmp_path / "secret.bin"
    target.write_bytes(b"do not touch")
    try:
        execute_file_method("policy", target, lambda _: None, lambda *_: None)
    except RuntimeError as exc:
        assert "unavailable" in str(exc).lower() or "planning" in str(exc).lower() or "backend" in str(exc).lower()
    else:
        raise AssertionError("unsupported method executed")
    assert target.read_bytes() == b"do not touch"
