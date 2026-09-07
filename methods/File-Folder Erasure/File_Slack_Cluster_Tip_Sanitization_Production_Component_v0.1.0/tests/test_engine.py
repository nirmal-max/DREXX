import json
import pytest
from slack_sanitizer.engine import calculate_tail, sanitize_tail, SyntheticBackend, write_audit

def test_tail_calculation():
    assert calculate_tail(10000,4096) == (10000,2288)
    assert calculate_tail(8192,4096) == (8192,0)

def test_tail_validation():
    with pytest.raises(ValueError): calculate_tail(-1,4096)
    with pytest.raises(ValueError): calculate_tail(1,0)

def test_zero_tail_sanitization(tmp_path):
    p=tmp_path/"file"; p.write_bytes(b"A"*5000)
    r=sanitize_tail(p,backend=SyntheticBackend(4096),pattern="zero",verify=True)
    assert r.status=="SANITIZED" and r.verified and r.tail_length==3192
    # SyntheticBackend models physical cluster-tip bytes separately and must not
    # change the file's logical length.
    assert p.stat().st_size==5000
    assert SyntheticBackend(4096) is not None

def test_random_tail_sanitization(tmp_path):
    p=tmp_path/"file"; p.write_bytes(b"A"*5000)
    backend=SyntheticBackend(4096)
    r=sanitize_tail(p,backend=backend,pattern="random",verify=True)
    assert r.status=="SANITIZED" and r.verified
    assert len(backend.tails[p])==3192

def test_no_slack(tmp_path):
    p=tmp_path/"file"; p.write_bytes(b"A"*4096)
    r=sanitize_tail(p,backend=SyntheticBackend(4096),verify=True)
    assert r.status=="NO_SLACK" and r.verified

def test_unsupported_backend_refuses(tmp_path):
    p=tmp_path/"file"; p.write_bytes(b"A"*100)
    r=sanitize_tail(p)
    assert r.status=="ERROR" and "unsupported filesystem" in r.error

def test_symlink_refused(tmp_path):
    real=tmp_path/"real"; real.write_bytes(b"A"*100)
    link=tmp_path/"link"; link.symlink_to(real)
    r=sanitize_tail(link,backend=SyntheticBackend())
    assert r.status=="ERROR" and real.read_bytes()==b"A"*100

def test_directory_refused(tmp_path):
    assert sanitize_tail(tmp_path,backend=SyntheticBackend()).status=="ERROR"

def test_invalid_pattern(tmp_path):
    p=tmp_path/"file"; p.write_bytes(b"A")
    assert sanitize_tail(p,backend=SyntheticBackend(),pattern="bad").status=="ERROR"

def test_audit(tmp_path):
    p=tmp_path/"file"; p.write_bytes(b"A"*100)
    r=sanitize_tail(p,backend=SyntheticBackend())
    out=write_audit(tmp_path/"audit.json",r)
    data=json.loads(out.read_text())
    assert data["method"]=="file-slack-cluster-tip-sanitization"
    assert data["result"]["verified"] is True
