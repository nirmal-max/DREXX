import json, os
from pathlib import Path
from trace_sanitizer.engine import scan,sanitize,write_audit


def test_scan_finds_nested_files(tmp_path):
    d=tmp_path/"cache"; d.mkdir()
    (d/"one.tmp").write_bytes(b"a"*3)
    (d/"sub").mkdir()
    (d/"sub"/"two.tmp").write_bytes(b"bb")
    items=scan(d)
    files=[x for x in items if x.kind=="file"]
    assert len(files)==2


def test_dry_scan_does_not_change(tmp_path):
    d=tmp_path/"cache"; d.mkdir()
    p=d/"x"; p.write_text("secret")
    before=p.read_bytes()
    items=scan(d)
    assert p.exists() and p.read_bytes()==before
    assert any(x.path==str(p) for x in items)


def test_sanitize_deletes_current_trace(tmp_path):
    d=tmp_path/"cache"; d.mkdir()
    (d/"a").write_bytes(b"a"*10)
    (d/"b").write_bytes(b"b"*20)
    r=sanitize(d,verify=True)
    assert r.status=="SANITIZED"
    assert r.items_deleted==2
    assert r.bytes_deleted==30
    assert not d.exists()


def test_secure_overwrite_and_verify(tmp_path):
    d=tmp_path/"cache"; d.mkdir()
    (d/"a").write_bytes(os.urandom(8192))
    r=sanitize(d,secure_overwrite=True,verify=True)
    assert r.status=="SANITIZED"
    assert r.overwritten_items==1
    assert r.verified_items==1


def test_symlink_not_followed(tmp_path):
    d=tmp_path/"cache"; d.mkdir()
    real=tmp_path/"real"; real.write_text("KEEP")
    link=d/"link"; link.symlink_to(real)
    r=sanitize(d,verify=True)
    assert real.read_text()=="KEEP"
    assert r.skipped_items>=1


def test_dangerous_root_rejected():
    from trace_sanitizer.engine import scan,TraceError
    import pathlib
    try:
        scan(pathlib.Path.cwd())
    except TraceError:
        return
    raise AssertionError("cwd should be rejected")


def test_audit(tmp_path):
    d=tmp_path/"cache"; d.mkdir()
    (d/"x").write_text("x")
    r=sanitize(d,verify=True)
    out=write_audit(tmp_path/"audit.json",r)
    data=json.loads(out.read_text())
    assert data["method"]=="temporary-cache-residual-trace-sanitization"
    assert data["result"]["status"]=="SANITIZED"
