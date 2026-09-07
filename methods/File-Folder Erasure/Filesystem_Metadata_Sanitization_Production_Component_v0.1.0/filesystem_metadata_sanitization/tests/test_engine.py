import json, os, stat
from pathlib import Path
from metadata_sanitizer.engine import inspect_metadata, sanitize_metadata, write_audit


def test_inventory(tmp_path):
    p=tmp_path/"secret.txt"
    p.write_text("secret")
    d=inspect_metadata(p)
    assert d["size"]==6
    assert d["name"]=="secret.txt"


def test_timestamp_normalization(tmp_path):
    p=tmp_path/"file"
    p.write_text("x")
    r=sanitize_metadata(p,normalize_times=True)
    assert r.status=="SANITIZED" and r.timestamps_normalized
    st=p.stat()
    assert st.st_atime_ns==0 and st.st_mtime_ns==0


def test_xattr_if_supported(tmp_path):
    p=tmp_path/"file"
    p.write_text("x")
    if not hasattr(os,"setxattr"):
        return
    try:
        os.setxattr(p,"user.sanitization_test",b"secret",follow_symlinks=False)
    except OSError:
        return
    r=sanitize_metadata(p,clear_xattrs=True)
    assert r.status=="SANITIZED"
    assert "user.sanitization_test" not in os.listxattr(p,follow_symlinks=False)


def test_permission_normalization_on_posix(tmp_path):
    if os.name=="nt":
        return
    p=tmp_path/"file"
    p.write_text("x")
    os.chmod(p,0o777)
    r=sanitize_metadata(p,normalize_permissions=True)
    assert r.status=="SANITIZED"
    assert stat.S_IMODE(p.stat().st_mode)==0o600


def test_rename(tmp_path):
    p=tmp_path/"secret.txt"
    p.write_text("x")
    r=sanitize_metadata(p,rename=True,name_token="sanitized")
    assert r.status=="SANITIZED" and r.renamed
    new=Path(r.new_name)
    assert new.exists()
    assert new.name.startswith(".sanitized-")


def test_symlink_refused(tmp_path):
    p=tmp_path/"real"; p.write_text("x")
    link=tmp_path/"link"; link.symlink_to(p)
    r=sanitize_metadata(link,normalize_times=True)
    assert r.status=="ERROR"
    assert p.read_text()=="x"


def test_recursive(tmp_path):
    d=tmp_path/"tree"; d.mkdir()
    (d/"a").write_text("a")
    (d/"b").mkdir()
    (d/"b"/"c").write_text("c")
    r=sanitize_metadata(d,normalize_times=True,recursive=True)
    assert r.status=="SANITIZED"
    assert (d/"a").stat().st_mtime_ns==0
    assert (d/"b"/"c").stat().st_mtime_ns==0


def test_audit(tmp_path):
    p=tmp_path/"file"; p.write_text("x")
    r=sanitize_metadata(p,normalize_times=True)
    out=write_audit(tmp_path/"audit.json",r)
    data=json.loads(out.read_text())
    assert data["method"]=="filesystem-metadata-sanitization"
    assert data["result"]["status"]=="SANITIZED"
