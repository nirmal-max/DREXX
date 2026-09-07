from __future__ import annotations
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib, json, os, secrets, stat, time
from .catalog import TraceRule, baseline_rules, expand_rule

class TraceError(RuntimeError):
    pass

@dataclass(frozen=True)
class ScanItem:
    rule_id: str
    label: str
    path: str
    kind: str
    size: int
    eligible: bool
    reason: str | None = None
    def to_dict(self): return asdict(self)

@dataclass(frozen=True)
class SanitizationResult:
    status: str
    requested_root: str
    items_seen: int
    items_deleted: int
    bytes_deleted: int
    overwritten_items: int
    verified_items: int
    skipped_items: int
    started_utc: str
    completed_utc: str
    errors: tuple[str, ...]
    def to_dict(self): return asdict(self)

def _utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def _canonical(p: Path):
    try: return p.resolve(strict=False)
    except OSError: return Path(os.path.abspath(p))

def _dangerous_root(p: Path):
    c=_canonical(p); home=_canonical(Path.home()); cwd=_canonical(Path.cwd())
    return c == Path(c.anchor) or c == home or c == cwd

def _safe_entry(p: Path):
    try: st=p.lstat()
    except OSError as e: return False, str(e)
    if stat.S_ISLNK(st.st_mode): return False, "symbolic link/reparse-point-like entry"
    if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)): return False, "not regular file or directory"
    return True, None

def scan(root, *, rule_id="custom", label="Explicit trace target"):
    root=Path(root)
    if not root.exists(): raise TraceError(f"target does not exist: {root}")
    if _dangerous_root(root): raise TraceError("refusing dangerous root target")
    items=[]
    ok,reason=_safe_entry(root)
    if not ok:
        items.append(ScanItem(rule_id,label,str(root),"unknown",0,False,reason)); return items
    for p in [root] + list(root.rglob("*")):
        ok,reason=_safe_entry(p)
        if not ok:
            items.append(ScanItem(rule_id,label,str(p),"skipped",0,False,reason)); continue
        st=p.stat(); kind="directory" if stat.S_ISDIR(st.st_mode) else "file"
        items.append(ScanItem(rule_id,label,str(p),kind,st.st_size,True))
    return items

def _write_all(f, data):
    view=memoryview(data); total=0
    while total < len(view):
        n=f.write(view[total:])
        if n is None or n <= 0: raise OSError("short write: no progress")
        total += n

def _hash_stream(path: Path, chunk=1024*1024):
    h=hashlib.sha256()
    with path.open("rb", buffering=0) as f:
        while True:
            block=f.read(chunk)
            if not block: break
            h.update(block)
    return h.digest()

def _secure_overwrite(path: Path, chunk=1024*1024):
    size=path.stat().st_size
    expected=hashlib.sha256()
    with path.open("r+b", buffering=0) as f:
        left=size
        while left:
            n=min(chunk,left)
            block=secrets.token_bytes(n)
            expected.update(block)
            _write_all(f,block)
            left-=n
        f.flush(); os.fsync(f.fileno())
    if path.stat().st_size != size:
        raise TraceError(f"verification failed: file size changed during overwrite: {path}")
    actual=_hash_stream(path,chunk)
    if actual != expected.digest():
        raise TraceError(f"verification failed: post-overwrite content mismatch: {path}")
    return True

def sanitize(root, *, secure_overwrite=False, verify=False, recursive=True, rule_id="custom", label="Explicit trace target"):
    started=_utc_now(); root=Path(root)
    if not verify:
        return SanitizationResult("ERROR",str(root),0,0,0,0,0,0,started,_utc_now(),("verification is required for destructive sanitization",))
    try: items=scan(root,rule_id=rule_id,label=label)
    except Exception as e: return SanitizationResult("ERROR",str(root),0,0,0,0,0,0,started,_utc_now(),(str(e),))
    errors=[]; deleted=bytes_deleted=overwritten=verified=skipped=0
    for item in sorted(items,key=lambda x:(x.kind!="file",len(Path(x.path).parts))):
        p=Path(item.path)
        if not item.eligible: skipped+=1; continue
        if item.kind=="file":
            try:
                if secure_overwrite: _secure_overwrite(p); overwritten+=1
                size=p.stat().st_size; p.unlink(); deleted+=1; bytes_deleted+=size
                if p.exists(): raise TraceError(f"verification failed: target still exists after deletion: {p}")
                verified+=1
            except (OSError,TraceError) as e: errors.append(f"{p}: {e}")
        elif item.kind=="directory":
            try: p.rmdir()
            except OSError: pass
    try:
        if root.exists() and root.is_dir() and not any(root.iterdir()): root.rmdir()
    except OSError as e: errors.append(f"{root}: {e}")
    status="ERROR" if errors else "SANITIZED"
    return SanitizationResult(status,str(root),len(items),deleted,bytes_deleted,overwritten,verified,skipped,started,_utc_now(),tuple(errors))

def write_audit(path,result):
    record={"schema":"secure-erasure.audit.v1","method":"temporary-cache-residual-trace-sanitization","created_utc":_utc_now(),"result":result.to_dict(),"assurance_note":"Covers only explicitly selected, currently addressable trace locations. It does not establish destruction of journals, snapshots, backups, replicas, swap/pagefile, memory, or controller-level physical copies."}
    out=Path(path); out.parent.mkdir(parents=True,exist_ok=True); tmp=out.with_suffix(out.suffix+".tmp")
    tmp.write_text(json.dumps(record,indent=2,sort_keys=True),encoding="utf-8"); os.replace(tmp,out); return out
