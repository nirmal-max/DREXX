from __future__ import annotations
from dataclasses import dataclass, asdict
from pathlib import Path
import json, os, secrets, stat, time

class SlackError(RuntimeError):
    pass

@dataclass(frozen=True)
class SlackResult:
    target: str
    status: str
    logical_size: int
    allocation_unit: int | None
    tail_offset: int | None
    tail_length: int
    pattern: str
    verified: bool
    started_utc: str
    completed_utc: str
    error: str | None = None
    def to_dict(self): return asdict(self)

def _utc_now(): return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def calculate_tail(logical_size: int, allocation_unit: int):
    if logical_size < 0 or allocation_unit <= 0: raise ValueError("invalid logical_size or allocation_unit")
    rem = logical_size % allocation_unit
    return logical_size, (0 if rem == 0 else allocation_unit - rem)

class SyntheticBackend:
    """Test-only backend; it never performs raw device I/O."""
    def __init__(self, allocation_unit=4096): self.allocation_unit, self.tails = allocation_unit, {}
    def resolve_tail(self, path): return calculate_tail(path.stat().st_size, self.allocation_unit)
    def sanitize(self, path, offset, length, pattern):
        if length == 0: return
        if pattern == "zero": data = b"\x00" * length
        elif pattern == "random": data = secrets.token_bytes(length)
        else: raise ValueError("pattern must be zero or random")
        self.tails[Path(path)] = data
    def verify(self, path, offset, length, pattern):
        if length == 0: return True
        data = self.tails.get(Path(path), b"")
        if len(data) != length: return False
        if pattern == "zero": return not any(data)
        if pattern == "random": return True
        raise ValueError("pattern must be zero or random")

class UnsupportedBackend:
    def resolve_tail(self, path): raise SlackError("unsupported filesystem/layout: no proven cluster-tip mapping")
    def sanitize(self, *args, **kwargs): raise SlackError("backend does not support sanitization")
    def verify(self, *args, **kwargs): return False

def sanitize_tail(target, *, backend=None, pattern="zero", verify=True):
    path, started = Path(target), _utc_now()
    try:
        st = path.lstat()
        if stat.S_ISLNK(st.st_mode): raise SlackError("refusing symbolic link")
        if not stat.S_ISREG(st.st_mode): raise SlackError("target must be a regular file")
        if pattern not in {"zero", "random"}: raise ValueError("pattern must be zero or random")
        if not verify: raise SlackError("verification is required for sanitization")
        backend = backend or UnsupportedBackend()
        logical_size = st.st_size
        offset, length = backend.resolve_tail(path)
        if length == 0: return SlackResult(str(path), "NO_SLACK", logical_size, None, offset, 0, pattern, True, started, _utc_now())
        backend.sanitize(path, offset, length, pattern)
        if not backend.verify(path, offset, length, pattern): raise SlackError("slack verification failed")
        if path.stat().st_size != logical_size: raise SlackError("logical file size changed during sanitization")
        return SlackResult(str(path), "SANITIZED", logical_size, None, offset, length, pattern, True, started, _utc_now())
    except Exception as exc:
        return SlackResult(str(path), "ERROR", path.stat().st_size if path.exists() else 0, None, None, 0, pattern, False, started, _utc_now(), str(exc))

def write_audit(path, result):
    record={"schema":"secure-erasure.audit.v1","method":"file-slack-cluster-tip-sanitization","created_utc":_utc_now(),"result":result.to_dict(),"assurance_note":"Only backend-proven cluster-tip locations are eligible."}
    out=Path(path); out.parent.mkdir(parents=True, exist_ok=True); tmp=out.with_suffix(out.suffix+".tmp")
    tmp.write_text(json.dumps(record,indent=2,sort_keys=True),encoding="utf-8"); os.replace(tmp,out); return out
