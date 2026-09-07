import hashlib
import os
import secrets

CHUNK = 4 * 1024 * 1024


def _target_size(f, fallback=None):
    if fallback is not None and fallback >= 0:
        return fallback
    st = os.fstat(f.fileno())
    if not os.path.isfile(f.name):
        raise ValueError("target size is required for non-regular devices")
    return st.st_size


def execute_file(path, passes=("random",), size=None):
    if not isinstance(path, str) or not path:
        raise ValueError("invalid target")
    if os.path.islink(path):
        raise ValueError("refusing symbolic link target")
    with open(path, "r+b", buffering=0) as f:
        target_size = _target_size(f, size)
        results = []
        for pattern in passes:
            if pattern not in ("random", "zero"):
                raise ValueError(f"unsupported overwrite pattern: {pattern}")
            f.seek(0)
            write_hash = hashlib.sha256()
            read_hash = hashlib.sha256()
            offset = 0
            while offset < target_size:
                n = min(CHUNK, target_size - offset)
                data = secrets.token_bytes(n) if pattern == "random" else b"\0" * n
                written = f.write(data)
                if written != n:
                    raise IOError(f"short write at {offset}: {written}/{n}")
                f.flush()
                f.seek(offset)
                got = f.read(n)
                if len(got) != n or got != data:
                    raise IOError(f"read-back mismatch at {offset}")
                write_hash.update(data)
                read_hash.update(got)
                offset += n
            os.fsync(f.fileno())
            results.append({"pattern": pattern, "bytes": target_size, "write_sha256": write_hash.hexdigest(), "readback_sha256": read_hash.hexdigest()})
        return results
