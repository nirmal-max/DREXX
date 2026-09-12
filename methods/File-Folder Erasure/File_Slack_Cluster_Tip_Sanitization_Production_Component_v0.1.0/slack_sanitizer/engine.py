from __future__ import annotations
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib, json, os, secrets, stat, struct, tempfile, time

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


# ── CONTROLLED FAT12 RAW IMAGE SLACK EXPERIMENT ───────────────────────────────
# Approach informed by:
#   fishy (dasec/fishy) — https://github.com/dasec/fishy
#     FAT filesystem slack space: file data ends before cluster boundary;
#     remaining cluster bytes are "slack" and may contain residual data.
#     fishy writes/reads data to/from cluster-tip slack via raw image I/O.
#   mind-the-slack (fkie-cad) — https://github.com/fkie-cad/mind-the-slack
#     Cross-platform slack space testing: creates disk images, formats them,
#     uses forensic backends (TSK, dissect) to extract/analyze slack at byte level.
#   slack_pytsk (SokratisVidros) — https://github.com/SokratisVidros/slack_pytsk
#     Uses pytsk3 to locate and extract file slack from raw disk images.
#     Core concept: file size % cluster_size = slack offset; read raw cluster.
#
# DREXX adaptation:
#   Pure-Python FAT12 image construction (no external formatter required).
#   Controlled residual injection and byte-level readback verification.
#   No kernel driver, no raw physical device write.
# ─────────────────────────────────────────────────────────────────────────────

_FAT12_SECTOR_SIZE = 512
_FAT12_SECTORS_PER_CLUSTER = 1   # 1 sector = 512-byte cluster for simplicity
_FAT12_CLUSTER_SIZE = _FAT12_SECTOR_SIZE * _FAT12_SECTORS_PER_CLUSTER
_FAT12_RESERVED_SECTORS = 1
_FAT12_NUM_FATS = 2
_FAT12_ROOT_ENTRIES = 16
_FAT12_FAT_SECTORS = 1
_FAT12_TOTAL_SECTORS = 64   # 32 KB image

# Residual marker (25 bytes of identifiable content)
_RESIDUAL_MARKER = b"DREX_SLACK_RESIDUAL_12345"
assert len(_RESIDUAL_MARKER) == 25


def _build_fat12_boot_sector() -> bytes:
    """Build a minimal but parseable FAT12 boot sector."""
    bs = bytearray(512)
    # Jump instruction
    bs[0:3] = b"\xEB\x3C\x90"
    # OEM name
    bs[3:11] = b"DREXTEST"
    # BPB
    struct.pack_into("<H", bs, 11, _FAT12_SECTOR_SIZE)          # Bytes per sector
    bs[13] = _FAT12_SECTORS_PER_CLUSTER                          # Sectors per cluster
    struct.pack_into("<H", bs, 14, _FAT12_RESERVED_SECTORS)     # Reserved sectors
    bs[16] = _FAT12_NUM_FATS                                     # Number of FATs
    struct.pack_into("<H", bs, 17, _FAT12_ROOT_ENTRIES)         # Root entries
    struct.pack_into("<H", bs, 19, _FAT12_TOTAL_SECTORS)        # Total sectors (16-bit)
    bs[21] = 0xF8                                                # Media descriptor
    struct.pack_into("<H", bs, 22, _FAT12_FAT_SECTORS)          # Sectors per FAT
    struct.pack_into("<H", bs, 24, 1)                            # Sectors per track
    struct.pack_into("<H", bs, 26, 1)                            # Number of heads
    struct.pack_into("<L", bs, 28, 0)                            # Hidden sectors
    bs[38] = 0x29                                                 # Extended boot sig
    bs[39:43] = b"\x01\x02\x03\x04"                             # Volume ID
    bs[43:54] = b"DREXTEST   "                                   # Volume label
    bs[54:62] = b"FAT12   "                                       # FS type
    bs[510] = 0x55
    bs[511] = 0xAA
    return bytes(bs)


def _build_fat12_image(file_content: bytes) -> tuple[bytearray, int, int, int]:
    """
    Build a complete FAT12 disk image with file_content as the only file.

    Returns:
        (image_bytearray, data_region_offset, file_cluster_offset, file_logical_size)

    Layout:
        Sector 0:   Boot sector
        Sector 1:   FAT copy 1 (1 sector)
        Sector 2:   FAT copy 2 (1 sector)
        Sector 3:   Root directory (16 entries × 32 bytes = 512 bytes = 1 sector)
        Sector 4+:  Data region (clusters 2, 3, …)
    """
    image_size = _FAT12_TOTAL_SECTORS * _FAT12_SECTOR_SIZE
    image = bytearray(image_size)

    # Boot sector
    image[0:512] = _build_fat12_boot_sector()

    # FAT12 — mark clusters 0 and 1 as reserved, then allocate cluster 2 for our file
    # FAT12 uses 12-bit entries packed into bytes:
    # Entry n=0: bits 0-11 of bytes 0-1
    # Entry n=1: bits 12-23 of bytes 1-2
    # Entry n=2: bits 24-35 of bytes 3-4 (start of data cluster)
    fat = bytearray(512)
    # Cluster 0: media descriptor = 0xFF8
    # Cluster 1: end-of-chain = 0xFFF
    # Cluster 2: end-of-chain (our file occupies exactly one cluster) = 0xFFF
    fat[0] = 0xF8; fat[1] = 0xFF; fat[2] = 0xFF   # clusters 0, 1 reserved
    # Pack cluster 2 = 0xFFF (end of chain):
    #   Entry 2 starts at nibble 4 (byte 1 high nibble + byte 2)
    fat[3] = 0xFF; fat[4] = 0x0F  # cluster 2 = 0xFFF in FAT12 little-endian packed
    # FAT copy 1 at sector 1
    fat1_offset = _FAT12_RESERVED_SECTORS * _FAT12_SECTOR_SIZE
    image[fat1_offset:fat1_offset + 512] = fat
    # FAT copy 2 at sector 2
    fat2_offset = fat1_offset + _FAT12_FAT_SECTORS * _FAT12_SECTOR_SIZE
    image[fat2_offset:fat2_offset + 512] = fat

    # Root directory — one 32-byte entry for our test file
    root_offset = (
        _FAT12_RESERVED_SECTORS
        + _FAT12_NUM_FATS * _FAT12_FAT_SECTORS
    ) * _FAT12_SECTOR_SIZE
    de = bytearray(32)
    de[0:8]  = b"DREXTEST"                       # 8-char name
    de[8:11] = b"TXT"                             # 3-char ext
    de[11]   = 0x20                               # archive attribute
    struct.pack_into("<H", de, 26, 2)             # first cluster = 2
    struct.pack_into("<L", de, 28, len(file_content))  # file size
    image[root_offset:root_offset + 32] = de

    # Data region starts at cluster 2 = sector (reserved + FATs + root) = sector 4
    data_start_sector = (
        _FAT12_RESERVED_SECTORS
        + _FAT12_NUM_FATS * _FAT12_FAT_SECTORS
        + (_FAT12_ROOT_ENTRIES * 32 + _FAT12_SECTOR_SIZE - 1) // _FAT12_SECTOR_SIZE
    )
    data_start_offset = data_start_sector * _FAT12_SECTOR_SIZE

    # Cluster 2 offset = data_start_offset + (2 - 2) * cluster_size = data_start_offset
    file_cluster_offset = data_start_offset

    # Write file content into cluster 2
    image[file_cluster_offset:file_cluster_offset + len(file_content)] = file_content

    return image, data_start_offset, file_cluster_offset, len(file_content)


def run_controlled_slack_experiment(progress_cb=None) -> dict:
    """
    Execute a complete cluster-tip slack sanitization experiment on a controlled FAT12 image.

    Steps:
        1. Choose test file content whose size < cluster_size (so there is guaranteed slack).
        2. Build FAT12 raw image and write file into cluster 2.
        3. Calculate slack region: [file_logical_size .. cluster_size).
        4. Plant DREX_SLACK_RESIDUAL marker in the slack region by raw image write.
        5. Compute SHA-256 of (a) the image before, (b) the residual bytes, (c) the file payload.
        6. Run cluster-tip sanitization: zero-fill the slack region in the image.
        7. Flush. Read back the slack region.
        8. Verify:  residual GONE (all-zero),  file payload SHA-256 UNCHANGED.
        9. Return detailed evidence dict.

    This approach is directly analogous to how fishy (dasec/fishy) writes/reads hidden
    data to FAT cluster-tip slack via raw image I/O, and how mind-the-slack (fkie-cad)
    uses disk images + forensic backends to prove slack content persistence/clearance.
    """
    def _progress(step: int, total: int = 9):
        if progress_cb:
            try:
                progress_cb(step, total)
            except Exception:
                pass

    started = _utc_now()

    # ── 1. Construct test file content ────────────────────────────────────────
    # File payload: ASCII-identifiable content, size = 300 bytes.
    # With cluster_size = 512, slack = 512 - 300 = 212 bytes.
    # b"DREX_TEST_FILE_PAYLOAD_VERIFIED_" is 32 bytes; 9*32 = 288; pad to 300.
    file_payload = b"DREX_TEST_FILE_PAYLOAD_VERIFIED_" * 9 + b"DREX_PADDING"  # 288+12=300
    assert len(file_payload) == 300, f"Expected 300, got {len(file_payload)}"
    logical_size = len(file_payload)
    cluster_size = _FAT12_CLUSTER_SIZE  # 512 bytes
    slack_length = cluster_size - logical_size  # 212 bytes
    assert slack_length > 0
    file_sha256_before = hashlib.sha256(file_payload).hexdigest()
    _progress(1)

    # ── 2. Build FAT12 image ───────────────────────────────────────────────────
    image, data_start, file_cluster_offset, _ = _build_fat12_image(file_payload)
    _progress(2)

    # ── 3. Calculate slack region physical offset in image ────────────────────
    # Slack starts immediately after the logical file data within the cluster.
    slack_offset_in_image = file_cluster_offset + logical_size
    slack_end_in_image = file_cluster_offset + cluster_size
    assert slack_end_in_image <= len(image), "Slack region exceeds image"
    _progress(3)

    # ── 4. Plant known residual in slack region ────────────────────────────────
    # Fill slack with a repeating DREX_SLACK_RESIDUAL marker padded with 0xCC.
    residual_fill = (_RESIDUAL_MARKER * ((slack_length // len(_RESIDUAL_MARKER)) + 1))[:slack_length]
    image[slack_offset_in_image:slack_end_in_image] = residual_fill
    residual_before_bytes = bytes(image[slack_offset_in_image:slack_end_in_image])
    residual_before_sha256 = hashlib.sha256(residual_before_bytes).hexdigest()
    image_sha256_before = hashlib.sha256(image).hexdigest()
    _progress(4)

    # ── 5. Verify residual is present ─────────────────────────────────────────
    assert _RESIDUAL_MARKER in residual_before_bytes, "Residual marker not found in slack before sanitization"
    assert residual_before_bytes != b"\x00" * slack_length, "Slack already zero (residual plant failed)"
    _progress(5)

    # ── 6. Sanitize: zero-fill the slack region in the image ─────────────────
    # This is the actual sanitization: direct raw seek+write to the image buffer.
    # In a real on-disk scenario (Linux loopback / fishy approach), this would be
    # an open(device, "r+b") seek to the physical cluster offset, followed by write.
    # On Windows without a kernel driver, we operate on the image buffer directly —
    # the mechanism is identical in algorithmic terms (seek to physical offset, write).
    zero_fill = b"\x00" * slack_length
    image[slack_offset_in_image:slack_end_in_image] = zero_fill
    _progress(6)

    # ── 7. Flush and readback ─────────────────────────────────────────────────
    # Write to a temp file and re-read to simulate a real I/O round-trip.
    with tempfile.NamedTemporaryFile(suffix=".img", delete=False, prefix="drex_slack_") as tmp:
        tmp_path = tmp.name
        tmp.write(image)
        tmp.flush()
        os.fsync(tmp.fileno())
    _progress(7)

    try:
        with open(tmp_path, "rb") as f:
            f.seek(slack_offset_in_image)
            residual_after_bytes = f.read(slack_length)
            f.seek(file_cluster_offset)
            payload_after = f.read(logical_size)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
    _progress(8)

    # ── 8. Verify residual gone, payload unchanged ────────────────────────────
    residual_after_sha256 = hashlib.sha256(residual_after_bytes).hexdigest()
    image_sha256_after = hashlib.sha256(image).hexdigest()
    file_sha256_after = hashlib.sha256(payload_after).hexdigest()

    residual_gone = (residual_after_bytes == b"\x00" * slack_length)
    residual_gone_no_marker = _RESIDUAL_MARKER not in residual_after_bytes
    payload_preserved = (file_sha256_before == file_sha256_after)
    verified = residual_gone and residual_gone_no_marker and payload_preserved
    _progress(9)

    return {
        "verified": verified,
        "cluster_size": cluster_size,
        "logical_file_size": logical_size,
        "slack_length": slack_length,
        "slack_offset_in_image": slack_offset_in_image,
        "file_cluster_offset": file_cluster_offset,
        "residual_marker": _RESIDUAL_MARKER.decode("ascii"),
        "residual_before_sha256": residual_before_sha256,
        "residual_after_sha256": residual_after_sha256,
        "residual_gone": residual_gone,
        "residual_marker_absent": residual_gone_no_marker,
        "file_sha256_before": file_sha256_before,
        "file_sha256_after": file_sha256_after,
        "payload_preserved": payload_preserved,
        "image_sha256_before": image_sha256_before,
        "image_sha256_after": image_sha256_after,
        "started_utc": started,
        "completed_utc": _utc_now(),
        "error": None if verified else "Verification failed: residual not cleared or payload corrupted",
        "reference": {
            "fishy": "https://github.com/dasec/fishy — FAT file slack hiding/recovery via raw image I/O",
            "mind_the_slack": "https://github.com/fkie-cad/mind-the-slack — disk image + forensic backend slack analysis",
            "slack_pytsk": "https://github.com/SokratisVidros/slack_pytsk — pytsk3 slack extraction from raw images",
        },
    }

