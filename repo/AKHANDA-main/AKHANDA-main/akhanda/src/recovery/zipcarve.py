r"""ZIP fragment reassembly, byte-identical, or nothing.

WHY ZIP. PNG proved the method; ZIP proves it matters. `.docx`, `.xlsx`, `.pptx`, `.jar`
and `.apk` are ZIP containers, so a fragmented-ZIP recovery is a fragmented-*document*
recovery. And like PNG, ZIP carries **CRC-32 per entry**, so membership is provable rather
than plausible.

WHAT IS DIFFERENT FROM THE PRIOR ART, PRECISELY. ZIP carving is not new. Garfinkel's 2007
ZIP Carver (DFRWS) locates components and **repackages them with a NEW central directory**
so the result opens in a standard unzip utility. That is right for data recovery and wrong
for evidence: a repackaged archive is a *different file*. Its hash does not match, so it
cannot be matched against a known-file set, cannot be compared to a hash recorded earlier in
a case, and cannot honestly be called "the file that was on the disk".

    This module never repackages. It reconstructs the original byte layout, and if the
    result is not byte-identical it returns NOTHING.

THE DESIGN ERROR THE FIRST ATTEMPT MADE, kept here because it is the whole lesson.
Every offset ZIP records, the central directory's position, each entry's local header, is
**relative to the start of the archive**. In a disk image the archive has no single base to
be relative to, so trusting those offsets reads unrelated bytes. The first version did
exactly that and returned nothing for every fragmented archive, safely and uselessly.

The fix is the instinct that made PNG work: **stop trusting recorded offsets and scan.**
Every structure is found by its own signature and validated by its own checksum, and then
the recorded offsets become useful again in a different way, as a *map* rather than as
addresses:

    delta = where_the_entry_actually_is − where_the_archive_says_it_is

Entries sharing a delta were stored together. **Each distinct delta is a fragment**, and the
count of deltas is the fragment count. That falls out of the format rather than being
estimated.
"""
from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import asdict, dataclass, field
from typing import Optional

EOCD_SIG = b"PK\x05\x06"
CDFH_SIG = b"PK\x01\x02"
LFH_SIG = b"PK\x03\x04"

EOCD_LEN = 22
CDFH_MIN = 46
LFH_MIN = 30
MAX_ENTRIES = 1 << 16
MAX_COMMENT = 1 << 16

STORED, DEFLATED = 0, 8


@dataclass
class ZipEntry:
    """One entry as the central directory DECLARES it, then as it was actually found."""
    name: str
    crc32: int
    comp_size: int
    uncomp_size: int
    method: int
    local_offset: int              # archive-relative, per the central directory
    found_at: Optional[int] = None  # image-absolute, per the scan
    header_len: int = 0
    # Set only for the entry cut in half by the fragmentation: how many of its data bytes
    # remained in the first fragment, and where the rest resumes in the second.
    straddle_head: Optional[int] = None
    straddle_tail_at: Optional[int] = None

    @property
    def delta(self) -> Optional[int]:
        """Image position minus archive position. Entries sharing one were stored together."""
        return None if self.found_at is None else self.found_at - self.local_offset

    def to_dict(self) -> dict:
        d = asdict(self)
        d["delta"] = self.delta
        return d


@dataclass
class ZipReassembly:
    type: str
    size: int
    sha256: str
    entries: int
    fragments: list
    reassembled: bool = True
    integrity_checked: str = ""
    decoded: bool = False
    names: list = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _find_all(buf, needle: bytes) -> list:
    """Every occurrence, scanning rather than trusting a recorded position."""
    out, i = [], 0
    data = buf if isinstance(buf, (bytes, bytearray)) else buf
    while True:
        try:
            i = data.find(needle, i)
        except (AttributeError, TypeError):
            data = bytes(buf)
            i = data.find(needle, i)
        if i == -1:
            return out
        out.append(i)
        i += 1


# ────────────────────────────────────────────────────── the central directory

def _parse_cdfh(buf, pos: int) -> Optional[tuple]:
    """One central-directory record at `pos`, or None if it is not one."""
    if pos + CDFH_MIN > len(buf) or bytes(buf[pos:pos + 4]) != CDFH_SIG:
        return None
    try:
        (_v, _n, _flags, method, _t, _d, crc, comp, uncomp,
         nlen, elen, clen, _ds, _ia, _ea, local) = struct.unpack(
            "<HHHHHHIIIHHHHHII", buf[pos + 4:pos + CDFH_MIN])
    except struct.error:
        return None
    end = pos + CDFH_MIN + nlen + elen + clen
    if end > len(buf) or nlen == 0 or nlen > 4096:
        return None
    name = bytes(buf[pos + CDFH_MIN:pos + CDFH_MIN + nlen])
    entry = ZipEntry(name=name.decode("utf-8", "replace"), crc32=crc, comp_size=comp,
                     uncomp_size=uncomp, method=method, local_offset=local)
    return entry, end


def _find_directories(buf) -> list:
    """Runs of back-to-back central-directory records, each with its EOCD.

    Found by scanning for CDFH signatures and walking forward record by record, the
    EOCD's `cd_offset` is archive-relative and useless here, which was the original bug.
    A run is accepted only when an EOCD follows it whose declared entry count matches what
    was actually walked, which is what stops four coincidental signature bytes inside
    compressed data from being read as a directory.
    """
    found, consumed = [], set()
    for start in _find_all(buf, CDFH_SIG):
        if start in consumed:
            continue
        entries, pos = [], start
        while len(entries) < MAX_ENTRIES:
            parsed = _parse_cdfh(buf, pos)
            if parsed is None:
                break
            entry, nxt = parsed
            entries.append(entry)
            consumed.add(pos)
            pos = nxt
        if not entries:
            continue
        if pos + EOCD_LEN > len(buf) or bytes(buf[pos:pos + 4]) != EOCD_SIG:
            continue
        try:
            (_d, _cd, _here, total, cd_size, _cd_off) = struct.unpack(
                "<HHHHII", buf[pos + 4:pos + 20])
            (comment_len,) = struct.unpack("<H", buf[pos + 20:pos + 22])
        except struct.error:
            continue
        if total != len(entries) or cd_size != pos - start:
            # The EOCD must agree with what was walked. Disagreement means this is not a
            # directory, or it is damaged -- either way it is not reassembled from a guess.
            continue
        found.append({"cd_start": start, "cd_size": cd_size, "eocd": pos,
                      "eocd_len": EOCD_LEN + comment_len, "entries": entries})
    return found


# ────────────────────────────────────────────────────── locating each entry

def _lfh_len(buf, pos: int) -> Optional[int]:
    if pos + LFH_MIN > len(buf) or bytes(buf[pos:pos + 4]) != LFH_SIG:
        return None
    (nlen, elen) = struct.unpack("<HH", buf[pos + 26:pos + 30])
    return LFH_MIN + nlen + elen


def _verify_at(buf, pos: int, entry: ZipEntry) -> bool:
    """CRC-32 IS THE ORACLE, exactly as it is for PNG chunks.

    The central directory states what the uncompressed data's CRC must be. Decompress what
    is here and compare. A wrong location, a wrong entry, or corrupted bytes all fail the
    same way, and none can pass by coincidence.
    """
    hdr = _lfh_len(buf, pos)
    if hdr is None:
        return False
    (nlen,) = struct.unpack("<H", buf[pos + 26:pos + 28])
    if bytes(buf[pos + LFH_MIN:pos + LFH_MIN + nlen]) != entry.name.encode("utf-8", "replace"):
        return False
    start, end = pos + hdr, pos + hdr + entry.comp_size
    if end > len(buf):
        return False
    blob = bytes(buf[start:end])
    try:
        if entry.method == STORED:
            raw = blob
        elif entry.method == DEFLATED:
            raw = zlib.decompressobj(-zlib.MAX_WBITS).decompress(blob)
        else:
            return False
    except zlib.error:
        return False
    if len(raw) != entry.uncomp_size:
        return False
    if (zlib.crc32(raw) & 0xFFFFFFFF) != entry.crc32:
        return False
    entry.header_len = hdr
    return True


def _locate(buf, entry: ZipEntry, hint: Optional[int], lfh_positions: list) -> Optional[int]:
    """Where is this entry really? Tries the fragment hint first, then scans.

    The hint is the delta already established by a sibling entry. Most entries in a
    two-fragment archive share one delta, so trying it first turns an O(entries x positions)
    scan into a handful of checks.
    """
    if hint is not None:
        at = entry.local_offset + hint
        if 0 <= at < len(buf) and _verify_at(buf, at, entry):
            return at
    for pos in lfh_positions:
        if _verify_at(buf, pos, entry):
            return pos
    return None


def _decompress(blob: bytes, method: int):
    try:
        if method == STORED:
            return blob
        if method == DEFLATED:
            return zlib.decompressobj(-zlib.MAX_WBITS).decompress(blob)
    except zlib.error:
        return None
    return None


def _recover_straddling(buf, entry: ZipEntry, head_delta: int, tail_delta: int) -> bool:
    """The entry cut in half by the fragmentation. CRC-32 decides where the cut was.

    THE HARD CASE, and the one that makes a ZIP carver useful rather than lucky. When an
    archive is split, one entry's local header sits at the end of the first fragment while
    its compressed data continues into the second. Those bytes are not contiguous anywhere
    in the image, so no scan can find them, the first version of this module simply
    reported the entry missing and gave up on the whole archive.

    Both deltas are already known from the entries that WERE found, so the only unknown is
    where inside this entry the cut falls. Every split point is tried and the CRC-32 the
    central directory recorded decides: a wrong split decompresses to the wrong bytes, or
    does not decompress at all. This is a search with an oracle, not an estimate.

    On the real .docx corpus the straddling entry is `word/document.xml`, which is to say,
    the document itself. Giving up on it means giving up on the file.
    """
    at = entry.local_offset + head_delta
    hdr = _lfh_len(buf, at)
    if hdr is None:
        return False
    (nlen,) = struct.unpack("<H", buf[at + 26:at + 28])
    if bytes(buf[at + LFH_MIN:at + LFH_MIN + nlen]) != entry.name.encode("utf-8", "replace"):
        return False

    data_start = at + hdr
    for head_len in range(0, entry.comp_size + 1):
        # The cut lands `head_len` bytes into this entry's data. Everything before it is
        # still in the first fragment; everything after resumes in the second.
        cut = entry.local_offset + hdr - at + data_start + head_len  # archive-relative cut
        cut_archive = entry.local_offset + hdr + head_len
        tail_at = cut_archive + tail_delta
        tail_len = entry.comp_size - head_len
        if tail_at < 0 or tail_at + tail_len > len(buf):
            continue
        blob = bytes(buf[data_start:data_start + head_len]) + bytes(buf[tail_at:tail_at + tail_len])
        raw = _decompress(blob, entry.method)
        if raw is None or len(raw) != entry.uncomp_size:
            continue
        if (zlib.crc32(raw) & 0xFFFFFFFF) == entry.crc32:
            entry.found_at = at
            entry.header_len = hdr
            entry.straddle_head = head_len
            entry.straddle_tail_at = tail_at
            return True
    return False


# ────────────────────────────────────────────────────── reassembly

def reassemble_zip(buf) -> list:
    """Recover ZIP archives whose entries are scattered. Byte-identical or nothing.

    Contiguous archives are deliberately NOT returned: that is the ordinary carver's job,
    and reporting them here too would double-count them in every recall figure.
    """
    out = []
    lfh_positions = _find_all(buf, LFH_SIG)

    for d in _find_directories(buf):
        entries = d["entries"]
        deltas: list = []
        hint = None
        ok = True

        missing = []
        for e in entries:
            at = _locate(buf, e, hint, lfh_positions)
            if at is None:
                missing.append(e)
                continue
            e.found_at = at
            hint = e.delta
            if e.delta not in deltas:
                deltas.append(e.delta)

        # An entry that no scan can find is either absent or STRADDLING the cut. Those are
        # different facts: the first means the archive is incomplete, the second means the
        # bytes are all present and simply not contiguous. Only the second is recoverable,
        # and only once two deltas are known to search between.
        if missing and len(deltas) >= 2:
            for e in missing[:]:
                for head_delta in deltas:
                    for tail_delta in deltas:
                        if head_delta == tail_delta:
                            continue
                        if _recover_straddling(buf, e, head_delta, tail_delta):
                            missing.remove(e)
                            break
                    if e not in missing:
                        break
        if missing:
            # A declared entry that is genuinely absent means the archive is incomplete.
            # There is no partial answer worth giving: a document missing a part is not the
            # document.
            continue

        cd_delta = d["cd_start"] - sum(
            e.header_len + e.comp_size for e in entries)  # where the CD sits, archive-wise
        scattered = len(deltas) > 1 or (deltas and cd_delta != deltas[0])
        if not scattered:
            continue        # contiguous archive; not this module's job

        # Rebuild the ORIGINAL layout from the offsets the archive recorded. Repackaging
        # with a fresh central directory would produce something that opens and is not the
        # same file.
        rebuilt = bytearray()
        for e in sorted(entries, key=lambda x: x.local_offset):
            if len(rebuilt) != e.local_offset:
                rebuilt = None
                break
            if e.straddle_head is None:
                rebuilt += bytes(buf[e.found_at:e.found_at + e.header_len + e.comp_size])
            else:
                # Header and the first part from one fragment, the remainder from the other.
                start = e.found_at
                rebuilt += bytes(buf[start:start + e.header_len + e.straddle_head])
                rebuilt += bytes(buf[e.straddle_tail_at:
                                     e.straddle_tail_at + e.comp_size - e.straddle_head])
        if rebuilt is None:
            continue
        rebuilt += bytes(buf[d["cd_start"]:d["cd_start"] + d["cd_size"]])
        rebuilt += bytes(buf[d["eocd"]:d["eocd"] + d["eocd_len"]])

        blob = bytes(rebuilt)
        if not _self_consistent(blob, len(entries)):
            continue

        by_delta: dict = {}
        for e in entries:
            by_delta.setdefault(e.delta, []).append(e)
        frags = [{"offset": min(x.found_at for x in group),
                  "length": sum(x.header_len + x.comp_size for x in group),
                  "entries": len(group), "delta": delta}
                 for delta, group in sorted(by_delta.items(), key=lambda kv: kv[1][0].found_at)]

        out.append(ZipReassembly(
            type="zip", size=len(blob), sha256=hashlib.sha256(blob).hexdigest(),
            entries=len(entries), fragments=frags, decoded=True,
            names=[e.name for e in sorted(entries, key=lambda x: x.local_offset)][:50],
            integrity_checked=f"CRC-32 verified on all {len(entries)} entries",
            reason=(
                f"assembled from {len(frags)} fragment(s) holding {len(entries)} entries. "
                "The archive's own central directory declares every entry with its CRC-32, "
                "and each was located by scanning and verified by decompressing it and "
                "matching that CRC. Fragments were identified by the offset delta between "
                "where each entry actually sits and where the archive says it sits, "
                "entries sharing a delta were stored together, so the fragment count falls "
                "out of the format rather than being estimated. The original byte layout "
                "was reconstructed from the recorded offsets, so this is the original file "
                "and not a repackaged equivalent: existing ZIP carvers rebuild a new "
                "central directory, which opens but does not hash to the original and so "
                "cannot be matched to a file seen earlier in a case."),
        ).to_dict())
    return out


def _self_consistent(blob: bytes, expected_entries: int) -> bool:
    """Does the rebuilt file parse as a standalone archive with the right entry count?

    The last check, and deliberately not the deciding one: the CRCs already proved every
    entry belongs. This catches a layout error that produced correct entries in the wrong
    arrangement.
    """
    end = blob.rfind(EOCD_SIG)
    if end == -1 or end + EOCD_LEN > len(blob):
        return False
    try:
        (_d, _cd, _here, total, _cds, cd_off) = struct.unpack("<HHHHII", blob[end + 4:end + 20])
    except struct.error:
        return False
    if total != expected_entries:
        return False
    return cd_off + 4 <= len(blob) and blob[cd_off:cd_off + 4] == CDFH_SIG


def reassemble_zip_file(image_path: str) -> list:
    """Memory-mapped entry point, matching recovery.reassemble.reassemble()."""
    import mmap
    from pathlib import Path

    p = Path(image_path)
    if not p.is_file():
        raise FileNotFoundError(f"image not found: {image_path}")
    if p.stat().st_size == 0:
        return []
    with open(p, "rb") as fh:
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            return reassemble_zip(mm)
