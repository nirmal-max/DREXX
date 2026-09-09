"""
Recovery engine, signature-based file carving.

Contract (docs/ENGINEERING_RULES.md section 5):
    carve(image_path) -> [ {filename, offset, size, sha256, type, truncated,
                            validated, confidence, reason, extracted_to} ]

VALIDATED AGAINST NIST CFReDS, NOT AGAINST FILES WE MADE UP.

The first version of this engine was tested only on images this project synthesised, and
it passed everything. Run against `L4_Graphic.dd` from the NIST Computer Forensic
Reference Data Set, the corpus NIST publishes precisely so tools can be checked rather
than trusted, it reported **50 artefacts where 9 files exist**, matched exactly one of
them byte-for-byte, and flagged **none** as uncertain while printing "every artifact had
a located footer". Two percent precision, stated with total confidence.

Three defects produced that, and all three are fixed here:

1. **A 3-byte header is not evidence.** `FF D8 FF` occurs constantly inside compressed
   data. Every signature now has a validator that checks the bytes that must follow, so a
   coincidence is rejected instead of carved.

2. **JPEG carving stopped at the thumbnail.** An EXIF thumbnail is a whole JPEG inside the
   APP1 segment of its parent, so the first `FF D9` encountered belongs to the thumbnail,
   not the photograph. Scanning for the first footer therefore split one photo into
   several "complete" files. The fix walks the JPEG segment structure, reading each
   segment's declared length and skipping over it, so the APP1 payload is stepped past
   whole, and the scan for the real end-of-image starts after the start-of-scan marker.

3. **Confidence was never reported.** `truncated` answered "did I find a footer", which is
   not the question an investigator asks. Every artefact now carries `validated` and a
   `confidence` of HIGH / MEDIUM / LOW, and the summary refuses to describe a low-
   confidence carve as a recovered file.

WHAT CARVING STILL CANNOT DO. None of the above changes these, and they are why carving
is a starting point for an examiner rather than an answer:

  - **Fragmented files come back broken.** Carving assumes a file is contiguous. NIST's
    L1 through L5 images exist to demonstrate exactly this, and no signature-based carver
    passes them. A file split across non-adjacent extents carves as garbage after the
    first fragment, and nothing in the byte stream announces it.
  - **There is no original filename.** The directory entry that held it is gone. The name
    in the output was invented from the byte offset, and the record says so.
  - **A missing or unlocatable end means the extent is a guess**, capped at the
    signature's maximum size and flagged.

Every recovered artefact is SHA-256 hashed at extraction time and that digest goes into
the ledger, so what the tool produced is fixed at recovery time and any later edit to a
recovered file is detectable.
"""

from __future__ import annotations
import hashlib
import mmap
import struct
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Callable, Optional

from attestation.canonical import result_digest

MB = 1024 * 1024

# Confidence in the extent, not in the content. HIGH means the file's own structure told
# us where it ends; LOW means we guessed and are saying so.
HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"


@dataclass(frozen=True)
class Signature:
    ext: str
    header: bytes
    footer: Optional[bytes]
    max_size: int
    description: str
    # Returns (is_valid, size_or_None, confidence, reason). `size` None means "fall back
    # to footer search". A validator that returns is_valid=False rejects the candidate
    # outright, that is what removes the coincidental header matches.
    validate: Optional[Callable] = None
    # For containers whose footer marker is the START of a trailer record rather than
    # the last bytes of the file. Given (mm, footer_pos, limit) it returns the true end
    # offset, or None when the record runs past the data we hold, in which case the
    # extent is genuinely unresolved and the artefact is reported truncated.
    footer_extend: Optional[Callable] = None


# ─────────────────────────────────────────────────────────────── validators

# JPEG markers that carry a 2-byte big-endian length immediately after the marker.
_JPEG_SIZED = set(range(0xC0, 0xD0)) - {0xD8, 0xD9} | set(range(0xE0, 0xF0)) | {
    0xC4, 0xDB, 0xDD, 0xDA, 0xFE,
}
# Markers that may legitimately follow SOI in a real JPEG. A byte outside this set means
# the FF D8 FF we matched was coincidence inside compressed data.
_JPEG_AFTER_SOI = set(range(0xC0, 0xD0)) | set(range(0xE0, 0xF0)) | {0xDB, 0xC4, 0xFE, 0xDD}


def _validate_jpeg(mm, start: int, limit: int):
    """Walk the JPEG segment structure to find the true end-of-image.

    This is the fix for the thumbnail defect. Each segment declares its own length, so
    stepping segment to segment steps *over* the APP1 payload that contains the EXIF
    thumbnail rather than wandering into it. Only after the start-of-scan marker do we
    scan bytes, and there we skip FF00 byte-stuffing and FFD0-FFD7 restart markers so a
    coincidental FFD9 inside entropy-coded data is not mistaken for the end.
    """
    if start + 4 > limit:
        return False, None, LOW, "truncated at image boundary"
    if mm[start + 3] not in _JPEG_AFTER_SOI:
        return False, None, LOW, "byte after SOI is not a valid JPEG marker"

    pos = start + 2
    saw_sos = False
    while pos + 4 <= limit:
        if mm[pos] != 0xFF:
            return False, None, LOW, "lost JPEG segment alignment"
        marker = mm[pos + 1]
        if marker == 0xFF:                       # fill byte, legal padding
            pos += 1
            continue
        if marker == 0xD9:                       # EOI with no scan: an empty JPEG
            return True, pos + 2 - start, HIGH, "structure walked to EOI"
        if marker not in _JPEG_SIZED:
            return False, None, LOW, f"unexpected marker 0xFF{marker:02X}"

        seglen = struct.unpack(">H", mm[pos + 2:pos + 4])[0]
        if seglen < 2:
            return False, None, LOW, "invalid segment length"
        if marker == 0xDA:                       # start of scan
            saw_sos = True
            pos += 2 + seglen
            break
        pos += 2 + seglen

    if not saw_sos:
        return False, None, LOW, "no start-of-scan segment found"

    # Entropy-coded data: scan for EOI, skipping stuffing and restart markers.
    while pos + 1 < limit:
        if mm[pos] != 0xFF:
            pos += 1
            continue
        nxt = mm[pos + 1]
        if nxt == 0x00 or 0xD0 <= nxt <= 0xD7:   # stuffed byte / restart marker
            pos += 2
            continue
        if nxt == 0xD9:
            return True, pos + 2 - start, HIGH, "structure walked past SOS to EOI"
        if nxt == 0xFF:
            pos += 1
            continue
        pos += 2

    return True, None, LOW, "valid JPEG header but end-of-image never reached"


def _validate_png(mm, start: int, limit: int):
    """Walk PNG chunks. Each declares its length, so the end is exact."""
    pos = start + 8                              # past the 8-byte signature
    saw_ihdr = False
    while pos + 8 <= limit:
        length = struct.unpack(">I", mm[pos:pos + 4])[0]
        ctype = bytes(mm[pos + 4:pos + 8])
        if not ctype.isalpha():
            return False, None, LOW, "invalid PNG chunk type"
        if ctype == b"IHDR":
            saw_ihdr = True
        if length > 0x7FFFFFFF:
            return False, None, LOW, "implausible PNG chunk length"
        pos += 12 + length                       # len + type + data + crc
        if ctype == b"IEND":
            if not saw_ihdr:
                return False, None, LOW, "PNG without IHDR"
            return True, pos - start, HIGH, "chunk structure walked to IEND"
    return False, None, LOW, "PNG chunks ran past the image boundary"


def _gif_skip_subblocks(mm, pos: int, limit: int) -> int:
    """Walk a GIF sub-block chain: [len][len bytes]... terminated by a zero length."""
    while pos < limit:
        n = mm[pos]
        pos += 1
        if n == 0:
            return pos
        pos += n
    return -1


def _validate_gif(mm, start: int, limit: int):
    """Walk the GIF block structure to the trailer, no byte search.

    Searching for the 0x00 0x3B trailer byte pair is why GIFs came back the wrong length:
    that pair occurs constantly inside LZW-compressed image data, so the first hit is
    almost never the real end. The block structure gives an exact answer: every extension
    and image block declares its own sub-block chain, so the trailer is arrived at rather
    than guessed.
    """
    if start + 13 > limit:
        return False, None, LOW, "truncated GIF header"

    w, h = struct.unpack("<HH", mm[start + 6:start + 10])
    if w == 0 or h == 0:
        return False, None, LOW, "GIF declares a zero dimension"

    packed = mm[start + 10]
    pos = start + 13
    if packed & 0x80:                                   # global colour table
        pos += 3 * (1 << ((packed & 0x07) + 1))

    while pos < limit:
        block = mm[pos]

        if block == 0x3B:                               # trailer
            return True, pos + 1 - start, HIGH, "block structure walked to trailer"

        if block == 0x21:                               # extension
            if pos + 2 > limit:
                return False, None, LOW, "truncated GIF extension"
            pos = _gif_skip_subblocks(mm, pos + 2, limit)
            if pos < 0:
                return False, None, LOW, "GIF extension sub-blocks ran past the image"
            continue

        if block == 0x2C:                               # image descriptor
            if pos + 10 > limit:
                return False, None, LOW, "truncated GIF image descriptor"
            ipacked = mm[pos + 9]
            pos += 10
            if ipacked & 0x80:                          # local colour table
                pos += 3 * (1 << ((ipacked & 0x07) + 1))
            pos += 1                                    # LZW minimum code size
            pos = _gif_skip_subblocks(mm, pos, limit)
            if pos < 0:
                return False, None, LOW, "GIF image sub-blocks ran past the image"
            continue

        return False, None, LOW, f"unexpected GIF block 0x{block:02X}"

    return False, None, LOW, "GIF trailer never reached"


def _validate_bmp(mm, start: int, limit: int):
    """BMP carries its own total file size at offset 2, an exact extent, no search."""
    if start + 14 > limit:
        return False, None, LOW, "truncated BMP header"
    size = struct.unpack("<I", mm[start + 2:start + 6])[0]
    reserved = struct.unpack("<I", mm[start + 6:start + 10])[0]
    offbits = struct.unpack("<I", mm[start + 10:start + 14])[0]
    if reserved != 0:
        return False, None, LOW, "BMP reserved field is not zero"
    if not (26 <= size <= 200 * MB) or start + size > limit:
        return False, None, LOW, "BMP declared size is implausible"
    if not (14 <= offbits < size):
        return False, None, LOW, "BMP pixel offset is out of range"
    return True, size, HIGH, "size read from the BMP header"


# TIFF field type -> bytes per element (TIFF 6.0 §2).
_TIFF_TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8,
                   11: 4, 12: 8}
_TIFF_STRIP_OFFSETS, _TIFF_STRIP_COUNTS = 273, 279
_TIFF_TILE_OFFSETS, _TIFF_TILE_COUNTS = 324, 325


def _tiff_values(mm, start, endian, typ, count, payload_off, limit):
    """Read a field's integer values, whether inline or at an external offset."""
    size = _TIFF_TYPE_SIZE.get(typ, 0)
    if size == 0 or typ not in (1, 3, 4):
        return []
    total = size * count
    base = start + payload_off if total > 4 else None
    raw_at = base if base is not None else None
    out = []
    fmt = {1: "B", 3: "H", 4: "I"}[typ]
    for i in range(count):
        if raw_at is not None:
            off = raw_at + i * size
        else:
            off = start + payload_off + i * size   # inline: payload_off is the field slot
        if off + size > limit:
            return out
        out.append(struct.unpack(endian + fmt, mm[off:off + size])[0])
    return out


def _validate_tiff(mm, start: int, limit: int):
    """Walk every IFD and every field to find the true end of the TIFF.

    TIFF has no end marker, so the previous version reported a size CAP and the carved
    bytes never matched the source file. The extent is nonetheless exact: it is the
    furthest byte reached by any IFD, any external field value, and any image strip or
    tile. Walking that gives the real boundary rather than a guess.
    """
    if start + 8 > limit:
        return False, None, LOW, "truncated TIFF header"

    bo = bytes(mm[start:start + 2])
    if bo not in (b"II", b"MM"):
        return False, None, LOW, "TIFF byte-order mark is neither II nor MM"
    endian = "<" if bo == b"II" else ">"

    if struct.unpack(endian + "H", mm[start + 2:start + 4])[0] != 42:
        return False, None, LOW, "TIFF magic is not 42"

    ifd_off = struct.unpack(endian + "I", mm[start + 4:start + 8])[0]
    if ifd_off < 8:
        return False, None, LOW, "TIFF IFD offset is out of range"

    end = 8
    seen = set()
    ifds = 0

    while ifd_off and ifd_off not in seen:
        seen.add(ifd_off)
        ifds += 1
        if ifds > 64:
            return False, None, LOW, "implausible number of TIFF IFDs"

        pos = start + ifd_off
        if pos + 2 > limit:
            return False, None, LOW, "TIFF IFD runs past the image boundary"

        count = struct.unpack(endian + "H", mm[pos:pos + 2])[0]
        if count == 0 or count > 4096:
            return False, None, LOW, "implausible TIFF IFD entry count"

        entries_end = ifd_off + 2 + count * 12 + 4
        if start + entries_end > limit:
            return False, None, LOW, "TIFF IFD entries run past the image boundary"
        end = max(end, entries_end)

        strips, counts = [], []
        tiles, tcounts = [], []

        for i in range(count):
            e = pos + 2 + i * 12
            tag = struct.unpack(endian + "H", mm[e:e + 2])[0]
            typ = struct.unpack(endian + "H", mm[e + 2:e + 4])[0]
            n = struct.unpack(endian + "I", mm[e + 4:e + 8])[0]
            size = _TIFF_TYPE_SIZE.get(typ, 0)
            if size == 0 or n > 1 << 28:
                continue

            total = size * n
            if total > 4:
                voff = struct.unpack(endian + "I", mm[e + 8:e + 12])[0]
                if start + voff + total > limit:
                    return False, None, LOW, "TIFF field value runs past the image"
                end = max(end, voff + total)
                payload = voff
            else:
                payload = (e + 8) - start          # inline, in the field slot

            if tag in (_TIFF_STRIP_OFFSETS, _TIFF_STRIP_COUNTS,
                       _TIFF_TILE_OFFSETS, _TIFF_TILE_COUNTS):
                vals = _tiff_values(mm, start, endian, typ, n, payload, limit)
                if tag == _TIFF_STRIP_OFFSETS:
                    strips = vals
                elif tag == _TIFF_STRIP_COUNTS:
                    counts = vals
                elif tag == _TIFF_TILE_OFFSETS:
                    tiles = vals
                else:
                    tcounts = vals

        for offs, lens in ((strips, counts), (tiles, tcounts)):
            for o, ln in zip(offs, lens):
                if start + o + ln > limit:
                    return False, None, LOW, "TIFF strip/tile runs past the image"
                end = max(end, o + ln)

        nxt = struct.unpack(endian + "I", mm[start + entries_end - 4:start + entries_end])[0]
        ifd_off = nxt

    return True, end, HIGH, "IFD and strip offsets walked to the true end of the TIFF"


def _validate_pcx(mm, start: int, limit: int):
    """Decode the PCX run-length stream to find the exact end.

    PCX has no end marker either, and the previous version reported a cap. But the header
    states the image geometry, so the exact number of decoded bytes is known in advance:
    bytesPerLine x planes x height. Running the RLE decoder until that many bytes have
    been produced lands on the real boundary, and the optional 769-byte VGA palette that
    may follow is accounted for rather than truncated away.
    """
    if start + 128 > limit:
        return False, None, LOW, "truncated PCX header"

    version, encoding, bpp = mm[start + 1], mm[start + 2], mm[start + 3]
    if version not in (0, 2, 3, 4, 5) or encoding != 1 or bpp not in (1, 2, 4, 8):
        return False, None, LOW, "PCX header fields are out of range"

    xmin, ymin, xmax, ymax = struct.unpack("<HHHH", mm[start + 4:start + 12])
    hdpi, vdpi = struct.unpack("<HH", mm[start + 12:start + 16])
    planes = mm[start + 65]
    bytes_per_line = struct.unpack("<H", mm[start + 66:start + 68])[0]

    if xmax < xmin or ymax < ymin or planes == 0 or planes > 4 or bytes_per_line == 0:
        return False, None, LOW, "PCX geometry is out of range"

    # The three-byte signature 0A 05 01 is far too short to stand on its own: it matched
    # coincidentally inside compressed data, and because a run-length decoder eventually
    # produces enough bytes from ANY input, the extent walk then "succeeded" and the
    # artefact was reported at HIGH confidence. These are the header invariants the PCX
    # specification actually requires, and they are what separates a file from a
    # coincidence.
    if mm[start + 64] != 0:
        return False, None, LOW, "PCX reserved byte at offset 64 is not zero"
    if bytes_per_line % 2:
        return False, None, LOW, "PCX bytesPerLine must be even (PCX spec)"

    width = xmax - xmin + 1
    needed = (width * bpp + 7) // 8
    if bytes_per_line < needed:
        return False, None, LOW, "PCX bytesPerLine is too small for the declared width"
    if bytes_per_line > needed + 8:
        return False, None, LOW, "PCX bytesPerLine is implausibly larger than the width"
    if not (0 < hdpi <= 8000) or not (0 < vdpi <= 8000):
        return False, None, LOW, "PCX DPI fields are out of range"
    if any(mm[start + 74 + i] != 0 for i in range(54)):
        return False, None, LOW, "PCX header filler bytes are not zero"

    height = ymax - ymin + 1
    expected = bytes_per_line * planes * height
    if expected <= 0 or expected > 256 * MB:
        return False, None, LOW, "PCX declares an implausible image size"

    pos = start + 128
    produced = 0
    while produced < expected and pos < limit:
        b = mm[pos]
        pos += 1
        if (b & 0xC0) == 0xC0:                      # run: low 6 bits are the count
            run = b & 0x3F
            if pos >= limit:
                return False, None, LOW, "PCX run-length stream truncated"
            pos += 1
            produced += run
        else:
            produced += 1

    if produced < expected:
        return False, None, LOW, "PCX data ended before the declared image size"

    # optional 256-colour VGA palette: 0x0C marker plus 768 bytes
    if pos < limit and mm[pos] == 0x0C and pos + 769 <= limit:
        pos += 769

    return True, pos - start, HIGH, "RLE stream decoded to the declared image size"


def _validate_pdf(mm, start: int, limit: int):
    if start + 8 > limit:
        return False, None, LOW, "truncated PDF header"
    if mm[start + 4] != 0x2D or not (0x30 <= mm[start + 5] <= 0x39):
        return False, None, LOW, "PDF version string is malformed"
    return True, None, MEDIUM, "valid PDF header; extent found by %%EOF search"


def _validate_zip(mm, start: int, limit: int):
    if start + 30 > limit:
        return False, None, LOW, "truncated ZIP local header"
    method = struct.unpack("<H", mm[start + 8:start + 10])[0]
    if method not in (0, 1, 6, 8, 9, 12, 14, 93, 95, 98):
        return False, None, LOW, "unknown ZIP compression method"
    return True, None, MEDIUM, "valid ZIP local header; extent found by EOCD search"


# ──────────────────────────────────────────────────────── footer extenders
#
# A footer marker is not always the end of the file. For ZIP the four bytes
# PK\x05\x06 open a 22-byte End of Central Directory record (plus an optional
# comment); cutting at the marker produces an archive that will not open, and
# reporting that as complete is the exact overclaim this project exists to
# prevent. These functions resolve the true end, and return None when the record
# runs past the bytes we have, which is a real truncation, and is reported.


def _extend_zip_eocd(mm, footer_pos: int, limit: int) -> Optional[int]:
    """PK\\x05\\x06 begins a 22-byte EOCD record; bytes 20-21 hold a comment length."""
    fixed_end = footer_pos + 22
    if fixed_end > limit:
        return None
    comment_len = int.from_bytes(mm[footer_pos + 20:footer_pos + 22], "little")
    end = fixed_end + comment_len
    return None if end > limit else end


def _extend_pdf_eof(mm, footer_pos: int, limit: int) -> Optional[int]:
    """%%EOF is normally followed by an end-of-line that belongs to the file."""
    end = footer_pos + 5                     # len(b"%%EOF")
    if end < limit and mm[end:end + 1] == b"\r":
        end += 1
    if end < limit and mm[end:end + 1] == b"\n":
        end += 1
    return end


# ─────────────────────────────────────────────────────────── signature table

SIGNATURES: tuple[Signature, ...] = (
    Signature("jpg", b"\xff\xd8\xff", b"\xff\xd9", 100 * MB,
              "JPEG image (JFIF/EXIF)", _validate_jpeg),
    Signature("png", b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82", 200 * MB,
              "PNG image", _validate_png),
    Signature("gif", b"GIF89a", b"\x00\x3b", 50 * MB, "GIF image (89a)", _validate_gif),
    Signature("gif", b"GIF87a", b"\x00\x3b", 50 * MB, "GIF image (87a)", _validate_gif),
    Signature("bmp", b"BM", None, 200 * MB, "Windows bitmap", _validate_bmp),
    Signature("tif", b"II\x2a\x00", None, 200 * MB, "TIFF, little-endian", _validate_tiff),
    Signature("tif", b"MM\x00\x2a", None, 200 * MB, "TIFF, big-endian", _validate_tiff),
    Signature("pcx", b"\x0a\x05\x01", None, 50 * MB, "PCX (version 5)", _validate_pcx),
    Signature("pdf", b"%PDF", b"%%EOF", 200 * MB, "PDF document", _validate_pdf,
              _extend_pdf_eof),
    Signature("zip", b"PK\x03\x04", b"PK\x05\x06", 400 * MB,
              "ZIP container (also .docx, .xlsx, .pptx, .odt)", _validate_zip,
              _extend_zip_eocd),
)

SIGNATURE_BY_EXT: dict[str, list[Signature]] = {}
for _s in SIGNATURES:
    SIGNATURE_BY_EXT.setdefault(_s.ext, []).append(_s)


@dataclass
class Artifact:
    filename: str      # invented from the offset, the original name is gone
    offset: int
    size: int
    sha256: str
    type: str
    truncated: bool    # the end was a capped guess, not a located boundary
    validated: bool    # the file's own structure was parsed and accepted
    confidence: str    # HIGH | MEDIUM | LOW, confidence in the EXTENT, not the content
    reason: str
    extracted_to: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _scan_one(mm, size: int, sig: Signature) -> list[tuple]:
    """Find every (start, end, truncated, confidence, reason) span for one signature.

    Rejected candidates are skipped by ONE byte, not by the whole maximum size: a
    coincidental header must not blind the scanner to a real file that follows it.
    """
    spans = []
    pos = 0
    while pos < size:
        start = mm.find(sig.header, pos)
        if start == -1:
            break

        limit = min(start + sig.max_size, size)

        if sig.validate is not None:
            ok, exact, confidence, reason = sig.validate(mm, start, limit)
            if not ok:
                pos = start + 1          # a coincidence, not a file
                continue
            if exact is not None:
                spans.append((start, start + exact, False, confidence, reason))
                pos = start + exact
                continue
            validator_reason = reason
        else:
            confidence, reason = MEDIUM, "no validator for this signature"
            validator_reason = ""

        end, truncated = limit, True
        if sig.footer:
            f = mm.find(sig.footer, start + len(sig.header), limit)
            if f != -1:
                end, truncated = f + len(sig.footer), False
                if sig.footer_extend is not None:
                    true_end = sig.footer_extend(mm, f, limit)
                    if true_end is None:
                        # The marker is there but its trailer record is not all
                        # present. The extent is unresolved, so say so rather than
                        # hand back a short file labelled complete.
                        end, truncated = limit, True
                        confidence = LOW
                        reason = ("footer marker found but its trailer record is "
                                  "incomplete; end is a capped estimate")
                    else:
                        end = true_end
            else:
                confidence = LOW
                # Keep the validator's diagnosis when it has one. It says WHY the extent
                # is unresolved ("end-of-image never reached"); the fallback only says
                # that it is. The specific reason is the one an examiner can act on.
                reason = validator_reason or "no footer located; end is a capped estimate"
        else:
            confidence = LOW
            reason = validator_reason or (
                "no footer defined for this type; end is a capped estimate")

        spans.append((start, end, truncated, confidence, reason))
        pos = end
    return spans


def carve(image_path: str, out_dir: str | None = None,
          types: list[str] | None = None) -> list[dict]:
    """Scan a raw image for known signatures and return recovered artefacts.

    `out_dir` writes each artefact to disk; omit it to scan and hash without extracting.
    `types` restricts the scan to named extensions (e.g. ["jpg", "pdf"]).
    """
    path = Path(image_path)
    if not path.is_file():
        raise FileNotFoundError(f"image not found: {image_path}")

    sigs = SIGNATURES
    if types:
        unknown = [t for t in types if t not in SIGNATURE_BY_EXT]
        if unknown:
            raise ValueError(f"unknown signature type(s): {unknown}")
        sigs = tuple(s for t in types for s in SIGNATURE_BY_EXT[t])

    out = Path(out_dir).resolve() if out_dir else None
    if out:
        out.mkdir(parents=True, exist_ok=True)

    size = path.stat().st_size
    if size == 0:
        return []

    artifacts: list[Artifact] = []
    with open(path, "rb") as fh:
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            for sig in sigs:
                for start, end, truncated, confidence, reason in _scan_one(mm, size, sig):
                    data = mm[start:end]
                    name = f"carved_{start:012d}.{sig.ext}"
                    art = Artifact(
                        filename=name, offset=start, size=len(data),
                        sha256=_sha256(data), type=sig.ext, truncated=truncated,
                        validated=sig.validate is not None, confidence=confidence,
                        reason=reason,
                    )
                    if out:
                        dest = out / name
                        dest.write_bytes(data)
                        art.extracted_to = str(dest)
                    artifacts.append(art)

    artifacts.sort(key=lambda a: a.offset)
    return [a.to_dict() for a in artifacts]


def result_hash(artifacts: list[dict]) -> str:
    """Digest of the whole recovery result, for the ledger entry.

    Commits to every artefact's offset, size, digest, and confidence, so the ledger fixes
    what was recovered AND how sure the tool was, not merely how many files were found.
    """
    return result_digest(artifacts)


def summarize(artifacts: list[dict]) -> dict:
    """Counts by type and by confidence, and a note that refuses to oversell the result.

    The previous version reported "every artifact had a located footer", which was
    literally true and thoroughly misleading: it was printed over a set that was 2 percent
    real files. The note now leads with how many extents are actually trustworthy.
    """
    by_type: dict[str, int] = {}
    by_conf: dict[str, int] = {HIGH: 0, MEDIUM: 0, LOW: 0}
    for a in artifacts:
        by_type[a["type"]] = by_type.get(a["type"], 0) + 1
        by_conf[a.get("confidence", LOW)] = by_conf.get(a.get("confidence", LOW), 0) + 1

    total = len(artifacts)
    truncated = sum(1 for a in artifacts if a["truncated"])
    high = by_conf[HIGH]

    if total == 0:
        note = "no artefacts matched a known signature"
    elif high == total:
        note = (f"all {total} artefact(s) had their extent confirmed by the file's own "
                "structure")
    else:
        note = (f"{high} of {total} artefact(s) had their extent confirmed by the file's "
                f"own internal structure. The remaining {total - high} are candidates "
                "whose end boundary was estimated, treat them as leads for an examiner, "
                "not as recovered files.")

    return {
        "total": total,
        "by_type": by_type,
        "by_confidence": by_conf,
        "high_confidence": high,
        "truncated": truncated,
        "note": note,
    }


def outcome_for(artifacts: list[dict]) -> str:
    """The signed `outcome` for a recovery entry.

    VERIFIED only when every extent was confirmed by the file's own structure. Anything
    less is PARTIAL, because a carve full of estimated boundaries is exactly the
    incompleteness that value exists to record.
    """
    if not artifacts:
        # A CARVE THAT RECOVERED NOTHING IS NOT A VERIFIED RECOVERY.
        #
        # This returned VERIFIED, on the reading that vacuous truth holds: every extent
        # was confirmed, because there were no extents. That is correct logic and the
        # wrong word. The value lands in a signed field that a certificate quotes to a
        # court, where "VERIFIED" reads as "the recovery was checked and it was good",
        # not as "nothing happened and nothing contradicted us".
        #
        # Caught on real NIST CFReDS data, not by a test: L2 and L3 are the images NIST
        # built to contain no contiguous file, and the ledger was labelling those runs
        # VERIFIED. The tool whose entire pitch is that it refuses to overclaim was
        # quietly overclaiming, in the field added specifically to stop that (G2).
        return "PARTIAL"
    return "VERIFIED" if all(a.get("confidence") == HIGH for a in artifacts) else "PARTIAL"
