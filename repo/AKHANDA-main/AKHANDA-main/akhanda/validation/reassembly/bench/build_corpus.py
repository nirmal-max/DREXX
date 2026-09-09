"""Build a PNG corpus with varied geometry, from the real images already in the repo.

WHY. The reassembly claim was penalised for resting on ONE file. `tests/data` holds seven
real photographs but only one is a PNG, so the bench had one shape to work with: 2580x1932,
8-bit RGB, ~13 MB, ~1,580 chunks.

Re-encoding the other six real images to PNG produces genuinely different structures --
different dimensions, colour types, bit depths, chunk counts and IDAT lengths -- from real
photographic content rather than generated patterns. Palette and greyscale variants are
added because the completeness check divides by colour type, and a formula that is only
ever exercised on RGB has only been tested on a quarter of its branches.

    python validation/reassembly/bench/build_corpus.py

Writes validation/reassembly/corpus/. Deterministic: the same inputs give the same corpus,
so a bench failure is reproducible rather than depending on which files happened to exist.
"""
from __future__ import annotations

import hashlib
import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DATA = ROOT / "tests" / "data"
CORPUS = ROOT / "validation" / "reassembly" / "corpus"

SOURCES = ["000_0021.png", "02010025.pcx", "02010026.jpg", "09260002.jpg",
           "100_0018.tif", "100_0183.gif", "100_0304crop.bmp"]

# (suffix, pillow mode, max edge). Each exercises a different PNG colour type, and the
# completeness check has a separate arithmetic branch for each.
VARIANTS = [
    ("rgb",  "RGB",  None),   # colour type 2 , 3 channels
    ("rgba", "RGBA", 900),    # colour type 6 , 4 channels
    ("gray", "L",    700),    # colour type 0 , 1 channel
    ("pal",  "P",    500),    # colour type 3 , palette, 1 channel + PLTE
]


def main() -> int:
    try:
        from PIL import Image
    except ImportError:
        print("Pillow is required to build the corpus", file=sys.stderr)
        return 2

    CORPUS.mkdir(parents=True, exist_ok=True)
    manifest = []

    for name in SOURCES:
        src = DATA / name
        if not src.is_file():
            print(f"  skip {name} (not present)")
            continue
        try:
            with Image.open(src) as im:
                im.load()
                base = im.copy()
        except Exception as exc:  # noqa: BLE001
            print(f"  skip {name}: {type(exc).__name__}: {exc}")
            continue

        for suffix, mode, max_edge in VARIANTS:
            work = base
            if max_edge and max(work.size) > max_edge:
                scale = max_edge / max(work.size)
                work = work.resize((max(1, int(work.width * scale)),
                                    max(1, int(work.height * scale))))
            try:
                conv = work.convert(mode)
            except Exception as exc:  # noqa: BLE001
                print(f"  skip {name}/{suffix}: {type(exc).__name__}: {exc}")
                continue

            buf = io.BytesIO()
            # optimize=False keeps encoding deterministic across Pillow versions; the
            # corpus must be rebuildable to the same bytes or a bench failure cannot be
            # told from a re-encode.
            conv.save(buf, "PNG", optimize=False)
            blob = buf.getvalue()

            out = CORPUS / f"{Path(name).stem}_{suffix}.png"
            out.write_bytes(blob)
            manifest.append({
                "file": out.name,
                "from": name,
                "mode": mode,
                "size": list(conv.size),
                "bytes": len(blob),
                "sha256": hashlib.sha256(blob).hexdigest(),
            })
            print(f"  {out.name:<28} {conv.size[0]}x{conv.size[1]:<5} {mode:<5} "
                  f"{len(blob):>9,} B")

    (CORPUS / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"\n{len(manifest)} PNGs written to {CORPUS}")
    if manifest:
        sizes = [m["bytes"] for m in manifest]
        modes = sorted({m["mode"] for m in manifest})
        print(f"colour types exercised: {modes}")
        print(f"size range: {min(sizes):,} B to {max(sizes):,} B")
    return 0


if __name__ == "__main__":
    sys.exit(main())
