"""GB-scale stress with ground truth. Measures what breaks at size, not just speed.

    python scripts/stress_scale.py --gb 1 2 4        # scaling series
    python scripts/stress_scale.py --gb 4 --keep     # keep the image for reuse

CFReDS is 292 MB. A forensic drive is 500 GB. Three things can be true at 292 MB and false
at 500 GB, and only one of them is throughput:

  1. MEMORY. The carver mmaps, so the image is not loaded -- but `mm[start:end]` copies
     each artefact, and a planted 200 MB file would spike. Peak RSS is sampled, not assumed.
  2. SCALING SHAPE. `carve()` loops signatures on the outside and scans the whole image for
     each one. That is one full pass PER SIGNATURE. Linear in size either way, but with a
     constant equal to the signature count -- and a constant of ~15 is the difference
     between a 10-minute drive and a 2.5-hour one. Measured across sizes so the shape is
     observed rather than reasoned about.
  3. CORRECTNESS AT DENSITY. More data means more chances for a false positive. Precision
     is computed against PLANTED ground truth, so "it found 900 things" is checked rather
     than reported.

GROUND TRUTH IS THE POINT. The image is built by planting real files at known offsets in
deterministic filler, so every recovered artefact can be scored: exact hit, wrong bytes, or
false positive. A throughput number without a precision number is a benchmark of how fast
the tool can be wrong.
"""
from __future__ import annotations

import argparse
import ctypes
import gc
import hashlib
import json
import os
import platform
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from recovery.engine import carve, outcome_for, result_hash, summarize  # noqa: E402

DATA = ROOT / "tests" / "data"
EVIDENCE = ROOT / "evidence"
SCRATCH = Path(os.environ.get("AKHANDA_SCRATCH", ROOT / "evidence" / "scale_tmp"))

# Real files with real headers and real trailers, so a hit is a genuine carve and not a
# magic-number match on bytes that were never a file.
SEEDS = ["09260002.jpg", "100_0183.gif", "02010025.pcx", "100_0018.tif",
         "000_0021.png", "100_0304crop.bmp"]

FILL_BLOCK = 1 << 20


# ------------------------------------------------------------------ peak memory

def peak_rss_mb() -> float:
    """Peak working set, without a psutil dependency.

    Windows: GetProcessMemoryInfo PeakWorkingSetSize. POSIX: getrusage ru_maxrss.
    Returns 0.0 where neither is available -- reported as unknown rather than as zero
    usage, because a memory figure that silently defaults to 0 is worse than none.
    """
    if platform.system() == "Windows":
        class PMC(ctypes.Structure):
            _fields_ = [("cb", ctypes.c_uint32), ("PageFaultCount", ctypes.c_uint32),
                        ("PeakWorkingSetSize", ctypes.c_size_t),
                        ("WorkingSetSize", ctypes.c_size_t),
                        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                        ("PagefileUsage", ctypes.c_size_t),
                        ("PeakPagefileUsage", ctypes.c_size_t)]
        # argtypes/restype are NOT optional here. Without them ctypes defaults the
        # HANDLE to c_int, which truncates a 64-bit process handle and makes the call
        # fail silently -- reporting 0.0 MB, which reads as "used no memory" rather than
        # "the measurement did not happen".
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        k32.GetCurrentProcess.restype = ctypes.c_void_p
        psapi.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p,
                                               ctypes.POINTER(PMC), ctypes.c_uint32]
        psapi.GetProcessMemoryInfo.restype = ctypes.c_int

        pmc = PMC()
        pmc.cb = ctypes.sizeof(PMC)
        ok = psapi.GetProcessMemoryInfo(k32.GetCurrentProcess(),
                                        ctypes.byref(pmc), pmc.cb)
        return round(pmc.PeakWorkingSetSize / 1e6, 1) if ok else 0.0
    try:
        import resource
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round((rss if sys.platform == "darwin" else rss * 1024) / 1e6, 1)
    except Exception:  # noqa: BLE001
        return 0.0


# ------------------------------------------------------------------ image builder

def _filler(seed: int, n: int) -> bytes:
    """Deterministic pseudorandom filler. NOT os.urandom: the image must be rebuildable
    byte-for-byte, or a divergence between runs cannot be told from a carver change."""
    out = bytearray()
    counter = seed
    while len(out) < n:
        out += hashlib.sha256(counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(out[:n])


def build_image(path: Path, target_bytes: int, spacing_mb: int = 16) -> dict:
    """Plant real files at known offsets in deterministic filler. Returns ground truth.

    Files are planted on 512-byte boundaries because that is where a real filesystem would
    put them; a carver that only finds byte-aligned plants would pass here and fail on a
    real disk.
    """
    seeds = []
    for name in SEEDS:
        p = DATA / name
        if p.is_file():
            seeds.append((name, p.read_bytes()))
    if not seeds:
        raise SystemExit(f"no seed files under {DATA}")

    truth = []
    spacing = spacing_mb << 20
    written = 0
    idx = 0

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as fh:
        while written < target_bytes:
            gap = min(spacing, target_bytes - written)
            fh.write(_filler(written // FILL_BLOCK, gap))
            written += gap
            if written >= target_bytes:
                break

            name, blob = seeds[idx % len(seeds)]
            idx += 1
            if written + len(blob) > target_bytes:
                break
            pad = (-written) % 512
            if pad:
                fh.write(b"\x00" * pad)
                written += pad
            truth.append({"offset": written, "size": len(blob), "name": name,
                          "sha256": hashlib.sha256(blob).hexdigest()})
            fh.write(blob)
            written += len(blob)

    return {"path": str(path), "bytes": path.stat().st_size, "planted": truth}


# ------------------------------------------------------------------ scoring

def score(artifacts: list, truth: list) -> dict:
    """Score against planted ground truth. Three outcomes, kept distinct.

        exact          the carved bytes hash to a planted file
        offset_hit     found at a planted offset but the bytes differ (truncated/overrun)
        false_positive at no planted offset at all

    Collapsing the middle case into either neighbour is the tempting simplification and
    the wrong one: an offset hit means the SCANNER worked and the boundary logic did not,
    which is a different bug from a spurious magic-number match.
    """
    by_offset = {t["offset"]: t for t in truth}
    by_hash = {t["sha256"] for t in truth}

    exact = offset_hit = false_pos = 0
    found_offsets = set()
    for a in artifacts:
        if a["sha256"] in by_hash and a["offset"] in by_offset:
            exact += 1
            found_offsets.add(a["offset"])
        elif a["offset"] in by_offset:
            offset_hit += 1
            found_offsets.add(a["offset"])
        else:
            false_pos += 1

    reported = len(artifacts)
    return {
        "planted": len(truth),
        "reported": reported,
        "exact": exact,
        "offset_hit": offset_hit,
        "false_positive": false_pos,
        "precision_pct": round(100.0 * exact / reported, 1) if reported else None,
        "recall_pct": round(100.0 * len(found_offsets) / len(truth), 1) if truth else None,
        "exact_recall_pct": round(100.0 * exact / len(truth), 1) if truth else None,
    }


# ------------------------------------------------------------------ one size

def run_size(gb: float, keep: bool) -> dict:
    target = int(gb * (1 << 30))
    img = SCRATCH / f"scale_{gb:g}gb.img"

    t0 = time.perf_counter()
    if img.is_file() and img.stat().st_size >= target * 0.99:
        truth_path = img.with_suffix(".truth.json")
        gt = json.loads(truth_path.read_text(encoding="utf-8"))
        build_s = 0.0
        reused = True
    else:
        gt = build_image(img, target)
        img.with_suffix(".truth.json").write_text(json.dumps(gt), encoding="utf-8")
        build_s = time.perf_counter() - t0
        reused = False

    size = img.stat().st_size
    gc.collect()
    rss_before = peak_rss_mb()

    t0 = time.perf_counter()
    artifacts = carve(str(img))
    carve_s = time.perf_counter() - t0

    digest = result_hash(artifacts)
    rss_after = peak_rss_mb()

    rec = {
        "gb": gb,
        "bytes": size,
        "mb": round(size / 1e6, 1),
        "image_reused": reused,
        "build_s": round(build_s, 1),
        "carve_s": round(carve_s, 2),
        "throughput_mb_s": round((size / 1e6) / carve_s, 1) if carve_s else None,
        "seconds_per_gb": round(carve_s / gb, 2) if gb else None,
        "peak_rss_mb": rss_after,
        "rss_growth_mb": round(rss_after - rss_before, 1),
        "artifacts": len(artifacts),
        "result_hash": digest,
        "outcome": outcome_for(artifacts),
        "summary": summarize(artifacts),
        "ground_truth": score(artifacts, gt["planted"]),
    }

    if not keep:
        img.unlink(missing_ok=True)
        img.with_suffix(".truth.json").unlink(missing_ok=True)
    return rec


def main() -> int:
    ap = argparse.ArgumentParser(description="GB-scale carve stress with ground truth.")
    ap.add_argument("--gb", type=float, nargs="+", default=[1.0],
                    help="sizes to run, in GB; several values give a scaling series")
    ap.add_argument("--keep", action="store_true", help="keep images for reuse")
    ap.add_argument("--out", default=str(EVIDENCE / "stress_scale.json"))
    args = ap.parse_args()

    free = None
    try:
        free = round(os.statvfs(SCRATCH.anchor).f_bavail
                     * os.statvfs(SCRATCH.anchor).f_frsize / 1e9, 1)
    except (AttributeError, OSError):
        try:
            import shutil
            free = round(shutil.disk_usage(SCRATCH.anchor).free / 1e9, 1)
        except OSError:
            pass

    need = max(args.gb) * 1.1
    if free is not None and free < need:
        print(f"need ~{need:.1f} GB free, have {free} GB", file=sys.stderr)
        return 2

    result = {
        "check": "GB-scale carve with planted ground truth",
        "ran_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python": platform.python_version(),
        "system": f"{platform.system()} {platform.machine()}",
        "free_gb_before": free,
        "sizes": [],
    }

    print(f"{'size':>7} {'carve':>9} {'MB/s':>8} {'s/GB':>7} {'peakRSS':>9} "
          f"{'found':>6} {'prec':>7} {'recall':>7}")
    for gb in args.gb:
        rec = run_size(gb, args.keep)
        result["sizes"].append(rec)
        g = rec["ground_truth"]
        print(f"{gb:>6}G {rec['carve_s']:>8.1f}s {rec['throughput_mb_s']:>8} "
              f"{rec['seconds_per_gb']:>7} {rec['peak_rss_mb']:>8}M "
              f"{rec['artifacts']:>6} {str(g['precision_pct']):>6}% "
              f"{str(g['recall_pct']):>6}%")

    # SCALING SHAPE. Seconds per GB should stay flat if the carver is linear in size. A
    # rising figure means something superlinear -- the number that decides whether a
    # 500 GB drive is a coffee break or an overnight job.
    if len(result["sizes"]) > 1:
        per_gb = [r["seconds_per_gb"] for r in result["sizes"] if r["seconds_per_gb"]]
        rss = [r["peak_rss_mb"] for r in result["sizes"]]
        drift = round(100.0 * (max(per_gb) - min(per_gb)) / min(per_gb), 1) if per_gb else 0
        result["scaling"] = {
            "seconds_per_gb": per_gb,
            "spread_pct": drift,
            "linear": drift < 25,
            "peak_rss_mb": rss,
            "rss_flat": (max(rss) - min(rss)) < 200 if rss else None,
            "meaning": (
                "seconds/GB flat and peak RSS flat => the carver is linear in image size "
                "and streams rather than accumulating. Extrapolation to a real drive is "
                "then arithmetic, not a hope."),
        }
        print(f"\nscaling  : {per_gb} s/GB, spread {drift}% "
              f"-> {'LINEAR' if result['scaling']['linear'] else 'NOT LINEAR'}")
        print(f"peak RSS : {rss} MB "
              f"-> {'FLAT (streams)' if result['scaling']['rss_flat'] else 'GROWING'}")
        if per_gb:
            print(f"projected: 500 GB drive ~ {max(per_gb) * 500 / 3600:.1f} h at this rate")

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"written  : {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
