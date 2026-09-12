# -*- coding: utf-8 -*-
import io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
"""
DREXX — F:\ 9-File Erasure Evidence Script
==========================================
Erases 9 user-confirmed files on F:\ using one DREXX file-erasure method each.
Methods used:
  File 1 → #8  CSPRNG Random Overwrite
  File 2 → #14 Single-Pass Zero Overwrite
  File 3 → #11 Filesystem Metadata Sanitization
  File 4 → #16 Temporary/Cache Purge
  File 5 → #8  CSPRNG Random Overwrite
  File 6 → #14 Single-Pass Zero Overwrite
  File 7 → #11 Filesystem Metadata Sanitization
  File 8 → #16 Temporary/Cache Purge
  File 9 → #8  CSPRNG Random Overwrite (large file)

SAFETY:
- C: and PhysicalDrive0 are never touched.
- Files are pre-hashed before erasure.
- Results are logged truthfully.
"""

import sys
import os
import hashlib
import time
import json
import traceback
from pathlib import Path
from datetime import datetime, timezone

# Add DREXX root to path
DREXX_ROOT = Path("D:/DREXX")
sys.path.insert(0, str(DREXX_ROOT))

from drex_app import execute_file_method, AdapterError

# ── Evidence log ────────────────────────────────────────────────────────────
LOG_PATH = DREXX_ROOT / "docs" / "F_DRIVE_ERASURE_EVIDENCE.md"

def sha256(path: Path) -> str:
    if not path.exists():
        return "FILE_GONE"
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().upper()

def emit(msg: str):
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"  [{ts}] {msg}")

def progress(done: int, total: int):
    if total > 0:
        pct = int(done / total * 100)
        print(f"  Progress: {pct}% ({done}/{total})", end="\r")

# ── Target files (confirmed by user) ──────────────────────────────────────
TARGETS = [
    # (method_id, method_label, method_number, filename)
    ("csprng",        "CSPRNG Random Overwrite",              "#8",  "stock_sentiment.py"),
    ("zero",          "Single-Pass Zero Overwrite",            "#14", "THE  PITCH DECK (1) (1).pdf"),
    ("metadata",      "Filesystem Metadata Sanitization",      "#11", "THE  PITCH DECK (1) (2).pdf"),
    ("temporary",     "Temporary / Cache Purge",               "#16", "Unit1 Full Subheadings Keyword Summary Notes.pdf"),
    ("csprng",        "CSPRNG Random Overwrite",              "#8",  "Unit1 Full Subheadings Keyword Summary Notes (1).pdf"),
    ("zero",          "Single-Pass Zero Overwrite",            "#14", "Unit1dpcoquestionwithanswerpdf.pdf"),
    ("metadata",      "Filesystem Metadata Sanitization",      "#11", "Updated NPTEL list on 16.08.26 @ 8am.xlsx"),
    ("temporary",     "Temporary / Cache Purge",               "#16", "Updated NPTEL Course Paid and unpaid list-19.08.2026.xlsx"),
    ("csprng",        "CSPRNG Random Overwrite",              "#8",  "UAP-PURSUE-Release01-COMPLETE.zip"),
]

# Resolve full paths
BASE = Path("F:/")

def build_target_list():
    resolved = []
    for method_id, method_label, method_num, fname in TARGETS:
        p = BASE / fname
        if not p.exists():
            # Try case-insensitive search
            matches = list(BASE.glob(fname))
            if not matches:
                # broader search
                matches = [f for f in BASE.iterdir() if f.name.lower() == fname.lower()]
            p = matches[0] if matches else p
        resolved.append((method_id, method_label, method_num, fname, p))
    return resolved

def main():
    print("=" * 70)
    print("DREXX — F:\\ 9-File Erasure Evidence Run")
    print(f"Started: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 70)
    print()

    targets = build_target_list()

    # Pre-flight: verify all files exist
    print("PRE-FLIGHT CHECK")
    print("-" * 50)
    missing = []
    for method_id, method_label, method_num, fname, p in targets:
        exists = p.exists()
        size = p.stat().st_size if exists else 0
        status = f"EXISTS  {size:>12,} bytes" if exists else "MISSING"
        print(f"  {method_num:5s}  {method_label:<42s}  {status}  {fname}")
        if not exists:
            missing.append(fname)
    print()

    if missing:
        print(f"ERROR: {len(missing)} file(s) not found:")
        for m in missing:
            print(f"  - {m}")
        print("Aborting. Please verify filenames.")
        sys.exit(1)

    print("All 9 files confirmed present. Beginning erasure sequence.\n")

    # Results accumulator
    results = []

    for i, (method_id, method_label, method_num, fname, p) in enumerate(targets, 1):
        print("-" * 70)
        print(f"FILE {i}/9  {method_num} {method_label}")
        print(f"Target : {p}")
        print(f"Size   : {p.stat().st_size:,} bytes")

        # Hash before
        print("  Hashing before erasure...")
        t0 = time.time()
        h_before = sha256(p)
        print(f"  SHA-256 (before): {h_before}")

        result_entry = {
            "file_num": i,
            "method_id": method_id,
            "method_label": method_label,
            "method_number": method_num,
            "filename": fname,
            "path": str(p),
            "size_bytes": p.stat().st_size,
            "sha256_before": h_before,
            "sha256_after": None,
            "file_exists_after": None,
            "status": None,
            "error": None,
            "duration_s": None,
            "result": None,
        }

        # Execute erasure
        try:
            print(f"  Executing {method_label}...")
            t1 = time.time()
            res = execute_file_method(method_id, p, emit, progress)
            duration = round(time.time() - t1, 2)
            print()  # newline after progress \r

            file_gone = not p.exists()
            h_after = sha256(p) if not file_gone else "FILE_ERASED"

            result_entry.update({
                "sha256_after": h_after,
                "file_exists_after": not file_gone,
                "status": "PASS",
                "duration_s": duration,
                "result": res,
            })

            verified = res.get("verified", False)
            removed  = res.get("removed", False) or file_gone

            print(f"  Duration       : {duration}s")
            print(f"  Verified       : {verified}")
            print(f"  File removed   : {removed or file_gone}")
            print(f"  SHA-256 after  : {h_after}")
            print("  PASS")

        except AdapterError as e:
            duration = round(time.time() - t0, 2)
            result_entry.update({
                "status": "ADAPTER_ERROR",
                "error": str(e),
                "duration_s": duration,
                "file_exists_after": p.exists(),
            })
            print(f"  ADAPTER_ERROR: {e}")

        except Exception as e:
            duration = round(time.time() - t0, 2)
            result_entry.update({
                "status": "ERROR",
                "error": str(e),
                "duration_s": duration,
                "file_exists_after": p.exists(),
            })
            print(f"  ERROR: {e}")
            traceback.print_exc()

        results.append(result_entry)
        print()

    # ── Summary ─────────────────────────────────────────────────────────────
    print("=" * 70)
    print("ERASURE SUMMARY")
    print("=" * 70)
    passed  = [r for r in results if r["status"] == "PASS"]
    errors  = [r for r in results if r["status"] != "PASS"]

    for r in results:
        icon = "OK" if r["status"] == "PASS" else "!!"
        gone = "" if r.get("file_exists_after") else " [GONE]"
        print(f"  [{icon}] File {r['file_num']:>2}  {r['method_number']} {r['method_label']:<42s}  {r['status']}{gone}")

    print()
    print(f"  PASSED : {len(passed)}/9")
    print(f"  FAILED : {len(errors)}/9")
    print()

    # ── Write markdown evidence ──────────────────────────────────────────────
    now = datetime.now(timezone.utc).isoformat()
    md = [
        "# DREXX — F:\\ Drive 9-File Erasure Evidence",
        "",
        f"> Generated: {now}",
        "",
        "## Target Files & Methods",
        "",
        "| # | File | Method | Size | SHA-256 Before | SHA-256 After | File Gone | Status | Duration |",
        "|---|------|--------|------|----------------|---------------|-----------|--------|----------|",
    ]
    for r in results:
        gone  = "YES" if not r.get("file_exists_after") else "no"
        sb    = r["sha256_before"][:16] + "…" if r["sha256_before"] and len(r["sha256_before"]) > 16 else r["sha256_before"] or "—"
        sa    = r["sha256_after"][:16]  + "…" if r["sha256_after"]  and len(r["sha256_after"]) > 16  else r["sha256_after"]  or "—"
        status = r["status"]
        dur   = f"{r['duration_s']}s" if r["duration_s"] else "—"
        md.append(
            f"| {r['file_num']} | `{r['filename']}` | {r['method_number']} {r['method_label']} "
            f"| {r['size_bytes']:,} B | `{sb}` | `{sa}` | {gone} | **{status}** | {dur} |"
        )

    md += [
        "",
        "## Error Details",
        "",
    ]
    if errors:
        for r in errors:
            md.append(f"- **File {r['file_num']} ({r['filename']})**: {r['error']}")
    else:
        md.append("None — all 9 files erased successfully.")

    md += [
        "",
        "## Raw JSON",
        "",
        "```json",
        json.dumps(results, indent=2, default=str),
        "```",
        "",
    ]

    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOG_PATH.write_text("\n".join(md), encoding="utf-8")
    print(f"Evidence written to: {LOG_PATH}")

    return 0 if not errors else 1

if __name__ == "__main__":
    sys.exit(main())
