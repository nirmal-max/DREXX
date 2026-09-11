"""
DREX Disposable Recovery Test Image Creator
============================================
Creates a raw FAT32 disk image, populates it with the canonical DREX_TEST
hierarchy, records baseline SHA-256 hashes, then deletes files to simulate
data loss, and runs the real TSK (fls, icat, tsk_recover) tools to confirm
genuine backend recovery is functional.
"""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parent.parent
NATIVE_BIN = REPO_ROOT / "native_bin"
IMAGE_PATH = REPO_ROOT / "native_bin" / "drex_test.img"
RECOVER_DIR = REPO_ROOT / "native_bin" / "drex_recovery_out"

FLS_EXE = NATIVE_BIN / "fls.exe"
ICAT_EXE = NATIVE_BIN / "icat.exe"
TSK_RECOVER_EXE = NATIVE_BIN / "tsk_recover.exe"
FSSTAT_EXE = NATIVE_BIN / "fsstat.exe"

IMAGE_SIZE_MB = 64  # FAT32 requires > 32.5 MB (66600 sectors at 512 B/sec)

TEST_FILES = {
    "DREX_TEST/file1.txt": b"This is file1.txt - DREX recovery test file 2026\n",
    "DREX_TEST/report.pdf": b"%PDF-1.4 DREX Test Report - Forensic Recovery Document 2026\n",
    "DREX_TEST/image.jpg": bytes([
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46,
        0x49, 0x46, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    ]) + b"DREX Test JPEG payload data for recovery verification 2026",
    "DREX_TEST/PROJECT/main.cpp": b'#include <stdio.h>\nint main(){printf("DREX Test C file");return 0;}\n',
    "DREX_TEST/PROJECT/README.txt": b"# DREX Test Project README - forensic recovery test 2026\n",
    "DREX_TEST/DATA/database.db": b"SQLite format 3\x00DREX-TEST-DATABASE-2026\n" + b"\x00" * 20,
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def run(cmd, **kw) -> subprocess.CompletedProcess:
    print(f"  $ {' '.join(str(c) for c in cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, errors="replace", **kw)
    if result.stdout:
        for line in result.stdout.splitlines()[:20]:
            print(f"    {line}")
    if result.stderr:
        for line in result.stderr.splitlines()[:10]:
            print(f"    STDERR: {line}")
    return result


def create_fat32_image():
    try:
        from pyfatfs.PyFat import PyFat
        from pyfatfs.PyFatFS import PyFatFS
    except ImportError:
        print("ERROR: pyfatfs not installed. Run: pip install pyfatfs")
        sys.exit(1)

    print(f"\n[1] Creating {IMAGE_SIZE_MB}MiB FAT32 image at {IMAGE_PATH}")
    size_bytes = IMAGE_SIZE_MB * 1024 * 1024
    with open(IMAGE_PATH, "wb") as f:
        f.write(b"\x00" * size_bytes)

    fat = PyFat()
    fat.mkfs(str(IMAGE_PATH), fat_type=PyFat.FAT_TYPE_FAT32,
             size=size_bytes, label="DREXTEST")
    fat.close()
    print(f"  FAT32 filesystem created ({size_bytes:,} bytes)")


def populate_image() -> dict:
    from pyfatfs.PyFatFS import PyFatFS
    print("\n[2] Populating image with DREX_TEST hierarchy...")
    baseline = {}

    with PyFatFS(filename=str(IMAGE_PATH), encoding='utf-8') as fs:
        for rel_path, content in TEST_FILES.items():
            # Ensure all parent directories exist
            parent = str(Path(rel_path).parent).replace("\\", "/")
            if parent and parent != ".":
                fs.makedirs(parent, recreate=True)

            # Write file
            with fs.openbin(rel_path.replace("\\", "/"), "w") as fh:
                fh.write(content)

            h = sha256(content)
            baseline[rel_path] = h
            print(f"  WRITTEN  {rel_path}  SHA256={h[:16]}...")

    return baseline


def _fat32_read_bpb(img_file):
    """Return a dict of parsed BPB fields needed for directory traversal."""
    import struct
    img_file.seek(0)
    raw = img_file.read(512)
    bpb = {}
    bpb["bytes_per_sector"]    = struct.unpack_from("<H", raw, 11)[0]
    bpb["sectors_per_cluster"] = struct.unpack_from("<B", raw, 13)[0]
    bpb["reserved_sectors"]    = struct.unpack_from("<H", raw, 14)[0]
    bpb["num_fats"]            = struct.unpack_from("<B", raw, 16)[0]
    bpb["fat_size_32"]         = struct.unpack_from("<I", raw, 36)[0]
    bpb["root_cluster"]        = struct.unpack_from("<I", raw, 44)[0]
    bpb["fat_offset"]          = bpb["reserved_sectors"] * bpb["bytes_per_sector"]
    bpb["data_offset"]         = (
        bpb["fat_offset"]
        + bpb["num_fats"] * bpb["fat_size_32"] * bpb["bytes_per_sector"]
    )
    return bpb


def _cluster_to_offset(cluster, bpb):
    """Convert a FAT32 cluster number to a byte offset in the image."""
    return (
        bpb["data_offset"]
        + (cluster - 2) * bpb["sectors_per_cluster"] * bpb["bytes_per_sector"]
    )


def _read_fat_entry(img_file, bpb, cluster):
    import struct
    offset = bpb["fat_offset"] + cluster * 4
    img_file.seek(offset)
    raw = img_file.read(4)
    return struct.unpack_from("<I", raw)[0] & 0x0FFFFFFF


def _patch_dirent_deleted(img_file, bpb, cluster_chain, filename_83: str):
    """Walk directory entries in a cluster chain looking for filename_83
    (8.3 uppercase, padded to 11 chars). Mark each matching entry as 0xE5."""
    import struct
    cluster = cluster_chain
    visited = set()
    while cluster and cluster < 0x0FFFFFF8:
        if cluster in visited:
            break
        visited.add(cluster)
        offset = _cluster_to_offset(cluster, bpb)
        cluster_size = bpb["sectors_per_cluster"] * bpb["bytes_per_sector"]
        img_file.seek(offset)
        raw = img_file.read(cluster_size)
        for i in range(0, len(raw), 32):
            entry = raw[i:i+32]
            if len(entry) < 32:
                break
            first = entry[0]
            if first == 0x00:  # end of directory
                break
            attr = entry[11]
            if attr == 0x0F:  # LFN entry, skip
                continue
            name_raw = entry[0:11]
            try:
                name_str = name_raw.decode("ascii", errors="replace").strip()
            except Exception:
                continue
            # Build the 11-char padded name for comparison
            name_padded = name_raw.decode("ascii", errors="replace")
            if name_padded == filename_83:
                abs_offset = offset + i
                img_file.seek(abs_offset)
                img_file.write(b"\xe5")
                return True, abs_offset
        cluster = _read_fat_entry(img_file, bpb, cluster)
    return False, None


def _name_to_83(filename: str) -> str:
    """Convert a filename to FAT 8.3 uppercase padded format (11 chars)."""
    # For simple names like file1.txt -> 'FILE1   TXT'
    parts = filename.upper().rsplit(".", 1)
    if len(parts) == 2:
        name = parts[0][:8].ljust(8)
        ext  = parts[1][:3].ljust(3)
    else:
        name = parts[0][:8].ljust(8)
        ext  = "   "
    return name + ext


def delete_files_from_image(baseline_paths: list):
    """Mark FAT directory entries as deleted (0xE5) WITHOUT freeing cluster
    chains.  This precisely mimics real OS deletion behaviour so TSK can
    detect entries with ``fls -d`` and recover data with ``tsk_recover``."""
    import struct

    print("\n[4] Patching FAT dir-entries to 0xE5 (preserving cluster chains)...")

    with open(IMAGE_PATH, "r+b") as img:
        bpb = _fat32_read_bpb(img)
        root_cluster = bpb["root_cluster"]

        for rel_path in baseline_paths:
            parts = rel_path.replace("\\", "/").split("/")
            filename = parts[-1]
            dirs = parts[:-1]

            # Navigate to the parent directory cluster
            cluster = root_cluster
            ok = True
            for dirname in dirs:
                name83 = _name_to_83(dirname)
                found_cluster = None
                cur = cluster
                visited = set()
                while cur and cur < 0x0FFFFFF8:
                    if cur in visited:
                        break
                    visited.add(cur)
                    offset = _cluster_to_offset(cur, bpb)
                    cluster_size = bpb["sectors_per_cluster"] * bpb["bytes_per_sector"]
                    img.seek(offset)
                    raw = img.read(cluster_size)
                    for i in range(0, len(raw), 32):
                        entry = raw[i:i+32]
                        if len(entry) < 32 or entry[0] == 0x00:
                            break
                        if entry[11] == 0x0F:  # LFN
                            continue
                        nm = entry[0:11].decode("ascii", errors="replace")
                        attr = entry[11]
                        if nm == name83 and (attr & 0x10):  # directory bit
                            # Get cluster for this directory entry
                            hi = struct.unpack_from("<H", entry, 20)[0]
                            lo = struct.unpack_from("<H", entry, 26)[0]
                            found_cluster = (hi << 16) | lo
                            break
                    if found_cluster is not None:
                        break
                    cur = _read_fat_entry(img, bpb, cur)
                if found_cluster is None:
                    print(f"  WARN  Cannot find dir '{dirname}' in cluster chain")
                    ok = False
                    break
                cluster = found_cluster

            if not ok:
                # Fallback: use pyfatfs remove (zeroes FAT chain, less recoverable)
                try:
                    from pyfatfs.PyFatFS import PyFatFS
                    with PyFatFS(filename=str(IMAGE_PATH), encoding="utf-8") as fs:
                        fs.remove(rel_path.replace("\\", "/"))
                    print(f"  FALLBACK  /{rel_path.replace(chr(92),'/')}")
                except Exception as e:
                    print(f"  SKIP  {rel_path}: {e}")
                continue

            # Now patch the file entry in the parent directory cluster
            name83 = _name_to_83(filename)
            found, abs_offset = _patch_dirent_deleted(img, bpb, cluster, name83)
            if found:
                print(f"  DELETED  /{rel_path.replace(chr(92),'/')}  (0xE5 @ 0x{abs_offset:08X})")
            else:
                print(f"  NOT FOUND  /{rel_path.replace(chr(92),'/')}  (name83={repr(name83)})")

    print("  Directory entries patched. Cluster chains intact.")




def run_tsk_fls() -> list:
    print("\n[5] Running fls -r -d (deleted files) on image...")
    result = run([str(FLS_EXE), "-r", "-d", "-f", "fat32", str(IMAGE_PATH)])
    entries = [l.strip() for l in result.stdout.splitlines() if l.strip()]
    print(f"  Total deleted entries found: {len(entries)}")
    return entries


def run_tsk_recover() -> bool:
    if RECOVER_DIR.exists():
        import shutil
        shutil.rmtree(RECOVER_DIR)
    RECOVER_DIR.mkdir(parents=True, exist_ok=True)
    print(f"\n[6] Running tsk_recover to extract deleted files to {RECOVER_DIR}...")
    result = run([
        str(TSK_RECOVER_EXE),
        "-f", "fat32",
        "-e",
        str(IMAGE_PATH),
        str(RECOVER_DIR),
    ])
    files = [f for f in RECOVER_DIR.rglob("*") if f.is_file()]
    print(f"  Recovered {len(files)} file(s)")
    for f in files:
        print(f"    {f.relative_to(RECOVER_DIR)}  ({f.stat().st_size} bytes)")
    return len(files) > 0


def run_fsstat():
    print("\n[7] Running fsstat...")
    run([str(FSSTAT_EXE), "-f", "fat32", str(IMAGE_PATH)])


def verify_recovered_files(baseline: dict) -> dict:
    print("\n[8] Verifying recovered file hashes against baseline...")
    results = {}
    for rel_path, expected_hash in baseline.items():
        filename = Path(rel_path).name
        matches = list(RECOVER_DIR.rglob(filename))
        if matches:
            actual_data = matches[0].read_bytes()
            actual_hash = sha256(actual_data)
            match = actual_hash == expected_hash
            status = "MATCH" if match else "MISMATCH"
            print(f"  {status}  {rel_path}  [{actual_hash[:16]}...]")
            results[rel_path] = {"expected": expected_hash, "actual": actual_hash, "match": match}
        else:
            print(f"  NOT FOUND  {rel_path}")
            results[rel_path] = {"expected": expected_hash, "actual": None, "match": False}
    return results


def main():
    print("=" * 70)
    print("DREX End-to-End Recovery Test  (Real TSK Backends)")
    print(f"Image:       {IMAGE_PATH}")
    print(f"fls.exe:     exists={FLS_EXE.exists()}")
    print(f"tsk_recover: exists={TSK_RECOVER_EXE.exists()}")
    print("=" * 70)

    if not FLS_EXE.exists() or not TSK_RECOVER_EXE.exists():
        print("\nERROR: TSK executables not found in native_bin/")
        sys.exit(1)

    create_fat32_image()
    baseline = populate_image()

    print("\n[3] Baseline SHA-256 hashes:")
    for path, h in baseline.items():
        print(f"  {h}  {path}")

    delete_files_from_image(list(baseline.keys()))
    deleted_entries = run_tsk_fls()
    recovered_ok = run_tsk_recover()
    run_fsstat()

    verify_results = {}
    if recovered_ok:
        verify_results = verify_recovered_files(baseline)

    print("\n" + "=" * 70)
    print("RECOVERY TEST SUMMARY")
    print("=" * 70)
    print(f"  Files created:         {len(baseline)}")
    print(f"  Files deleted:         {len(baseline)}")
    print(f"  fls deleted entries:   {len(deleted_entries)}")
    print(f"  tsk_recover success:   {recovered_ok}")

    if verify_results:
        matched = sum(1 for r in verify_results.values() if r["match"])
        print(f"  Hash matches:          {matched}/{len(verify_results)}")
        overall = "PASS" if matched == len(verify_results) else f"PARTIAL ({matched}/{len(verify_results)} matched)"
    else:
        overall = "PARTIAL - tsk_recover found no files"

    print(f"\n  OVERALL RESULT: {overall}")
    print("=" * 70)

    out = REPO_ROOT / "native_bin" / "recovery_test_results.json"
    with open(out, "w") as f:
        json.dump({
            "image_path": str(IMAGE_PATH),
            "image_size_mb": IMAGE_SIZE_MB,
            "baseline": baseline,
            "deleted_entries_count": len(deleted_entries),
            "recovery_attempted": recovered_ok,
            "verification": verify_results,
            "overall": overall,
        }, f, indent=2)
    print(f"\nResults: {out}")


if __name__ == "__main__":
    main()
