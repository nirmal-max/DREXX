"""
DREXX Drive Capability Probe — F: (SanDisk Ultra)
==================================================
Non-destructive probe. No data is written or erased.
Prints the full capability map from probe_drive_capabilities().

Run as Administrator for accurate write-capability detection.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from drex_app import probe_drive_capabilities, verify_drive_identity, DriveInfo, discover_drives, fmt_bytes

def main():
    print("=" * 70)
    print("DREXX Drive Capability Probe — F: (SanDisk Ultra USB)")
    print("=" * 70)

    # Discover drives
    drives = discover_drives()
    print(f"\nDiscovered {len(drives)} logical drives:")
    for d in drives:
        print(f"  {d.path}  model={d.model}  serial={d.serial}  device_path={d.device_path}")

    # Find F:
    target = next((d for d in drives if d.path.upper().startswith("F:")), None)
    if target is None:
        print("\n[ERROR] F: not found. Is the SanDisk Ultra inserted?")
        sys.exit(1)

    print(f"\nTarget drive: {target.path}")
    print(f"  Model:    {target.model}")
    print(f"  Serial:   {target.serial}")
    print(f"  Capacity: {fmt_bytes(target.capacity)}")
    print(f"  DevPath:  {target.device_path}")

    print("\nProbing capabilities (non-destructive)...")
    caps = probe_drive_capabilities(target)

    print("\n--- Capability Report ---")
    for k, v in caps.items():
        if k == "probe_errors":
            continue
        print(f"  {k:35s}: {v}")

    if caps.get("probe_errors"):
        print("\n--- Probe Warnings ---")
        for e in caps["probe_errors"]:
            print(f"  [!] {e}")

    phys_num = caps.get("physical_disk_number")
    if phys_num is not None:
        print(f"\n--- Identity Verification (PhysicalDisk {phys_num}) ---")
        identity = verify_drive_identity(target, int(phys_num))
        for k, v in identity.items():
            print(f"  {k:30s}: {v}")

    print("\n--- Method Availability Summary ---")
    from drex_app import drive_method_status
    methods = [
        ("nist",      "NIST SP 800-88 Rev.2"),
        ("smart",     "Smart Sanitization"),
        ("native",    "Device-Native Sanitize"),
        ("ata",       "ATA Secure Erase"),
        ("nvme",      "NVMe Secure Erase"),
        ("ieee",      "IEEE 2883 Purge"),
        ("overwrite", "Verified Overwrite"),
    ]
    for mid, name in methods:
        status, reason = drive_method_status(mid, target)
        print(f"  #{methods.index((mid, name))+1} {name:30s} -> {status}")
        if status == "UNSUPPORTED_HARDWARE":
            print(f"     Evidence: {reason[:120]}")

    # Save report
    report = {
        "target": target.path,
        "model": target.model,
        "serial": target.serial,
        "capabilities": {k: str(v) for k, v in caps.items() if k != "probe_errors"},
        "probe_errors": caps.get("probe_errors", []),
    }
    out = Path(__file__).parent.parent / "DREXX_FINAL_EVIDENCE" / "F_drive_capability_probe.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(f"\nReport saved: {out}")
    print("\nProbe complete. No data was written or erased.")

if __name__ == "__main__":
    main()
