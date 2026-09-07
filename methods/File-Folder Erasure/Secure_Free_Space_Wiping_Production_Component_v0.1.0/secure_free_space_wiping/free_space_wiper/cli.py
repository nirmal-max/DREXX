from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from .engine import wipe_free_space, estimate_free_space


def _write_audit(path, result):
    from .engine import write_audit
    try:
        write_audit(path, result)
    except (OSError, ValueError, TypeError) as exc:
        raise RuntimeError(f"audit write failed: {exc}") from exc


def main(argv=None):
    p = argparse.ArgumentParser(description="Allocation-based secure free-space wiper.")
    p.add_argument("target")
    p.add_argument("--execute", action="store_true")
    p.add_argument("--confirm")
    p.add_argument("--pattern", choices=["zero", "random"], default="zero")
    p.add_argument("--reserve-bytes", type=int, default=64 * 1024 * 1024)
    p.add_argument("--chunk-size", type=int, default=1024 * 1024)
    p.add_argument("--no-verify", action="store_true", help="Disable verification only for non-destructive/integration use; destructive execution always requires verification.")
    p.add_argument("--audit")
    args = p.parse_args(argv)

    target = Path(args.target)
    if not args.execute:
        try:
            free = estimate_free_space(target)
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(json.dumps({"mode":"dry-run","target":str(target),"action":"secure-free-space-wiping","pattern":args.pattern,"reported_free_bytes":free,"reserve_bytes":args.reserve_bytes,"planned_upper_bound":max(0,free-args.reserve_bytes),"warning":"No data was changed. This operation can temporarily consume most free space."}, indent=2))
        return 0

    if args.confirm != str(target):
        print("error: --confirm must exactly match the target", file=sys.stderr)
        return 2
    if args.reserve_bytes < 0:
        print("error: reserve-bytes must be non-negative", file=sys.stderr)
        return 2
    if args.no_verify:
        print("error: --no-verify is not permitted for destructive execution", file=sys.stderr)
        return 2

    try:
        result = wipe_free_space(target, pattern=args.pattern, reserve_bytes=args.reserve_bytes, chunk_size=args.chunk_size, verify=True)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.audit:
        try:
            _write_audit(args.audit, result)
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 3
    print(json.dumps(result.to_dict(), indent=2))
    return 1 if result.error or not result.verified else 0


if __name__ == "__main__":
    raise SystemExit(main())
