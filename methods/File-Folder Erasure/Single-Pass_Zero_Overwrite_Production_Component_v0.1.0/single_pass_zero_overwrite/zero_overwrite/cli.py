from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
from .engine import overwrite_file, overwrite_tree, write_audit, OverwriteError


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Single-pass zero overwrite for applicable regular files.")
    p.add_argument("target")
    p.add_argument("--execute", action="store_true", help="Actually overwrite/delete; default is dry-run.")
    p.add_argument("--confirm", help="Must exactly match the target path when --execute is used.")
    p.add_argument("--verify", action="store_true", help="Read back and verify all bytes are zero.")
    p.add_argument("--keep", action="store_true", help="Keep the zeroed file instead of unlinking it.")
    p.add_argument("--audit", help="Write JSON audit record to this path.")
    args = p.parse_args(argv)

    target = Path(args.target)
    if not args.execute:
        print(json.dumps({"mode": "dry-run", "target": str(target), "action": "single-pass-zero-overwrite", "warning": "No data was changed. Use --execute --confirm <target> to execute."}, indent=2))
        return 0

    if args.confirm != str(target):
        print("error: --confirm must exactly match the target path", file=sys.stderr)
        return 2

    if not args.verify:
        print("error: --verify is required for destructive execution; refusing to overwrite/delete", file=sys.stderr)
        return 2

    try:
        if target.is_dir():
            results = overwrite_tree(target, verify=True, remove=not args.keep)
        else:
            results = [overwrite_file(target, verify=True, remove=not args.keep)]
    except (OSError, OverwriteError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.audit:
        try:
            write_audit(args.audit, results)
        except (OSError, ValueError, TypeError) as exc:
            print(f"error: audit write failed: {exc}", file=sys.stderr)
            return 3

    print(json.dumps([r.to_dict() for r in results], indent=2))
    return 1 if any(r.error for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
