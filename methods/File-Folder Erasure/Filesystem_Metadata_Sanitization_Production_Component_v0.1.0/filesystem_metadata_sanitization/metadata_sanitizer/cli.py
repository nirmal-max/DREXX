from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import inspect_metadata, sanitize_metadata, write_audit


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Filesystem metadata sanitization.")
    p.add_argument("target")
    p.add_argument("--execute", action="store_true")
    p.add_argument("--confirm")
    p.add_argument("--clear-xattrs", action="store_true")
    p.add_argument("--normalize-times", action="store_true")
    p.add_argument("--normalize-permissions", action="store_true")
    p.add_argument("--rename", action="store_true")
    p.add_argument("--name-token", default="sanitized")
    p.add_argument("--recursive", action="store_true")
    p.add_argument("--audit")
    return p


def main(argv=None):
    args = _build_parser().parse_args(argv)
    target = Path(args.target)

    requested = {
        "clear_xattrs": args.clear_xattrs,
        "normalize_times": args.normalize_times,
        "normalize_permissions": args.normalize_permissions,
        "rename": args.rename,
        "recursive": args.recursive,
    }

    if not args.execute:
        print(json.dumps({"mode": "dry-run", "inspection": inspect_metadata(target), "requested_actions": requested, "warning": "No data or metadata was changed."}, indent=2))
        return 0

    if args.confirm is None:
        print("error: --confirm is required with --execute", file=sys.stderr)
        return 2
    if args.confirm != str(target):
        print("error: --confirm must exactly match target", file=sys.stderr)
        return 2
    if not any((args.clear_xattrs, args.normalize_times, args.normalize_permissions, args.rename)):
        print("error: --execute requires at least one sanitization action", file=sys.stderr)
        return 2

    result = sanitize_metadata(target, clear_xattrs=args.clear_xattrs, normalize_times=args.normalize_times,
                               normalize_permissions=args.normalize_permissions, rename=args.rename,
                               name_token=args.name_token, recursive=args.recursive)

    if args.audit:
        try:
            write_audit(args.audit, result)
        except (OSError, ValueError, TypeError) as exc:
            print(f"error: audit write failed: {exc}", file=sys.stderr)
            return 3

    print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.status == "SANITIZED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
