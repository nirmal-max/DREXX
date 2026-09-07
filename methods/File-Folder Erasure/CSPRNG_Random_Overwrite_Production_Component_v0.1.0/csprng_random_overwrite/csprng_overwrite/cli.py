from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .engine import (
    CSPRNGOverwriteError,
    overwrite_file,
    overwrite_tree,
    write_audit,
)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="CSPRNG random overwrite for applicable regular files."
    )
    p.add_argument("target")
    p.add_argument(
        "--execute",
        action="store_true",
        help="Actually overwrite/delete; default is dry-run.",
    )
    p.add_argument(
        "--confirm",
        help="Must exactly match target when --execute is used.",
    )
    p.add_argument(
        "--verify",
        action="store_true",
        help="Required for destructive execution; verify post-overwrite content.",
    )
    p.add_argument(
        "--keep",
        action="store_true",
        help="Keep the overwritten file instead of unlinking it.",
    )
    p.add_argument("--chunk-size", type=int, default=1024 * 1024)
    p.add_argument("--audit", help="Write JSON audit record to this path.")
    args = p.parse_args(argv)

    target = Path(args.target)
    if not args.execute:
        print(
            json.dumps(
                {
                    "mode": "dry-run",
                    "target": str(target),
                    "action": "csprng-random-overwrite",
                    "warning": "No data was changed. Use --execute --confirm <target> --verify to execute.",
                },
                indent=2,
            )
        )
        return 0

    if not args.verify:
        print(
            "error: --verify is required when --execute is used; refusing destructive execution",
            file=sys.stderr,
        )
        return 2

    if args.confirm != str(target):
        print("error: --confirm must exactly match the target path", file=sys.stderr)
        return 2

    try:
        if target.is_dir():
            results = overwrite_tree(
                target,
                verify=True,
                remove=not args.keep,
                chunk_size=args.chunk_size,
            )
        else:
            results = [
                overwrite_file(
                    target,
                    verify=True,
                    remove=not args.keep,
                    chunk_size=args.chunk_size,
                )
            ]
    except (OSError, CSPRNGOverwriteError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.audit:
        try:
            write_audit(args.audit, results)
        except OSError as exc:
            print(f"error: failed to write audit record: {exc}", file=sys.stderr)
            return 2

    print(json.dumps([r.to_dict() for r in results], indent=2))
    return 1 if any(r.error for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
