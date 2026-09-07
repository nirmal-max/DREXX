from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from .engine import sanitize_tail, write_audit, SyntheticBackend

def main(argv=None):
    p=argparse.ArgumentParser(description="Conservative file-slack/cluster-tip sanitizer.")
    p.add_argument("target"); p.add_argument("--execute",action="store_true"); p.add_argument("--confirm")
    p.add_argument("--pattern",choices=["zero","random"],default="zero"); p.add_argument("--verify",action="store_true")
    p.add_argument("--synthetic-backend",action="store_true"); p.add_argument("--audit")
    args=p.parse_args(argv); target=Path(args.target)
    if not args.execute:
        print(json.dumps({"mode":"dry-run","target":str(target),"method":"file-slack-cluster-tip-sanitization","warning":"No data was changed."},indent=2)); return 0
    if not args.verify:
        print("error: --verify is required when --execute is used; refusing sanitization",file=sys.stderr); return 2
    if args.confirm != str(target):
        print("error: --confirm must exactly match target",file=sys.stderr); return 2
    backend=SyntheticBackend() if args.synthetic_backend else None
    result=sanitize_tail(target,backend=backend,pattern=args.pattern,verify=True)
    if args.audit: write_audit(args.audit,result)
    print(json.dumps(result.to_dict(),indent=2))
    return 0 if result.status in {"SANITIZED","NO_SLACK"} else 1

if __name__ == "__main__": raise SystemExit(main())
