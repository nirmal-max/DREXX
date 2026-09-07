from __future__ import annotations
import argparse,json,sys
from pathlib import Path
from .engine import scan,sanitize,write_audit

def main(argv=None):
    p=argparse.ArgumentParser(description="Policy-driven temporary/cache/residual-trace sanitizer.")
    p.add_argument("target")
    p.add_argument("--execute",action="store_true")
    p.add_argument("--confirm")
    p.add_argument("--secure-overwrite",action="store_true")
    p.add_argument("--verify",action="store_true")
    p.add_argument("--audit")
    args=p.parse_args(argv); target=Path(args.target)
    if not args.execute:
        try: items=scan(target)
        except Exception as e: print(f"error: {e}",file=sys.stderr); return 2
        print(json.dumps({"mode":"dry-run","target":str(target),"items":[i.to_dict() for i in items],"warning":"No data was changed."},indent=2)); return 0
    if args.confirm != str(target):
        print("error: --confirm must exactly match target",file=sys.stderr); return 2
    if not args.verify:
        print("error: --verify is required when --execute is used; refusing destructive execution",file=sys.stderr); return 2
    try:
        r=sanitize(target,secure_overwrite=args.secure_overwrite,verify=True)
        if args.audit: write_audit(args.audit,r)
    except OSError as e:
        print(f"error: failed to write audit record: {e}",file=sys.stderr); return 2
    print(json.dumps(r.to_dict(),indent=2))
    return 0 if r.status=="SANITIZED" else 1

if __name__=="__main__": raise SystemExit(main())
