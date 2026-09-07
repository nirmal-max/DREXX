from __future__ import annotations
import argparse,json,sys
from pathlib import Path
from .engine import DeviceProfile,choose_plan,execute_plan,write_audit


def main(argv=None):
    p=argparse.ArgumentParser(description="Storage-aware sanitization policy and guarded executor.")
    p.add_argument("profile_json")
    p.add_argument("--allow-logical-hdd-fallback",action="store_true")
    p.add_argument("--execute",action="store_true")
    p.add_argument("--confirm")
    p.add_argument("--audit")
    args=p.parse_args(argv)

    profile=DeviceProfile.from_dict(json.loads(Path(args.profile_json).read_text()))
    plan=choose_plan(profile,approved_logical_fallback=args.allow_logical_hdd_fallback)

    if not args.execute:
        print(json.dumps({"mode":"dry-run","profile":profile.to_dict(),"plan":plan.to_dict(),
                          "warning":"No device command was executed."},indent=2))
        return 0 if plan.status!="REFUSED" else 1

    if args.confirm != profile.path:
        print("error: --confirm must exactly match device path",file=sys.stderr)
        return 2

    try:
        result=execute_plan(plan,confirm_target=profile.path,dry_run=False)
    except Exception as e:
        print(json.dumps({"status":"ERROR","error":str(e)},indent=2))
        return 1

    if args.audit:
        write_audit(args.audit,profile=profile,plan=plan,result=result)
    print(json.dumps(result,indent=2))
    return 0 if result["status"]=="EXECUTED" else 1


if __name__=="__main__":
    raise SystemExit(main())
