from __future__ import annotations
import argparse, json, sys
from .engine import LocalKeyStore, create_envelope, save_envelope, load_envelope, destroy_key, verify_erasure, write_audit

def _store(path): return LocalKeyStore(path)

def main(argv=None):
    p=argparse.ArgumentParser(description="Cryptographic erasure component.")
    sub=p.add_subparsers(dest="cmd",required=True)
    c=sub.add_parser("create-key"); c.add_argument("key_id"); c.add_argument("--store",default=".crypto-keys")
    e=sub.add_parser("create-secret"); e.add_argument("output"); e.add_argument("--key-id",required=True); e.add_argument("--store",default=".crypto-keys"); e.add_argument("--text",default="test secret")
    d=sub.add_parser("destroy-key"); d.add_argument("key_id"); d.add_argument("--store",default=".crypto-keys"); d.add_argument("--execute",action="store_true"); d.add_argument("--confirm"); d.add_argument("--target-id"); d.add_argument("--verify",action="store_true"); d.add_argument("--audit")
    v=sub.add_parser("verify"); v.add_argument("envelope"); v.add_argument("key_id"); v.add_argument("--store",default=".crypto-keys")
    a=p.parse_args(argv); ks=_store(a.store)
    if a.cmd=="create-key": ks.create_key(a.key_id); print(json.dumps({"status":"CREATED","key_id":a.key_id})); return 0
    if a.cmd=="create-secret":
        if not ks.exists(a.key_id): ks.create_key(a.key_id)
        env=create_envelope(ks,a.key_id,a.text.encode(),a.output); save_envelope(a.output,env)
        print(json.dumps({"status":"ENCRYPTED","output":a.output,"key_id":a.key_id})); return 0
    if a.cmd=="verify":
        env=load_envelope(a.envelope); ok,reason=verify_erasure(ks,env)
        print(json.dumps({"verified":ok,"reason":reason},indent=2)); return 0 if ok else 1
    if a.cmd=="destroy-key":
        if not a.execute:
            print(json.dumps({"mode":"dry-run","action":"destroy-key","key_id":a.key_id,"warning":"No key was destroyed."},indent=2)); return 0
        if not a.verify:
            print("error: --verify is required when --execute is used; refusing destructive execution",file=sys.stderr); return 2
        if a.confirm != a.key_id:
            print("error: --confirm must exactly match key_id",file=sys.stderr); return 2
        target=a.target_id or a.key_id
        try:
            destroy_key(ks,a.key_id)
            if ks.exists(a.key_id): raise RuntimeError("key still exists after destruction")
            if a.target_id:
                env=load_envelope(a.target_id); verified,reason=verify_erasure(ks,env)
                if not verified: raise RuntimeError(f"verification failed: {reason}")
            if a.audit:
                try: write_audit(a.audit,action="destroy-key",key_id=a.key_id,target_id=target,status="SANITIZED")
                except (OSError,ValueError,TypeError) as exc: raise RuntimeError(f"audit write failed: {exc}") from exc
            print(json.dumps({"status":"SANITIZED","key_id":a.key_id,"target_id":target,"verified":True},indent=2)); return 0
        except Exception as exc:
            if a.audit:
                try: write_audit(a.audit,action="destroy-key",key_id=a.key_id,target_id=target,status="ERROR",details={"error":str(exc)})
                except (OSError,ValueError,TypeError): pass
            print(json.dumps({"status":"ERROR","error":str(exc)})); return 1

if __name__=="__main__": raise SystemExit(main())
