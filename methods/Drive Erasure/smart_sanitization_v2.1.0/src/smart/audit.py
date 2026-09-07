import json,hashlib,os
from .models import utc,evidence_hash
def write(out,record):
    os.makedirs(out,exist_ok=True); rec=dict(record); rec["timestamp_utc"]=utc(); rec["schema_version"]="2.0"; rec["evidence_sha256"]=evidence_hash(rec)
    p=os.path.join(out,"evidence.json"); open(p,"w").write(json.dumps(rec,indent=2,sort_keys=True)); open(p+".sha256","w").write(rec["evidence_sha256"]+"  evidence.json\n"); return p
