import argparse,json
from .models import Device
from .runner import make_plan
def main():
 p=argparse.ArgumentParser(); p.add_argument("path"); p.add_argument("--media-type",default="HDD"); p.add_argument("--requested",default="best"); a=p.parse_args(); d=Device(a.path,a.media_type,capabilities={}); print(json.dumps(make_plan(d,a.requested).to_dict(),indent=2))
if __name__=="__main__": main()
