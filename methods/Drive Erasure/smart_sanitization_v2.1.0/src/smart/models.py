from dataclasses import dataclass, asdict
from enum import Enum
import hashlib, json, os, time, uuid

class Outcome(str,Enum): READY="READY"; BLOCKED="BLOCKED"; PLANNED="PLANNED"; VERIFIED="VERIFIED"; FAILED="FAILED"; INDETERMINATE="INDETERMINATE"
@dataclass(frozen=True)
class Device:
    path:str; media_type:str; model:str=""; serial:str=""; size_bytes:int=0; mounted:bool=False; system_disk:bool=False
    capabilities:dict=None
    def caps(self): return self.capabilities or {}
@dataclass(frozen=True)
class Plan:
    module:str; outcome:str; method:str; assurance:str; rationale:str; commands:tuple=(); verification:tuple=(); warnings:tuple=()
    def to_dict(self): return asdict(self)
def evidence_hash(record):
    return hashlib.sha256(json.dumps(record,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def utc(): return time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())
