from pathlib import Path
import hashlib
class VirtualDisk:
    def __init__(self,path,size=8192): self.path=Path(path); self.path.write_bytes(b"X"*size)
    def verify_zero(self): return self.path.read_bytes()==b"\0"*self.path.stat().st_size
    def corrupt(self,offset=0):
        b=bytearray(self.path.read_bytes()); b[offset]^=0xFF; self.path.write_bytes(b)
