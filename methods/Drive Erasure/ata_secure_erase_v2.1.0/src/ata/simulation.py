from dataclasses import dataclass
@dataclass
class FakeATA:
    security_supported:bool=True; enhanced:bool=True; frozen:bool=False; enabled:bool=False; state:str="ready"
    def erase(self, enhanced=False, failure=None):
        if self.frozen: return False
        if self.enabled: return False
        if failure in ("power_loss","reset","firmware_error"): self.state="indeterminate"; return False
        self.state="erased"; return True
