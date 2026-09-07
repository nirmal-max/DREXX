from dataclasses import dataclass
from enum import Enum
class State(str,Enum): READY="ready"; RUNNING="running"; COMPLETE="complete"; FAILED="failed"; RESET="reset"; DISAPPEARED="disappeared"
@dataclass
class FakeNVMe:
    sanicap:set
    state:State=State.READY
    firmware="simulated"
    def sanitize(self, action, failure=None):
        if action not in self.sanicap: raise ValueError("unsupported action")
        if failure=="power_loss": self.state=State.FAILED; return False
        if failure=="reset": self.state=State.RESET; return False
        if failure=="firmware_error": self.state=State.FAILED; return False
        self.state=State.COMPLETE; return True
