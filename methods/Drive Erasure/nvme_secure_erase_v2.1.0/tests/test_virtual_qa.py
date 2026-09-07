import sys; sys.path.insert(0,"src")
from nvme.simulation import FakeNVMe,State
def test_firmware_profiles():
 d=FakeNVMe({"block","crypto","overwrite"}); assert d.sanitize("crypto") and d.state==State.COMPLETE
def test_power_loss_and_reset_are_not_success():
 for f in ("power_loss","reset","firmware_error"):
  d=FakeNVMe({"block"}); assert not d.sanitize("block",f)
