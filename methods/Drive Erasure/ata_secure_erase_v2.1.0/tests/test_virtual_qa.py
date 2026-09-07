import sys; sys.path.insert(0,"src")
from ata.simulation import FakeATA
def test_frozen_and_enabled_are_safe_stops():
 assert not FakeATA(frozen=True).erase(); assert not FakeATA(enabled=True).erase()
def test_failures_indeterminate():
 for f in ("power_loss","reset","firmware_error"):
  d=FakeATA(); assert not d.erase(failure=f) and d.state=="indeterminate"
