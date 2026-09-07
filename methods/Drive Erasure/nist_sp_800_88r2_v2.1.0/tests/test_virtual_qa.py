import sys; sys.path.insert(0,"src")
from nist.simulation import FailureMatrix
def test_all_faults_have_non_success_policy():
 assert len(FailureMatrix.cases())==5 and all(v=="STOP_OR_INDETERMINATE" for v in FailureMatrix.expected().values())
