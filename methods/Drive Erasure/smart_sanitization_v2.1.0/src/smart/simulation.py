class FailureMatrix:
    @staticmethod
    def cases(): return ["different_firmware","power_loss","controller_reset","unusual_firmware","bridge"]
    @staticmethod
    def expected(): return {c:"STOP_OR_INDETERMINATE" for c in FailureMatrix.cases()}
