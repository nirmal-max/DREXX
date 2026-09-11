# Regression gate acceptance criteria

The repository-wide regression workflow must finish successfully with:

- Python compilation successful.
- Every discovered `tests` directory executed.
- Every discovered suite passes in all 100 consecutive iterations.

This gate is software-only. Real ATA/NVMe/device-native commands and physical destruction require separately qualified hardware tests and must never be inferred from simulated tests.