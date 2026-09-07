# v2.1.0 Virtual Hardware QA

This build includes fault-injection tests for the software layer. Tested scenarios include:
- different controller/firmware capability profiles
- power-loss/interruption simulation
- controller reset simulation
- unusual/unsupported firmware capability responses
- transport/bridge capability changes where applicable
- verification corruption for overwrite
- physical destruction machine qualification/attestation simulation

A virtual test cannot establish behavior of real device firmware, NAND wear leveling, remapped sectors, physical destruction equipment, or real power-loss electrical behavior. Those remain hardware-qualification gates.
