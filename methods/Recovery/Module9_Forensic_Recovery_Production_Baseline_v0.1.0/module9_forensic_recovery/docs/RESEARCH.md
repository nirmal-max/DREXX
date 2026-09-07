# Module 9 research record

## NIST CFTT

NIST CFTT exists specifically because forensic tools need objective,
repeatable testing. Its methodology is functionality-driven: define
requirements/assertions/test cases, build a test environment, execute tests
and publish results.

Sources:
https://www.nist.gov/itl/csd/secure-systems-and-applications/computer-forensics-tool-testing-program-cftt
https://www.nist.gov/itl/csd/secure-systems-and-applications/computer-forensics-tool-testing-program-cftt/cftt-general-0

Design implication:
Module 9 treats acquisition, write protection and verification as separate
testable capabilities instead of one "forensic mode" switch.

## NIST disk-imaging testing

NIST maintains disk-imaging specifications, test support software and
published federated test results for forensic imaging tools. The test program
covers imaging accuracy and reproducibility.

Source:
https://www.nist.gov/itl/csd/secure-systems-and-applications/computer-forensics-tool-testing-program-cftt/cftt-2

## The Sleuth Kit / Autopsy architecture

TSK is a library/CLI layer for volume and filesystem analysis and can be
integrated into larger forensic applications. Its framework uses modules and
shared case artifacts/results.

Sources:
https://sleuthkit.org/sleuthkit/
https://www.sleuthkit.org/sleuthkit/framework.php

Design implication:
Module 9 provides the evidence/case layer around Modules 4–8 instead of
duplicating their recovery algorithms.

## Hashing

A forensic acquisition workflow needs cryptographic verification of evidence
and derived images. This baseline uses SHA-256 for modern integrity records.
Legacy MD5/SHA-1 compatibility can be added as metadata-only adapters when
required by an external case, but they are not used as the primary integrity
claim.

## Commercial/IP boundary

No proprietary EnCase, FTK, Autopsy or TSK implementation is copied.
The case/event model is original and based on public forensic workflow
principles.
