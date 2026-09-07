# Module 9 — Forensic Recovery

Evidence-preserving recovery and acquisition control layer.

## Design objective

Module 9 is not "another scanner." It creates an auditable forensic case
record around acquisition and analysis:

source identity
 -> acquisition event
 -> source/image hashes
 -> write-protection declaration
 -> tool/version/configuration
 -> immutable event chain
 -> analysis observations
 -> verification
 -> report

The engine is deliberately fail-closed about write protection. A software
flag saying "write protected" is NOT treated as proof of a physical hardware
write blocker. Hardware write blocking must be independently verified.

## CLI

forensicctl init --case CASE --examiner NAME --description TEXT
forensicctl acquire --case CASE --source IMAGE --evidence EVIDENCE_COPY
forensicctl hash --case CASE --file EVIDENCE_COPY
forensicctl verify --case CASE --file EVIDENCE_COPY
forensicctl event --case CASE --type analysis --message "Module 4 scan completed"

All case events are chained by SHA-256 over the canonical previous event and
the new event payload. The case directory is intended to be stored separately
from evidence.

## Forensic modes

- acquisition
- verification
- analysis logging
- evidence manifest
- chain-of-custody events
- integrity checking
- report generation

The baseline supports regular files/images. Platform-specific physical-device
acquisition and certified hardware write-blocker integration are separate
adapters.
