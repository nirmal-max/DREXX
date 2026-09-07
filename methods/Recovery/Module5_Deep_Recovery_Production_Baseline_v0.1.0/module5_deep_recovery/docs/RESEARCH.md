# Deep Recovery research

## R-Studio

R-Studio's IntelligentScan describes a multi-record recognition approach:
MBR/GPT, filesystem boot records, folder/MFT records, filesystem structures
and known-file signatures are recognized, valid field values and relationships
are considered, and candidate partitions/filesystems are reconstructed.
This directly motivates the candidate-evidence architecture in Module 5.

Sources:
https://www.r-studio.com/data_recovery_technology.html
https://www.r-studio.com/Unformat_Help/inteligentscantechnology.html

## UFS Explorer

UFS Explorer documents lost-file scanning as a configurable process with a
selected storage region and filesystem types. Its recovery workflow also
separates scan-parameter selection from the scanning phase.

Source:
https://www.ufsexplorer.com/manual/std/

## DMDE

DMDE Full Scan explicitly searches for filesystem structures, can virtually
reconstruct damaged directory structures, and reports quality indicators for
found volume versions. It also supports saving scan state/results.

Sources:
https://dmde.com/manual/fullscan.html
https://dmde.com/manual/reconstruction.html

Module 5 therefore models multiple candidate volume versions rather than
forcing one answer from the first recognizable boot sector.

## The Sleuth Kit

TSK separates volume and filesystem analysis and is designed as a reusable
library for disk-image analysis. Its model reinforces the separation between
volume discovery and filesystem/object analysis.

Source:
https://sleuthkit.org/sleuthkit/

## Important engineering distinction

"Deep" means deeper structural search and validation, not simply reading every
byte once with no model. A production implementation must retain competing
hypotheses, confidence/evidence, region boundaries, and resumability.

No proprietary source from R-Studio, UFS Explorer, DMDE or TSK is copied.
