# Module 5 — Deep Recovery

Deep Recovery is the thorough logical-structure recovery layer. It is not a
single brute-force scan. It performs a multi-pass search over the selected
source region, discovers filesystem anchors, validates geometry, scores
independent evidence, clusters overlapping candidates, and produces a
reconstruction plan for the strongest filesystem versions.

## What it does

1. coarse anchor discovery across the source
2. adaptive refinement around candidate regions
3. filesystem-specific structural validation
4. candidate scoring
5. overlap/duplicate clustering
6. ranked reconstruction candidates
7. resumable scan-state output

Supported candidate families:
- NTFS
- FAT12/16/32
- exFAT
- EXT2/3/4

This layer is intentionally deeper than Module 4: it can find filesystem
structures when the original partition boundaries are missing, shifted or
overwritten, and it can retain multiple competing volume hypotheses.

It does NOT silently become:
- Module 3 raw file carving
- Module 6 fragmented-content reconstruction
- Module 7 RAID reconstruction
- Module 8 failing-media handling
- Module 9 forensic evidence packaging

## CLI

deepscan --source image.raw --output deep.json
deepscan --source image.raw --offset 0 --size 10737418240 --output deep.json
deepscan --source image.raw --state scan.dstate --output deep.json
deepscan --source image.raw --resume scan.dstate --output deep.json
