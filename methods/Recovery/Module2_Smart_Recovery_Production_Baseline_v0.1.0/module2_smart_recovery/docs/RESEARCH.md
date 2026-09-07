# Module 2 Research — Smart Strategy Selection

## 1. R-Studio IntelligentScan

R-Studio publicly describes IntelligentScan as a process that reads disk data,
analyzes known record structures, validates field values and relationships, and
uses those observations to determine likely record types. It documents MBR/GPT,
NTFS, FAT/exFAT, ReFS, HFS/HFS+, APFS, Ext2/3/4 and UFS/FFS record families, plus
known-file signatures for raw carving.

The key architectural lesson for Smart is **evidence-weighted classification**,
not a single deterministic rule. R-Studio states that ambiguous records may be
assigned probabilities and that relations among records are used to generate
possible partitions and reconstruct filesystems. It also explicitly notes that
this approach is probabilistic and cannot guarantee correctness.

Sources:
- R-Studio IntelligentScan Technology
- R-Studio Data Recovery Technology
- R-Studio Recovery Manual

## 2. UFS Explorer

UFS Explorer's documented scan workflow distinguishes filesystem indexing from
broader unused-space/structure analysis. This supports the Smart concept of
starting with a low-cost evidence probe and escalating only when the evidence
requires it rather than forcing every source through the most expensive scan.

## 3. The Sleuth Kit

TSK provides a useful architectural benchmark because it separates volume-system
analysis, filesystem structures, metadata, file names and data units. Its
non-intrusive analysis model supports the idea that Smart should consume
structured evidence from lower-level providers rather than implement one giant
scanner.

## 4. NIST/CFTT

NIST's Deleted File Recovery program publishes specifications and test support
for evaluating recovery tools. The Smart engine therefore needs a labeled corpus
where the correct next strategy is known, not merely a test that checks whether
some output was produced.

## 5. Why the implementation is conservative

Smart must not silently turn into Deep, Targeted or Damaged Media mode. If the
available evidence says that filesystem metadata is insufficient, Smart returns
an explicit handoff recommendation. This preserves predictable runtime and makes
strategy selection measurable.

## 6. Scoring model

The current v0.1 baseline uses transparent heuristic scores rather than an
opaque ML model. Reasons are emitted with every score. This is intentional for
an early production system: calibration can be measured against a labeled corpus
before introducing a learned model.

Future calibration fields should include:

- filesystem identification confidence
- metadata integrity score
- partition-boundary confidence
- extent completeness
- candidate density
- read-error rate
- bad-sector/latency signals
- corruption indicators
- file-type/content validation
- expected scan cost
- expected recovery yield

## 7. Commercial/IP boundary

No R-Studio or UFS Explorer source code is included. Their public behavior is
used as a technical benchmark. The Smart implementation is original and the
package contains no proprietary third-party recovery engine.
