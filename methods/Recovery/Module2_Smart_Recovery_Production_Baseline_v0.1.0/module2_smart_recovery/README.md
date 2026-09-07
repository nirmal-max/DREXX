# Module 2 — Smart Recovery

A production-oriented C++20 **strategy-selection/orchestration engine** for the
second recovery mode in the project architecture.

## What Smart does

Smart is not simply another scanner. It first obtains low-cost filesystem and
metadata evidence, scores candidate recovery strategies, and chooses the next
most appropriate strategy.

Current executable strategies:

- **Quick** — executable through the Module 1 filesystem-metadata engine.
- **Filesystem** — planning/handoff state; full Module 4 execution is intentionally
  not embedded yet.
- **Targeted** — planning/handoff state; Module 3 engine is the future executor.
- **Deep** — planning/handoff state; Module 5 engine is the future executor.
- **Damaged Media** — planning/handoff state; Module 8 engine is the future executor.
- **Forensic Review** — planning/handoff state; Module 9 engine is the future executor.

This is deliberate: Smart must not fake capabilities that have not yet been
implemented. As modules 3–9 become available, the same planner contract can
invoke them.

## Decision model

Smart uses evidence rather than a single hard-coded filesystem rule:

    source
      -> Quick evidence probe
      -> partition/filesystem evidence
      -> metadata candidate quality
      -> corruption/read-error signals
      -> weighted strategy ranking
      -> selected strategy
      -> execute available strategy OR explicit handoff

This follows the public description of R-Studio IntelligentScan: the product
identifies filesystem/storage records from known structures and field/relationship
constraints, can assign probabilities when classification is ambiguous, and uses
those records to reconstruct possible partitions/filesystems. It also explicitly
warns that the reconstruction is probabilistic rather than guaranteed.

UFS Explorer is the complementary benchmark for separating filesystem indexing
from broader scanning/recovery workflows.

## Build

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build -j
    ctest --test-dir build --output-on-failure

Windows:

    cmake -S . -B build -A x64
    cmake --build build --config Release

## CLI

    smartscan --source evidence.raw
    smartscan --source evidence.raw --output smart-plan.json
    smartscan --source \\\\.\\PhysicalDrive0 --output smart-plan.json

The result is JSON containing the selected strategy, weighted ranking,
rationale, Quick evidence status, candidate count, and warnings.

## Safety

The source abstraction is read-only. Smart does not write to the scanned source.
Recovery output, when a future executor is attached, must always target a
separate destination.

## Commercial release gates

This package is a serious engineering baseline, not a claim of universal
commercial certification. Before shipping commercially, complete:

- real NTFS/FAT/exFAT/APFS/EXT4/ReFS corpus validation
- NIST/CFTT regression corpus
- fuzzing and malformed-image testing
- Windows physical-device integration testing
- source identity and scan-state persistence
- large-disk performance profiling
- strategy calibration against labeled recovery cases
- false-positive/false-negative measurement
- legal/license/security review
- code signing and installer testing
- end-to-end integration of Modules 3–9
