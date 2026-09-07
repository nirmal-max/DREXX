# Module 6 — Fragment Recovery

A production-oriented C++20 framework for reconstructing files from multiple
physical fragments when filesystem metadata is missing, incomplete, or
untrusted.

## Core principle

Fragment recovery must NOT simply concatenate every plausible block. Mature
recovery practice shows that raw known-file recovery is strongest for
unfragmented files, while fragmented recovery needs additional structural
evidence. This module therefore treats reconstruction as a scored hypothesis
problem.

Pipeline:

candidate anchors
 -> fragment inventory
 -> boundary/type validation
 -> adjacency/continuation evidence
 -> content continuity scoring
 -> candidate chains
 -> conflict resolution
 -> reconstruction plan
 -> optional extraction

## Evidence sources

- filesystem extents supplied by an upstream module
- known file headers/trailers
- format-specific continuation evidence
- cluster/block alignment
- expected size constraints
- local content continuity
- non-overlap and allocation constraints

## Current baseline

The shipped baseline implements:
- read-only source
- generic fragment model
- signature-based anchor discovery
- block/cluster-aligned fragment inventory
- chain generation with bounded branching
- deterministic scoring
- overlap/conflict rejection
- reconstruction to a separate destination
- JSON chain explanation

It intentionally does not claim arbitrary universal file-fragment ordering.
A production release requires format-specific reconstruction plugins and a
large ground-truth corpus.

## CLI

fragmentscan --source image.raw --type pdf --block-size 4096 --output fragments.json
fragmentscan --source image.raw --type jpeg --block-size 4096 --recover 1 --destination recovered

The recovered output is named using candidate id and type. Original paths/names
are unavailable when reconstruction relies only on content.
