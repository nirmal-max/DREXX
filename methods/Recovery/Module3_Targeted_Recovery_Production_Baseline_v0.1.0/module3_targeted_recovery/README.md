# Module 3 — Targeted Recovery

A production-oriented C++20 targeted known-file recovery engine.

## Purpose

Targeted mode deliberately searches for **specific requested file types** using
known content signatures and format-aware validation. It is not Quick metadata
recovery and it is not a general Deep/Fragment engine.

The implementation is based on the documented ideas behind UFS Explorer
IntelliRAW, R-Studio Known File Types, DMDE Raw File Search, Stellar's raw
recovery workflow, and PhotoRec-style signature carving. No proprietary source
code is copied.

## Features

- read-only image/file source
- Windows PhysicalDrive read-only support
- user-selectable rule database
- built-in PDF/JPEG/PNG/ZIP/DOCX/XLSX/PPTX/MP4/MP3 signatures
- configurable hexadecimal/text signatures
- start/end signatures
- bounded file-size rules
- byte-mask matching
- chunked streaming scan
- overlap-safe boundary handling
- candidate de-duplication
- format-aware validators for selected formats
- confidence/evidence scoring
- safe destination-only recovery
- JSON output
- cancellation hooks
- CMake build and deterministic tests

## CLI

List rules:
  targetedscan --list-rules

Scan:
  targetedscan --source evidence.raw --types pdf,jpeg,png --output targeted.json

Recover:
  targetedscan --source evidence.raw --types pdf,jpeg --recover 3 --destination recovered

Custom rules:
  targetedscan --source image.raw --rules rules/custom.json --types custom.bin

## Recovery boundary

Known-content recovery is strongest for files whose contents are substantially
contiguous. It does not reconstruct arbitrary fragmented files. Fragment
inference belongs to Module 6.

A raw candidate normally does not have its original filesystem path/name.
Names are generated from type + offset + candidate id.

## Safety

The source is never opened for writing. Output must be a separate destination.
The engine does not mount filesystems or execute external recovery programs.
