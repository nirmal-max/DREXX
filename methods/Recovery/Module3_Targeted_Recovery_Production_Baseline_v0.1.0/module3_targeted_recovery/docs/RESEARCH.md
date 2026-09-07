# Module 3 research record

## UFS Explorer / IntelliRAW

UFS Explorer documents IntelliRAW as raw/known-content recovery used when
filesystem-based recovery is not possible. Its custom-rule documentation
describes identifying characteristic byte sequences, especially near the start
or end of a file, and defining binary or text-like rules. It also supports
user-defined rules.

Design adopted:
- rule-driven known-content scanning
- start/end signatures
- custom rule support
- explicit raw-candidate results
- no silent filesystem reconstruction

## R-Studio

R-Studio documents "Known File Types" as a raw-file search. It lets users
choose the file types for a scan and define custom types. R-Studio explicitly
notes that known-file scanning can recover only unfragmented files.

Design adopted:
- session-selectable type set
- custom rule definitions
- contiguous-file recovery as the default contract
- bounded/unknown-size handling
- candidate confidence and warnings

R-Studio's IntelligentScan also recognizes structural records and file
signatures; those structural capabilities remain outside Targeted except for
format validation.

## DMDE

DMDE documents Raw File Search using file signatures, including custom byte
signatures, variable offsets and masks. It explicitly warns that raw recovery
does not preserve original filenames/directories and is unreliable for
fragmented files.

Design adopted:
- hexadecimal signatures
- byte masks
- offset windows
- generated names
- no claim of original path recovery

## PhotoRec

PhotoRec is a mature signature-carving reference. Its principal lesson for this
module is a broad, extensible file-signature database and carving-oriented
validation. This implementation does not embed PhotoRec code.

## Stellar

Stellar is treated as a commercial workflow benchmark for selecting file types,
raw scanning and result presentation. No proprietary implementation is copied.

## NIST/CFTT

NIST CFTT provides deleted-file recovery specifications and test support
material. Targeted needs its own known-content corpus because carving is a
different task, but NIST is useful for regression discipline and evidence
handling.

## Commercial/IP boundary

No UFS Explorer, R-Studio, Stellar, DMDE, or PhotoRec source code is bundled.
Rules in this package are original minimal examples. A commercial product
should license/curate a larger signature database separately and audit every
rule's provenance.
