# Module 6 research record

## R-Studio

R-Studio states that Known File Types recovery can successfully recover only
unfragmented files in its raw scan workflow. Its file-recovery explanation also
shows that fragmentation can cause a file to be cut at another file's signature
and lose later content.

Sources:
https://www.r-studio.com/Unformat_Help/discscan.html
https://www.r-studio.com/file-recovery-basics.html

Design implication:
Module 6 must be a separate reconstruction engine, not Module 3 with a larger
signature database.

## UFS Explorer

UFS Explorer describes IntelliRAW as known-content recovery for non-fragmented
files and explicitly notes mediocre results for highly fragmented content.
Its filesystem-oriented workflow instead uses metadata when available.

Source:
https://www.ufsexplorer.com/manual/standard/creating-custom-intelliraw-rules/

Design implication:
fragment recovery should combine metadata extents, content signatures and
format-specific evidence whenever possible.

## The Sleuth Kit

TSK models file content as data units and metadata as structures containing
pointers/runs to those data units. Its database schema also stores one or more
layout rows for a file depending on how fragmented it is.

Sources:
https://sleuthkit.org/sleuthkit/docs/api-docs/4.12.1/fspage.html
https://wiki.sleuthkit.org/SQLite-Database-v6-Schema/

Design implication:
the internal representation is a list of ordered physical extents, not a
single start/end pair.

## NIST / forensic validation

NIST CFTT is used as a validation philosophy: ground truth, repeatable tests,
known media and explicit expected results. Fragment reconstruction requires a
dedicated corpus because a successful header match is not enough.

## Commercial/IP boundary

No R-Studio, UFS Explorer, TSK or other proprietary source is copied. This
package contains an original generic reconstruction engine and small original
signature rules.
