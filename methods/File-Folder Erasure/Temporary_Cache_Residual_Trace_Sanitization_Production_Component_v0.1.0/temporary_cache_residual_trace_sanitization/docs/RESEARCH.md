# Deep research — Temporary / Cache / Residual-Trace Sanitization

## NIST SP 800-88 Rev. 2
The current final revision (September 2025) frames sanitization around making access
to target data infeasible for a given level of effort and selecting appropriate
techniques and controls. It does not prescribe a universal cache/log/temp cleaner.

## Microsoft SDelete
SDelete v2.06 is useful for the secure-delete layer. Microsoft documents ordinary
file overwrites, free-space cleansing and filename handling. It also explicitly notes
that its free-space operation does not securely delete file names stored in free
directory space.

This supports a separation between current application traces and filesystem-internal
historical metadata.

## BleachBit
BleachBit is the strongest open-source reference for application-trace cleaning.
Its official documentation describes cleaners for cache, cookies, logs, recent-file
lists and temporary files. Its source uses CleanerML rules with explicit search
methods such as file, glob, walk.files and walk.all, and commands such as delete and
truncate. The project also includes application-specific cleaners for browsers and
system components.

Important design lesson: trace cleaning must be an explicit catalog. A generic
"delete every cache folder" rule is unsafe.

BleachBit's documentation also notes that secure overwrite is slower and has filesystem
limitations, including ext3/ext4 journal-mode caveats.

## Eraser
Eraser was reviewed as a Windows secure deletion reference. Its architecture is
useful for integrating secure file deletion with selected file/folder targets, but
the present module does not copy its code.

## SDelete vs BleachBit
SDelete is primarily a secure-delete/free-space tool. BleachBit is primarily an
application/system trace cleaner. This module combines the useful architectural
ideas without copying source:
- explicit target rules;
- preview/dry-run;
- secure overwrite as an optional operation;
- application-specific trace catalogs;
- audit evidence;
- conservative filesystem behavior.

## Residual traces that need separate modules
The following are not safely solved by deleting cache directories:
- browser SQLite history and WAL/SHM files;
- Windows Registry artifacts;
- Windows Event Logs;
- Prefetch;
- Windows Search indexes;
- jump lists;
- thumbnails and icon caches;
- shell/recent-document databases;
- Linux journal/systemd logs;
- shell histories;
- application-specific logs;
- swap/pagefile;
- crash dumps;
- memory;
- snapshots;
- backups and replicas.

Some require database-aware vacuum/transaction handling, service coordination,
or OS-specific privileged APIs.

## Production conclusion
This module should be the policy-driven orchestration layer for currently addressable
temporary/cache/residual files. It should call specialized cleaners for databases and
OS artifacts instead of recursively deleting arbitrary directories.
