# Security and safety

- source is opened read-only
- no source writes
- destination is required to differ from source
- output writes are bounded
- map updates are atomic via temporary file + rename
- unreadable sectors are filled only in the destination image
- failed reads never become fabricated source data
- resource limits prevent unlimited retries
- cancellation leaves a resumable map

Commercial release requires:
- real HDD/SSD bad-sector corpus
- USB bridge instability tests
- power-loss/restart tests
- multi-terabyte performance tests
- Windows physical-device adapter
- Linux direct-I/O adapter
- SMART/health telemetry adapter
- fuzzing and ASan/UBSan
- independent verification against ddrescue and mature imaging products
