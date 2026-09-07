# Security

- evidence source is opened read-only by the baseline
- evidence copy is created separately
- destination is refused when it aliases the source path
- SHA-256 is computed over the exact bytes
- case events are chained
- case writes use temporary-file replacement
- reports identify tool version/configuration
- no claim of physical write blocking is made without an external adapter

Commercial release gates:
- authenticated examiner identity
- signed event records
- append-only/WORM case storage option
- OS/device-level write-block verification
- hardware write-blocker certification matrix
- timezone/clock evidence
- access-control audit
- crash/power-loss tests
- NIST-style acquisition corpus
- independent hash verification
- cross-platform physical-device adapters
