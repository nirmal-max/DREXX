# Security model

- source opened read-only
- every scan range is bounds checked
- rule offsets and sizes are validated
- candidate sizes are capped
- output paths are sanitized
- no shell/mount operations
- cancellation is checked inside scan/recovery loops
- malformed rules cannot request unbounded allocation
- scanning uses bounded memory

Commercial release should add fuzzing of the rule parser, validators and
scanner, plus ASan/UBSan, Windows verifier, corpus mutation and large-image
resource exhaustion tests.
