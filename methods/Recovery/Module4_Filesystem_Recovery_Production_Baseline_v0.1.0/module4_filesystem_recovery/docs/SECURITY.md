# Security model

- source handles are read-only
- all declared offsets/sizes are bounds checked
- parser allocations are capped
- FAT/extent chains have loop and length guards
- directory recursion has a depth limit
- no mounting, shell commands or source writes
- output is generated separately
- malformed images should fail closed

Commercial release must add fuzzing for every provider, ASan/UBSan, Windows
Application Verifier, malformed-image corpus, differential tests and
resource-exhaustion tests.
