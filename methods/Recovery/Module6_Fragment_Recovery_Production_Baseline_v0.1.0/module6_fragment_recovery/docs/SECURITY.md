# Security

- source is read-only
- no filesystem mounting
- all offsets and lengths are bounds checked
- maximum fragment count and chain length are enforced
- graph branching is bounded
- overlap is rejected unless explicitly permitted by a future format plugin
- destination filenames are sanitized
- extraction writes only to a separate destination
- malformed input fails closed

Commercial release requires fuzzing of signature parsing, graph generation,
validators and extraction, plus ASan/UBSan, resource exhaustion tests and
large-image benchmarks.
