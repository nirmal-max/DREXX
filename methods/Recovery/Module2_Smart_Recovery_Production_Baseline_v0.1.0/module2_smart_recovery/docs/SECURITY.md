# Security

- Source access is read-only.
- Smart does not mount or modify the source filesystem.
- Parser bounds checks are inherited from the Module 1 core.
- Strategy selection does not execute shell commands.
- JSON output is generated directly by the program.
- Future executors must preserve the same source/destination separation.

Required release testing: ASan, UBSan, Windows Application Verifier, malformed
filesystem corpus, fuzzing of partition/filesystem parsers, resource exhaustion,
and cancellation under load.
