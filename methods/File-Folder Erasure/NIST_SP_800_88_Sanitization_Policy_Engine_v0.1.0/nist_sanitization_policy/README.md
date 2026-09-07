# NIST SP 800-88 Rev. 2–Based Sanitization Policy Engine

A standalone, non-destructive policy engine for selecting and documenting an appropriate
media-sanitization strategy. It does **not** issue destructive disk commands.

## Scope

This component implements the policy/decision layer for an integrated sanitization platform.
It evaluates:

- media technology (HDD, SSD, NVMe, USB flash, SD/memory card, optical, virtual/unknown)
- encryption/key-management status
- device-native sanitization capabilities
- interface/transport constraints
- target scope (logical/file, namespace, full media)
- assurance objective (clear/purge)
- verification availability
- unsupported/ambiguous conditions

The engine returns a typed recommendation, rationale, warnings, verification requirements,
and an audit-ready decision record.

## Important standards position

NIST SP 800-88 Rev. 2 (September 2025) is a program-level guide. Unlike Rev. 1,
it does not prescribe a fixed catalog of overwrite algorithms for every medium. It
directs organizations toward IEEE 2883, NSA specifications, or an organizationally
approved standard, while expanding guidance for cryptographic erase.

Therefore this project deliberately treats "NIST 800-88" as the **policy authority**
and delegates technology-specific execution to capability adapters.

## Safety

This package is intentionally non-destructive. It can recommend:

- cryptographic erase
- device-native purge
- NVMe Sanitize
- ATA Secure Erase
- logical clear/overwrite
- manual/organizational review

It does not execute those operations.

## Run

```bash
python -m sanitization_policy --help
python -m sanitization_policy examples/hdd_clear.json
pytest -q
```

## Commercial integration

The code is organized so a commercial product can put its own licensed execution adapters
behind the `ExecutionPlan` returned by the policy engine. Do not claim that a recommendation
itself proves successful sanitization; execution and verification must produce evidence.

## Reference research

See `docs/RESEARCH.md` and `docs/SOURCE_MATRIX.md`.
