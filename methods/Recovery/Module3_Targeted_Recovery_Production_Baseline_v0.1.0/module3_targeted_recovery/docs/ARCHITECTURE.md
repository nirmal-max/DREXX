# Architecture

Source
  -> rule registry
  -> streaming signature scanner
  -> candidate detector
  -> end-boundary resolver
  -> format validator
  -> confidence engine
  -> candidate store
  -> safe extractor

Targeted is deliberately independent of filesystem metadata.

## Candidate types

START_ONLY
  A start signature was found. Size is inferred by the rule's strategy.

START_END
  Start and end signatures bound a candidate.

FIXED_SIZE
  Rule provides a fixed or computed size.

FORMAT_VALIDATED
  Candidate bytes pass a format-specific structural check.

## Escalation

Targeted reports:
- recovered contiguous candidates
- ambiguous candidates
- truncated candidates
- unsupported rules
- likely fragmented candidates

It does not attempt arbitrary fragment ordering.
