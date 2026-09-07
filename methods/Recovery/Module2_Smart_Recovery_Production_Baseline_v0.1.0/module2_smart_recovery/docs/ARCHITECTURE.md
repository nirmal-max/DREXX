# Module 2 Architecture

```text
                         SMART
                           |
                   +-------+-------+
                   | Evidence Probe|
                   +-------+-------+
                           |
                   +-------v-------+
                   |  Evidence      |
                   |  Normalizer    |
                   +-------+-------+
                           |
                   +-------v-------+
                   | Strategy       |
                   | Scorer         |
                   +-------+-------+
                           |
                   +-------v-------+
                   | Ranking +      |
                   | Explainability |
                   +-------+-------+
                           |
          +----------------+----------------+
          |                |                |
        QUICK          TARGETED           DEEP ...
          |
   Module 1 executor
```

The Smart layer depends on the shared Module 1 source/filesystem/candidate
interfaces. It does not duplicate physical-device access or filesystem parsing.

## Future executor contract

Each later module should expose:

    CapabilityReport probe(source, evidence)
    RecoveryPlan plan(source, evidence)
    RecoveryResult execute(plan, destination, cancellation)

Smart can then choose an executor based on measurable evidence and estimated
cost/yield.
