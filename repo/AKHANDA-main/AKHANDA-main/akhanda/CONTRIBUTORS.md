# Contributors and Provenance

## Prior work incorporated

**AetherProof**, open-source attestation/receipt engine.
Sole author: Pulkit Kr Srivastava. Licence: Apache-2.0 (v0.5.1).
Public repository and package predate SIH26149's publication.
Akhanda extends it; it is not a rename of it.

Apache-2.0 is permissive, so Akhanda carries no copyleft obligation and teammate
contributions create no licence conflict.

## Akhanda contributors

Record who wrote what. SIH policy places IP in the solution with the students who
developed it, so this file is the record of that.

| Component | Contributor | Notes |
|---|---|---|
| Attestation core (chain, encoding, signing, verification) | Pulkit Kr Srivastava | Extends own AetherProof primitives |
| Custody tiers, key handling, chain persistence | Pulkit Kr Srivastava | New for Akhanda |
| Witness node + divergence detection | Pulkit Kr Srivastava | New for Akhanda |
| Presence integration + firmware | Pulkit Kr Srivastava | New for Akhanda |
| Anchoring (Merkle + OpenTimestamps) | Pulkit Kr Srivastava | Merkle fix carried from AetherProof |
| Certificate generator (NIST + BSA) | Pulkit Kr Srivastava | New for Akhanda |
| CLI | Pulkit Kr Srivastava | New for Akhanda |
| Erasure engine | Pulkit Kr Srivastava (reference) / (role 2) | Reference implementation + guard written by the lead; role 2 owns real-media testing and extending the media decision tree |
| Recovery engine | Pulkit Kr Srivastava (reference) / (role 3) | Reference carver written by the lead; role 3 owns extending the signature table and the FAT32 test corpus |
| Console | Pulkit Kr Srivastava (reference) / (role 4) | Working reference with in-browser re-verification; role 4 owns the interface it becomes |
| Test evidence pack | (role 5) | 153 automated tests exist; role 5 owns executing the matrix on real hardware and capturing the evidence |
| Compliance mapping + deck | (role 6) | `CLAUSE_MAP` in src/certificate/generator.py is the machine-checkable half; role 6 owns verifying each clause against the source texts and the deck |

**A note on the reference implementations.** Where a component is marked "(reference)",
the lead wrote a working version so that no teammate is blocked on an empty file and the
demo cannot fail because one role ran out of time. Ownership of those components still
sits with the named role: they extend it, test it on real media, and must be able to
explain it. A teammate who only runs code they did not understand cannot answer for it in
Q&A, and that is where hackathon projects lose marks.

Fill in names as teammates join. Keep it current; it is the honest answer if a judge
asks who built which part.
