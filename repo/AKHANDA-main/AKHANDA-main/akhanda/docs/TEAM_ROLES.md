# Team Roles and Specifications

Design principle: nothing on the critical path leaves the lead's hands, and every
teammate task has a clear acceptance test so "done" is a fact, not an opinion.
First-year students do bounded, verifiable work well. They cannot do open-ended systems
work, so none is assigned to them.

SIH requires exactly 6 members, at least 1 female, all from the same institution
(GITAM University, Hyderabad).

---

## Role 1, Lead (you)

Owns the entire critical path. Roughly 70 to 80 percent of the technical value.

- Chain schema and length-prefixed encoding
- Ed25519 signing, co-signing, and the verification walk
- Witness node service on the Pi
- Presence integration over serial
- External anchoring and the certificate generator
- The architecture narrative in the pitch

Acceptance test: the full test suite passes and the tamper-injection demo runs reliably.

---

## Role 2, Erasure engine

Needs: comfortable on the Linux command line, willing to read man pages.

Deliverable: `erase(device, level) -> {method_used, verified, sample_results}`.
Calls `dd`, `hdparm`, or `blkdiscard` and does read-back sampling.

Acceptance test: writes a known pattern to the 16GB USB stick, erases it, confirms by
sampling that the pattern is gone, and returns method_used = "Clear" honestly.

---

## Role 3, Recovery engine

Needs: basic Python, patience with binary data.

Deliverable: `carve(image_path) -> [{filename, offset, sha256, type}]`.
Signature-based carving is header/footer magic-byte matching. Learnable in a few days;
study PhotoRec and Scalpel signature tables.

Acceptance test: recovers three known deleted files from a prepared FAT32 image.

---

## Role 4, Console

Needs: can follow a React or plain HTML template. Given a component kit, assembles
rather than designs.

Deliverable: a page showing chain entries, per-entry verification state, the witness
head beside the workstation head, and a certificate preview.

Acceptance test: renders correct state from a `chain.json` file the lead provides,
without the backend running.

---

## Role 5, Test and evidence

Needs: methodical. No coding beyond running scripts.

Deliverable: execute and document the full test matrix. Screenshots, command outputs,
before-and-after evidence. Also owns rehearsing the tamper-injection demo until it is
reliable.

This is the most underrated role. Their output is what proves every claim in the pitch.

Acceptance test: a documented evidence pack covering every row of the test matrix.

---

## Role 6, Compliance and pitch

Needs: reads dense documents carefully. No coding at all.

Deliverable: field-by-field mapping of the system to NIST 800-88 Rev. 2 and BSA Section
63(4), plus the presentation deck.

This is real, valuable, judge-facing work requiring zero technical skill, which makes it
the right slot for the least technical teammate. Assign the female-member requirement by
fit, not by quota.

Acceptance test: every certificate field maps to a named clause in one of the two
standards, and the deck follows the agreed structure.

---

## Parallelism

Only the lead's first task is on the critical path. Once the entry format is frozen and
published, roles 2, 3, 4, and 5 proceed in parallel without blocking on anyone. Role 6
works independently throughout.
