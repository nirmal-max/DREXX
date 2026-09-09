# Engineering rules

The rules the source refers to. They are not style preferences, each exists because
breaking it produced a real defect, and most are enforced by a test that must not be
deleted.

---

## 1. Length-prefix every field before hashing

Never join fields with a delimiter. Every field is encoded as
`len(field).to_bytes(4,'big') + field_bytes` before it enters a hash.

A pipe-joined encoding lets two different records produce identical signing bytes. That
is a signature forgery primitive, not a formatting choice. There is a regression test for
this and it must never be removed.

## 2. Every claim in code must be true

If the tool achieves NIST **Clear**, the record says Clear, never Purge. An outcome is
never labelled stronger than what was actually achieved. This is the entire spirit of the
project, and every other rule serves it.

## 3. Additive, never substitutive, but asking for a component makes it required

Optional components degrade cleanly when you **opt out**: `--no-witness` records
`SOFTWARE_KEY` and carries on. That is the intended fallback.

What is **not** permitted is silent downgrade. If you asked for a component and it goes
missing, the operation is **BLOCKED**, and the blocked attempt is itself written to the
chain as a `REFUSED` entry.

The loose reading, "a device is missing, quietly record a weaker tier", is a
silent-omission vector with a one-second trigger: unplug the co-signer and the tool
downgrades itself without complaint. Recording the refusal is what turns unplugging from
a way to hide an operation into a way to log one.

For an irreversible operation the check is a **preflight**, before the destructive step.
The window between preflight and co-signature cannot be closed by any tool that destroys
data; it is narrowed to one operation, flagged `DEGRADED`, and stated rather than denied.

See `src/attestation/policy.py`.

## 4. No overclaiming in output or documentation

Say "hardware confirmed presence", never "hardware protected key". Say "the same class of
cryptographic guarantee", never "legally guaranteed".

## 5. Small, verifiable functions

Every module exposes documented functions with clear input and output contracts, so other
components can be built against them without reading the internals.

## 6. Test as you build

Every module has a matching test in `tests/`. A feature is not done until its test passes.

## 7. Outcome quality belongs in the signed preimage

If a field describes how well an operation went, verified, truncated, partial, it goes
in `HASHED_FIELDS`, not only in the result record. A flag outside the signature lets the
entry and the certificate present a failed operation as a clean one, which is the exact
overclaim this project exists to prevent.

`outcome` is the field; `OUTCOMES` is its closed vocabulary.

## 8. The verification path is implemented three times, on purpose

Python, JavaScript (`console/index.html`), and Rust (`rust/akhanda-verify`).

Two implementations by one author can share a misreading of the spec and agree while both
are wrong. A third, in a language with different string and integer semantics, catches
that class of error. `tests/test_three_implementations.py` asserts all three produce
identical entry hashes and identical verdicts.

**If you change `HASHED_FIELDS`, change all three in the same commit.** That test is the
canary and it must never be marked `xfail`.

---

## Hard lines, claims this project must never make

- **The presence device does not securely store keys.** CVE-2019-17391 extracts ESP32
  eFuse keys by voltage glitching, unpatchable on shipped silicon. Its only role is
  presence confirmation. Never call it a secure element, HSM, or key vault.
- **OpenTimestamps is not legally recognised in Indian courts.** It provides a
  cryptographic guarantee of the same class courts increasingly accept. That is the
  claim. Nothing stronger.
- **USB flash and SD cards cannot reach NIST Purge.** They support neither ATA Secure
  Erase nor NVMe Sanitize. On this media the tool achieves Clear, and says Clear.
- **The chain does not prevent omission.** It proves nothing was altered after being
  written. It cannot prove nothing was withheld. Stated openly as a known limit, never
  hidden.

---

## Known limits register

A gap that is written down is a limitation. A gap that is not written down is an
overclaim waiting to be found by someone else.

| Limit | Status |
|---|---|
| Omission, the chain cannot prove nothing was withheld | Structural, disclosed. Recording refusals narrows it; nothing closes it |
| Operator and witness keys are readable files on disk | Deferred, disclosed. `AKHANDA_KEY_PASSPHRASE` encrypts the operator key at rest |
| No access control on who may run the tool | Deferred, out of scope. Stated plainly when asked |
| Timestamps come from the local clock | Deferred, partly covered by external anchoring |
| Presence device is designed, not shipped | So `FULL_CUSTODY` is never printed |
| NIST Purge on SSD, real flash wipe, genuine bad sectors | Not tested, requires lab media |

## Custody tiers

`SOFTWARE_KEY` < `PRESENCE_CONFIRMED` < `WITNESS_COSIGNED` < `FULL_CUSTODY`

A certificate quotes the **weakest** tier among the operations it covers, so one degraded
step cannot hide behind several good ones. `src/attestation/tiers.py` is the only place a
tier is set.
