# Akhanda, Build Log

Append-only record of what was built, what was found, and what was proven. One entry per
completed task. Findings are recorded whether or not they flatter the project, a build
log that only lists successes is a marketing document.

Format: **what changed · why · how it was proven · test count after**.

---

## 26 August 2026

### Attestation core hardened
Added `chain_id` binding, the `akhanda.entry` domain tag, a signed `operator_key_id`, and
`ChainReport` (which distinguishes *verified* from *unverifiable* from *broken*, so a key
rotation never false-flags an authentic chain).
**Proven:** an entry lifted from another case file no longer verifies; a forger who edits
content and re-chains the whole tail passes the key-free layer and fails the key-bound one.
→ **27 tests**

### Custody tiers, key persistence, atomic chain store
`tiers.resolve()` is the single place a tier is decided, and it takes facts, not
intentions. Keys read `AKHANDA_HOME` per call (a home captured at import time silently
ignored the env var for half the tool). Chain writes are temp-then-`os.replace`.
→ **149 tests**

### Erasure, recovery, witness, presence, anchor, certificate, CLI
Reference implementations for every module, with a two-gate safety guard on block-device
writes and RFC 6962 Merkle (odd node promoted, never duplicated, the CVE-2012-2459
pattern the previous code had).
**Proven:** the console re-implements the entry encoding in JavaScript and a test asserts
Python and JS produce identical hashes, including on delimiter-laden and Devanagari fields.
→ **153 tests**

### Pre-mortem: five real gaps found, three fixed
Ran the pre-mortem skill and **probed the code rather than reasoning about it**. Three
launch-blocking findings, all reproduced before being fixed:

| Finding | Evidence |
|---|---|
| `cli verify` never checked the witness signature | Forged every `concur_sig` with a random key; verify returned `ok=True, dual_signed=2` |
| Certificate printed "chain verified" with zero signatures checked | `signatures_verified: 0` alongside the word "verified", no limit disclosing it |
| The chain committed to a result record thrown away by default | `--result-out` was opt-in; the ledger held a hash of a file that no longer existed |

**Fixed:** witness pubkey cached locally and re-verified (so verification works offline);
the certificate now names *which layer ran*; result records are always persisted and
re-checked, and an altered record exits 1.
→ **206 tests**

### Fail-closed policy (judge-simulator P0)
Silent downgrade removed. Asking for a component makes it required; a missing one **blocks
the operation before it runs** and writes a `REFUSED` entry, so unplugging the co-signer
records the attempt instead of hiding it.
**Proven live:** `preflight: BLOCKED`, exit 3, target byte-identical, refusal in the chain.
Preflight runs *before* the destructive step because an erase cannot be undone; the
residual window between preflight and co-signature is stated rather than denied.
**Conflict resolved:** this contradicted docs/ENGINEERING_RULES.md rule 3 as written. Rule 3 was rewritten
,  opting out still degrades cleanly, silent downgrade is gone.
→ **227 tests**

### Update package reviewed (`AKHANDA_Update_26Aug.zip`)
Checked all seven files and **verified every item marked VERIFY** rather than trusting it.
- **GAP-1 confirmed, and worse than reported**, a refusal dragged the tier to
  `SOFTWARE_KEY`, deflated the BSA Part B ratio (2 of 3), *and* did not appear in the
  certificate at all.
- **Of the five §7 items, one was real** (`lowest()` over an empty list defaulted instead
  of refusing). The other four were not bugs: presence never raises, carve caps and flags
  a missing footer, refusals are swept by `verify_all_results`, and `merkle_root` over one
  entry returns the *tagged* leaf.
- **The shipped `file_eraser.py` had four real bugs** despite 13 passing tests.

### GAP-1 fixed, all three parts
`tiers.lowest(op_types=...)` excludes refusals (a blocked attempt performed no work and
cannot bound the custody of work that did); the Part B denominator counts performed
operations only; `refused_attempts` is reported on its own line.
**Caught during the fix:** the block landed *nested inside* `chain` instead of top-level.
The tests found it. It would have shipped as a silent half-fix.
**Result:** tier `FULL_CUSTODY` (was `SOFTWARE_KEY`), ratio 2 of 2 (was 2 of 3), refusal
visible.
→ **256 tests**

### File eraser rewritten (PS module b)
All four bugs fixed:

| Bug | Fix |
|---|---|
| `_verify_overwritten` returned True for a file **never overwritten**, it wrote unreproducible bytes so had nothing to compare against | Deterministic seeded pattern, byte-for-byte comparison, same construction as the drive eraser |
| Docstring claimed an unknown filesystem downgrades the outcome; it produced the **strongest** value | Real detection (Win32 `GetVolumeInformationW`, `/proc/mounts`); unknown → `UNVERIFIED` |
| One failed target reported the whole op as `NotPerformed` while files were destroyed | `method_used` reflects what happened; `performed` carries the count; `outcome` still quotes the weakest |
| One boolean gate | Three: confirm token, `AKHANDA_ALLOW_FILE_ERASE=1`, and `REFUSED_ROOTS` |

**Proven on real hardware:** NTFS on this machine's NVMe SSD, `filesystem: ntfs · Clear ·
VERIFIED · performed 3 of 3`, files gone, plaintext absent from the directory. Wired as
`cli erase-files` through the same fail-closed preflight.

### Format break: the signed `outcome` field
`verified` lived outside the signature, so a wipe whose read-back **failed** produced an
entry identical to a clean one. `outcome` is now the 15th hashed field with a closed
vocabulary. `ENTRY_VERSION` bumped; the verifier **refuses** an unknown version rather
than checking it against the wrong field list. Python, JavaScript, and Rust updated in one
commit.

### Independent Rust verifier
Third implementation of the verification path. `#![forbid(unsafe_code)]` on both crate
roots, no network, no configuration, exit code as the interface.
**Why three:** two implementations by one author can share a misreading of the spec and
agree while both are wrong. `cargo test` and `cargo clippy -- -D warnings` both clean.
**Proven:** the binary independently caught a real tamper (`Clear` → `Purge`) in a chain
built by Python, exit 1.
→ **303 Python + 8 Rust**

### Three bugs found by real hardware that no test could
| What | Why no test caught it |
|---|---|
| Presence discovery returned **COM4, a Bluetooth port**, as the presence device | Every test mocked the enumeration. This laptop has six paired Bluetooth ports and zero ESP32s; the blind `ports[0]` fallback picked one, so preflight reported a device that did not exist |
| Filesystem detection always returned `"unknown"`, which produced the strongest outcome | The stub's own docstring claimed a downgrade the code never performed |
| File-erase verification passed on a file never overwritten | Unreproducible bytes meant nothing to compare against; 13 shipped tests all passed |

### Carver validated against NIST CFReDS, the finding that mattered most
Downloaded NIST's Computer Forensic Reference Data Set (the corpus NIST publishes so
tools can be *checked* rather than trusted) and scored against published ground truth.

**Before:**

| Image | NIST ground truth | Reported | Exact matches | Precision | Flagged uncertain |
|---|---|---|---|---|---|
| `L4_Graphic.dd` | 9 files | **50** | 1 | **2.0%** | **0** |
| `L1_Graphic.dd` | 7 files | **48** | 1 | **2.1%** | **0** |

The carver was confidently wrong, printing *"every artifact had a located footer"* over a
set that was 98% noise, in the one project whose thesis is that it does not overclaim.

Three causes, all fixed:
1. **A 3-byte header is not evidence.** Every signature now has a structural validator.
2. **JPEG carving stopped at the EXIF thumbnail**, a whole JPEG inside its parent's APP1
   segment, so the first `FF D9` split one photo into several "complete" files. Now walks
   the segment structure, stepping over APP1 whole.
3. **Confidence was never reported.** Every artefact carries `validated` and
   `HIGH`/`MEDIUM`/`LOW`, and the summary refuses to call a low-confidence carve a
   recovered file.

**After:**

| Image | Reported | Exact | Precision | Recall | Signed outcome |
|---|---|---|---|---|---|
| `L1_Graphic.dd` | 6 | 3 | **50.0%** | **42.9%** | `PARTIAL` |
| `L4_Graphic.dd` | 6 | 1 | **16.7%** | 14.3% | `PARTIAL` |

L4's recall is unchanged **and that is correct**, L4 is NIST's nested/fragmented case,
which signature carving cannot solve. The tool now says so instead of pretending. All six
graphic types NIST uses are detected; the old table saw three.

**The tests were as fake as the carver's assumptions.** The old suite passed twelve tests
against JPEGs it invented, no DQT, no SOF, no start-of-scan. Every image in the recovery
suite is now produced by a real encoder and must survive `Image.verify()`. The NIST
scoreboard is a permanent test that skips **loudly** when the corpus is absent.
→ **325 tests**

---

## 27 August 2026

### G-WSL, measured: a WSL2 co-signer has no custody boundary at all
The design's central sentence is that the concurring key is held somewhere "the
workstation never sees". Measured on this machine rather than assumed. Every command ran
as the ordinary desktop user, **not elevated**:

| Test | Result |
|---|---|
| Non-root user inside Linux reads the 0600 root key | `Permission denied`, POSIX works |
| **Windows** user reads the same file via `\\wsl.localhost` | **Read succeeded, full contents** |
| Windows user **writes** the witness's own head log | **Write succeeded**, `FORGED-TO-MATCH-REWRITTEN-CHAIN` |
| `wsl --user root --exec id` from an unelevated shell | `uid=0(root)`, no password, works with root locked |
| `ext4.vhdx` opened read-write and copied wholesale | 1,218 MB exfiltrated; ACL grants `Authenticated Users: Modify` |

**Why this is the finding that matters:** `compare_witness_head()` detects a full-chain
rewrite, Act 3 of the demo, *because the operator cannot write to the witness's record*.
On WSL2 they can, with one `Set-Content`. The detection does not degrade; it stops working.
Microsoft's own guidance confirms controlling which Linux user a Windows user may become is
**currently unsupported**, so this is by design and not a misconfiguration to fix.

**Recorded, not just noted:** `docs/COSIGNER_HOSTING.md` ranks the four hosting options by
the boundary each actually provides; `tests/test_cosigner_boundary.py` makes the
measurement executable and is written to **fail if the boundary ever appears**, so the
document cannot silently go stale. `witness/node.py` no longer promises a boundary without
pointing at where it is measured per host.

**Conclusion:** WSL2 is fine for development and rehearsal. It is not a co-signer, and
presenting it as one is exactly the overclaim this project exists to refuse.

### Correction recorded: VT-x was never disabled
`VirtualizationFirmwareEnabled: False` reads as "VT-x off in BIOS". It is not , 
`HypervisorPresent: True`, VBS running, and `systeminfo` says *"a hypervisor has been
detected"*. Hyper-V already holds VMX root, so Windows reports the flags from inside the
guest it is running in. **Consequence: KVM is Linux-host only and is the wrong answer
here.** Hardware is 2 cores / 4 threads and 19.8 GB, memory is ample, cores are the
constraint during a live demo.

### G3 fixed, two-phase presence binding
The human was shown `result_hash[:16]`, a value that is **never signed**, while the
module's own docstring claimed they were seeing the entry hash.

The circularity is real: `presence_ref` is inside the preimage, so the final entry hash
cannot exist until after the press. The fix shows the **pre-hash**, the entry hashed with
`presence_ref` empty, and the device's token records which value was shown. The final
hash then covers that token, and both values are recoverable from the stored entry.

`presence_ref` is now `<device>:<nonce>:<pre_hash_prefix>`, and
`verify_presence_binding()` re-derives the pre-hash and checks it. Before this the field
was **unfalsifiable**: any entry could assert `PRESENCE_CONFIRMED` with an arbitrary
string and no verifier could contradict it.

The two-phase ordering lives in `Chain.append(presence_fn=...)`, one implementation, not
one per caller. Implemented and tested in **both** Python and Rust, because a verifier
that skips a check the format requires is not a second opinion.
→ **333 Python + 12 Rust**

### Carver taken from 2% to 100%, by writing the real format logic
Automated the benchmark first (`scripts/benchmark_carver.py`), because a number nobody
can re-run is an anecdote. It scores every NIST image in `tests/data` against published
ground truth and writes `evidence/carver_benchmark.json`.

**Two measurement errors of my own, found and corrected:**

1. **I predicted 90% on L0 instead of measuring it.** Measured, it was 50%. The prediction
   was worthless and should never have been stated.
2. **The denominator was wrong.** Recall was divided by all seven corpus files regardless
   of which were actually in each image. NIST's L0 holds **six**, so the tool was being
   marked down for a file that was never there. Recall now divides by files contiguously
   present, and where nothing is contiguous it reports **n/a**, not 0%, there was no
   intact file to recover.

**The real work: three formats had shortcut extent logic and it was the whole gap.**
Every miss traced to the same cause, the carve started at exactly the right offset and
ended at the wrong byte, so the SHA-256 never matched.

| Format | Was | Now |
|---|---|---|
| **TIFF** | "no end marker" → size cap, LOW confidence | Walks every IFD, every external field value, every strip and tile offset → exact end |
| **PCX** | "no end marker" → size cap, LOW confidence | Decodes the RLE stream to the geometry declared in the header, plus the optional 769-byte VGA palette → exact end |
| **GIF** | Searched for the `00 3B` trailer byte pair | Walks the block structure, extensions, image descriptors, sub-block chains, and *arrives* at the trailer |
| **PCX (again)** | 3-byte signature accepted on its own; the RLE decoder "succeeds" on any input, so false positives were reported at **HIGH** | Full header invariants: reserved byte, even `bytesPerLine`, width consistency, DPI range, filler bytes |

**Measured, on NIST data, re-runnable:**

| Level | Files present | Reported | Exact | Precision | Recall |
|---|---|---|---|---|---|
| **L0** non-fragmented | 6 | 6 | **6** | **100.0%** | **100.0%** |
| **L1** sequential frags | 6 | 6 | **6** | **100.0%** | **100.0%** |
| L2 non-sequential | 0 | 3 | 0 | 0% | n/a |
| L3 missing fragments | 0 | 2 | 0 | 0% | n/a |
| L4 nested | 3 | 5 | 2 | 40.0% | 66.7% |

~130 MB/s throughput. All six graphic formats NIST uses are detected and resolved from
their own structure; every L0 hit is HIGH confidence.

**Why there is no single headline number.** L2 and L3 contain no contiguous file at all , 
signature carving cannot reassemble non-contiguous extents, which is exactly why NIST
built those images. Averaging L0 and L2 into one figure would hide the distinction an
examiner needs. The benchmark prints per level and refuses to emit a blend.

**Tests ratcheted to what is now achieved**, not to what would be comfortable: L0 must
stay at 100% precision, 100% recall, every hit HIGH confidence, all six formats. Three
older tests asserted TIFF was LOW confidence, they had encoded the weakness as expected
behaviour and were rewritten.
→ **338 tests**

---

## Open gaps

| ID | Gap | Status |
|---|---|---|
| G9 | No co-signer or presence device has run on real hardware | OPEN, outranks everything else |
| G-USB | Drive erasure has never touched real removable media; the flash decision tree is reasoned, not observed | OPEN |
| G-FRAG | Carving cannot reassemble fragmented files (NIST L1, L5). Structural, not fixable by signature carving | Disclosed, measured |
| G5 | Witness key is a readable file; passphrase-derived key never persisted is the cheap honest fix | Deferred, disclosed |
| G6 | No access control on who may run the tool | Deferred, out of scope |
| G7 | Timestamps come from the local clock | Deferred, partly covered by anchoring |
| G8 | The chain cannot prove nothing was withheld | Structural. Recording refusals narrows it; nothing closes it |

---

# Prep sprint, session of 31 Aug 2026

Window is 1, 3 Sept; internal hackathon is 4, 5 Sept at GITAM, 24 h. No new features from
here. This session: consolidate, then close the prep-window gaps in roadmap order.

## Housekeeping

**22 zero-byte junk files deleted from the repo root**, `Purge`, `serial`, `str`,
`3}]`, `{fe.detect_filesystem(p)!r}` and similar. All were accidental PowerShell
redirect targets from earlier sessions (`>` with an unquoted expression). Every one was
confirmed 0 bytes before deletion; nothing with content was touched.

**Project consolidated to a single folder on D:.** Everything now lives under
`D:\akhanda\`:

| Path | Holds |
|---|---|
| `research/roadmap/` | `AKHANDA_Build_Roadmap.md`, `BUILD_PROMPT.md`, research summary (was `D:\AKHANDA RESEARCH\`) |
| `research/reference/` | 29 AKHANDA documents, Mission Control, Gap Ledger, Frontend Guide, Architecture, Sections A, J (were loose in `Downloads\`) |
| `evidence/` | benchmark JSON, wipe logs, `.ots` receipts |
| `docs/` | this log, clause map, SOPs |

Copies, not moves, the originals are untouched, so nothing that referenced the old
paths broke. 4.3 MB total.

**Git initialised.** The repo had no version control at all, which meant the freeze gate,
the CI jobs and "record the result then freeze" had nothing to hang on. `rust/**/target/`
(136 MB of build artefacts) is now ignored.

**Baseline confirmed before changing anything: 338 tests collected, all passing.**

## G23, file eraser CLI wiring, ALREADY CLOSED, verified not assumed

The concern was that `file_eraser.py` might be co-located with passing unit tests but
never actually reachable from the CLI. It is reachable. `cli.py:330` calls
`_preflight_or_refuse(...)` and only then reaches `file_eraser.erase_path(...)` at
`cli.py:333`, preflight gates the eraser, in the right order, on the real path.

What is genuinely missing is a test that *proves* that ordering, so a future refactor
cannot quietly reverse it. `tests/test_fix_fail_closed.py` covers `erase` and `recover`
end to end but never `erase-files`. Integration test outstanding.

## G19, presence layer, it is (b), the ESP32 button

Read the code rather than the description. `src/presence/client.py` is a real pyserial
implementation talking to `firmware/esp32/presence.ino` over USB at 115200. It is **not**
WebAuthn/FIDO2 and it is **not** a stub.

The function-level docstrings were already honest, `request_presence` explains the
two-phase pre-hash binding correctly and states plainly why the human cannot be shown the
final entry hash. The **module** docstring was stale: it advertised
`request_presence(entry_hash_prefix)` when the signature is
`request_presence(pre_hash, port=None, timeout_s=15.0)`, i.e. it named the exact value
that G3 was fixed to stop using. Corrected, and the module now states its own status:
designed and built, never run against attached hardware, WebAuthn relying party is Phase 1
and is not implemented.

**Say "designed" for the presence layer until an entry exists with a real `presence_ref`.**

## G8, chain verification benchmark, CLOSED

`scripts/benchmark_chain.py`, emitting `evidence/chain_benchmark.json`. 500 real signed
entries, no mocking; signing is part of the measured cost.

| Measurement | 500 entries |
|---|---|
| Build (sign) per entry | 0.055 ms |
| Verify, key-free layer | 3.9 ms median |
| Verify, signatures re-checked | 81.1 ms median, 162 µs/entry |
| Tamper localisation | 36.7 ms median, seq 250 tampered → **located at 250** |

**G13 answered as a side effect: hashing is not the throughput ceiling.** The key-free
layer, every SHA-256 recompute and every prev_hash link over the whole chain, is
3.9 ms. Ed25519 signature verification is the other 77 ms. Chain verification is
signature-bound, not hash-bound, so the carver's ~130 MB/s is nowhere near a limit.

The script asserts no threshold. A threshold measured on one laptop is a claim about
that laptop; the numbers above are what **this** machine did and should be quoted with
the machine named.

## G25, tail truncation, RESOLVED, and the resolution found a hole

The contradiction: the GITAM Proposal counts truncation as a detected tampering class
(5/5); the Gap Ledger calls it a limitation. **Both are half right, and stating either
one alone is an overclaim or an underclaim.**

What the code actually does:

* **Local verification cannot detect it.** There is no truncation logic anywhere in
  `src/attestation/core.py`, and there correctly should not be. A chain with its tail
  removed is internally perfect: seq is still contiguous from 0, every `prev_hash` still
  links, every signature still verifies. Nothing inside the chain knows how long the
  chain was meant to be.
* **Comparison against the witness detects it.** `witness/client.py::compare_witness_head`
  recomputes the witness head from the hashes the workstation now holds and compares it
  to the head the witness independently recorded on a machine the operator cannot write
  to. Drop co-signed entries and the recomputed head stops matching.

The honest sentence, to be used everywhere: **tail truncation is undetectable by local
verification alone, and detected when the chain is checked against the witness's
independent head or an external anchor.** It is neither "a detected class" flatly nor "a
limitation" flatly, it is a limitation of the offline verifier and a strength of the
witness boundary, which is precisely the argument for having the witness.

**The hole this surfaced.** `compare_witness_head` starts by selecting the co-signed
entries and returns `checked=False, "no entry in this chain was ever co-signed"` when
that list is empty. So an operator who truncates back past the *first* co-signature turns
a divergence into an **unchecked**, the strongest available tampering signal degrades
into silence, by deleting more rather than less. The witness already returns its own
`count` and `seq` from `GET /witness/head`; comparing that count against the number of
co-signed entries the workstation holds closes it. Not yet implemented, this is
verification-path code and is being raised before it is touched.

## G25, the truncation hole, closed

`compare_witness_head` now compares the witness's own reported `count` against the number
of co-signed entries the workstation holds, **before** it looks at anything else. If the
witness counted more than the workstation shows, entries left the chain after the witness
recorded them, and that is reported as `diverged=True` naming how many are missing.

The ordering is the fix. The `not cosigned` early return used to be reached first, so an
operator who truncated back past the *first* co-signature got `checked=False, "no entry
was ever co-signed"`, a verdict indistinguishable from an honest chain that never used a
witness. Deleting more was quieter than deleting less. It is now louder.

Four tests pin it, in `tests/test_witness.py`:

* truncating co-signed entries is detected, not reported as agreement
* **truncating every co-signature does not go quiet**, the regression this exists for
* the reason names how many entries are missing
* a witness that genuinely counted nothing still reads as `unchecked`, not `diverged`
  (the fix must not turn an honest never-used-a-witness chain into a false alarm)

→ **342 tests**, all passing. The three-implementation canary is unaffected, as expected:
this is the witness comparison layer, not `HASHED_FIELDS`.

## Hardware prep, scripts written, nothing executed

Tasks 1, 4 all need a second machine, a second Windows account, or a USB stick. They are
written as runnable scripts that capture their own evidence, so running them produces the
artefact rather than requiring someone to remember to write one.

| Script | Gap | Writes |
|---|---|---|
| `scripts/prep/lb03_setup.ps1` | LB-03 |, (elevated, run once) |
| `scripts/prep/lb03_verify.ps1` | LB-03 | `evidence/lb03_witness_boundary.json` |
| `scripts/prep/g1_handshake.py` | G1 | `evidence/g1_handshake.json` |
| `scripts/prep/g2b_usb_wipe.md` | G2b, G9 | procedure + `evidence/g2b_*.img` |
| `scripts/prep/g24_link_check.py` | G24 | `evidence/g24_link_check.json` |

**A path error caught before it cost anything.** The runbook's `icacls` line named
`C:\Users\witness\.akhanda_witness` with an underscore. `src/witness/node.py:54` uses
`.akhanda-witness` with a **hyphen**. `icacls` on a non-existent path succeeds at doing
nothing and returns cleanly, so the boundary would have looked configured while the key
sat there readable, and LB-03 would have "passed" a test of a directory that did not
exist. The scripts use the hyphen and read the path from the source of truth.

`lb03_verify.ps1` treats **Access Denied as the PASS condition** and writes the captured
exception into the evidence file. It also distinguishes a third case the brief did not:
a read that fails for some *other* reason is recorded `INCONCLUSIVE`, not `PASS`. A read
that fails because the file is missing proves nothing about an access boundary.

`g1_handshake.py` splits into two phases because a human physically stops the witness
between them, and it **merges** into the evidence file rather than overwriting, running
phase B would otherwise discard phase A's result. Phase B was smoke-tested against a dead
port and passes: preflight blocks, a `REFUSED` / `NotPerformed` entry is written carrying
no co-signature, and the refused chain still verifies.

## Architecture document brought in line with reality

`docs/ARCHITECTURE.html` §10 was the largest remaining overclaim in the repository. It
showed a **Raspberry Pi Zero 2W co-signer labelled BUILT** and an **ESP32 button labelled
BUILT**, with KVM and FIDO2 as "PLANNED" alternatives. Neither had ever run on hardware,
and the Pi is no longer the design at all.

Rewritten:

* **Co-signer**, separate OS account, `SELECTED · LB-03`. Pi and KVM guest shown together
  as `DROPPED`, with why: the Pi bought physical separation at the cost of a device that
  must enumerate and join a network on stage; the KVM guest is reachable by whoever owns
  the hypervisor, who on a laptop is the operator.
* **Presence**, ESP32 `DESIGNED · NOT RUN`, WebAuthn `PHASE 1`.
* The co-signer card now says **dual control, never physical separation**, and states that
  an `Administrators` token reaches both accounts. That is the true boundary and it should
  be said before a judge says it.
* The presence card states that no entry in this repository carries a device-produced
  `presence_ref`, so `FULL_CUSTODY` has never been reached.
* A **SUPERSEDED** card keeps the old Pi/ESP32 `BUILT` labels described rather than
  deleted. A document that silently rewrites its own history is the exact failure this
  project exists to make impossible.
* The port contract in the diagram said `request_presence(prefix)`, the pre-G3 signature,
  naming the very value G3 was fixed to stop showing the human. Now `request_presence(pre_hash)`.
* The virtualization requirement is gone with the Pi and KVM; what replaces it is the
  link, which is now named as the single point of failure for the second signature.
* Benchmark numbers from `evidence/chain_benchmark.json` replace the hand-waved
  performance paragraph.

Also fixed while in there: **`Team Anvaya` → `Team Syntax Squad`** (2 places, task 13),
and a **duplicated `rust/akhanda-verify` row** in the file table, the same 4 lines
appeared twice, inflating the apparent module count.

HTML re-validated after the surgery: 1,484 lines, **0 tag-nesting errors**, 15 sections,
5 SVGs and 5 figcaptions all balanced.

## Still open at the end of this session

| ID | What | Blocker |
|---|---|---|
| LB-03 | Witness boundary never tested | Needs the elevated setup run + a second login |
| G1 | Phase A never run | Needs the second machine and a live link |
| G2b | No real media wiped | Needs the USB stick |
| G9 | Bad-sector skip-and-log has no fixture | Code path unwritten, CI fixture unwritten |
| G24 | Link never tested on the day's transport | Needs the USB-Ethernet adapter |
| G23 | Wiring verified, but no test pins the ordering | Cheap, not yet done |
| G5 | No real anchor submitted | Needs one window of internet |
| G10 | Verifier not packaged into exports | Not started |
| BVCL | `bvcl/` not started | ~1 day, advisory-only test is the constraint |
| A1, A5 | Accuracy fixes | Legal owner |

## GB-scale carve, with ground truth, the 8 GB run is the load-bearing one

CFReDS is 292 MB. A forensic drive is 500 GB. Three things could have been true at 292 MB
and false at scale, and only one of them was throughput.

`scripts/stress_scale.py` builds images by **planting real files at known 512-byte-aligned
offsets in deterministic filler**, so every recovered artefact is scored rather than
counted: exact hit, offset hit with wrong bytes, or false positive. A throughput number
without a precision number is a benchmark of how fast the tool can be wrong.

Run twice on the same machine, and **the two runs disagree in a way worth keeping**.

**Run 1**, machine already at 77% memory load, 4.9 GB free:

| size | carve | MB/s | s/GB | peak RSS | found | precision | recall |
|---|---|---|---|---|---|---|---|
| 1 GB | 6.4 s | 168.5 | 6.37 | 1.1 GB | 47 | 100.0% | 100.0% |
| 2 GB | 13.2 s | 163.3 | 6.57 | 2.2 GB | 95 | 100.0% | 100.0% |
| 4 GB | 35.4 s | 121.3 | 8.85 | 4.3 GB | 191 | 100.0% | 100.0% |
| 8 GB | 84.9 s | 101.1 | 10.62 | 8.6 GB | 382 | 100.0% | 100.0% |

**Run 2**, same code, same images, more headroom:

| size | carve | MB/s | s/GB | peak RSS | found | precision | recall |
|---|---|---|---|---|---|---|---|
| 1 GB | 6.3 s | 169.1 | 6.34 | 1.1 GB | 47 | 100.0% | 100.0% |
| 2 GB | 12.4 s | 173.4 | 6.19 | 2.2 GB | 95 | 100.0% | 100.0% |
| 4 GB | 24.8 s | 172.9 | 6.21 | 4.4 GB | 191 | 100.0% | 100.0% |
| 8 GB | 49.5 s | 173.6 | 6.18 | 8.6 GB | 382 | 100.0% | 100.0% |

**The correction, stated plainly because the first table was quoted before the second run
existed.** Run 1 looked like the carver degrading with size, 168 → 101 MB/s, 38.9% spread
in seconds/GB. It was not. Run 2 holds **173 MB/s flat across all four sizes, 2.6% spread**.
The carver is **linear in image size**; run 1 measured contention on a machine that was
already 77% committed. A single benchmark pass on a loaded machine measures the machine.

**What both runs agree on, which is the part that matters:**

* **Correctness is unaffected by scale.** 100% precision and 100% recall at every size in
  both runs, up to 382 planted files.
* **The 8 GB run completes with the image larger than free RAM.** Peak working set tracks
  image size because mmap pages count toward it, but they are **file-backed and evictable**,
  so the process degrades in throughput rather than dying. That was the question worth
  answering and it is answered the same way in both runs.

**Projection, as arithmetic rather than a hope:** 6.18 s/GB × 500 GB ≈ **0.9 hours** for a
full 500 GB drive on a quiet machine, and ≈ 1.5 h on a busy one. Quote the busy number.

**The algorithmic cost, named:** `carve()` loops signatures on the outside, so it makes
**one full pass per signature, 10 passes** over the image. Linear either way, but with a
constant of 10. A single-pass multi-signature scan would cut wall time roughly tenfold and
is the obvious optimisation if a drive ever needs doing in minutes. It is **not** being done
before the freeze: 0.9 h is already acceptable, and rewriting the scanner three days out
trades a working carver for a faster unproven one.

### A measurement bug the first run found, in the measuring code

The entire first scale series reported `peak RSS 0.0 MB`. The Windows
`GetProcessMemoryInfo` call was failing silently because ctypes defaults a HANDLE to
`c_int`, which truncates a 64-bit process handle. The function returned 0.0 on failure, and
**0.0 MB reads as "used no memory" rather than "the measurement did not happen"**. Fixed
with explicit `argtypes`/`restype`, and `test_memory_is_measured_not_assumed` now fails
rather than letting a comfortable default be quoted.

### `tests/test_scale.py`, 9 tests, seconds not minutes

The GB runs are the evidence; these are the guard that the evidence means what it says. A
suite that took eight minutes would be run weekly and would stop catching anything, so what
is pinned here is the machinery: that the scorer **can actually fail** (fed wrong answers it
must report 0%), that an offset hit is never counted as exact, that images are byte-for-byte
reproducible, that plants are sector-aligned, and that four times the data does not take
much more than four times the work.

→ **445 tests.**
