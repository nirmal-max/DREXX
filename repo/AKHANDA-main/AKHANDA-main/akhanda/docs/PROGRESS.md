# AKHANDA, progress and state

**Written 1 September 2026.** A handover document: what is built, what is proven, what is
open, and what needs a human. Read this first after a break.

**Internal hackathon: 4, 5 September 2026, GITAM, 24 hours.**

---

## Current numbers, all measured

| | |
|---|---|
| Python tests | **620 passed, 0 skipped** |
| Rust tests | 12 passed, clippy clean |
| Automation | **11 checks, all green, 382 s** (`scripts/run_all.py`) |
| Adversarial audit | **8 of 8 claims survived falsification** |
| Source | ~7,600 lines · tests ~7,000 lines |

Run everything: `python scripts/run_all.py` → `evidence/run_all.{log,json}`

---

## Built and proven

| Capability | Evidence |
|---|---|
| **Fragmented PNG recovery** | NIST CFReDS L2, **byte-identical**. 140/140 synthetic cases, 0 false positives, 0 wrong files |
| **Fragmented ZIP/.docx recovery** | **27/27 byte-identical** on 9 real Word documents, 3 split points each |
| Chain: dual signature, tamper localisation | 500 entries verify in 81 ms; tamper located to exact seq in 37 ms |
| Three independent verifiers | Python ≡ JavaScript ≡ Rust, byte-for-byte |
| GB-scale carving | 8 GB at 173 MB/s, 100% precision/recall, linear |
| Bad-sector skip-and-log | G9, skipped ranges are signed evidence |
| Device identity | NIST Appendix C + BSA Part A blocks; *unavailable is never blank* |
| NIST Rev. 2 validation | §4.5.2 approve/reject; **the tool never auto-approves** |
| Post-quantum signatures | ML-DSA-65 alongside Ed25519; stripping detectable |
| Self-attestation | `tool_ref`, every entry names the build that wrote it |
| Case Merkle root | Deleting a whole device is detected |
| Signer continuity | A signer may change; a signer may not change *silently* |
| NTFS alternate data streams | The residual trace a VERIFIED erasure used to leave behind |
| Hardening | bandit + pip-audit; a real `file://` transport hole found and fixed |

---

## The three strongest claims

Scored formally in `research/round2/`. Correlated evidence combined by geometric mean.

| Claim | p |
|---|---|
| **The second signature is the standard's own requirement**, NIST Rev. 2 Appendix C has a `Concurrence` block; BSA §63(4) needs Part A + Part B | **0.995** |
| Fragment reassembly is a genuine advance | 0.991 |
| Post-quantum custody is defensible | 0.988 |
| The Indian capacity gap makes chained custody *more* necessary (CAG: 40% vacancy) | 0.98 |

**Two claims were retired by our own research**, say them nowhere:
- ~~"No existing tool chains its own operations"~~, **falsified.** US20110184910A1 (2010, expired 2023) hash-chains custody records.
- ~~"We are a first mover"~~, **falsified.** Blancco and BitRaser are both STQC-certified; Blancco builds in Pune.

---

## Open, needs a human

### Hardware to buy (~₹1,200)
USB-to-Ethernet adapter + cable (~₹500, 900) · **a sacrificial USB stick (~₹300)**

### 4h 45m of manual work

| Task | Needs | Time |
|---|---|---|
| `lb03_setup.ps1` → create `witness` login → `icacls` | Elevated PS + 2nd login | 45 min |
| `g24_link_check.py`, static IPs, firewall TCP 8000 | The adapter | 30 min |
| `g1_handshake.py --phase a`, kill witness, `--phase b`. **Record screen** | Both laptops | 1 hr |
| `g2b_usb_wipe.md`, image, wipe, image, grep canary | The stick | 1.5 hr |
| **InPASS patent search** (CAPTCHA) + grab CUSAT number | Any teammate | **30 min** |
| `fs_matrix.ps1`, NTFS/FAT32/exFAT/ReFS on **VHD files, no physical disk** | Elevated shell | 20 min |
| `vhd_erase.ps1`, **real block-device erasure, no hardware needed** | Elevated shell | 20 min |
| `cli anchor`, one real OpenTimestamps receipt | Internet once | 10 min |

**The patent search is the highest-value 30 minutes available**, it is the last thing that
could still disprove the main claim. Until it is done, **never say "no patent exists."**

### Delegate, no coding
**User manuals** (a listed PS deliverable, missing entirely) · a **prior-art slide** naming
Seagate, Covax, CUSAT, Delhi FSL, Blancco *before a judge does* · **delete "first mover"**
from every artefact.

### Still on the code list
`cargo audit` (15 min) · three-fragment reassembly (currently returns nothing, which is safe)

---

## No USB stick? Use a VHD

`scripts/prep/vhd_erase.ps1`, a `.vhdx` is a **file** Windows attaches as a genuine
`\\.\PhysicalDriveN`. Real device path, real block layer, deleted afterwards.

**Proves:** the six-gate guard on a real device path, the named-target gate, device
identification over a real handle, overwrite + read-back on a real block device.
**Does not prove:** flash behaviour (no translation layer, so no overprovisioning residue),
firmware sanitize, bad sectors, USB enumeration. **A block-device test, not a media test.**

---

## The Note 10+, checked, and it cannot be used

`validation/device_note10/ANALYSIS.md`. Probed read-only: **nothing written, no files
enumerated, no backup.**

**Verdict: `MTP_ONLY_NO_BLOCK_DEVICE`.** The phone enumerates perfectly, the water damage
has not touched the USB stack, but it presents as **MTP**, which serves *named objects, not
sectors*. `Win32_DiskDrive count: 1`, only the laptop's NVMe. There is no
`\\.\PhysicalDrive1` to address.

**No host-side tool can image or erase it at block level**, not AKHANDA, not FTK, not dd.
That is the transport, not the software. And even with raw UFS access, Android FBE means
userdata is ciphertext without the PIN.

**Say to a judge:** *"Mobile is a different evidence class. We measured that on a real
Note 10+ rather than assuming it. Our scope is block storage, which is what the problem
statement names."*

If the phone is genuinely being disposed of: **Settings → Reset → Factory data reset**
performs a cryptographic erase of the Keymaster keys, a genuine Purge-class outcome,
stronger than any host-side overwrite.

---

## Where things live

```
src/                    the tool, attestation · erasure · recovery · witness · anchor
tests/                  620 tests
validation/
  reassembly/           226-case fragment bench + results
  device_note10/        the phone probe, its log and analysis
research/
  round2/               deep research: NIST/BSA primary sources, patents, competitors
  reference/            29 project documents
evidence/               every recorded run, run_all, audit, benchmarks, hardening
scripts/
  run_all.py            THE runner. 11 checks, no early exit, nothing skipped silently
  prep/                 hardware runbooks, each capturing its own evidence
docs/ARCHITECTURE.html  23 sections, the technical account
```

---

## Rules this project holds itself to

1. **Never label an outcome stronger than what was achieved.** Clear is not Purge.
2. **Unavailable is not blank.** An unread field and an empty one look identical on a
   certificate, and a reader will assume the wrong one.
3. **Skipped is not passed. Not-run is not passed either.**
4. **Failures are recorded more fully than passes**, the full output, untruncated.
5. **Drift is a question, not a verdict.** A changed digest asks which side is right.
6. **The tool assembles the case; a human decides.** Validation is not automatable.
7. **Attack your own claims before a judge does.** Two were retired that way, and two
   hollow tests were caught by it.
