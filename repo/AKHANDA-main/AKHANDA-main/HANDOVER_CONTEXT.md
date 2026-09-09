# AKHANDA, full handover and session context

**Written 4 September 2026.** Read this first on the new laptop, or hand it to anyone
picking the project up. Everything needed to continue is either here or named here.

---

## 1. The competition

| | |
|---|---|
| Event | **Smart India Hackathon 2026** |
| Problem statement | **SIH26149** |
| Title | *Design and Development of an Integrated Secure Data Erasure and Advanced File Recovery Tool for Digital Forensics and Data Sanitization* |
| Sponsoring organisation | **National Technical Research Organisation (NTRO)** |
| Theme | Blockchain & Cybersecurity |
| Category | **Software** |
| Official portal | https://sih.gov.in/ |
| Master list, all 226 statements | https://blinknbuild.in/Assets/SIH_2026_All_226_Problem_Statements_Master_Catalogue.pdf |
| Official 2026 guidelines PDF | https://sih-uit.vercel.app/assets/sih-2026-guidelines.pdf |

**Title, theme and sponsoring organisation were confirmed against the official 226-statement
master catalogue**, not a blog. The detailed background text sits behind the portal's own
problem-statement view and is not publicly indexed, open it once to confirm no extra
required feature is listed.

### The nine official idea-selection criteria

Quoted verbatim from the SIH 2026 guidelines PDF:

> *"Evaluation criteria will include **novelty of the idea, complexity, clarity and details
> in the prescribed format, feasibility, practicability, sustainability, scale of impact,
> user experience and potential for future work progression.**"*

The submission deck covers all nine, checked by an audit script.

### Rules that shape the build

- **Six slides maximum**, including the title slide. Altering the official template risks
  disqualification.
- **500 ideas per problem statement**, then it freezes. Submit early.
- Team of **6, all from one college, at least one female member mandatory**.
- One power socket per team, bring an extension strip.
- Nobody leaves the room during the 24 hours without written approval.

---

## 2. The team

| Role | Member |
|---|---|
| Team lead, core engineering | **Pulkit Kr Srivastava** (B.Tech CSE, AI & ML) |
| Frontend | **Aadya Pandey** |
| Testing and QA | **Karthik** |
| Presentation | **Ankit** |
| Legal and compliance | **B Rohan** |
| Research and field | **Kanishq** |

**Team name: Syntax Squad.** GITAM (Deemed to be University), Hyderabad.
Faculty mentor: S. Aparna (Assoc. Prof., CSSE). SPOC: Mr Fakhruddin Sheik (Dy. Director, VDC).

*Earlier drafts said "Team Anvaya". That was wrong and is corrected everywhere.*

---

## 3. Where the project stands

| | |
|---|---|
| Tests | **630 pass, 0 skipped, 0 failed** (corpus present) |
| Automated checks | **11 of 11 green** |
| Adversarial audit | **8 of 8 claims survived falsification** |
| Recovery | **4 of 4 byte-identical**; 140/140 on the fragment bench |
| Independent verifiers | **3** (Python, browser JavaScript, Rust) agree exactly |
| Security scan | **0 HIGH severity findings**; frontend 0 npm vulnerabilities |
| Git history | **46 commits** |
| Cross-machine dual signature | **CONFIRMED on real hardware, 3 September 2026** |

Operator key `9608a3150d1394a4` · witness key `0b1088f7140ef514` (exists only on laptop B)
· chain `1d33c5ee78fbc0c1`.

### The honest bounds, never soften these

- Custody tier reached is **`WITNESS_COSIGNED`**, never `FULL_CUSTODY`. The highest tier needs
  a presence device that is **designed but not built**.
- **NIST Purge on an SSD, a real flash wipe, and genuine bad-sector handling are NOT TESTED.**
  The code exists and is unit-tested; the hardware could not be obtained.
- The ledger proves nothing was **altered**. It cannot prove nothing was **withheld**.
- OpenTimestamps is **not** legally recognised in Indian courts.
- USB flash and SD cards **cannot** reach NIST Purge. The tool records Clear and says Clear.
- The ESP32 is a presence device, never a secure key store.

---

## 4. Standards and law, with sources

| What | Identifier | Where |
|---|---|---|
| Media sanitization | **NIST SP 800-88 Rev. 2**, finalised 26 Sep 2025 | https://csrc.nist.gov/pubs/sp/800/88/r2/final · https://doi.org/10.6028/NIST.SP.800-88r2 |
| Previous revision | SP 800-88 Rev. 1 (Dec 2014) | https://doi.org/10.6028/NIST.SP.800-88r1 |
| Post-quantum signature | **NIST FIPS 204** (ML-DSA) | https://csrc.nist.gov/pubs/fips/204/final |
| Crypto modules | FIPS 140-3 | https://doi.org/10.6028/NIST.FIPS.140-3 |
| Key management | SP 800-57 Part 1 Rev. 5 | https://doi.org/10.6028/NIST.SP.800-57pt1r5 |
| Storage sanitization | **IEEE 2883** | https://standards.ieee.org/ieee/2883/10277/ |
| Sanitization conformance | IEEE 2883.1 | https://standards.ieee.org/ieee/2883.1/11015/ |
| Merkle tree construction | **RFC 6962** | https://www.rfc-editor.org/rfc/rfc6962 |
| Indian evidence law | **BSA 2023 §63(4)** + Schedule Parts A/B, in force July 2024 | https://www.indiacode.nic.in/ (search "Bharatiya Sakshya Adhiniyam") |
| Data protection | **DPDP Act 2023 §8(7)**, erasure duty | https://www.meity.gov.in/data-protection-framework |
| Recovery test data | **NIST CFReDS** reference images | https://cfreds.nist.gov/ |

### Vulnerabilities we cite

| CVE | What it is | Why it matters |
|---|---|---|
| **CVE-2019-17391** | ESP32 eFuse key extraction by voltage glitching, unpatchable on shipped silicon | why the presence device is **never** called a secure key store |
| **CVE-2012-2459** | Merkle tree duplication flaw | fixed in our anchor code; odd nodes promoted, never duplicated |

### Patents and prior art

| Reference | What it is | Where |
|---|---|---|
| **US20110184910A1** (2010, **expired**) | chains audit records. **No second signer, no sanitization** | https://patents.google.com/patent/US20110184910A1 |
| CUSAT filing, Dec 2025 | academic, no product | `research/round2/03_PATENT_PRIOR_ART.md` |

**Still outstanding:** the Indian patent office search (InPASS,
https://iprsearch.ipindia.gov.in/) has a CAPTCHA and was never completed. **Until it is done,
never say "no patent exists"**, say "we found no prior art combining these four properties,
and here is what we searched."

---

## 5. Market and competitors

| Claim | Figure | Source |
|---|---|---|
| Reachable Indian market (non-mobile) | **≈ $650 million** | Deloitte, DSCI, in `research/round2/05_MARKET_MOAT_NOVELTY.md` |
| Growth | **≈ 40% CAGR** | same |

| Competitor | Strength | What they cannot do |
|---|---|---|
| **Blancco**, **BitRaser** | STQC-certified erasure, established | each certificate signed alone; nothing links jobs; no recovery |
| **EnCase**, **FTK** | imaging and analysis at scale | no certificate native to Indian evidence law; foreign; per-seat cost |
| **Autopsy** (free) | capable open-source carving | no signed chain, no certificate, no second party |
| **Cellebrite**, **Magnet** | mobile evidence | different discipline entirely |

**Why incumbents cannot follow quickly:** Blancco and BitRaser hold STQC certification, so
changing certificate structure means re-certification, years and money. EnCase and FTK are
foreign, and a certificate for one country's evidence law is poor economics for them. None
cross from wiping into recovery, because those are separate product lines with separate buyers.

**Two claims we retired, deliberately recorded:**
1. *"No tool chains its own operations"*, falsified by US20110184910A1.
2. *"First mover"*, Blancco and BitRaser are STQC-certified; Blancco builds in Pune.

---

## 6. Provenance, disclose, never hide

Akhanda extends **AetherProof**, the team lead's own open-source attestation engine
(Apache-2.0), published **before** this problem statement was released. Sole author: Pulkit
Kr Srivastava. Stated on the references slide.

**Naming discipline:** AetherProof is the engine. Akhanda is the SIH deliverable. Never used
interchangeably.

---

## 7. What is where

### The zips on the D drive

| File | Size | Contains |
|---|---|---|
| **`AKHANDA_SIH26149_COMPLETE_20260904.zip`** | 42.7 MB | **everything**, full git history (46 commits), code, four PDFs, the deck, frontend, witness, research |
| `AKHANDA_RESEARCH_COMPLETE.zip` | 3.6 MB | all research + INDEX mapping every claim to its source |
| `AKHANDA_FRONTEND_for_Aadya.zip` | 0.1 MB | frontend + her command set and responsiveness guide |

**If you move only one file, move the first.** It contains the other two.

### The documents

| File | For |
|---|---|
| `Akhanda_User_Manual.pdf` | every command, every button, every file |
| `Akhanda_Judge_QA.pdf` | per-member questions and the presenter's full set |
| `Akhanda_Plan_B_No_Hotspot.pdf` | contingency, read before the day |
| `Akhanda_Operating_Guide.pdf` | the project map in plain words |
| `Akhanda_SIH26149_IdeaSubmission.pptx` | six-slide submission. **Team ID still blank** |

### Key artefacts

| Thing | Path |
|---|---|
| The real ledger | `demo-data/chain.json` |
| The certificate | `demo-data/certificate.json` |
| Attestation core (the 16 signed fields) | `src/attestation/core.py` |
| Browser verifier | `frontend/src/lib/verify.ts` |
| Witness node | `witness/node.py` |
| Independent Rust checker | `rust/akhanda-verify/` |
| Demo generator | `scripts/demo_bundle.py` |

---

## 8. Picking up from here

### On the new laptop
1. Follow `START_HERE_NEW_LAPTOP.md` inside the master zip.
2. Install Python (**tick Add to PATH**), Node, Rust, Git.
3. `pip install -r requirements.txt`, `npm install`, run the tests.
4. Expect **630 collected, 0 failures**. About 34 skip without the NIST corpus, each saying so.

### Still open

| Item | Status |
|---|---|
| **Team ID** on slide 1 | blank, fill from the portal |
| **InPASS patent search** | not done. 30 minutes, CAPTCHA |
| **React frontend responsiveness** | thin: **0 `sm:` breakpoints, 0 `overflow-x-auto`**, and it renders 64-character hashes. Details in Aadya's guide |
| NIST Purge on SSD, flash wipe, bad sectors | not tested, hardware never obtained |
| Forensic laboratory pilot | not started |
| STQC certification | not started, costed as a next step |
| User manuals for the PS deliverable | **done**, `Akhanda_User_Manual.pdf` |

### The demo, in one line
Start `node.py` on laptop B, run `demo_bundle.py --witness http://<ip>:8000` on laptop A,
open the console, load `chain.json`, press **Inject Tamper**, then **Restore**.

*(There is no file called `inject.json`. "Inject Tamper" is a button; it edits the record in
memory and recomputes the hashes. Nothing on disk changes.)*

### The sentence that carries the pitch
> *"Every tool in this space signs each certificate on its own. That proves one page was not
> edited. It does not prove the file is complete. We are the only ones who can show you which
> record is missing."*

---

## 9. The working rules that produced this

1. Never label an outcome stronger than achieved. Clear is not Purge.
2. Unavailable is not blank, an unread field and an empty one must never look the same.
3. Skipped is not passed. Not-run is not passed.
4. Record failures more fully than successes.
5. The tool assembles the case; a human decides.
6. **Attack your own claims before a judge does.** Two claims were retired that way, and two
   hollow tests were caught.
7. Verify market, patent and legal facts against the primary source, dated.
8. State the honest bound **before** the headline.

### Bugs found this way, worth telling judges about

| What | Why no test caught it |
|---|---|
| The carver produced an unopenable ZIP while reporting it complete | the byte-identical test covered only the three formats where it could not happen |
| A fresh clone on Windows failed four tests | line endings changed on checkout; the local working copy could never reveal it |
| The frontend's tamper demo was a 900 ms timer with pre-labelled rows | nothing computed a hash anywhere in it |
| `find_device()` returned a Bluetooth port as the presence device | every test mocked port enumeration |

---

*Akhanda · अखण्ड, "unbroken" · Syntax Squad · GITAM Hyderabad · SIH 2026, SIH26149, NTRO.*
