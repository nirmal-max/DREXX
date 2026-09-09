# Research still to be performed

What is **not** yet done, why each matters, where to look, and roughly how long. Ordered by
what would change most if the answer came back badly.

A note on how to use this: each item says what claim it protects. If you cannot complete an
item, **weaken the claim rather than keep it**, that is the rule that has held all the way
through this project.

---

## Priority 1, could contradict a claim we are making

### 1.1 Indian patent search (InPASS)

| | |
|---|---|
| **Status** | **NOT DONE.** Attempted, blocked by a CAPTCHA |
| **Where** | https://iprsearch.ipindia.gov.in/PublicSearch/ |
| **Time** | about 30 minutes |
| **Protects** | the novelty claim, which is the single most valuable thing we say |

**Search terms to run:** *data sanitization chain of custody*, *secure erasure certificate*,
*forensic evidence integrity blockchain*, *dual signature audit log*, *tamper evident erasure*.
Also search applicants: **C-DAC**, **CDOT**, **NTRO**, **DRDO**, and the major Indian
universities.

**Until this is done, never say "no patent exists."** Say instead:

> *"We searched Google Patents and the published prior art and found nothing combining
> cross-operation chaining, dual-party signing, statute-native certification and post-quantum
> signatures. We have not yet completed the Indian patent office search."*

That sentence is defensible. The stronger one is not.

### 1.2 The official problem-statement detail page

| | |
|---|---|
| **Status** | title, theme, category and organisation confirmed from the official master catalogue. **The detailed description was never read** |
| **Where** | https://sih.gov.in/, log in, open SIH26149 |
| **Time** | 10 minutes |
| **Protects** | the completeness claim: that we answer every part of the statement |

The portal's detail view carries a background paragraph, an expected-solution paragraph and
sometimes a dataset link or a YouTube explainer. **Read it once and check no required feature
is listed that we have not built.** This is cheap and could otherwise be embarrassing.

### 1.3 The market figure, at its primary source

| | |
|---|---|
| **Status** | the ≈$650M and ≈40% CAGR figures are recorded from Deloitte, DSCI, but **the original report was never opened** |
| **Where** | https://www.dsci.in/ resource library; Deloitte India cybersecurity reports |
| **Time** | 20 minutes |
| **Protects** | every market claim on slide 5 |

Get the report title, the year and the exact page. A judge who asks *"where is that from?"*
should get a citation, not a recollection. If the number turns out to cover a different
segment, **change the slide**, a smaller honest number beats a large unsourced one.

---

## Priority 2, would strengthen the pitch materially

### 2.1 Case law citing BSA section 63(4)

| | |
|---|---|
| **Status** | not searched |
| **Where** | https://indiankanoon.org/ , https://main.sci.gov.in/judgments |
| **Time** | 30 minutes |
| **Would add** | a real judgment where electronic evidence turned on the certificate |

Search *"Bharatiya Sakshya Adhiniyam 63(4)"*, *"section 65B certificate"* (the predecessor
provision, which has far more case law), and *"electronic evidence certificate mandatory"*.
The Anvar v. Basheer and Arjun Panditrao lines of cases under section 65B are the obvious
background. **One real case where evidence was excluded for a defective certificate is the
strongest possible opening line.**

### 2.2 What changed between SP 800-88 Rev. 1 and Rev. 2

| | |
|---|---|
| **Status** | we know Rev. 2 adds a validation step; the full change list was never read |
| **Where** | https://csrc.nist.gov/pubs/sp/800/88/r2/final |
| **Time** | 45 minutes |
| **Protects** | the claim that our certificate is built against Rev. 2, not Rev. 1 |

Specifically check: the **validation** section (does our implementation match what Rev. 2
asks for?), **logical sanitization** for cloud and virtualised storage (do we address it, or
should we say we do not?), and whether the certificate appendix changed. If our format was
built against Rev. 1 assumptions anywhere, that is a real correctness risk.

### 2.3 IEEE 2883 against NIST 800-88

| | |
|---|---|
| **Status** | IEEE 2883 is cited but never compared |
| **Where** | https://standards.ieee.org/ieee/2883/10277/ |
| **Time** | 30 minutes |
| **Would add** | an answer to *"why NIST and not IEEE?"* |

IEEE 2883 is the newer storage-sanitization standard and uses different vocabulary. Being
able to say which one we follow and why is a mark of seriousness.

### 2.4 A competitor's actual certificate output

| | |
|---|---|
| **Status** | we describe how Blancco and BitRaser certificates work; **we have never seen one** |
| **Where** | vendor sample reports, or ask any laboratory that uses them |
| **Time** | opportunistic |
| **Protects** | the central differentiator |

**This is the highest-value single artefact still missing.** One real competitor certificate,
held up beside ours, showing it carries no link to the previous operation, would settle the
argument in five seconds. Until then the claim rests on documentation rather than an exhibit.

---

## Priority 3, needed to go beyond the hackathon

### 3.1 STQC certification: the real process and cost

| | |
|---|---|
| **Status** | named as a next step; never researched |
| **Where** | https://www.stqc.gov.in/ |
| **Time** | 1 hour |
| **Would add** | a credible answer to *"how does this reach a real laboratory?"* |

Find the scheme that applies, the documentation required, the approximate cost and the
timeline. **"STQC certification, roughly N months and roughly ₹X"** is a far better answer
than "we would seek certification."

### 3.2 Who actually procures forensic tools in India

| | |
|---|---|
| **Status** | we know the user; we do not know the buyer |
| **Where** | GeM (https://gem.gov.in/) for published tenders; state FSL and police procurement notices |
| **Time** | 1 hour |
| **Would add** | the route to a first customer |

Search past tenders for *data sanitization software*, *forensic tools*, *disk wiping*. Real
tender values and specifications tell you both what the state pays and what it demands.

### 3.3 A forensic laboratory contact

| | |
|---|---|
| **Status** | attempted, could not be arranged in the window |
| **Where** | start with the college's own cyber-forensics faculty, then NFSU, then the state FSL |
| **Time** | ongoing |
| **Would add** | the pilot that turns a prototype into a product |

The approach and the questions are already written in
`research/round2/09_FORENSIC_LAB_CONVERSATION_AND_TOOLS.md`. **Do not burn a hackathon day
waiting for an institution**, a college laboratory or a data-recovery shop provides the same
physics.

---

## Priority 4, technical questions we should be able to answer

### 4.1 Post-quantum migration deadlines

| | |
|---|---|
| **Status** | we cite FIPS 204; we do not cite a deadline |
| **Where** | NSA CNSA 2.0 suite timeline; NIST IR 8547 (transition to post-quantum) |
| **Time** | 30 minutes |
| **Would add** | *"why now"* for the quantum judge |

A published government date by which classical signatures must be retired turns our
post-quantum work from a nice extra into a requirement we already meet.

### 4.2 SSD sanitization behaviour in the literature

| | |
|---|---|
| **Status** | we assert flash cannot reach Purge by overwriting. **True, but we cite no study** |
| **Where** | *"Reliably Erasing Data from Flash-Based Solid State Drives"* (Wei et al., USENIX FAST 2011) is the canonical paper |
| **Time** | 20 minutes |
| **Protects** | the honesty claim, which is our whole character |

Being able to name the study that measured residual data after overwriting flash makes the
Clear-not-Purge decision look like engineering judgement rather than caution.

### 4.3 Whether anyone has combined all four properties

| | |
|---|---|
| **Status** | searched informally; never written up as a systematic review |
| **Where** | IEEE Xplore, ACM DL, Google Scholar, DFRWS proceedings |
| **Time** | 2 hours |
| **Protects** | the conjunction claim |

Search *chain of custody blockchain digital forensics*, *tamper evident audit log sanitization*,
*dual signature evidence integrity*. Record what each paper does and does **not** do. This is
the academic form of the novelty argument.

---

## If you have only one hour

| Do this | Because |
|---|---|
| **1.2** read the official PS detail page | 10 min, and it could reveal a missing requirement |
| **1.1** the InPASS search | 30 min, and it protects the novelty claim |
| **1.3** the market figure at source | 20 min, and it is the number most likely to be challenged |

Those three remove every claim currently resting on something we have not personally checked.

---

## The rule, restated

If an item here cannot be completed, **do not keep the claim it protects.** Weaken it, or
state what was searched and what was not. Every retired claim in this project was retired
because someone checked, and the project is stronger for it, the two we dropped
(*"no tool chains its own operations"* and *"first mover"*) cost us nothing and would have
cost us everything if a judge had found them first.
