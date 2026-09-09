# Fragment reassembly, validation results

**Purpose:** the reassembly claim was scored at **p ≈ 0.85**, penalised (×0.4) for resting on
*one file, one format, one disk image*. The penalty was correct. This bench removes it by
widening the evidence, not by re-arguing the same run.

**Run:** 1 September 2026 · `validation/reassembly/bench/fragment_bench.py --repeats 2`
**Raw:** `results/fragment_bench.json`

---

## Headline

| | |
|---|---|
| **Cases** | **226** |
| Two-fragment recovery | **140 / 140, 100%, byte-identical** |
| Boundary-straddling chunk recovered | **140 / 140** |
| Negative cases correctly refused | **58 / 58, zero false positives** |
| Beyond-capability cases safely refused | **28 / 28** |
| **Files reported that were not byte-identical to the original** | **0** |

> **Across 226 cases the tool never once reported a file that was not the original, byte for
> byte.** That single number is the assurance claim; everything below is how it was earned.

**"Recovered" means the SHA-256 matches the original.** Never "a decoder accepted it", a
distinction this bench proved is load-bearing, below.

---

## Corpus, what "one file" became

`tests/data` holds seven real photographs but only one is a PNG. Re-encoding all seven into
four colour types produced **28 structurally distinct PNGs** from real photographic content:

| | |
|---|---|
| Files | **28** (was 1) |
| Colour types | **4**, RGB, RGBA, greyscale, palette (was 1) |
| Size range | **44,397 B → 8,632,434 B**, three orders of magnitude |
| Dimensions | 375×500 to 2580×1932 |

The colour types matter specifically: the completeness check below divides by colour type,
so a formula only ever exercised on RGB has been tested on a quarter of its branches.

---

## THE BUG THIS BENCH FOUND

**This is the reason the bench exists, and it justifies the whole exercise.**

The first run reported the three-fragment case as *recovered*. It was not. The module
returned a file **5,193,132 bytes short**, its entire middle fragment missing, and Pillow
decoded it happily as **"PNG 2580×1932 RGB"**.

Every chunk in that file was CRC-valid and genuinely belonged to the original. They simply
were not all of it. **A decoder cannot tell those apart.** Offered as evidence, it would be
a photograph with a hole in the middle that opens perfectly and proves nothing.

### The fix is arithmetic, not judgement

IHDR *declares* the geometry, so the decompressed pixel stream has exactly one correct
length:

```
height × (1 + ceil(width × channels × bit_depth / 8))
```

the `+1` being PNG's per-row filter byte. For the file above: 1932 × (1 + 2580×3) =
**14,955,612 bytes**. The original inflates to exactly that. A file missing a fragment
cannot.

`_completeness_check()` now runs **before** the decoder check and rejects anything whose
IDAT stream does not inflate to the declared length, short (data missing) or long (foreign
data spliced in).

**After the fix the same case returns nothing.** Silence at the edge of a capability is
honest; a plausible wrong answer is not.

---

## The three case families

### Positive, the file is present in pieces and must come back exactly

| Pattern | Cases | Recovered |
|---|---|---|
| Two fragments, **order reversed** (the CFReDS L2 shape) | 56 | **56** |
| Two fragments, in order, separated by a gap | 56 | **56** |
| First fragment ending at the **final byte of the image** | 28 | **28** |
| **Total** | **140** | **140, 100%** |

Split points are randomised (fixed seed, so failures reproduce) and chosen to land *inside*
chunks, because the straddling chunk is the hard part. **It was recovered in all 140.**

Half the reversed cases salt the gap with **PNG-shaped decoys**, correct type tokens,
deliberately wrong CRCs. All 140 still recovered exactly, so the scanner is rejecting on
checksum rather than on the four-byte token.

### Negative, nothing valid is present and nothing must be reported

| Case | × | Refused |
|---|---|---|
| **First half of one PNG + second half of another** | 1 | ✅ |
| 6 MB of PNG-shaped decoys, all CRCs wrong | 1 | ✅ |
| Truncated, header present, no IEND | 28 | ✅ |
| Headless, tail present, no IHDR (**the CFReDS L3 shape**) | 28 | ✅ |
| **Total** | **58** | **58, zero false positives** |

**The mixed case is the most important test in this file.** Both halves consist of genuine,
CRC-valid chunks; every fragment "belongs" to a real file, just not the same one. A spliced
result decodes perfectly and is evidentially worthless. **The tool refused it.**

### Limit, beyond the documented capability; silence is the correct answer

| Case | × | Safely returned nothing |
|---|---|---|
| Three fragments, shuffled | 28 | **28** |

The module documents **two** fragments. Failing to recover three is correct behaviour.
Returning something *wrong* is not, and before the completeness fix, it did exactly that in
all 28.

---

## What CFReDS itself says (the real disk images)

| Image | PNG structure found | Handled by |
|---|---|---|
| L0, L1, L4 | 1 run, IHDR and IEND together, **contiguous** | the ordinary carver |
| **L2** | **2 runs, split and reversed** | **reassembly, byte-identical** |
| **L3** | 528 of 1,584 chunks, **no IHDR, no PNG signature** | **nothing, and this is honest** |

**L3 verified directly:** the file contains **zero** PNG signatures, and its two `IHDR` byte
occurrences are coincidental with implausible declared lengths (1,363,691,330 and
1,112,296,010). The source file's IHDR is not present verbatim anywhere.

Without IHDR there is no width, height or bit depth, **no valid PNG can be constructed, by
any tool, from what L3 contains.** That is a property of the image, not a limitation of the
method, and the bench's "headless" negative cases confirm the tool refuses rather than
guesses.

---

## Bayesian re-score

### Before, `01_FINDINGS_VERIFIED.md`

| Evidence | LR | |
|---|---|---|
| Byte-identical recovery from CFReDS L2 | 25 | measured |
| Control: plain carver recovers nothing from L2 | 8 | measured |
| **One file, one format, one image** | **0.4** | **penalty** |

Correlated (same run) → √(25 × 8) ≈ 14.1. Prior 0.5 × 14.1 × 0.4 = odds 5.6 → **p ≈ 0.85**.

### After

| Evidence | LR | Basis |
|---|---|---|
| 140/140 two-fragment cases byte-identical, 28 files, 4 colour types | **22** | **measured** |
| 58/58 negatives refused, including the mixed-file splice | **14** | **measured** |
| 0 wrong files across all 226 cases | **9** | **measured** |
| Byte-identical recovery from real CFReDS L2 | 25 | measured |
| Control: plain carver recovers nothing from L2 | 8 | measured |
| PNG only, no second format validated | **0.55** | **penalty, honest** |

The first three come from **one bench run** → ∛(22 × 14 × 9) ≈ **14.1**.
The two CFReDS figures come from **one image** → √(25 × 8) ≈ **14.1**.
These two groups are independent, synthetic fragmentation vs a real NIST disk image.

Prior 0.5 (odds 1) × 14.1 × 14.1 × 0.55 = odds **109** → **p ≈ 0.991**

| | Before | After |
|---|---|---|
| Fragment reassembly | **0.85** | **0.991** |

**The narrowness penalty is gone.** It has been replaced by a smaller, honest one: this is
still **one format**. PNG was chosen because CRC-32 per chunk makes membership *provable*;
extending to ZIP (which also carries a CRC-32 per entry, and covers .docx, .xlsx, .apk) is
the next real capability step and would remove the remaining 0.55.

### Why not higher

- **One format.** Kept at 0.55 deliberately.
- **Synthetic fragmentation is not disk fragmentation.** Real filesystems fragment on
  cluster boundaries with patterns a bench does not reproduce. The CFReDS L2 case is the
  only *real* fragmentation tested, and it is one image.
- **Interlaced (Adam7) PNGs are reported unverifiable**, not handled. Rare, and refused
  rather than guessed.

---

## What changed in the product

| File | Change |
|---|---|
| `src/recovery/reassemble.py` | `_completeness_check()`, IDAT must inflate to the length IHDR declares. Runs **before** the decoder check. |
| | The evidence string now records the completeness proof alongside the CRC count. |

## Reproducing

```
python validation/reassembly/bench/build_corpus.py      # 28 PNGs, deterministic
python validation/reassembly/bench/fragment_bench.py --repeats 2
```

Exit 0 only when all positives recover, all negatives refuse, all limits stay silent, **and
zero wrong files are reported.**
