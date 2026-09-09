"""Scale properties of the carver, tested with planted ground truth.

WHY THIS FILE IS SMALL WHEN THE REAL RUNS ARE HUGE. The GB-scale evidence runs live in
`scripts/stress_scale.py` and take minutes; a test suite that took eight minutes would be
run once a week and would stop catching anything. What is pinned here is the machinery and
the properties that can be checked in seconds:

  * the ground-truth harness actually scores (a scorer that always says 100% is worse than
    no scorer, because it produces a number people quote)
  * throughput does not collapse between two sizes
  * peak memory is measured rather than defaulting to a comfortable zero
  * precision stays exact on planted data

The large runs are the evidence; these are the guard that the evidence means what it says.

Recorded on this machine, 31 Aug 2026, 21.3 GB RAM. Run twice, and the two runs disagree
in a way worth keeping:

    RUN 1 - machine already at 77% memory load, 4.9 GB free
    size   carve    MB/s   s/GB   peakRSS   found  precision  recall
    1 GB    6.4s   168.5   6.37    1.1 GB      47     100.0%  100.0%
    2 GB   13.2s   163.3   6.57    2.2 GB      95     100.0%  100.0%
    4 GB   35.4s   121.3   8.85    4.3 GB     191     100.0%  100.0%
    8 GB   84.9s   101.1  10.62    8.6 GB     382     100.0%  100.0%

    RUN 2 - same code, same images, more headroom
    1 GB    6.3s   169.1   6.34    1.1 GB      47     100.0%  100.0%
    2 GB   12.4s   173.4   6.19    2.2 GB      95     100.0%  100.0%
    4 GB   24.8s   172.9   6.21    4.4 GB     191     100.0%  100.0%
    8 GB   49.5s   173.6   6.18    8.6 GB     382     100.0%  100.0%

Run 1 looked like the carver degrading with size, 38.9% spread in seconds/GB. It was not.
Run 2 is flat at 173 MB/s, 2.6% spread: the carver IS linear in image size, and run 1
measured contention on a machine that was already 77% committed. A single benchmark pass on
a loaded machine measures the machine. That is why the throughput test below is deliberately
loose - a tight bound would fail for reasons that have nothing to do with the carver.

Both runs agree on the two things that matter. Correctness is unaffected by scale: 100%
precision and recall at every size, up to 382 planted files. And the 8 GB run completes with
the image larger than free RAM - peak working set tracks image size because mmap pages count
toward it, but they are FILE-BACKED and evictable, so the process degrades in throughput
rather than dying.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from recovery.engine import carve, result_hash  # noqa: E402
from stress_scale import build_image, peak_rss_mb, score  # noqa: E402

DATA = ROOT / "tests" / "data"
pytestmark = pytest.mark.skipif(not DATA.is_dir(),
                                reason="seed files not present in this checkout")

SMALL = 48 << 20    # 48 MB - several plants, still ~0.3 s
LARGE = 192 << 20   # 192 MB - 4x, enough to see a slope if there is one


@pytest.fixture(scope="module")
def small(tmp_path_factory):
    p = tmp_path_factory.mktemp("scale") / "small.img"
    return p, build_image(p, SMALL, spacing_mb=4)


# ------------------------------------------------------------------ the harness works

def test_the_harness_plants_files_it_can_find(small):
    path, truth = small
    assert len(truth["planted"]) >= 4, "too few plants to score anything"
    got = score(carve(str(path)), truth["planted"])
    assert got["exact"] > 0


def test_precision_and_recall_are_exact_on_planted_data(small):
    """If this is ever not 100%, the number in every other scale claim is wrong."""
    path, truth = small
    got = score(carve(str(path)), truth["planted"])
    assert got["precision_pct"] == 100.0
    assert got["recall_pct"] == 100.0


def test_the_scorer_can_actually_fail(small):
    """A scorer that always reports 100% is worse than none: it produces a number people
    quote. Feed it a wrong answer and it must say so."""
    path, truth = small
    artifacts = carve(str(path))
    fake = [dict(a, sha256="ff" * 32, offset=a["offset"] + 7) for a in artifacts]
    got = score(fake, truth["planted"])
    assert got["precision_pct"] == 0.0
    assert got["false_positive"] == len(fake)


def test_an_offset_hit_is_not_counted_as_exact(small):
    """Found at the right place with the wrong bytes is a boundary bug, which is a
    different failure from a spurious magic-number match and must not be merged into it."""
    path, truth = small
    artifacts = carve(str(path))
    wrong_bytes = [dict(a, sha256="ab" * 32) for a in artifacts]
    got = score(wrong_bytes, truth["planted"])
    assert got["exact"] == 0
    assert got["offset_hit"] == len(artifacts)
    assert got["false_positive"] == 0


def test_the_image_is_reproducible(tmp_path):
    """Deterministic filler, so a divergence between runs is a carver change and not the
    image being rebuilt differently."""
    a, b = tmp_path / "a.img", tmp_path / "b.img"
    build_image(a, SMALL, spacing_mb=4)
    build_image(b, SMALL, spacing_mb=4)
    assert a.read_bytes() == b.read_bytes()
    assert result_hash(carve(str(a))) == result_hash(carve(str(b)))


# ------------------------------------------------------------------ scale properties

def test_plants_are_sector_aligned(small):
    """A real filesystem puts files on 512-byte boundaries. A carver that only found
    byte-aligned plants would pass a synthetic test and fail a real disk."""
    _, truth = small
    assert all(t["offset"] % 512 == 0 for t in truth["planted"])


def test_memory_is_measured_not_assumed():
    """peak_rss_mb returned 0.0 for the whole first scale run because the Windows call
    silently failed on a truncated handle -- reading as "used no memory". A measurement
    that defaults to a comfortable value is worse than an absent one."""
    rss = peak_rss_mb()
    assert rss > 0, "peak RSS is unavailable on this platform; the figure cannot be quoted"
    assert rss < 100_000


def test_throughput_does_not_collapse_with_size(tmp_path):
    """Four times the data must not take much more than four times the work.

    Deliberately loose. This is a smoke check against something superlinear creeping in,
    not a performance budget: CI machines are noisy and a tight bound here would fail for
    reasons unrelated to the carver. The real numbers live in evidence/stress_scale.json.
    """
    import time

    small_img = tmp_path / "s.img"
    large_img = tmp_path / "l.img"
    build_image(small_img, SMALL, spacing_mb=4)
    build_image(large_img, LARGE, spacing_mb=4)

    carve(str(small_img))  # warm the page cache so the first run is not penalised
    t0 = time.perf_counter()
    carve(str(small_img))
    small_s = max(time.perf_counter() - t0, 1e-3)

    t0 = time.perf_counter()
    carve(str(large_img))
    large_s = time.perf_counter() - t0

    ratio = (large_s / small_s) / (LARGE / SMALL)
    assert ratio < 3.0, (
        f"4x the data took {ratio:.1f}x the per-byte time; something is superlinear")


def test_more_data_does_not_manufacture_false_positives(tmp_path):
    """Density is where precision usually goes. Deterministic filler is not real disk
    noise, so this is a floor and not a guarantee -- and it is stated as one."""
    img = tmp_path / "dense.img"
    truth = build_image(img, LARGE, spacing_mb=2)
    got = score(carve(str(img)), truth["planted"])
    assert got["false_positive"] == 0
    assert got["precision_pct"] == 100.0
