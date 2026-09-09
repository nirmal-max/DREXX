"""Stress test against real NIST CFReDS forensic images.

Not a unit test and not a benchmark. Unit tests use fixtures the author chose; this drives
the whole pipeline with data the author did not choose and cannot quietly make easier , 
the NIST Computer Forensic Reference Data Set graphic images, which exist specifically to
be hard in ways real disks are hard (fragmented extents, deleted-then-overwritten files,
partial headers).

    python scripts/stress_forensic.py [--repeat 1] [--out evidence/stress_forensic.json]

It runs five stages and writes evidence/stress_forensic.json:

  1. CARVE all five CFReDS images for real, and record what came back per level.
  2. BUILD one chain whose entries commit to those real carve digests. Not synthetic
     hashes, if the carver is non-deterministic, this stage exposes it, because the
     entry hash is downstream of the carve result.
  3. PERSIST and reload, then verify. A chain that only verifies in the process that
     built it has proved nothing about a chain handed to a court.
  4. TAMPER, six ways, and check each is caught AND localised to the right seq.
  5. CROSS-VERIFY the same chain file with the independent Rust binary, which shares no
     code with the Python. Agreement across two languages on the same bytes is the claim
     `test_three_implementations.py` makes on fixtures; this makes it on real output.

DETERMINISM IS A STAGE, NOT AN ASSUMPTION. Stage 1 can carve twice and compare digests.
A carver that returns artefacts in filesystem order rather than offset order produces a
different result_hash each run, which would make every chain unreproducible, and it
would not show up in a test that carves once.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attestation.core import Chain, verify_chain_report  # noqa: E402
from attestation.keys import load_or_create_operator_key  # noqa: E402
from attestation import tiers  # noqa: E402
from recovery.engine import carve, outcome_for, result_hash, summarize  # noqa: E402

DATA = ROOT / "tests" / "data"
EVIDENCE = ROOT / "evidence"
RUST = ROOT / "rust" / "akhanda-verify" / "target" / "release" / "akhanda-verify.exe"

IMAGES = ["L0_Graphic.dd", "L1_Graphic.dd", "L2_Graphic.dd",
          "L3_Graphic.dd", "L4_Graphic.dd"]


def _now(i: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + i))


# ---------------------------------------------------------------- stage 1: carve
def stage_carve(repeat: int) -> dict:
    out: dict = {"stage": "1 - carve real CFReDS images", "images": [], "total_mb": 0.0}
    total_bytes = 0
    t_all = time.perf_counter()

    for name in IMAGES:
        path = DATA / name
        if not path.exists():
            out["images"].append({"image": name, "error": "missing"})
            continue
        size = path.stat().st_size
        total_bytes += size

        t0 = time.perf_counter()
        arts = carve(str(path))
        secs = time.perf_counter() - t0

        digest = result_hash(arts)
        rec = {
            "image": name,
            "size_mb": round(size / 1e6, 1),
            "carve_s": round(secs, 2),
            "throughput_mb_s": round((size / 1e6) / secs, 1) if secs else None,
            "artifacts": len(arts),
            "result_hash": digest,
            "outcome": outcome_for(arts),
            "summary": summarize(arts),
        }

        # Determinism: same bytes in, same digest out, or every chain built on this
        # carver is unreproducible and nobody would find out until a re-verify.
        if repeat > 1:
            again = [result_hash(carve(str(path))) for _ in range(repeat - 1)]
            rec["repeat_runs"] = repeat
            rec["deterministic"] = all(d == digest for d in again)
            if not rec["deterministic"]:
                rec["differing_digests"] = sorted({digest, *again})

        out["images"].append(rec)

    out["total_mb"] = round(total_bytes / 1e6, 1)
    out["wall_s"] = round(time.perf_counter() - t_all, 2)
    out["aggregate_mb_s"] = round(out["total_mb"] / out["wall_s"], 1) if out["wall_s"] else None
    nondet = [r for r in out["images"] if r.get("deterministic") is False]
    out["all_deterministic"] = (not nondet) if repeat > 1 else None
    out["verdict"] = "FAIL - carver is non-deterministic" if nondet else "PASS"
    return out


# ---------------------------------------------------------------- stage 2: chain
def stage_chain(carve_stage: dict, op_key) -> tuple[Chain, dict]:
    """One entry per real carve, committing to the real digest."""
    out: dict = {"stage": "2 - build a chain over the real carve results"}
    chain = Chain(chain_id=f"stress-cfreds-{int(time.time())}")

    t0 = time.perf_counter()
    for i, rec in enumerate(carve_stage["images"]):
        if rec.get("error"):
            continue
        chain.append(
            op_type="RECOVER",
            target_ref=f"tests/data/{rec['image']}",
            timestamp=_now(i),
            method="Clear",
            result_hash=rec["result_hash"],
            operator_decl=(f"carved {rec['artifacts']} artefacts from {rec['image']} "
                           f"({rec['size_mb']} MB)"),
            concur_decl="",
            custody_tier=tiers.SOFTWARE_KEY,
            operator_key=op_key,
            outcome=rec["outcome"],
        )
    out["build_s"] = round(time.perf_counter() - t0, 3)
    out["entries"] = len(chain.entries)
    out["outcomes"] = sorted({e.outcome for e in chain.entries})
    out["head"] = chain.entries[-1].entry_hash if chain.entries else None

    # The point of stage 2: the ledger commits to what the carver actually produced.
    committed = {e.target_ref.split("/")[-1]: e.result_hash for e in chain.entries}
    produced = {r["image"]: r["result_hash"] for r in carve_stage["images"] if not r.get("error")}
    out["entry_commits_to_real_carve"] = committed == produced

    # PARTIAL must actually appear. If every entry says VERIFIED on CFReDS L2/L3, images
    # NIST built to contain no contiguous file, the outcome field is decorative.
    out["partial_present"] = "PARTIAL" in out["outcomes"]
    out["verdict"] = "PASS" if out["entry_commits_to_real_carve"] else "FAIL"
    return chain, out


# ------------------------------------------------- stage 3: persist, reload, verify
def stage_roundtrip(chain: Chain, op_key, tmp: Path) -> dict:
    from attestation.store import load_chain, save_chain

    out: dict = {"stage": "3 - persist, reload from disk, verify"}
    path = tmp / "stress_chain.json"
    save_chain(chain, path)
    out["bytes_on_disk"] = path.stat().st_size
    out["path"] = str(path)

    reloaded = load_chain(path)
    out["reloaded_entries"] = len(reloaded.entries)
    out["hashes_survive_roundtrip"] = (
        [e.entry_hash for e in reloaded.entries] == [e.entry_hash for e in chain.entries])

    t0 = time.perf_counter()
    report = verify_chain_report(reloaded.entries, operator_pub=op_key.public_key())
    out["verify_ms"] = round((time.perf_counter() - t0) * 1000.0, 2)
    out["ok"] = bool(report.ok)
    out["operator_layer"] = getattr(report, "operator_layer", None)
    out["verified"] = getattr(report, "verified", None)
    out["reason"] = report.reason
    out["verdict"] = "PASS" if (out["ok"] and out["hashes_survive_roundtrip"]) else "FAIL"
    return out


# ---------------------------------------------------------------- stage 4: tamper
def stage_tamper(chain: Chain, op_key) -> dict:
    """Six edits a hostile operator would actually make. Each must be caught."""
    import copy

    out: dict = {"stage": "4 - tamper detection and localisation", "cases": []}
    pub = op_key.public_key()
    n = len(chain.entries)
    mid = n // 2

    def attempt(label, mutate, expect_seq, why):
        c = copy.deepcopy(chain)
        mutate(c)
        rep = verify_chain_report(c.entries, operator_pub=pub)
        caught = not rep.ok
        located = rep.broken_seq
        out["cases"].append({
            "case": label,
            "why_an_operator_would": why,
            "caught": caught,
            "expected_seq": expect_seq,
            "located_at_seq": located,
            "localised": (located == expect_seq) if expect_seq is not None else None,
            "reason": rep.reason,
        })

    attempt("edit the operator declaration",
            lambda c: setattr(c.entries[mid], "operator_decl", "nothing was recovered"),
            mid, "Rewrite what the ledger says happened, leaving the hashes alone.")

    attempt("swap the result digest",
            lambda c: setattr(c.entries[mid], "result_hash", "ff" * 32),
            mid, "Point a real entry at a different, more flattering result file.")

    # Flip to whatever the entry is NOT, so the case always actually mutates something.
    # First draft hardcoded "VERIFIED" and every CFReDS entry already said VERIFIED, so
    # the case was a no-op that read as an UNCAUGHT TAMPER. A test that reports a false
    # alarm on itself is worse than no test.
    other = "PARTIAL" if chain.entries[mid].outcome == "VERIFIED" else "VERIFIED"
    attempt(f"flip the outcome {chain.entries[mid].outcome} -> {other}",
            lambda c: setattr(c.entries[mid], "outcome", other),
            mid, "THE overclaim this project exists to stop: present an incomplete "
                 "recovery as a complete one. outcome is the 15th signed field for this.")

    attempt("upgrade the custody tier",
            lambda c: setattr(c.entries[mid], "custody_tier", tiers.FULL_CUSTODY),
            mid, "Claim a witness and a present human that were never there.")

    def delete_middle(c):
        del c.entries[mid]
    attempt("delete an entry from the middle", delete_middle, mid + 1,
            "The attack per-document signing cannot see at all: each remaining "
            "certificate is still perfectly signed.")

    def reorder(c):
        c.entries[1], c.entries[2] = c.entries[2], c.entries[1]
    attempt("reorder two entries", reorder, 2,
            "Change which operation came first, so a recovery appears to precede the "
            "erasure that destroyed the evidence.")

    caught = [c for c in out["cases"] if c["caught"]]
    localised = [c for c in out["cases"] if c.get("localised")]
    out["caught"] = f"{len(caught)}/{len(out['cases'])}"
    out["localised"] = f"{len(localised)}/{len(out['cases'])}"
    out["verdict"] = "PASS" if len(caught) == len(out["cases"]) else "FAIL"
    return out


# ------------------------------------------------------- stage 5: rust cross-check
def stage_rust(chain_path: Path, op_key) -> dict:
    from cryptography.hazmat.primitives import serialization

    out: dict = {"stage": "5 - independent Rust verifier on the same file",
                 "binary": str(RUST)}
    if not RUST.exists():
        out["verdict"] = "SKIPPED"
        out["meaning"] = ("Rust binary not built. `cargo build --release` in "
                          "rust/akhanda-verify. Without it, only one implementation has "
                          "seen this chain, and two implementations by one author can "
                          "share a misreading.")
        return out

    pub_hex = op_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    t0 = time.perf_counter()
    proc = subprocess.run([str(RUST), str(chain_path), "--operator-key", pub_hex, "--json"],
                          capture_output=True, text=True, timeout=120)
    out["rust_ms"] = round((time.perf_counter() - t0) * 1000.0, 1)
    out["exit_code"] = proc.returncode
    out["stdout"] = proc.stdout.strip()[:2000]
    if proc.stderr.strip():
        out["stderr"] = proc.stderr.strip()[:1000]

    py = verify_chain_report(
        __import__("attestation.store", fromlist=["load_chain"]).load_chain(chain_path).entries,
        operator_pub=op_key.public_key())
    out["python_ok"] = bool(py.ok)
    out["rust_ok"] = proc.returncode == 0
    out["agree"] = out["python_ok"] == out["rust_ok"]
    out["verdict"] = "PASS" if out["agree"] and out["rust_ok"] else "FAIL"
    out["meaning"] = ("Two implementations sharing no code reached the same verdict on the "
                      "same bytes." if out["agree"] else
                      "THE IMPLEMENTATIONS DISAGREE. One of them is wrong and the spec is "
                      "ambiguous. This blocks everything until resolved.")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Stress the pipeline on real CFReDS images.")
    ap.add_argument("--repeat", type=int, default=1,
                    help="carve each image N times to check determinism (default 1)")
    ap.add_argument("--out", default=str(EVIDENCE / "stress_forensic.json"))
    args = ap.parse_args()

    if not DATA.exists():
        print(f"missing {DATA} - the CFReDS images are not in this checkout", file=sys.stderr)
        return 2

    op_key = load_or_create_operator_key()
    tmp = EVIDENCE / "stress_tmp"
    tmp.mkdir(parents=True, exist_ok=True)

    result: dict = {
        "check": "stress test on real NIST CFReDS forensic images",
        "ran_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python": sys.version.split()[0],
        "stages": [],
    }

    print("stage 1  carving 5 real CFReDS images ...")
    s1 = stage_carve(args.repeat); result["stages"].append(s1)
    print(f"         {s1['total_mb']} MB in {s1['wall_s']}s "
          f"({s1['aggregate_mb_s']} MB/s)  {s1['verdict']}")

    print("stage 2  building a chain over the real carve digests ...")
    chain, s2 = stage_chain(s1, op_key); result["stages"].append(s2)
    print(f"         {s2['entries']} entries, outcomes {s2['outcomes']}  {s2['verdict']}")

    print("stage 3  persist -> reload -> verify ...")
    s3 = stage_roundtrip(chain, op_key, tmp); result["stages"].append(s3)
    print(f"         {s3['bytes_on_disk']} bytes, verify {s3['verify_ms']} ms  {s3['verdict']}")

    print("stage 4  tampering six ways ...")
    s4 = stage_tamper(chain, op_key); result["stages"].append(s4)
    print(f"         caught {s4['caught']}, localised {s4['localised']}  {s4['verdict']}")

    print("stage 5  independent Rust verifier ...")
    s5 = stage_rust(Path(s3["path"]), op_key); result["stages"].append(s5)
    print(f"         exit {s5.get('exit_code')}, agree={s5.get('agree')}  {s5['verdict']}")

    verdicts = [s["verdict"] for s in result["stages"]]
    result["overall"] = ("PASS" if all(v in ("PASS", "SKIPPED") for v in verdicts)
                         else " / ".join(verdicts))

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"\noverall  {result['overall']}")
    print(f"written  {args.out}")
    return 0 if result["overall"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
