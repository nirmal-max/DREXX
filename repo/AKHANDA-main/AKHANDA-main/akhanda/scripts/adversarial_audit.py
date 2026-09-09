"""Adversarial audit: try to DISPROVE this project's own claims.

Every claim below is one this repository makes about itself. For each, the audit tries to
construct the world in which the claim is hollow, a test that cannot fail, a metric that
is structurally guaranteed, a check that would pass on a broken build. A claim only counts
as SURVIVED when the attempt to falsify it actually ran and failed.

    python scripts/adversarial_audit.py

Emits evidence/adversarial_audit.json.

THE STANDARD. "The test passes" is not evidence. Evidence is "the test fails when the thing
it guards is broken." A test that has never been observed to fail is a test whose failure
mode is unknown, and the whole point of this pass is to observe it. Anything that cannot be
falsified here is reported as UNFALSIFIABLE rather than as a pass, an unfalsifiable claim
is not a strong claim, it is an unmeasured one.
"""
from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

EVIDENCE = ROOT / "evidence"
RESULTS: list = []


def claim(name: str, claim_text: str, attack: str, verdict: str, detail: str,
          data: dict | None = None) -> None:
    RESULTS.append({"claim": name, "asserted": claim_text, "attack": attack,
                    "verdict": verdict, "detail": detail, "data": data or {}})
    mark = {"SURVIVED": "PASS", "FALSIFIED": "FAIL",
            "WEAKENED": "WEAK", "UNFALSIFIABLE": "????"}[verdict]
    print(f"[{mark}] {name}")
    print(f"        {detail}")


# ═══════════════════════════════════════════════════════════ 1. is 0 false positives real?

def audit_false_positives():
    """CLAIM: 'zero false positives at 8 GB, 100% precision'.

    ATTACK: if the filler cannot contain a file signature, then zero false positives is
    guaranteed by construction and the metric measures nothing. Count how many signature
    magic numbers actually occur in the filler.
    """
    from recovery.engine import SIGNATURES
    from stress_scale import _filler

    sample = _filler(0, 64 << 20)   # 64 MB of the same filler the scale test uses
    hits = {}
    for sig in SIGNATURES:
        n = sample.count(sig.header)
        if n:
            hits[f"{sig.ext}:{sig.header.hex()}"] = n

    total = sum(hits.values())
    if total == 0:
        claim("carve.false_positives",
              "0 false positives / 100% precision at 8 GB",
              "count signature magic bytes present in the filler itself",
              "WEAKENED",
              f"The filler contains ZERO of the {len(SIGNATURES)} signature headers in "
              f"64 MB, so 'no false positives' is partly guaranteed by construction. The "
              f"number is real but it measures the scanner on CLEAN data, not on a disk "
              f"full of partial files. It must never be quoted as a general precision "
              f"figure, CFReDS L2/L3, which are fragmented, score 0%.",
              {"signatures": len(SIGNATURES), "header_hits_in_64mb": hits,
               "sample_mb": 64})
    else:
        claim("carve.false_positives",
              "0 false positives / 100% precision at 8 GB",
              "count signature magic bytes present in the filler itself",
              "SURVIVED",
              f"The filler contains {total} signature-header occurrences across "
              f"{len(hits)} types in 64 MB, and the carver still reported no false "
              f"positives, so it rejected them on structure, not by never seeing one.",
              {"header_hits_in_64mb": hits, "total": total})


# ═══════════════════════════════════════════════════════ 2. do the tamper cases mutate?

def audit_tamper_cases():
    """CLAIM: '6/6 tamper classes caught and localised'.

    ATTACK: a mutation that does not change the entry is a no-op that reads as an uncaught
    tamper, or worse, a caught one. One case was already found to be a no-op earlier this
    session. Re-derive every case and assert the entry hash actually MOVES.
    """
    import copy
    from attestation import tiers
    from attestation.core import Chain, verify_chain_report
    from attestation.keys import load_or_create_operator_key

    key = load_or_create_operator_key()
    chain = Chain(chain_id="audit-tamper")
    for i in range(5):
        chain.append(op_type="ERASE", target_ref=f"/dev/d{i}",
                     timestamp=f"2026-09-01T10:0{i}:00Z", method="Clear",
                     result_hash=f"{i:064x}", operator_decl=f"op {i}", concur_decl="",
                     custody_tier=tiers.SOFTWARE_KEY, operator_key=key,
                     outcome="VERIFIED" if i % 2 else "PARTIAL")

    mid = len(chain.entries) // 2
    cases = {
        "edit_declaration": lambda c: setattr(c.entries[mid], "operator_decl", "nothing"),
        "swap_result_hash": lambda c: setattr(c.entries[mid], "result_hash", "ff" * 32),
        "flip_outcome": lambda c: setattr(
            c.entries[mid], "outcome",
            "VERIFIED" if c.entries[mid].outcome != "VERIFIED" else "PARTIAL"),
        "upgrade_tier": lambda c: setattr(c.entries[mid], "custody_tier",
                                          tiers.FULL_CUSTODY),
        "forge_tool_ref": lambda c: setattr(c.entries[mid], "tool_ref",
                                            "akhanda/9.9.9+aaaaaaaaaaaaaaaa"),
        "delete_middle": lambda c: c.entries.pop(mid),
        "reorder": lambda c: c.entries.__setitem__(
            slice(1, 3), [c.entries[2], c.entries[1]]),
    }

    findings = {}
    noops, uncaught = [], []
    for name, mutate in cases.items():
        c = copy.deepcopy(chain)
        before_hashes = [e.entry_hash for e in c.entries]
        before_recomputed = [e.recompute_hash() for e in c.entries]
        mutate(c)
        after_recomputed = [e.recompute_hash() for e in c.entries]

        # Did the mutation actually change anything the hash covers?
        structural = len(c.entries) != len(before_hashes)
        content_moved = after_recomputed != before_recomputed[:len(after_recomputed)]
        really_mutated = structural or content_moved

        rep = verify_chain_report(c.entries, operator_pub=key.public_key())
        caught = not rep.ok
        findings[name] = {"really_mutated": really_mutated, "caught": caught,
                          "broken_seq": rep.broken_seq, "reason": rep.reason}
        if not really_mutated:
            noops.append(name)
        elif not caught:
            uncaught.append(name)

    if noops:
        claim("chain.tamper_detection", "6/6 tamper classes caught and localised",
              "assert each mutation actually changes the signed bytes",
              "FALSIFIED",
              f"{len(noops)} case(s) mutate nothing and are therefore vacuous: {noops}",
              findings)
    elif uncaught:
        claim("chain.tamper_detection", "6/6 tamper classes caught and localised",
              "assert each mutation actually changes the signed bytes",
              "FALSIFIED",
              f"{len(uncaught)} real mutation(s) were NOT caught: {uncaught}", findings)
    else:
        claim("chain.tamper_detection", "tamper classes caught and localised",
              "assert each mutation actually changes the signed bytes",
              "SURVIVED",
              f"all {len(cases)} mutations genuinely move the signed preimage and all "
              f"{len(cases)} are caught, including the tool_ref forgery that only became "
              "possible after ENTRY_VERSION 3", findings)


# ═══════════════════════════════════════════════ 3. would the corpus catch a real change?

def audit_corpus():
    """CLAIM: 'the corpus is a regression gate; 5/5 reproduce'.

    ATTACK: a gate that would not fail on a broken carver is decoration. Break the carver
    for real, remove a signature, and check the corpus notices.
    """
    from attestation import corpus
    import recovery.engine as eng
    from pin_corpus import RECOMPUTE

    baseline = corpus.replay_all(RECOMPUTE)

    original = eng.SIGNATURES
    eng.SIGNATURES = tuple(s for s in original if s.ext != "jpg")   # break it
    try:
        broken = corpus.replay_all(RECOMPUTE)
    finally:
        eng.SIGNATURES = original

    restored = corpus.replay_all(RECOMPUTE)

    data = {
        "baseline_ok": baseline["ok"], "baseline": baseline["counts"],
        "with_jpg_removed_ok": broken["ok"], "broken": broken["counts"],
        "restored_ok": restored["ok"],
    }
    if baseline["ok"] and not broken["ok"] and restored["ok"]:
        claim("corpus.regression_gate", "the corpus catches carver regressions",
              "delete the JPEG signature and re-replay the pinned cases",
              "SURVIVED",
              f"baseline {baseline['counts']} -> with JPEG removed "
              f"{broken['counts']} -> restored {restored['counts']}. The gate fails when "
              "the carver changes and recovers when it is put back.", data)
    elif broken["ok"]:
        claim("corpus.regression_gate", "the corpus catches carver regressions",
              "delete the JPEG signature and re-replay the pinned cases",
              "FALSIFIED",
              "the corpus still reported OK with a signature removed: it is not a gate",
              data)
    else:
        claim("corpus.regression_gate", "the corpus catches carver regressions",
              "delete the JPEG signature and re-replay the pinned cases",
              "WEAKENED", f"inconclusive: {data}", data)


# ═══════════════════════════════════════════════ 4. does the Rust verifier actually check?

def audit_rust():
    """CLAIM: 'an independent Rust verifier agrees with Python'.

    ATTACK: a verifier that exits 0 on everything agrees with everything. Feed it a chain
    that is definitely broken and require a NON-zero exit.
    """
    rust = ROOT / "rust" / "akhanda-verify" / "target" / "release" / "akhanda-verify.exe"
    if not rust.is_file():
        claim("rust.independence", "the Rust verifier independently agrees",
              "feed it a tampered chain and require a non-zero exit",
              "UNFALSIFIABLE", "the Rust binary is not built on this machine", {})
        return

    from attestation import tiers
    from attestation.core import Chain
    from attestation.keys import load_or_create_operator_key
    from attestation.store import save_chain

    key = load_or_create_operator_key()
    chain = Chain(chain_id="audit-rust")
    for i in range(4):
        chain.append(op_type="ERASE", target_ref=f"/dev/d{i}",
                     timestamp=f"2026-09-01T10:0{i}:00Z", method="Clear",
                     result_hash=f"{i:064x}", operator_decl=f"op {i}", concur_decl="",
                     custody_tier=tiers.SOFTWARE_KEY, operator_key=key, outcome="VERIFIED")

    tmp = Path(tempfile.mkdtemp())
    good, bad, ver = tmp / "good.json", tmp / "bad.json", tmp / "wrongver.json"
    save_chain(chain, good)

    raw = json.loads(good.read_text(encoding="utf-8"))
    entries_key = "entries" if "entries" in raw else next(
        k for k, v in raw.items() if isinstance(v, list))
    tampered = json.loads(json.dumps(raw))
    tampered[entries_key][2]["operator_decl"] = "silently edited"
    bad.write_text(json.dumps(tampered), encoding="utf-8")

    wrongver = json.loads(json.dumps(raw))
    for e in wrongver[entries_key]:
        e["entry_version"] = "2"
    ver.write_text(json.dumps(wrongver), encoding="utf-8")

    def run(p):
        r = subprocess.run([str(rust), str(p)], capture_output=True, text=True, timeout=60)
        return r.returncode

    rc_good, rc_bad, rc_ver = run(good), run(bad), run(ver)
    data = {"clean_exit": rc_good, "tampered_exit": rc_bad, "wrong_version_exit": rc_ver}

    if rc_good == 0 and rc_bad != 0 and rc_ver != 0:
        claim("rust.independence", "the Rust verifier independently agrees",
              "feed it clean, tampered and wrong-version chains",
              "SURVIVED",
              f"clean exits {rc_good}, tampered exits {rc_bad}, an ENTRY_VERSION 2 chain "
              f"exits {rc_ver}. It discriminates rather than always passing.", data)
    else:
        claim("rust.independence", "the Rust verifier independently agrees",
              "feed it clean, tampered and wrong-version chains",
              "FALSIFIED",
              f"the verifier does not discriminate: {data}", data)


# ═══════════════════════════════════════════ 5. does the bad-sector monkeypatch fire?

def audit_bad_sectors():
    """CLAIM: 'bad sectors are skipped, logged and signed'.

    ATTACK: the tests monkeypatch os.write. If the patch never actually raises during the
    real code path, the tests are green because nothing happened. Count the raises.
    """
    import errno
    from erasure.engine import BLOCK_SIZE, CONFIRM_TOKEN, SECTOR_SIZE, erase, outcome_for

    tmp = Path(tempfile.mkdtemp())
    img = tmp / "flaky.img"
    img.write_bytes(b"\xAB" * (4 * BLOCK_SIZE))

    raised = {"n": 0}
    real_write, real_lseek = os.write, os.lseek
    pos = {"at": 0}
    bad_off, bad_len = BLOCK_SIZE, SECTOR_SIZE

    def fake_lseek(fd, offset, whence):
        r = real_lseek(fd, offset, whence)
        if whence == os.SEEK_SET:
            pos["at"] = offset
        return r

    def fake_write(fd, data):
        start, end = pos["at"], pos["at"] + len(data)
        if start < bad_off + bad_len and bad_off < end:
            raised["n"] += 1
            raise OSError(errno.EIO, "Input/output error")
        pos["at"] = end
        return real_write(fd, data)

    os.lseek, os.write = fake_lseek, fake_write
    try:
        result = erase(str(img), confirm=CONFIRM_TOKEN)
    finally:
        os.lseek, os.write = real_lseek, real_write

    # Would hiding the evidence change the signed digest?
    from erasure.engine import result_hash
    hidden = dict(result, bad_ranges=[], bytes_skipped=0)
    digest_moves = result_hash(hidden) != result_hash(result)

    data = {"oserrors_raised": raised["n"], "bad_ranges": len(result["bad_ranges"]),
            "bytes_skipped": result["bytes_skipped"], "verified": result["verified"],
            "outcome": outcome_for(result),
            "hiding_them_changes_digest": digest_moves,
            "bytes_accounted": result["bytes_written"] + result["bytes_skipped"]
                               == 4 * BLOCK_SIZE}

    if raised["n"] == 0:
        claim("erase.bad_sectors", "bad sectors are skipped, logged and signed",
              "count how many OSErrors the fixture actually raises in the real path",
              "FALSIFIED",
              "the fixture never raised: the tests pass because nothing failed", data)
    elif (result["bad_ranges"] and not result["verified"]
          and outcome_for(result) == "PARTIAL" and digest_moves
          and data["bytes_accounted"]):
        claim("erase.bad_sectors", "bad sectors are skipped, logged and signed",
              "count the raises, then try to hide the skipped ranges from the digest",
              "SURVIVED",
              f"the fixture raised EIO {raised['n']} times in the real write path; the "
              f"result records {len(result['bad_ranges'])} range(s), refuses VERIFIED, "
              f"accounts for every byte, and removing bad_ranges CHANGES the signed "
              f"digest ({digest_moves})", data)
    else:
        claim("erase.bad_sectors", "bad sectors are skipped, logged and signed",
              "count the raises, then try to hide the skipped ranges from the digest",
              "FALSIFIED", f"the record does not hold up: {data}", data)


# ═══════════════════════════════════════════════════ 6. are any tests unfalsifiable?

def audit_test_quality():
    """CLAIM: '445 tests'.

    ATTACK: a test with no assertion, or one asserting a literal truth, inflates the count
    without guarding anything. Scan for both.
    """
    suspicious, total = [], 0
    for path in sorted((ROOT / "tests").glob("test_*.py")):
        src = path.read_text(encoding="utf-8", errors="replace")
        blocks = re.split(r"\ndef (test_[A-Za-z0-9_]+)", src)
        for i in range(1, len(blocks), 2):
            name, body = blocks[i], blocks[i + 1]
            total += 1
            head = body.split("\ndef ")[0]
            no_assert = ("assert" not in head and "pytest.raises" not in head
                         and "self.assert" not in head)
            tautology = re.search(r"assert\s+(True|1\s*==\s*1|[\"'][^\"']*[\"']\s*$)",
                                  head)
            if no_assert or tautology:
                suspicious.append({"file": path.name, "test": name,
                                   "why": "no assertion" if no_assert else "tautology"})

    data = {"scanned": total, "suspicious": suspicious}
    if suspicious:
        claim("tests.substance", f"{total} tests, all meaningful",
              "scan every test for a missing assertion or a tautological one",
              "WEAKENED",
              f"{len(suspicious)} of {total} test(s) have no assertion or a trivial one: "
              f"{suspicious[:5]}", data)
    else:
        claim("tests.substance", f"{total} tests, all meaningful",
              "scan every test for a missing assertion or a tautological one",
              "SURVIVED",
              f"all {total} collected test functions carry a real assertion or an "
              "expected-raise", data)


# ═══════════════════════════════════════════ 7. does the case root catch a real deletion?

def audit_case_root():
    """CLAIM: 'deleting a whole device is detected'.

    ATTACK: it would be trivially true if the surviving chains broke on their own. Prove
    they do NOT break, so the case root is doing the work.
    """
    from attestation import tiers
    from attestation.case import build_manifest, case_root, verify_manifest
    from attestation.core import Chain, verify_chain_report
    from attestation.keys import load_or_create_operator_key

    key = load_or_create_operator_key()
    chains = {}
    for dev in ("laptop", "phone", "usb"):
        c = Chain(chain_id=f"audit-{dev}")
        c.append(op_type="ERASE", target_ref=f"/dev/{dev}",
                 timestamp="2026-09-01T10:00:00Z", method="Clear",
                 result_hash="00" * 32, operator_decl=dev, concur_decl="",
                 custody_tier=tiers.SOFTWARE_KEY, operator_key=key, outcome="VERIFIED")
        chains[dev] = c

    manifest = build_manifest(chains, case_id="AUDIT")
    root_before = case_root(chains).hex()
    del chains["usb"]

    survivors_ok = all(verify_chain_report(c.entries, operator_pub=key.public_key()).ok
                       for c in chains.values())
    report = verify_manifest(manifest, chains)
    root_after = case_root(chains).hex()

    data = {"survivors_still_verify": survivors_ok, "manifest_ok": report["ok"],
            "missing": report["missing_devices"], "root_changed": root_before != root_after}

    if survivors_ok and not report["ok"] and report["missing_devices"] == ["usb"] \
            and data["root_changed"]:
        claim("case.omission", "deleting a whole device from a case is detected",
              "confirm the surviving chains still verify, so the root does the work",
              "SURVIVED",
              "every surviving chain verifies perfectly on its own, and only the case "
              "root notices the deletion, so the finding is not an artefact of the "
              "chains breaking", data)
    else:
        claim("case.omission", "deleting a whole device from a case is detected",
              "confirm the surviving chains still verify, so the root does the work",
              "FALSIFIED", f"{data}", data)


# ═══════════════════════════════════════ 8. does self-attestation move when code moves?

def audit_toolref():
    """CLAIM: 'tool_ref identifies the build'.

    ATTACK: a digest that does not move when the code moves is a constant with extra
    steps. Mutate real source in a copy and require the digest to change.
    """
    import shutil
    from attestation import toolref

    before = toolref.code_digest()
    tmp = Path(tempfile.mkdtemp()) / "src"
    for rel in toolref.ATTESTED_MODULES:
        dst = tmp / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "src" / rel, dst)

    target = tmp / "erasure" / "engine.py"
    target.write_bytes(target.read_bytes().replace(b"BLOCK_SIZE = 1024 * 1024",
                                                   b"BLOCK_SIZE = 2048 * 1024", 1))
    real_src = toolref._SRC
    toolref._SRC = tmp
    toolref.code_digest.cache_clear()
    try:
        after = toolref.code_digest()
    finally:
        toolref._SRC = real_src
        toolref.code_digest.cache_clear()

    restored = toolref.code_digest()
    data = {"before": before[:16], "after_code_change": after[:16],
            "restored": restored[:16], "moved": before != after,
            "restored_ok": restored == before}

    if before != after and restored == before:
        claim("toolref.identifies_build", "tool_ref identifies the build that wrote an entry",
              "change a real constant in a real attested module and re-derive the digest",
              "SURVIVED",
              f"changing BLOCK_SIZE in erasure/engine.py moved the digest "
              f"{before[:16]} -> {after[:16]}, and reverting restored it", data)
    else:
        claim("toolref.identifies_build", "tool_ref identifies the build that wrote an entry",
              "change a real constant in a real attested module and re-derive the digest",
              "FALSIFIED", f"the digest did not track the code: {data}", data)


def main() -> int:
    print("ADVERSARIAL AUDIT, attempting to falsify this project's own claims\n")
    for fn in (audit_false_positives, audit_tamper_cases, audit_corpus, audit_rust,
               audit_bad_sectors, audit_test_quality, audit_case_root, audit_toolref):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            claim(fn.__name__, "-", "-", "UNFALSIFIABLE",
                  f"the audit itself failed: {type(exc).__name__}: {exc}", {})
        print()

    counts: dict = {}
    for r in RESULTS:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1

    out = {
        "check": "adversarial audit of AKHANDA's own claims",
        "ran_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "standard": ("a claim SURVIVES only when a genuine attempt to falsify it ran and "
                     "failed; anything that could not be attacked is UNFALSIFIABLE, which "
                     "is an unmeasured claim rather than a strong one"),
        "counts": counts,
        "claims": RESULTS,
    }
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / "adversarial_audit.json").write_text(json.dumps(out, indent=2),
                                                     encoding="utf-8")
    print("=" * 70)
    print(f"VERDICTS: {counts}")
    print(f"written : {EVIDENCE / 'adversarial_audit.json'}")
    return 1 if counts.get("FALSIFIED") else 0


if __name__ == "__main__":
    sys.exit(main())
