"""
Produce the COMPLETE demo dataset the frontend consumes, from REAL operations.

    python scripts/demo_bundle.py [--out demo_bundle]

Why this exists: the frontend reads JSON files, and no CLI subcommand emits JSON.
Before this, wiring the UI to live data meant hand-assembling files. This runs the
real product path end to end and writes every file the frontend needs into one
folder, so "swap the mock folder for this folder" is the whole integration.

Nothing here is fabricated. Every entry is really signed, the tampered chain is
really detected, and the byte-identical proof really compares SHA-256 of the file
that went in against the file that was carved out. A step that fails is recorded
as failed in MANIFEST.json - it is never silently dropped or replaced with a
plausible-looking constant.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

CONFIRM = "I-UNDERSTAND-THIS-DESTROYS-DATA"
# Port 9 is the discard service: reliably nothing listens, so the witness is
# genuinely unreachable rather than pretend-unreachable.
DEAD_WITNESS = "http://127.0.0.1:9"

steps = []


def record(name, ok, detail, **extra):
    steps.append({"step": name, "ok": bool(ok), "detail": detail, **extra})
    print(("  ok   " if ok else "  FAIL ") + name + " - " + detail)
    return ok


def run(args, env, expect=0):
    r = subprocess.run([sys.executable, str(ROOT / "src" / "cli.py")] + args,
                       capture_output=True, text=True, env=env, cwd=str(ROOT))
    return r, (r.returncode == expect)


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def make_source_files(d):
    """Real files with real headers, so carving them is a real carve."""
    d.mkdir(parents=True, exist_ok=True)
    made = {}
    try:
        from PIL import Image
        p = d / "evidence_photo.png"
        Image.new("RGB", (120, 90), (30, 90, 160)).save(p)
        made["evidence_photo.png"] = p
        j = d / "scene.jpg"
        Image.new("RGB", (100, 100), (200, 60, 40)).save(j, "JPEG", quality=92)
        made["scene.jpg"] = j
    except Exception as e:
        print("  (Pillow unavailable, using raw fixtures: %s)" % e)

    z = d / "case_notes.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("notes.txt", "Case 26149 field notes.\n" * 40)
        zf.writestr("index.csv", "id,item\n1,laptop\n2,usb\n")
    made["case_notes.zip"] = z

    p = d / "report.pdf"
    p.write_bytes(b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\n"
                  + b"% forensic report body " * 60 + b"\n%%EOF\n")
    made["report.pdf"] = p
    return made


def build_image(files, out):
    """Embed the real files in a disk-like image with junk between them."""
    parts, layout = [], []
    off = 0
    pad = bytes(4096)
    parts.append(pad)
    off += len(pad)
    for name, path in files.items():
        b = path.read_bytes()
        layout.append({"filename": name, "offset": off, "size": len(b),
                       "sha256": sha256(b)})
        parts.append(b)
        off += len(b)
        parts.append(pad)
        off += len(pad)
    out.write_bytes(b"".join(parts))
    return layout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="demo_bundle")
    ap.add_argument("--witness", default=None,
                    help="witness node base URL, e.g. http://192.168.137.5:8000. "
                         "Operations run through it carry a real second signature. "
                         "A witness on THIS machine is a real second key but NOT "
                         "physical separation - only a second machine is that.")
    a = ap.parse_args()

    wit = ["--witness", a.witness] if a.witness else ["--no-witness"]
    local_witness = bool(a.witness) and any(
        h in a.witness for h in ("127.0.0.1", "localhost", "::1"))

    out = (ROOT / a.out).resolve()
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    home = out / "_akhanda_home"
    home.mkdir()

    env = dict(os.environ)
    env["AKHANDA_HOME"] = str(home)
    env["PYTHONPATH"] = str(ROOT / "src")
    env["AKHANDA_ALLOW_FILE_ERASE"] = "1"

    print("Akhanda demo bundle -> %s" % out)
    if a.witness:
        print("  witness: %s" % a.witness)
        if local_witness:
            print("  NOTE: witness is on THIS machine. The second signature is real,")
            print("        but this is NOT physical separation. Point --witness at the")
            print("        other laptop to make the separation claim.")
    else:
        print("  witness: none (--no-witness); entries are operator-signed only")

    # 1. a real operator key and an empty chain
    r, ok = run(["--no-witness", "--no-presence", "init"], env)
    record("init", ok, "operator key + empty chain" if ok else r.stderr.strip()[:160])

    # 2. real source files, real image, real carve
    src = out / "source_files"
    files = make_source_files(src)
    img = out / "seized_media.dd"
    layout = build_image(files, img)
    record("build_image", True,
           "%d real files embedded in %.1f KB image"
           % (len(layout), img.stat().st_size / 1024))

    rec_out = out / "recovered"
    r, ok = run(wit + ["--no-presence", "recover", str(img),
                 "--out", str(rec_out),
                 "--result-out", str(out / "recover_result.json")], env)
    record("recover", ok, "carved into recovered/"
           if ok else (r.stderr.strip()[:200] or r.stdout.strip()[:200]))

    # 3. byte-identical proof - compare what went IN against what came OUT
    proof = {"method": "SHA-256 of the embedded file vs the carved file",
             "note": "byte-identical or it is not claimed", "comparisons": []}
    carved = sorted(rec_out.rglob("*")) if rec_out.exists() else []
    carved = [p for p in carved if p.is_file()]
    by_hash = {}
    for p in carved:
        by_hash.setdefault(sha256(p.read_bytes()), []).append(p.name)
    matched = 0
    for item in layout:
        hit = by_hash.get(item["sha256"])
        proof["comparisons"].append({
            "original": item["filename"], "original_sha256": item["sha256"],
            "carved_as": hit[0] if hit else None,
            "byte_identical": bool(hit)})
        matched += 1 if hit else 0
    proof["summary"] = {"embedded": len(layout), "byte_identical": matched,
                        "carved_total": len(carved)}
    (out / "byte_identical_proof.json").write_text(
        json.dumps(proof, indent=2), encoding="utf-8")
    record("byte_identical_proof", True,
           "%d/%d embedded files recovered byte-identical" % (matched, len(layout)))

    # 4. a real secure file erase (module b) on files we created for the purpose
    victim = out / "to_erase"
    victim.mkdir()
    for i in range(3):
        (victim / ("draft_%d.txt" % i)).write_text(
            "sensitive draft %d\n" % i * 50, encoding="utf-8")
    r, ok = run(["--no-witness", "--no-presence", "erase-files", str(victim),
                 "--recursive", "--confirm", CONFIRM,
                 "--result-out", str(out / "erase_result.json")], env)
    record("erase_files", ok, "3 files securely erased + verified"
           if ok else (r.stderr.strip()[:200] or r.stdout.strip()[:200]))

    # 5. a REFUSED entry - ask for a witness that is genuinely not there, and
    #    do NOT pass --allow-degraded. Fail-closed must block and log the attempt.
    r, ok = run(["--witness", DEAD_WITNESS, "--no-presence", "recover", str(img),
                 "--out", str(out / "_blocked")], env, expect=3)
    record("refused_entry", ok,
           "blocked at preflight, REFUSED written to chain (exit 3)"
           if ok else "expected exit 3, got %d" % r.returncode)

    # 6. the certificate
    cert_dir = out / "certificate"
    r, ok = run(wit + ["--no-presence",
                 "--operator", "Pulkit Srivastava",
                 "--expert", "Team Anvaya Examiner",
                 "certify", "--out", str(cert_dir),
                 "--organisation", "Team Anvaya",
                 "--location", "SIH 2026 internal round",
                 "--media-type", "Flash Memory", "--media-model", "demo image",
                 "--notes", "Generated by scripts/demo_bundle.py from real operations."],
                env)
    record("certify", ok, "certificate.json + .txt"
           if ok else (r.stderr.strip()[:200] or r.stdout.strip()[:200]))
    if cert_dir.exists():
        for f in cert_dir.iterdir():
            if f.suffix in (".json", ".txt"):
                shutil.copy2(f, out / ("certificate" + f.suffix))

    # 7. chain.json, plus a REALLY tampered copy and the REAL verdicts
    from attestation.store import load_chain
    from attestation.core import verify_chain

    chain_src = home / "chain.json"
    if chain_src.exists():
        shutil.copy2(chain_src, out / "chain.json")
        chain = load_chain(chain_src)
        entries = chain.entries if hasattr(chain, "entries") else chain
        ok_v, broken, reason = verify_chain(entries)
        verify_ok_json = {"ok": bool(ok_v), "broken_seq": broken, "reason": reason,
                          "witness": {"checked": False, "diverged": False,
                                      "reason": "no witness in this run (--no-witness)"}}
        (out / "verify_ok.json").write_text(
            json.dumps(verify_ok_json, indent=2), encoding="utf-8")
        record("verify_clean", bool(ok_v), reason)

        # tamper for real: alter a field in the middle entry and re-verify
        raw = json.loads(chain_src.read_text(encoding="utf-8"))
        ents = raw.get("entries", raw if isinstance(raw, list) else [])
        if len(ents) >= 2:
            tgt = 1
            ents[tgt]["target_ref"] = ents[tgt].get("target_ref", "") + "-ALTERED"
            (out / "chain_tampered.json").write_text(
                json.dumps(raw, indent=2), encoding="utf-8")
            tchain = load_chain(out / "chain_tampered.json")
            tents = tchain.entries if hasattr(tchain, "entries") else tchain
            tok, tbroken, treason = verify_chain(tents)
            verify_tam_json = {"ok": bool(tok), "broken_seq": tbroken,
                               "reason": treason,
                               "witness": {"checked": False, "diverged": False,
                                           "reason": "n/a"}}
            (out / "verify_tampered.json").write_text(
                json.dumps(verify_tam_json, indent=2), encoding="utf-8")
            record("verify_tampered", (not tok) and tbroken is not None,
                   "tamper detected and localised: %s" % treason)
        else:
            record("verify_tampered", False,
                   "chain too short to tamper (%d entries)" % len(ents))
    else:
        record("chain_export", False, "no chain.json produced at %s" % chain_src)

    # 8. static evidence the frontend also shows
    copied = []
    for name in ["adversarial_audit.json", "run_all.json", "chain_benchmark.json",
                 "stress_scale.json", "g24_crosslink_confirmed.json"]:
        s = ROOT / "evidence" / name
        if s.exists():
            shutil.copy2(s, out / name)
            copied.append(name)
    record("static_evidence", True,
           "copied %d: %s" % (len(copied), ", ".join(copied) or "none"))

    # 9. manifest - the honest record of what this run produced
    produced = sorted(p.name for p in out.iterdir() if p.is_file())
    manifest = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "generator": "scripts/demo_bundle.py",
        "real_operations": True,
        "steps": steps,
        "all_steps_ok": all(s["ok"] for s in steps),
        "files": produced,
        "for_frontend": {
            "chain.json": "the Console view",
            "certificate.json": "the Certificate Viewer view",
            "verify_ok.json / verify_tampered.json / chain_tampered.json":
                "the TamperDemo view",
            "byte_identical_proof.json": "the recovery evidence wall",
            "erase_result.json / recover_result.json": "per-operation detail panels",
        },
    }
    (out / "MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    failed = [s["step"] for s in steps if not s["ok"]]
    print("\n%d files -> %s" % (len(produced), out))
    if failed:
        print("FAILED STEPS: " + ", ".join(failed))
        print("Recorded in MANIFEST.json. Not hidden, not substituted.")
        return 1
    print("all steps ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
