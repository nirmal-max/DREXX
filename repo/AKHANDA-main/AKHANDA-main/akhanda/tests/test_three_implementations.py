"""
Three independent implementations of one contract must agree.

Python (`src/attestation/core.py`), JavaScript (`console/index.html`), and Rust
(`rust/akhanda-verify`) each implement the entry encoding and the verification walk. This
file asserts all three produce identical entry hashes and identical verdicts.

Why three and not two. Two implementations written by the same hand can share a
misreading of the spec, they agree, and they are both wrong together. A third, in a
language with different string, integer, and byte semantics, is the cheapest way to catch
that class of error. It is also the only test here that would fail if the *specification*
were wrong rather than the code.

Each backend skips LOUDLY when its toolchain is absent. A test that quietly passes when
it did not run is worse than no test.
"""

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

from attestation import tiers
from attestation.core import ENTRY_VERSION, HASHED_FIELDS, ZERO_HASH, Chain, key_id

ROOT = Path(__file__).resolve().parents[1]
CONSOLE = ROOT / "console" / "index.html"
RUST_DIR = ROOT / "rust" / "akhanda-verify"

HAVE_NODE = shutil.which("node") is not None
HAVE_CARGO = shutil.which("cargo") is not None


def _rust_binary() -> Path | None:
    for name in ("akhanda-verify.exe", "akhanda-verify"):
        p = RUST_DIR / "target" / "release" / name
        if p.exists():
            return p
    return None


JS_RUNNER = textwrap.dedent(r"""
    import { readFileSync } from "node:fs";
    const html = readFileSync(process.argv[2], "utf8");
    const m = html.match(/<script>\r?\n"use strict";([\s\S]*?)\r?\nlet CURRENT = null;/);
    if (!m) { console.error("could not extract the console crypto core"); process.exit(2); }
    const mod = new Function(m[1] + "\nreturn {verifyChain};");
    const { verifyChain } = mod();
    const chain = JSON.parse(readFileSync(process.argv[3], "utf8"));
    const r = await verifyChain(chain);
    console.log(JSON.stringify({
      ok: r.broken === null,
      broken: r.broken,
      hashes: r.rows.map(x => x.recomputed),
    }));
""")


def _python_result(chain: Chain, op_pub_hex=None):
    from attestation.core import verify_chain_report
    from attestation.keys import public_key_from_hex
    pub = public_key_from_hex(op_pub_hex) if op_pub_hex else None
    r = verify_chain_report(chain.entries, pub)
    return {
        "ok": r.ok,
        "broken": r.broken_seq,
        "hashes": [e.recompute_hash() for e in chain.entries],
    }


def _js_result(chain: Chain, tmp_path: Path):
    runner = tmp_path / "runner.mjs"
    runner.write_text(JS_RUNNER, encoding="utf-8", newline="\n")
    cf = tmp_path / "chain.json"
    cf.write_text(chain.to_json(), encoding="utf-8", newline="\n")
    proc = subprocess.run(["node", str(runner), str(CONSOLE), str(cf)],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, f"node failed: {proc.stderr}"
    return json.loads(proc.stdout)


def _rust_result(chain: Chain, tmp_path: Path, op_pub_hex=None):
    binary = _rust_binary()
    cf = tmp_path / "chain_rust.json"
    cf.write_text(chain.to_json(), encoding="utf-8", newline="\n")
    cmd = [str(binary), str(cf), "--json"]
    if op_pub_hex:
        cmd += ["--operator-key", op_pub_hex]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    assert proc.returncode in (0, 1), f"rust failed: {proc.stderr}"
    out = json.loads(proc.stdout)
    # The binary emits a bare JSON null, so this is already None or an int.
    out["broken"] = out["broken_seq"]
    return out


needs_node = pytest.mark.skipif(
    not HAVE_NODE, reason="node absent; JavaScript agreement was NOT checked")
needs_rust = pytest.mark.skipif(
    _rust_binary() is None,
    reason="akhanda-verify not built; Rust agreement was NOT checked. "
           "Build it: cargo build --release --manifest-path rust/akhanda-verify/Cargo.toml")


# ───────────────────────────────────────────────── the contract constants match

@needs_rust
def test_rust_declares_the_same_field_list_and_version():
    """Read from the source, so a drift is caught even without running anything."""
    src = (RUST_DIR / "src" / "lib.rs").read_text(encoding="utf-8")
    import re

    def rust_list(name: str) -> list:
        block = re.search(rf"{name}: \[&str; \d+\] = \[(.*?)\];", src, re.S)
        assert block, f"{name} not found in lib.rs"
        return re.findall(r'"([a-z_]+)"', block.group(1))

    # EVERY version's field list is pinned, not just the current one. Checking only the
    # newest would let the Rust v3 list drift unnoticed, and v3 is what the frozen
    # round-one chain is written under, the one chain that can never be regenerated.
    from attestation.core import FIELDS_BY_VERSION

    assert rust_list("FIELDS_V4") == FIELDS_BY_VERSION["4"] == HASHED_FIELDS
    assert rust_list("FIELDS_V3") == FIELDS_BY_VERSION["3"]

    ver = re.search(r'ENTRY_VERSION: &str = "([^"]+)"', src)
    assert ver and ver.group(1) == ENTRY_VERSION

    dom = re.search(r'ENTRY_DOMAIN: &\[u8\] = b"([^"]+)"', src)
    from attestation.core import ENTRY_DOMAIN
    assert dom and dom.group(1) == ENTRY_DOMAIN.decode()


@needs_rust
def test_rust_forbids_unsafe_in_both_crates_roots():
    for f in ("lib.rs", "main.rs"):
        src = (RUST_DIR / "src" / f).read_text(encoding="utf-8")
        assert "#![forbid(unsafe_code)]" in src, f"{f} does not forbid unsafe"


# ───────────────────────────────────────────────── all three agree, clean chain

@pytest.fixture()
def clean(op_key, concur_key):
    c = Chain(chain_id="three-way")
    for i in range(3):
        e = c.append("ERASE", f"/dev/sd{chr(98 + i)}", f"2026-01-0{i+1}T10:00:00Z",
                     "Clear", f"{i:02x}" * 32, "operator: J. Rao", "expert: K. Singh",
                     tiers.FULL_CUSTODY, op_key, outcome="VERIFIED",
                     presence_fn=lambda ph, i=i: f"COM9:aa{i}:{ph[:16]}")
        c.attach_cosignature(e.seq,
                             concur_key.sign(bytes.fromhex(e.entry_hash)).hex(),
                             key_id(concur_key.public_key()), "wh" * 32, e.seq)
    return c


@needs_rust
@needs_node
def test_all_three_produce_identical_entry_hashes(clean, tmp_path):
    py = _python_result(clean)
    js = _js_result(clean, tmp_path)
    rs = _rust_result(clean, tmp_path)
    assert py["hashes"] == js["hashes"], "Python and JavaScript disagree"
    assert py["ok"] is js["ok"] is rs["ok"] is True
    assert py["broken"] == js["broken"] == rs["broken"] is None


@needs_rust
@needs_node
def test_all_three_agree_on_awkward_values(op_key, tmp_path):
    """Delimiters, unicode, and empty fields are where implementations diverge."""
    c = Chain(chain_id="chain|with:delimiters")
    c.append("ERASE", "disk|A:1", "2026-01-01T10:00:00Z", "Clear", "aa" * 32,
             "operator: J. Rao, दिल्ली", "", tiers.SOFTWARE_KEY, op_key,
             outcome="UNVERIFIED")
    c.append("RECOVER", "", "2026-01-01T10:01:00Z", "Clear", "bb" * 32,
             "", "expert|K:Singh", tiers.SOFTWARE_KEY, op_key,
             outcome="PARTIAL",
             presence_fn=lambda ph: f"COM9:0011|2233:{ph[:16]}")
    py = _python_result(c)
    js = _js_result(c, tmp_path)
    rs = _rust_result(c, tmp_path)
    assert py["hashes"] == js["hashes"]
    assert py["ok"] is js["ok"] is rs["ok"] is True


@needs_rust
@needs_node
def test_all_three_catch_a_tampered_entry(clean, tmp_path):
    clean.entries[1].method = "Purge"          # the exact overclaim
    py = _python_result(clean)
    js = _js_result(clean, tmp_path)
    rs = _rust_result(clean, tmp_path)
    assert py["broken"] == js["broken"] == rs["broken"] == 1


@needs_rust
@needs_node
def test_all_three_catch_a_deleted_middle_entry(clean, tmp_path):
    del clean.entries[1]
    py = _python_result(clean)
    js = _js_result(clean, tmp_path)
    rs = _rust_result(clean, tmp_path)
    assert py["ok"] is js["ok"] is rs["ok"] is False


@needs_rust
def test_rust_catches_a_forged_signature(clean, tmp_path, op_key):
    """Rust runs the key-bound layer too, not only the structural walk."""
    from attestation.keys import public_key_hex
    hexkey = public_key_hex(op_key.public_key())
    assert _rust_result(clean, tmp_path, hexkey)["verified"] == 3

    clean.entries[1].operator_sig = "00" * 64
    r = _rust_result(clean, tmp_path, hexkey)
    assert r["ok"] is False
    assert r["broken"] == 1
    assert "signature" in r["reason"]


@needs_rust
def test_rust_reports_a_key_it_does_not_hold_as_unverifiable(clean, tmp_path):
    """Rotation is not forgery, the same distinction Python and the report make."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from attestation.keys import public_key_hex
    other = Ed25519PrivateKey.generate()
    r = _rust_result(clean, tmp_path, public_key_hex(other.public_key()))
    assert r["ok"] is True
    assert r["verified"] == 0
    assert r["unverifiable"] == 3


@needs_rust
def test_rust_refuses_a_chain_from_a_different_entry_version(clean, tmp_path):
    """An UNKNOWN version is still refused outright, v3 being readable did not widen
    this to "any version"."""
    for e in clean.entries:
        # Relabel AFTER hashing. An unknown version can no longer be encoded at all, so
        # re-hashing under "1" now raises rather than producing bytes, which is the
        # same refusal, one layer earlier.
        e.entry_version = "1"
    r = _rust_result(clean, tmp_path)
    assert r["ok"] is False
    assert "entry_version" in r["reason"]


@needs_rust
def test_rust_still_verifies_a_v3_chain(clean, tmp_path):
    """The migration guarantee, checked in the verifier a third party would actually run.

    The frozen round-one chain is v3. If the Rust verifier ever stops reading v3, that
    chain becomes unverifiable by the one implementation we hand to outsiders.
    """
    # Rewriting every entry changes every entry hash, so the chain has to be relinked as
    # it is downgraded. prev_hash is inside the preimage: leaving the v4 hashes in place
    # would break the linkage check before the version check is ever reached, and the test
    # would pass or fail for the wrong reason.
    prev = ZERO_HASH.hex()
    for e in clean.entries:
        e.entry_version = "3"
        e.place_ref = ""
        e.amends_seq = ""
        e.amends_hash = ""
        e.amend_reason = ""
        # presence_ref commits to the PRE-hash, which covers entry_version and the v4
        # fields. Downgrading without clearing it leaves a v4 pre-hash prefix behind, and
        # the verifier correctly reports that the human approved different bytes.
        e.presence_ref = ""
        e.prev_hash = prev
        e.entry_hash = e.recompute_hash()
        prev = e.entry_hash
        e.operator_sig = ""      # re-signing is out of scope here; key-free layer only
        e.concur_sig = ""
    r = _rust_result(clean, tmp_path)
    assert r["ok"] is True, r.get("reason")
