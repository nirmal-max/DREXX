"""
Cross-implementation agreement: the Python encoder and the browser encoder must produce
identical entry hashes for the same entry.

Why this is the strongest test in the suite. Every other test checks the implementation
against itself, the same author, the same assumptions, the same blind spots. This one
runs the console's JavaScript, extracted from the actual page that ships, against chains
built by Python, and compares digests. A misread of the length-prefix rule on either side
shows up here and nowhere else.

Skipped when node is unavailable, and the skip says so rather than passing silently, a
test that quietly passes when it did not run is worse than no test.
"""

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

from attestation import tiers
from attestation.core import Chain

ROOT = Path(__file__).resolve().parents[1]
CONSOLE = ROOT / "console" / "index.html"

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None,
    reason="node is not installed; cross-implementation agreement was NOT checked",
)

RUNNER = textwrap.dedent("""
    import { readFileSync } from "node:fs";
    const html = readFileSync(process.argv[2], "utf8");
    const m = html.match(/<script>\\n"use strict";([\\s\\S]*?)\\nlet CURRENT = null;/);
    if (!m) { console.error("could not extract the console crypto core"); process.exit(2); }
    const mod = new Function(m[1] + "\\nreturn {verifyChain};");
    const { verifyChain } = mod();
    const chain = JSON.parse(readFileSync(process.argv[3], "utf8"));
    const r = await verifyChain(chain);
    console.log(JSON.stringify({
      broken: r.broken,
      hashes: r.rows.map(x => x.recomputed),
      problems: r.rows.map(x => x.problems),
    }));
""")


def _run_js(chain_json: str, tmp_path: Path) -> dict:
    runner = tmp_path / "runner.mjs"
    runner.write_text(RUNNER, encoding="utf-8")
    chain_file = tmp_path / "chain.json"
    chain_file.write_text(chain_json, encoding="utf-8")
    proc = subprocess.run(
        ["node", str(runner), str(CONSOLE), str(chain_file)],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, f"node failed: {proc.stderr}"
    return json.loads(proc.stdout)


def test_javascript_recomputes_the_same_entry_hashes(sample_chain, tmp_path):
    out = _run_js(sample_chain.to_json(), tmp_path)
    assert out["hashes"] == [e.entry_hash for e in sample_chain.entries]
    assert out["broken"] is None


def test_javascript_agrees_on_awkward_field_values(op_key, tmp_path):
    """Delimiters, unicode, and empty fields are where two encoders diverge."""
    c = Chain(chain_id="chain|with:delimiters")
    c.append("ERASE", "disk|A:1", "2026-01-01T10:00:00Z", "Clear", "aa" * 32,
             "operator: J. Rao, दिल्ली", "", tiers.SOFTWARE_KEY, op_key,
             presence_ref="")
    c.append("RECOVER", "", "2026-01-01T10:01:00Z", "Clear", "bb" * 32,
             "", "expert|K:Singh", tiers.SOFTWARE_KEY, op_key,
             presence_fn=lambda ph: f"COM3:0011|2233:{ph[:16]}")
    out = _run_js(c.to_json(), tmp_path)
    assert out["hashes"] == [e.entry_hash for e in c.entries]
    assert out["broken"] is None


def test_javascript_catches_a_tampered_entry(sample_chain, tmp_path):
    sample_chain.entries[1].result_hash = "de" * 32
    out = _run_js(sample_chain.to_json(), tmp_path)
    assert out["broken"] == 1
    assert "content altered: hash mismatch" in out["problems"][1]


def test_javascript_catches_a_deleted_middle_entry(sample_chain, tmp_path):
    del sample_chain.entries[1]
    out = _run_js(sample_chain.to_json(), tmp_path)
    assert out["broken"] is not None
