"""Supply-chain and transport hardening, from a real scan rather than a checklist.

Every test here corresponds to a finding an actual tool reported against this source:
`bandit -r src/` and `pip-audit`. The findings that were noise are recorded in
evidence/hardening.md with the reason; the ones below were real and are pinned so they
cannot come back.

THE ONE THAT MATTERED. `urlopen` honours every scheme urllib knows, `file://` included.
The witness URL is configuration, so a URL the operator supplies decides what gets opened.
Pointed at `file:///anything`, the client would read a local file and return it as a
witness response -- and the "independent second party" would be a path on the operator's
own disk. That is the failure the witness exists to prevent, reached through the transport
instead of the crypto.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from witness.client import (  # noqa: E402
    ALLOWED_SCHEMES, WitnessTransportRefused, _check_url,
)


# ───────────────────────────────────────── the transport allowlist

@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "file:///C:/Windows/win.ini",
    "ftp://host/witness",
    "data:application/json,{}",
    "gopher://host/1",
])
def test_a_non_http_witness_url_is_refused(url):
    """A witness read from a local file is the operator co-signing their own work."""
    with pytest.raises(WitnessTransportRefused):
        _check_url(url)


@pytest.mark.parametrize("url", [
    "http://192.168.50.1:8000/witness/head",
    "https://witness.lab.local/witness/pubkey",
])
def test_a_real_witness_url_is_allowed(url):
    """The other half. A guard that refuses everything blocks the demo, not the attack."""
    assert _check_url(url) == url


def test_a_url_with_no_host_is_refused():
    """A witness with no host is not a second machine."""
    with pytest.raises(WitnessTransportRefused):
        _check_url("http:///witness/head")


def test_the_allowlist_is_an_allowlist_not_a_blocklist():
    """A blocklist of bad schemes would have to enumerate every scheme urllib grows."""
    assert set(ALLOWED_SCHEMES) == {"http", "https"}


def test_the_refusal_explains_why_rather_than_just_refusing():
    with pytest.raises(WitnessTransportRefused, match="co-signing their own work"):
        _check_url("file:///tmp/fake_witness.json")


# ───────────────────────────────────────── checks that survive -O

def test_the_witness_key_type_check_is_not_an_assert():
    """Python -O strips asserts. This one is the only thing between a wrong key file and
    a witness that signs with it, so it must be a raise."""
    src = (ROOT / "src" / "witness" / "node.py").read_text(encoding="utf-8")
    assert "assert isinstance(key, Ed25519PrivateKey)" not in src
    assert "raise TypeError" in src


def test_no_attested_module_relies_on_assert_for_a_security_check():
    """A broad sweep, not a spot check: asserts anywhere in the signing or guard path
    would vanish under -O and take their protection with them."""
    import re
    offenders = []
    for rel in ("attestation/core.py", "attestation/keys.py", "attestation/policy.py",
                "erasure/engine.py", "witness/node.py", "witness/client.py"):
        text = (ROOT / "src" / rel).read_text(encoding="utf-8")
        for i, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("assert ") and not stripped.startswith("assert_"):
                offenders.append(f"{rel}:{i}  {stripped[:60]}")
    assert not offenders, f"security-path asserts vanish under -O: {offenders}"


# ───────────────────────────────────────── subprocess argv

def test_macos_filesystem_detection_uses_an_absolute_path():
    """A bare "stat" resolves through PATH, and the answer decides whether an erasure is
    recorded VERIFIED or PARTIAL. Not a decision to delegate to the environment."""
    src = (ROOT / "src" / "erasure" / "file_eraser.py").read_text(encoding="utf-8")
    assert '"/usr/bin/stat"' in src
    assert '["stat", "-f"' not in src


def test_no_subprocess_call_uses_a_shell():
    """shell=True turns an argument into a command line. Nothing here needs it."""
    offenders = []
    for path in (ROOT / "src").rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="replace")
        if "shell=True" in text:
            offenders.append(str(path.relative_to(ROOT)))
    assert not offenders, f"shell=True found in {offenders}"


# ───────────────────────────────────────── the scan itself stays clean

def _bandit_available() -> bool:
    try:
        subprocess.run([sys.executable, "-m", "bandit", "--version"],
                       capture_output=True, timeout=60, check=True)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


@pytest.mark.skipif(not _bandit_available(), reason="bandit not installed")
def test_bandit_reports_no_high_severity_findings():
    """The gate. LOW and MEDIUM findings are triaged in evidence/hardening.md; a HIGH one
    is a stop, and this fails rather than letting it be triaged later."""
    import json
    proc = subprocess.run(
        [sys.executable, "-m", "bandit", "-r", str(ROOT / "src"), "-f", "json", "-q"],
        capture_output=True, text=True, timeout=600, check=False)
    report = json.loads(proc.stdout)
    high = [r for r in report["results"] if r["issue_severity"] == "HIGH"]
    assert not high, f"bandit HIGH severity: {[(r['test_id'], r['filename']) for r in high]}"


@pytest.mark.skipif(not _bandit_available(), reason="bandit not installed")
def test_the_medium_findings_are_the_ones_already_triaged():
    """Pins the triage. A NEW medium finding fails here rather than blending into a count
    somebody once decided was acceptable."""
    import json
    proc = subprocess.run(
        [sys.executable, "-m", "bandit", "-r", str(ROOT / "src"), "-f", "json", "-q"],
        capture_output=True, text=True, timeout=600, check=False)
    report = json.loads(proc.stdout)
    medium = {(r["test_id"], Path(r["filename"]).name)
              for r in report["results"] if r["issue_severity"] == "MEDIUM"}
    # Triaged, NOT suppressed. A `# nosec` comment would make these disappear from every
    # future scan, which is how a real finding gets buried next to an accepted one. They
    # stay visible in the report and are pinned here with the reason instead.
    known = {
        ("B104", "node.py"),    # binds 0.0.0.0: deliberate and configurable, a witness
                                # nobody can reach degrades every operation to
                                # SOFTWARE_KEY. See §17.
        ("B310", "client.py"),  # urlopen: MITIGATED by _check_url, which rejects every
                                # scheme but http/https before urlopen sees the URL.
                                # bandit cannot see the guard; test_a_non_http_witness_url
                                # _is_refused proves it, and this row keeps the finding
                                # in view rather than hiding it.
    }
    assert medium <= known, f"new MEDIUM findings: {sorted(medium - known)}"
