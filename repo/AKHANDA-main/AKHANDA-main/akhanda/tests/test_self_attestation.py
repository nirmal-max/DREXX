"""Self-attestation, every entry names the build that wrote it (ENTRY_VERSION 3).

The claim under test is narrow and worth stating precisely, because the neighbouring
claims are ones this project must NOT make:

    IT DOES     say which build produced an entry, as a signed fact.
    IT DOES NOT say that build was correct, validated, or approved.
    IT DOES NOT change its own behaviour. A self-modifying forensic tool is a process the
                certificate cannot describe, and BSA 2023 s.63(4) requires the certificate
                to describe the process.

What this buys is that validation starts to mean something. A validation report is about a
specific code digest; before this field, an entry could not be checked against one.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from attestation import tiers, toolref  # noqa: E402
from attestation.core import ENTRY_VERSION, HASHED_FIELDS, Chain, entry_hash  # noqa: E402
from attestation.keys import load_or_create_operator_key  # noqa: E402

SRC = Path(__file__).resolve().parents[1] / "src"


@pytest.fixture(scope="module")
def op_key():
    return load_or_create_operator_key()


@pytest.fixture
def entry(op_key):
    c = Chain(chain_id="attest-test")
    return c.append(
        op_type="ERASE", target_ref="/dev/x", timestamp="2026-09-01T00:00:00Z",
        method="Clear", result_hash="00" * 32, operator_decl="d", concur_decl="",
        custody_tier=tiers.SOFTWARE_KEY, operator_key=op_key, outcome="VERIFIED")


# ------------------------------------------------------------------ it is SIGNED, not beside

def test_tool_ref_is_in_the_signed_preimage():
    """Beside the signature it could be edited to make one build's output look like
    another's -- the same defect `outcome` was moved inside the preimage to fix (G2)."""
    assert "tool_ref" in HASHED_FIELDS


def test_the_entry_version_was_bumped():
    """A field added without a version bump lets an old verifier mis-read a new chain.

    Bumped to 4 when place_ref and the three AMEND fields were added. The companion
    guarantee, that v3 chains still verify rather than being refused, is tested in
    tests/test_amend.py::test_a_real_v3_chain_still_verifies_under_this_build.
    """
    assert ENTRY_VERSION == "4"


def test_editing_tool_ref_breaks_the_entry_hash(entry):
    original = entry.entry_hash
    entry.tool_ref = "akhanda/9.9.9+deadbeefdeadbeef"
    assert entry.recompute_hash() != original


def test_an_entry_records_a_real_tool_ref(entry):
    assert entry.tool_ref == toolref.tool_ref()
    assert entry.tool_ref.startswith("akhanda/")
    assert "+" in entry.tool_ref


def test_the_caller_cannot_supply_the_tool_ref(op_key):
    """A tool_ref passed in by the operator would be a claim about the tool made by the
    party the tool exists to constrain. It is read at the moment of signing, or not at all.
    """
    import inspect
    assert "tool_ref" not in inspect.signature(Chain.append).parameters


# ------------------------------------------------------------------ the digest is honest

def test_the_digest_is_stable_across_calls():
    assert toolref.code_digest() == toolref.code_digest()


def test_the_digest_covers_the_modules_that_can_change_an_entry():
    """Every attested module must exist. A path that quietly stopped matching a real file
    would be hashed as absent forever, and the digest would stop tracking that module."""
    missing = [m for m in toolref.ATTESTED_MODULES if not (SRC / m).is_file()]
    assert not missing, f"attested modules not found on disk: {missing}"


def test_every_engine_that_writes_a_result_is_attested():
    """The list is hand-maintained, so this pins it against the package on disk.

    The real risk is not a wrong entry in the list -- it is a NEW module that affects what
    an entry says and never gets added. This catches the load-bearing subset.
    """
    must_cover = {
        "attestation/core.py", "attestation/canonical.py", "attestation/tiers.py",
        "attestation/policy.py", "erasure/engine.py", "recovery/engine.py",
    }
    assert must_cover <= set(toolref.ATTESTED_MODULES)


def test_changing_attested_source_changes_the_digest(tmp_path, monkeypatch):
    """The whole field is worthless if the digest does not move when the code moves."""
    before = toolref.code_digest()

    fake = tmp_path / "src"
    for rel in toolref.ATTESTED_MODULES:
        dst = fake / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes((SRC / rel).read_bytes())
    target = fake / "recovery" / "engine.py"
    target.write_bytes(target.read_bytes() + b"\n# one added comment\n")

    monkeypatch.setattr(toolref, "_SRC", fake)
    toolref.code_digest.cache_clear()
    try:
        assert toolref.code_digest() != before
    finally:
        monkeypatch.undo()
        toolref.code_digest.cache_clear()


def test_a_deleted_module_changes_the_digest(tmp_path, monkeypatch):
    """Absence is hashed, not skipped. Removing a module must be detectable in the tool's
    own self-description, or deleting code would be the one change it cannot see."""
    before = toolref.code_digest()
    fake = tmp_path / "src"
    for rel in toolref.ATTESTED_MODULES:
        if rel == "anchor/ots.py":
            continue
        dst = fake / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes((SRC / rel).read_bytes())

    monkeypatch.setattr(toolref, "_SRC", fake)
    toolref.code_digest.cache_clear()
    try:
        assert toolref.code_digest() != before
    finally:
        monkeypatch.undo()
        toolref.code_digest.cache_clear()


def test_line_endings_do_not_change_the_digest(tmp_path, monkeypatch):
    """A chain written on Linux must verify on Windows. Git rewrites line endings on
    checkout, so a raw byte digest would report a different tool for identical code --
    a false alarm exactly where cross-platform verification matters most."""
    def build(transform):
        root = tmp_path / transform.__name__
        for rel in toolref.ATTESTED_MODULES:
            dst = root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(transform((SRC / rel).read_bytes()))
        return root

    def lf(b):
        return b.replace(b"\r\n", b"\n")

    def crlf(b):
        return lf(b).replace(b"\n", b"\r\n")

    digests = []
    for style in (lf, crlf):
        monkeypatch.setattr(toolref, "_SRC", build(style))
        toolref.code_digest.cache_clear()
        digests.append(toolref.code_digest())
        monkeypatch.undo()
    toolref.code_digest.cache_clear()
    assert digests[0] == digests[1]


# ------------------------------------------------------------------ comparison is honest

def test_an_entry_from_this_build_is_recognised(entry):
    result = toolref.compare(entry.tool_ref)
    assert result["same_build"] is True


def test_a_different_build_is_reported_not_rejected():
    """Chains outlive builds. An entry written by last month's version is normal, and
    this field exists to make that visible rather than to forbid it."""
    result = toolref.compare("akhanda/0.0.9+1111111111111111")
    assert result["known"] is True
    assert result["same_build"] is False
    assert "expected" in result["reason"].lower()


def test_same_version_different_digest_is_called_out_specifically():
    """The dangerous case: the source changed and the version did not. A validation
    result measured against one of the two digests does not cover the other."""
    same_version_other_digest = f"akhanda/{toolref.TOOL_VERSION}+0000000000000000"
    result = toolref.compare(same_version_other_digest)
    assert result["same_build"] is False
    assert "without the version being bumped" in result["reason"]


def test_an_entry_with_no_tool_ref_is_unknown_not_trusted():
    result = toolref.compare("")
    assert result["known"] is False
    assert result["same_build"] is False


def test_describe_states_that_naming_is_not_validating():
    """The one sentence that keeps this feature from becoming an overclaim."""
    meaning = toolref.describe()["meaning"].lower()
    assert "does not mean the tool is validated" in meaning


# ------------------------------------------------------------------ it is NOT self-modifying

def test_the_tool_does_not_rewrite_its_own_attested_source():
    """Stated as a test because it is the boundary the whole design rests on.

    Nothing in the attested set may open its own package for writing. A tool that edits
    itself is a process the certificate cannot describe, which is precisely what makes
    self-improvement inadmissible rather than merely risky.
    """
    import re
    suspicious = re.compile(r"""open\([^)]*['"][wa]b?['"]|\.write_(text|bytes)\(""")
    offenders = []
    for rel in toolref.ATTESTED_MODULES:
        src = (SRC / rel).read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(src.splitlines(), 1):
            if suspicious.search(line) and "__file__" in line:
                offenders.append(f"{rel}:{lineno}")
    assert not offenders, f"attested module writes to its own source: {offenders}"


def test_the_digest_is_computed_from_source_not_asserted():
    """A hardcoded digest would be a claim, not a measurement."""
    src = (SRC / "attestation" / "toolref.py").read_text(encoding="utf-8")
    assert "hashlib.sha256" in src
    assert toolref.code_digest() not in src, (
        "the current digest appears as a literal in toolref.py; it must be computed")
