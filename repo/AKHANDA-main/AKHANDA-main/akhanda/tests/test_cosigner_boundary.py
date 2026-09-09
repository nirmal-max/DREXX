"""
Does the co-signer host actually provide a key-custody boundary?

The project's central claim is one sentence in `src/witness/node.py`: the concurring key
is held on a machine "which the workstation never sees". That is either true or the whole
design is decoration, so it gets a test rather than a paragraph.

Measured on the development machine: **WSL2 provides no boundary at all.** An
unprivileged Windows user reads and writes root-owned 0600 files inside the distro through
`\\wsl.localhost`, and `wsl --user root --exec` runs as uid 0 with no password even when
the root account is locked. Full evidence in `docs/COSIGNER_HOSTING.md`.

These tests run only on Windows with a WSL distro present, and skip loudly otherwise. They
are written to FAIL if the boundary ever appears, because that would mean Microsoft
changed the model and `docs/COSIGNER_HOSTING.md` needs rewriting, which is exactly the
kind of silent drift a stale document hides.
"""

import os
import platform
import shutil
import subprocess

import pytest

IS_WINDOWS = platform.system() == "Windows"
HAVE_WSL = shutil.which("wsl") is not None


def _distros() -> list[str]:
    if not (IS_WINDOWS and HAVE_WSL):
        return []
    try:
        out = subprocess.run(["wsl", "--list", "--quiet"], capture_output=True,
                             timeout=30).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    text = out.decode("utf-16-le", errors="ignore")
    if "\x00" in text or not text.strip():
        text = out.decode("utf-8", errors="ignore").replace("\x00", "")
    return [d.strip() for d in text.splitlines() if d.strip()]


DISTROS = _distros()

needs_wsl = pytest.mark.skipif(
    not DISTROS,
    reason="no WSL distro on this machine; the co-signer boundary claim was NOT measured. "
           "See docs/COSIGNER_HOSTING.md for what was measured on the dev laptop.")


@pytest.fixture(scope="module")
def distro() -> str:
    return DISTROS[0]


def _wsl(distro: str, *args, user: str = "root") -> subprocess.CompletedProcess:
    return subprocess.run(["wsl", "-d", distro, "--user", user, "--exec", *args],
                          capture_output=True, text=True, timeout=90)


# ─────────────────────────────────────────────── the escalation Microsoft documents

@needs_wsl
def test_unelevated_windows_user_becomes_root_without_a_password(distro):
    """`wsl --user root` is a supported feature, not a misconfiguration. Controlling
    which Linux user a Windows user may become is currently unsupported by Microsoft."""
    import ctypes
    assert ctypes.windll.shell32.IsUserAnAdmin() == 0, \
        "run this test unelevated; elevated proves nothing"

    r = _wsl(distro, "id", "-u")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "0", (
        "uid is no longer 0, if WSL gained a user boundary, "
        "docs/COSIGNER_HOSTING.md must be rewritten")


@needs_wsl
def test_root_shell_works_even_with_the_root_account_locked(distro):
    """Locking root inside the distro does not remove the Windows-side path to it."""
    _wsl(distro, "bash", "-c", "passwd -l root >/dev/null 2>&1 || true")
    status = _wsl(distro, "bash", "-c", "passwd -S root").stdout
    assert " L " in status or status.split()[1:2] == ["L"], f"root not locked: {status}"
    assert _wsl(distro, "id", "-un").stdout.strip() == "root"


# ───────────────────────────────────── the 9P share ignores Linux permissions entirely

@needs_wsl
def test_windows_reads_a_root_only_key_out_of_the_distro(distro, tmp_path):
    """The exact claim under test: 'the workstation never sees this key'."""
    secret = "WITNESS-KEY-CANARY-" + os.urandom(4).hex()
    _wsl(distro, "bash", "-c",
         f"mkdir -p /root/.akhanda-boundary-test && "
         f"printf '%s' '{secret}' > /root/.akhanda-boundary-test/k.pem && "
         f"chmod 600 /root/.akhanda-boundary-test/k.pem")
    try:
        # a non-root user inside Linux is correctly refused
        denied = _wsl(distro, "bash", "-c",
                      "id -u nobody >/dev/null 2>&1 && "
                      "su nobody -s /bin/sh -c "
                      "'cat /root/.akhanda-boundary-test/k.pem' 2>&1 || true")
        assert "Permission denied" in denied.stdout or denied.stdout.strip() == "", \
            f"POSIX permissions did not apply inside the distro: {denied.stdout!r}"

        # and the Windows side reads it anyway
        unc = rf"\\wsl.localhost\{distro}\root\.akhanda-boundary-test\k.pem"
        assert os.path.exists(unc), f"{unc} not reachable"
        with open(unc, "r", encoding="utf-8") as fh:
            assert fh.read().strip() == secret, (
                "the key is no longer readable from Windows, if WSL gained a boundary, "
                "docs/COSIGNER_HOSTING.md must be rewritten")
    finally:
        _wsl(distro, "rm", "-rf", "/root/.akhanda-boundary-test")


@needs_wsl
def test_windows_can_forge_the_witness_head_log(distro):
    """The one that breaks Act 3 of the demo.

    `compare_witness_head()` detects a full-chain rewrite BECAUSE the operator cannot
    write to the witness's own record. On WSL2 they can, with one write. The detection
    does not degrade, it stops working.
    """
    _wsl(distro, "bash", "-c",
         "mkdir -p /root/.akhanda-boundary-test && "
         "printf 'REAL-HEAD\\n' > /root/.akhanda-boundary-test/witness_log.jsonl && "
         "chmod 600 /root/.akhanda-boundary-test/witness_log.jsonl")
    try:
        unc = rf"\\wsl.localhost\{distro}\root\.akhanda-boundary-test\witness_log.jsonl"
        with open(unc, "w", encoding="utf-8") as fh:
            fh.write("FORGED-HEAD\n")
        seen = _wsl(distro, "cat", "/root/.akhanda-boundary-test/witness_log.jsonl")
        assert "FORGED-HEAD" in seen.stdout, (
            "the head log is no longer writable from Windows, "
            "docs/COSIGNER_HOSTING.md must be rewritten")
    finally:
        _wsl(distro, "rm", "-rf", "/root/.akhanda-boundary-test")


# ──────────────────────────────────────── the documentation must state the conclusion

def test_the_hosting_document_records_the_measurement():
    """A finding that lives only in a chat log is a finding that will be forgotten."""
    from pathlib import Path
    doc = Path(__file__).resolve().parents[1] / "docs" / "COSIGNER_HOSTING.md"
    assert doc.is_file(), "docs/COSIGNER_HOSTING.md is missing"
    text = doc.read_text(encoding="utf-8")
    assert "WSL2 provides no key-custody boundary" in text
    assert "It is not a co-signer" in text
    assert "VT-x is enabled" in text


def test_the_witness_node_does_not_promise_a_boundary_it_may_not_have():
    """`node.py` says the workstation never sees the key. That is true on a separate
    machine and false on WSL2, so the file must point at where that is decided."""
    from pathlib import Path
    src = Path(__file__).resolve().parents[1] / "src" / "witness" / "node.py"
    text = src.read_text(encoding="utf-8")
    assert "COSIGNER_HOSTING" in text, (
        "witness/node.py claims the workstation never sees the concurring key without "
        "pointing at docs/COSIGNER_HOSTING.md, where that claim is measured per host")
