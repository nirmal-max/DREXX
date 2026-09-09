"""Shared fixtures. Keeps `src` importable and every test isolated from the real
~/.akhanda directory, a test that writes into the operator's live chain is a test that
destroys evidence."""

import os
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from attestation.core import Chain  # noqa: E402


@pytest.fixture()
def akhanda_home(tmp_path, monkeypatch):
    """Point AKHANDA_HOME at a temp dir for the duration of one test."""
    home = tmp_path / "akhanda_home"
    home.mkdir()
    monkeypatch.setenv("AKHANDA_HOME", str(home))
    return home


@pytest.fixture()
def op_key():
    return Ed25519PrivateKey.generate()


@pytest.fixture()
def concur_key():
    return Ed25519PrivateKey.generate()


@pytest.fixture()
def sample_chain(op_key):
    """Three entries, one operator key, no witness. The baseline every test starts from."""
    c = Chain(chain_id="testchain00000001")
    c.append("RECOVER", "disk-A", "2026-01-01T10:00:00Z", "Clear",
             "aa" * 32, "operator: J. Rao", "expert: pending", "SOFTWARE_KEY", op_key)
    c.append("RECOVER", "disk-A", "2026-01-01T10:05:00Z", "Clear",
             "bb" * 32, "operator: J. Rao", "expert: pending", "SOFTWARE_KEY", op_key)
    c.append("ERASE", "disk-B", "2026-01-01T11:00:00Z", "Clear",
             "cc" * 32, "operator: J. Rao", "expert: pending", "SOFTWARE_KEY", op_key)
    return c


def real_image_bytes(fmt: str = "JPEG", size=(24, 18)) -> bytes:
    """A genuinely encoded image, for tests that need the carver to find something.

    A hand-built byte pattern, an SOI marker, some filler, an EOI marker, is not a
    JPEG. It has no quantisation table, no frame header, and no start-of-scan, so no
    decoder would accept it. The carver's structural validators reject those patterns,
    and correctly so: accepting them is exactly what produced 2% precision against the
    NIST CFReDS corpus. Any test that needs a carvable file uses this instead.
    """
    from PIL import Image
    import io
    im = Image.new("RGB", size)
    for x in range(size[0]):
        for y in range(size[1]):
            im.putpixel((x, y), ((x * 11) % 256, (y * 7) % 256, ((x + y) * 3) % 256))
    buf = io.BytesIO()
    im.save(buf, format=fmt)
    return buf.getvalue()


@pytest.fixture()
def evidence_image(tmp_path):
    """A raw image with one real JPEG and one real PNG buried in slack space."""
    import os
    blob = (os.urandom(512) + real_image_bytes("JPEG") + os.urandom(512)
            + real_image_bytes("PNG") + os.urandom(512))
    p = tmp_path / "evidence.dd"
    p.write_bytes(blob)
    return p
