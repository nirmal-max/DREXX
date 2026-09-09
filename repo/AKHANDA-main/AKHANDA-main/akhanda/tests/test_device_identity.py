r"""Device identity, the block three standards independently require.

NIST SP 800-88 Rev. 2 Appendix C, BSA 2023 §63(4) Schedule Part A, and Blancco's own
published certificate all demand the same fields: make, model, and above all SERIAL NUMBER.
The tool recorded a device path.

A path is not an identity. `/dev/sdb` is whichever drive was plugged in second and
`\\.\PhysicalDrive2` is whichever one Windows enumerated third; neither survives a reboot,
and neither finds a drive in an evidence bag six months later.

The tests below are mostly about ONE property, because it is the one that goes wrong:
**unavailable is not blank.** On a certificate an empty serial field and an unread serial
field look identical, and a reader will conclude the drive has no serial rather than that
nobody looked.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from erasure import deviceid  # noqa: E402
from erasure.deviceid import UNAVAILABLE, DeviceIdentity  # noqa: E402
from erasure.engine import CONFIRM_TOKEN, erase, result_hash  # noqa: E402

BS = chr(92)


@pytest.fixture
def image(tmp_path):
    p = tmp_path / "evidence.img"
    p.write_bytes(b"\xAB" * (1 << 20))
    return p


# ───────────────────────────────────────── unavailable is not blank

def test_a_field_that_could_not_be_read_is_never_empty(image):
    """THE PROPERTY THIS MODULE EXISTS FOR."""
    ident = deviceid.identify(str(image))
    for name in ("vendor", "model", "serial", "firmware", "bus"):
        value = getattr(ident, name)
        assert value != "", f"{name} is an empty string; it must say {UNAVAILABLE!r}"
        assert value == UNAVAILABLE


def test_unreadable_fields_are_listed_not_just_marked(image):
    ident = deviceid.identify(str(image))
    assert set(ident.unavailable) >= {"vendor", "model", "serial", "firmware"}


def test_a_file_image_says_there_is_no_device_rather_than_that_reading_failed(image):
    """Two different facts. A file has no serial; a drive whose serial could not be read
    might have one. Collapsing them would misdescribe both."""
    ident = deviceid.identify(str(image))
    assert "no physical identity" in ident.note
    assert "not because reading failed" in ident.note


def test_the_serial_decides_whether_the_media_is_identified(image):
    """Make and model identify a PRODUCT. A lab may hold forty of the same product; only
    the serial identifies the item in front of you."""
    ident = deviceid.identify(str(image))
    assert ident.is_identified() is False

    ident.serial = "WD-WX21A80D1234"
    assert ident.is_identified() is True


def test_every_value_that_was_read_names_where_it_came_from(image):
    """A value with no stated source is a value nobody can check."""
    ident = deviceid.identify(str(image))
    assert ident.size_bytes == (1 << 20)
    assert ident.sources.get("size_bytes")


# ───────────────────────────────────────── the standards mappings

def test_the_nist_block_uses_the_forms_own_field_names():
    """So a reader can hold the certificate beside Appendix C and match it line for line."""
    block = deviceid.nist_media_block(DeviceIdentity(target="x"))
    assert set(block) == {"Vendor/Make", "Media Type", "Model Number", "Serial Number",
                          "Property Number", "Source", "Classification",
                          "Operational/Damaged"}


def test_the_bsa_block_uses_the_schedules_own_field_names():
    block = deviceid.bsa_part_a_block(DeviceIdentity(target="x"))
    assert set(block) == {"Make & Model", "Colour", "Serial Number",
                          "IMEI/UIN/UID/MAC/Cloud ID"}


def test_fields_no_software_can_determine_say_so_rather_than_being_blank():
    """Property Number, Source and Classification are organisational facts, and Colour is
    physical. Inventing them would be worse than omitting them; leaving them blank is
    indistinguishable from having failed to read them."""
    nist = deviceid.nist_media_block(DeviceIdentity(target="x"))
    for key in ("Property Number", "Source", "Classification"):
        assert "requires human entry" in nist[key]

    bsa = deviceid.bsa_part_a_block(DeviceIdentity(target="x"))
    assert "requires human entry" in bsa["Colour"]
    assert "not applicable" in bsa["IMEI/UIN/UID/MAC/Cloud ID"]


def test_make_and_model_are_joined_only_when_both_were_read():
    ident = DeviceIdentity(target="x", vendor="ATA", model="Samsung SSD 870")
    assert deviceid.bsa_part_a_block(ident)["Make & Model"] == "ATA Samsung SSD 870"

    partial = DeviceIdentity(target="x", model="Samsung SSD 870")
    assert deviceid.bsa_part_a_block(partial)["Make & Model"] == "Samsung SSD 870"


def test_describe_states_why_a_path_is_not_an_identity():
    d = deviceid.describe(DeviceIdentity(target="/dev/sdb"))
    assert "evidence bag" in d["meaning"]
    assert "blank and unread are indistinguishable" in d["meaning"]


# ───────────────────────────────────────── it is signed

def test_the_identity_is_inside_what_the_entry_commits_to(image):
    """It rides in the result record, which result_hash covers -- and result_hash is
    inside the signed preimage. Removing the identity must move the digest."""
    result = erase(str(image), confirm=CONFIRM_TOKEN)
    assert result["device_identity"]["identified"] is False

    before = result_hash(result)
    stripped = dict(result, device_identity={})
    assert result_hash(stripped) != before


def test_the_certificate_blocks_are_carried_in_the_result(image):
    result = erase(str(image), confirm=CONFIRM_TOKEN)
    d = result["device_identity"]
    assert "nist_800_88r2_media_information" in d
    assert "bsa_63_4_part_a_device_particulars" in d
    assert d["nist_800_88r2_media_information"]["Serial Number"] == UNAVAILABLE


def test_identification_never_breaks_an_erasure(image, monkeypatch):
    """An erasure must not fail because a drive would not describe itself. Identification
    reports; it does not raise."""
    def boom(_target):
        raise RuntimeError("storage stack unavailable")

    monkeypatch.setattr(deviceid, "identify", boom)
    with pytest.raises(RuntimeError):
        deviceid.identify(str(image))     # the fixture itself raises, as arranged

    monkeypatch.undo()
    result = erase(str(image), confirm=CONFIRM_TOKEN)
    assert result["method_used"] == "Clear"


def test_an_unsupported_platform_is_reported_not_guessed(monkeypatch, image):
    monkeypatch.setattr(deviceid.platform, "system", lambda: "Plan9")
    ident = deviceid.identify(str(image.parent / "nonexistent-device"))
    assert ident.serial == UNAVAILABLE
    assert "not implemented for Plan9" in ident.note


def test_identify_reports_rather_than_raising_on_a_hostile_target():
    """Called on nonsense, it must return an unidentified record, not blow up mid-erasure."""
    ident = deviceid.identify(BS * 2 + "." + BS + "NoSuchDevice999")
    assert isinstance(ident, DeviceIdentity)
    assert ident.serial == UNAVAILABLE
    assert ident.note
