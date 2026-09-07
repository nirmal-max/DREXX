import sys
sys.path.insert(0, "src")

from nist.models import Device
from nist.policy import plan


def test_ready_special():
    d = Device(
        "/dev/x", "HDD", size_bytes=100,
        capabilities={
            "nist_qualified": True,
            "native_sanitize": True,
            "purge_qualified": True,
            "crypto_erase": True,
            "key_management_qualified": True,
            "nvme_sanitize": True,
            "block_erase": True,
            "ata_secure_erase": True,
            "ata_sanitize": True,
            "enhanced": True,
            "scsi_sanitize": True,
            "destruction_equipment_qualified": True,
            "qualified_media": ["HDD"],
        },
    )
    assert plan(d).outcome == "PLANNED"
    assert plan(d).assurance == "PURGE"


def test_unqualified_purge_is_blocked():
    d = Device("/dev/x", "HDD", size_bytes=100, capabilities={"native_sanitize": True})
    assert plan(d).outcome == "BLOCKED"


def test_destroy_requires_qualified_equipment():
    d = Device("/dev/x", "HDD", size_bytes=100, capabilities={})
    assert plan(d, "DESTROY").outcome == "BLOCKED"


def test_clear_requires_approved_technique():
    d = Device("/dev/x", "HDD", size_bytes=100, capabilities={})
    assert plan(d, "CLEAR").outcome == "BLOCKED"
