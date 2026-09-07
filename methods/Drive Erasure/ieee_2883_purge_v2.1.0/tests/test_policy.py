import sys
sys.path.insert(0, "src")
from ieee.models import Device
from ieee.policy import plan


def D(**kw):
    x = Device("/dev/test", "HDD", size_bytes=100, capabilities={})
    return Device(
        x.path,
        kw.get("media_type", x.media_type),
        size_bytes=kw.get("size_bytes", 100),
        mounted=kw.get("mounted", False),
        system_disk=kw.get("system_disk", False),
        capabilities=kw.get("capabilities", {}),
    )


def test_mount_block():
    assert plan(D(mounted=True)).outcome == "BLOCKED"


def test_system_block():
    assert plan(D(system_disk=True)).outcome == "BLOCKED"


def test_unqualified_device_is_blocked():
    assert plan(D(capabilities={"native_sanitize": True})).outcome == "BLOCKED"


def test_qualified_native_device_is_planned():
    d = D(capabilities={"native_sanitize": True, "purge_qualified": True})
    assert plan(d).method == "DEVICE_NATIVE_SANITIZE"
    assert plan(d).assurance == "PURGE"
