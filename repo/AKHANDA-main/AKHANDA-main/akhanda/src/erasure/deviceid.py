r"""Physical identity of the media, what the certificate has to name.

WHY THIS EXISTS. Three independent authorities require the same block of fields, and the
tool recorded none of them. It recorded a device *path*.

    NIST SP 800-88 Rev. 2, Appendix C, Fig. 2, "MEDIA INFORMATION"
        Vendor/Make · Media Type · Model Number · Serial Number · Property Number ·
        Source · Classification · Operational/Damaged

    BSA 2023 §63(4), Schedule Part A
        Make & Model · Colour · Serial Number · IMEI/UIN/UID/MAC/Cloud ID

    Blancco's own certificate, "Asset Details"
        Manufacturer · Chassis type · Model/market name · Colour · Serial numbers

A path is not an identity. `/dev/sdb` is whichever drive was plugged in second, and
`\\.\PhysicalDrive2` is whichever one Windows enumerated third. Neither survives a reboot,
and neither identifies a drive sitting in an evidence bag six months later. A certificate
that says "we erased /dev/sdb" identifies nothing.

    identify(target) -> DeviceIdentity
    nist_media_block(identity)   -> the Rev. 2 Appendix C fields
    bsa_part_a_block(identity)   -> the §63(4) Schedule Part A fields

UNAVAILABLE IS NOT BLANK, AND THAT IS THE WHOLE DESIGN. A serial number that could not be
read must never appear as an empty string beside one that was read successfully. On a
certificate the two are indistinguishable, and the reader will assume the drive has no
serial rather than that nobody looked. Every field here is either a value with a stated
source, or an explicit "unavailable" with the reason.

WHERE THIS IS SIGNED. Device identity goes into the erasure RESULT RECORD, not into a new
hashed entry field. `result_hash` is already inside the signed preimage and the stored
result is re-verified against it, so the identity is tamper-evident without breaking the
entry format, a 17th field would mean ENTRY_VERSION 4 and a synchronised change across
three verifier implementations, to gain a property the result record already provides.
"""
from __future__ import annotations

import ctypes
import os
import platform
import subprocess
from ctypes import wintypes
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

UNAVAILABLE = "unavailable"

# Windows IOCTL_STORAGE_QUERY_PROPERTY
_IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400
_StorageDeviceProperty = 0
_PropertyStandardQuery = 0
_GENERIC_READ = 0x80000000
_FILE_SHARE = 0x00000001 | 0x00000002
_OPEN_EXISTING = 3
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

_BUS_TYPES = {
    0: "unknown", 1: "scsi", 2: "atapi", 3: "ata", 4: "1394", 5: "ssa", 6: "fibre",
    7: "usb", 8: "raid", 9: "iscsi", 10: "sas", 11: "sata", 12: "sd", 13: "mmc",
    14: "virtual", 15: "file-backed-virtual", 17: "nvme",
}


@dataclass
class DeviceIdentity:
    """What could actually be read about the physical media, and what could not."""
    target: str
    vendor: str = UNAVAILABLE
    model: str = UNAVAILABLE
    serial: str = UNAVAILABLE
    firmware: str = UNAVAILABLE
    bus: str = UNAVAILABLE
    media_type: str = UNAVAILABLE
    size_bytes: Optional[int] = None
    removable: Optional[bool] = None
    # Provenance per field: which interface produced it. A value with no stated source is
    # a value nobody can check.
    sources: dict = field(default_factory=dict)
    unavailable: list = field(default_factory=list)
    method: str = ""
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def is_identified(self) -> bool:
        """Enough to name this drive in an evidence bag six months from now?

        Serial number is the load-bearing field: make and model identify a PRODUCT, and a
        lab may hold forty of the same product. Only the serial identifies the item.
        """
        return self.serial != UNAVAILABLE


def _clean(raw: bytes) -> str:
    text = raw.decode("latin-1", "replace").strip().strip("\x00").strip()
    return " ".join(text.split())


# ─────────────────────────────────────────────────────────────── Windows

class _STORAGE_PROPERTY_QUERY(ctypes.Structure):
    _fields_ = [("PropertyId", ctypes.c_int), ("QueryType", ctypes.c_int),
                ("AdditionalParameters", ctypes.c_byte * 1)]


class _STORAGE_DEVICE_DESCRIPTOR(ctypes.Structure):
    _fields_ = [("Version", wintypes.DWORD), ("Size", wintypes.DWORD),
                ("DeviceType", ctypes.c_byte), ("DeviceTypeModifier", ctypes.c_byte),
                ("RemovableMedia", ctypes.c_byte), ("CommandQueueing", ctypes.c_byte),
                ("VendorIdOffset", wintypes.DWORD), ("ProductIdOffset", wintypes.DWORD),
                ("ProductRevisionOffset", wintypes.DWORD),
                ("SerialNumberOffset", wintypes.DWORD),
                ("BusType", ctypes.c_int), ("RawPropertiesLength", wintypes.DWORD),
                ("RawDeviceProperties", ctypes.c_byte * 1)]


def _identify_windows(target: str, ident: DeviceIdentity) -> DeviceIdentity:
    """IOCTL_STORAGE_QUERY_PROPERTY on the device handle.

    Deliberately not WMI: WMI needs a service running, can be slow or disabled, and
    returns a different serial format than the drive itself reports. This asks the
    storage stack directly.
    """
    ident.method = "IOCTL_STORAGE_QUERY_PROPERTY"
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                ctypes.c_void_p]
    k32.CreateFileW.restype = ctypes.c_void_p
    k32.DeviceIoControl.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
                                    wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                    ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    k32.DeviceIoControl.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [ctypes.c_void_p]

    # Read-only, shared. Identification must never require write access -- asking for it
    # on an evidence drive is exactly the wrong instinct.
    handle = k32.CreateFileW(target, _GENERIC_READ, _FILE_SHARE, None,
                             _OPEN_EXISTING, 0, None)
    if handle == _INVALID_HANDLE_VALUE or handle is None:
        err = ctypes.get_last_error()
        ident.note = (f"cannot open {target} for identification (error {err}); "
                      "an elevated shell is normally required for a physical drive")
        ident.unavailable = ["vendor", "model", "serial", "firmware", "bus", "media_type"]
        return ident

    try:
        query = _STORAGE_PROPERTY_QUERY()
        query.PropertyId = _StorageDeviceProperty
        query.QueryType = _PropertyStandardQuery
        buf = ctypes.create_string_buffer(4096)
        returned = wintypes.DWORD()

        ok = k32.DeviceIoControl(handle, _IOCTL_STORAGE_QUERY_PROPERTY,
                                 ctypes.byref(query), ctypes.sizeof(query),
                                 buf, ctypes.sizeof(buf), ctypes.byref(returned), None)
        if not ok:
            ident.note = f"IOCTL_STORAGE_QUERY_PROPERTY failed ({ctypes.get_last_error()})"
            ident.unavailable = ["vendor", "model", "serial", "firmware", "bus"]
            return ident

        desc = ctypes.cast(buf, ctypes.POINTER(_STORAGE_DEVICE_DESCRIPTOR)).contents
        raw = buf.raw

        def at(offset: int) -> str:
            if not offset or offset >= len(raw):
                return UNAVAILABLE
            end = raw.find(b"\x00", offset)
            return _clean(raw[offset:end if end != -1 else len(raw)]) or UNAVAILABLE

        ident.vendor = at(desc.VendorIdOffset)
        ident.model = at(desc.ProductIdOffset)
        ident.firmware = at(desc.ProductRevisionOffset)
        ident.serial = at(desc.SerialNumberOffset)
        ident.bus = _BUS_TYPES.get(desc.BusType, f"bustype-{desc.BusType}")
        ident.removable = bool(desc.RemovableMedia)
        ident.media_type = ("removable" if desc.RemovableMedia else "fixed") + f"/{ident.bus}"
        for name in ("vendor", "model", "firmware", "serial"):
            (ident.sources.__setitem__(name, "IOCTL_STORAGE_QUERY_PROPERTY")
             if getattr(ident, name) != UNAVAILABLE else ident.unavailable.append(name))
        ident.sources["bus"] = "STORAGE_DEVICE_DESCRIPTOR.BusType"
    finally:
        k32.CloseHandle(handle)
    return ident


# ─────────────────────────────────────────────────────────────── Linux

def _identify_linux(target: str, ident: DeviceIdentity) -> DeviceIdentity:
    """sysfs. No external tools, no root beyond reading the device node."""
    ident.method = "/sys/block"
    name = Path(target).name
    base = Path("/sys/block") / name
    if not base.is_dir():
        ident.note = f"{target} is not a whole block device in /sys/block"
        ident.unavailable = ["vendor", "model", "serial", "firmware", "bus", "media_type"]
        return ident

    def read(rel: str) -> str:
        try:
            return (base / rel).read_text().strip() or UNAVAILABLE
        except OSError:
            return UNAVAILABLE

    for attr, rel in (("vendor", "device/vendor"), ("model", "device/model"),
                      ("firmware", "device/rev")):
        val = read(rel)
        setattr(ident, attr, val)
        if val != UNAVAILABLE:
            ident.sources[attr] = f"/sys/block/{name}/{rel}"
        else:
            ident.unavailable.append(attr)

    # Serial: sysfs exposes it in several places depending on the transport. Each is tried
    # and the one that answered is RECORDED, so the certificate can say where it came from.
    for rel in ("device/serial", "device/wwid", "wwid", "serial"):
        val = read(rel)
        if val != UNAVAILABLE:
            ident.serial = val
            ident.sources["serial"] = f"/sys/block/{name}/{rel}"
            break
    else:
        ident.unavailable.append("serial")

    try:
        ident.removable = (base / "removable").read_text().strip() == "1"
        rot = (base / "queue/rotational").read_text().strip() == "1"
        ident.media_type = ("HDD" if rot else "SSD/flash")
        ident.sources["media_type"] = f"/sys/block/{name}/queue/rotational"
    except OSError:
        ident.unavailable.append("media_type")

    try:
        sectors = int((base / "size").read_text().strip())
        ident.size_bytes = sectors * 512
        ident.sources["size_bytes"] = f"/sys/block/{name}/size x 512"
    except (OSError, ValueError):
        pass

    try:
        ident.bus = "usb" if "usb" in os.path.realpath(base) else "internal"
        ident.sources["bus"] = "realpath of the sysfs node"
    except OSError:
        ident.unavailable.append("bus")
    return ident


# ─────────────────────────────────────────────────────────────── entry point

def identify(target: str) -> DeviceIdentity:
    """Physical identity of `target`. Reports, never raises.

    A file image has no physical identity and says so, rather than reporting empty fields
    that would read as a drive with no serial number.
    """
    ident = DeviceIdentity(target=target)
    p = Path(target)

    if p.is_file():
        ident.method = "none"
        ident.media_type = "file image"
        ident.size_bytes = p.stat().st_size
        ident.sources["size_bytes"] = "file size"
        ident.unavailable = ["vendor", "model", "serial", "firmware", "bus"]
        ident.note = ("a file-backed image has no physical identity; these fields are "
                      "absent because there is no device, not because reading failed")
        return ident

    system = platform.system()
    try:
        if system == "Windows":
            return _identify_windows(target, ident)
        if system == "Linux":
            return _identify_linux(target, ident)
    except Exception as exc:  # noqa: BLE001 - identification must never break an erasure
        ident.note = f"identification failed: {type(exc).__name__}: {exc}"
        ident.unavailable = ["vendor", "model", "serial", "firmware", "bus", "media_type"]
        return ident

    ident.method = "none"
    ident.note = f"device identification is not implemented for {system}"
    ident.unavailable = ["vendor", "model", "serial", "firmware", "bus", "media_type"]
    return ident


# ─────────────────────────────────────────────────────────── standards mapping

def nist_media_block(ident: DeviceIdentity) -> dict:
    """The MEDIA INFORMATION block of NIST SP 800-88r2 Appendix C, Fig. 2.

    Field names are the form's own, so a reader can hold the certificate beside the
    standard and match them line for line. Fields the standard asks for that no software
    can determine, Property Number, Source, Classification, are marked as requiring
    human entry rather than left blank or invented.
    """
    return {
        "Vendor/Make": ident.vendor,
        "Media Type": ident.media_type,
        "Model Number": ident.model,
        "Serial Number": ident.serial,
        "Property Number": "requires human entry (organisational asset tag)",
        "Source": "requires human entry (custody origin)",
        "Classification": "requires human entry (sensitivity of the data)",
        "Operational/Damaged": ("damaged, unreadable regions were recorded"
                                if ident.note and "bad" in ident.note.lower()
                                else "requires human assessment"),
    }


def bsa_part_a_block(ident: DeviceIdentity) -> dict:
    """The device particulars of the BSA 2023 §63(4) Schedule, Part A.

    Colour and IMEI/UIN/UID cannot be read from a storage interface, colour is physical
    and IMEI belongs to a handset, not a disk. They are named as human-entry fields
    because the Schedule asks for them and a certificate that silently omits a statutory
    field is a certificate that fails on inspection.
    """
    return {
        "Make & Model": (f"{ident.vendor} {ident.model}"
                         if ident.vendor != UNAVAILABLE and ident.model != UNAVAILABLE
                         else ident.model),
        "Colour": "requires human entry (not readable from the storage interface)",
        "Serial Number": ident.serial,
        "IMEI/UIN/UID/MAC/Cloud ID": ("not applicable to block storage; required for "
                                      "handsets and networked devices"),
    }


def describe(ident: DeviceIdentity) -> dict:
    """Identity plus both statutory mappings, for the certificate generator."""
    return {
        "identity": ident.to_dict(),
        "identified": ident.is_identified(),
        "nist_800_88r2_media_information": nist_media_block(ident),
        "bsa_63_4_part_a_device_particulars": bsa_part_a_block(ident),
        "meaning": (
            "A device path names whichever drive was enumerated in that position at that "
            "moment; it does not identify a drive in an evidence bag six months later. "
            "Fields that could not be read are marked unavailable with a reason, never "
            "left blank, on a certificate, blank and unread are indistinguishable, and a "
            "reader will assume the drive has no serial rather than that nobody looked."),
    }
